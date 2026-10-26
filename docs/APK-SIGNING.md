# APK signing

blocktools Alpine packages (`scripts/package-native.sh apk`) are signed with one stable RSA key,
`blocktools@tsavo-2026.rsa`. This page says where it lives, how it is used and what has been measured.

## Where the key lives

- **Private key:** only in the maintainer's HashiCorp Vault, KV v2 mount `secret`, path
  `blocktools/apk-signing` (fields `private_key`, `key_name`). It is not in this repository, in CI
  secrets or in any runner.
- **Read access:** one AppRole, `blocktools-apk-signer`. Its policy `blocktools-apk-signer` grants `read`
  on `secret/data/blocktools/apk-signing` and nothing else. Its tokens have no default policy and live 5
  minutes (10 at most). Its role id and secret id sit in files mode 600 on the build host.
- **Public key:** [`packaging/alpine/keys/blocktools@tsavo-2026.rsa.pub`](../packaging/alpine/keys/blocktools@tsavo-2026.rsa.pub),
  stable URL
  `https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/alpine/keys/blocktools@tsavo-2026.rsa.pub`.
  SHA-256 of the file: `07ca30cd9d1d599342d87514b8585326a28880d62308fe9304007b62db66c09f`.

## How packages are signed

1. `scripts/package-native.sh apk` builds the package with `abuild`. abuild always signs, so the build
   uses a **throwaway** key generated inside the build container (`abuild-keygen -n`). A package with
   only that signature is a test artifact and is not trusted by anyone.
2. `scripts/apk-sign-host.sh FILE.apk...` runs on the build **host**, never inside a CI runner
   container (the self-hosted runners take every same-repo push and can reach the host Docker socket, so
   they hold no credential for this key). It logs in with the AppRole, reads the key into a 0600 file in
   a 0700 directory on `/dev/shm`, revokes its token, and runs `scripts/apk-sign-pkg.py` in a one-shot
   Alpine container with that directory mounted read-only. The helper drops the throwaway signature and
   signs the control section with RSA/SHA-1, as abuild does for packages. A trap shreds the key on exit.
   The key never goes to argv, stdout, stderr or the repository, and the script refuses if the AppRole
   files are missing, the login is refused, the policy does not cover the path, or `key_name` differs.
3. Each signed APK is then checked by `scripts/apk-verify.sh` with `apk verify` in a clean Alpine
   container whose `/etc/apk/keys` holds **only** the repository public key.

`scripts/package-native.sh apk` with `APK_SIGN_HOST=1` runs step 2 right after the build.

## Tests

`scripts/apk-sign-test.sh` uses a throwaway dev-mode Vault container (never the real Vault) and a
throwaway key, and checks:

- a package signed through Vault verifies against its public key;
- it does not verify against a different key;
- the script refuses, and leaves the package untouched, when the AppRole's policy does not cover the path;
- no PEM private-key block appears in the output;
- no key directory is left on `/dev/shm`.

`scripts/secret-scan.sh` also fails if any tracked file contains a PEM private-key block.

## Installing the key on Alpine

```sh
wget -O /etc/apk/keys/blocktools@tsavo-2026.rsa.pub \
  https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/alpine/keys/blocktools@tsavo-2026.rsa.pub
sha256sum /etc/apk/keys/blocktools@tsavo-2026.rsa.pub   # expect 07ca30cd...db66c09f, as above
apk add ./blocktools-<version>-r0.apk                     # a downloaded, signed package
```

The file name in `/etc/apk/keys` must stay `blocktools@tsavo-2026.rsa.pub`; apk finds the key by the
name recorded in the signature.

## APK repository (built, NOT live)

`scripts/apk-repo-build.sh OUTDIR signed.apk...` (Battleaxe host only) lays out `OUTDIR/x86_64/` with the
signed APKs and an `APKINDEX.tar.gz` built by `apk index` and signed by `abuild-sign` with the same Vault
key, through the same tmpfs, read-only-bind, output-suppressed flow as `apk-sign-host.sh`. It refuses
input APKs that do not verify against the repo key, and finishes by checking that an Alpine container
trusting only the repo key accepts the index and one with no key flags it UNTRUSTED.

Intended hosting: GitHub Pages from a `gh-pages` branch pushed from the Battleaxe host (the signed files
exist only there; CI runners never get the key). Intended repository URL:
`https://tsavo.github.io/blocktools/alpine` (with `x86_64/APKINDEX.tar.gz` under it). **Pages is not
enabled and nothing is published yet; these commands do not work until it is:**

```sh
wget -O /etc/apk/keys/blocktools@tsavo-2026.rsa.pub \
  https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/alpine/keys/blocktools@tsavo-2026.rsa.pub
echo https://tsavo.github.io/blocktools/alpine >> /etc/apk/repositories
apk update && apk add blocktools
```

Measured 2026-10-26 on Battleaxe, repo served over local HTTP to `alpine:latest` (Alpine 3.24.3,
apk-tools 3.0.8, x86_64): with the key, `apk update` and `apk add blocktools` succeeded; without the key,
`apk update` reported `UNTRUSTED signature` and `apk add blocktools` failed; a package with one flipped
byte failed `apk verify` and `apk add` from the repo ("file format is invalid or inconsistent").

**The current payload does not run on Alpine.** The packaged binaries are glibc builds
(interpreter `/lib64/ld-linux-x86-64.so.2`): plain exit 127; with `gcompat` 1 of 43 binaries started,
the rest fail on `libgcc_s.so.1`/glibc symbols. The package declares `arch=x86_64` and no dependencies.
A usable repo needs a musl build (`x86_64-unknown-linux-musl`, the `MUSL_BINDIR` that
`package-native.sh apk` already expects) before publishing.

## Limits (what is not there or not measured)

- **No hosted APK repository yet.** The index is built and tested locally (above) but not published.
- Signed APKs are not attached to any release yet, and the release workflow does not call the signer.
- Measured: signing and `apk verify` in `alpine:3.20` containers on x86_64. `apk add` from a
  signed index measured in an Alpine 3.24 container (apk-tools v3, v2 package format). Not measured:
  arm64, a bare-metal/VM Alpine host, a hosted URL.
- The key has no expiry. Rotation means a new key name, a new `.pub` in this directory and a new Vault
  version; old packages still verify only against the old key.
