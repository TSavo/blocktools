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

## APK repository (live on GitHub Pages)

Repository URL: `https://tsavo.github.io/blocktools/alpine` (served from the `gh-pages` branch, `alpine/`).

```sh
wget -O /etc/apk/keys/blocktools@tsavo-2026.rsa.pub \
  https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/alpine/keys/blocktools@tsavo-2026.rsa.pub
echo https://tsavo.github.io/blocktools/alpine >> /etc/apk/repositories
apk update && apk add blocktools
```

The same `.pub` is also at `https://tsavo.github.io/blocktools/alpine/blocktools@tsavo-2026.rsa.pub`
(same SHA-256). Current package: `blocktools-0.1.1-r0`, built from tag v0.1.1 (it replaced the pre-release
`0.1.1_pre20261026-r0`, which apk orders below `0.1.1`, measured with `apk version -t`). Payload: every CLI in `package-native.sh` CLIS as static-pie musl binaries (`x86_64-unknown-linux-musl`, built
in `rust:alpine`), plus `blocktools` and `recover.sh`; `arch=x86_64`, `depends="bash"` (for `recover.sh`).

How it is built (Battleaxe host only, by `scripts/release-repos.sh build`, see RELEASE-REPOS.md):
`scripts/package-native.sh apk`, `scripts/apk-sign-host.sh`, then `scripts/apk-repo-build.sh OUTDIR signed.apk...`. That script refuses APKs not signed by the repo
key, builds `APKINDEX.tar.gz` with `apk index`, signs it with `abuild-sign` using the Vault key through
the same tmpfs, read-only-bind, output-suppressed flow as `apk-sign-host.sh`, and checks that Alpine
trusts it with the repo key and flags it UNTRUSTED without. The published files were scanned for PEM
private-key blocks before the push (none).

Measured 2026-10-26 in fresh `alpine:latest` containers (Alpine 3.24.3, apk-tools 3.0.8, x86_64):
- live Pages URL, key from the raw GitHub URL: `apk update` and `apk add blocktools` succeeded, and
  43 of 43 installed executables ran `--help` (exit below 126);
- live Pages URL without the key: `UNTRUSTED signature`, and `apk add blocktools` failed;
- local HTTP copy with one byte flipped in the package: `apk add` failed ("file format is invalid or
  inconsistent") and nothing was installed.

Repeated for `0.1.1-r0` on 2026-10-26 (Alpine 3.24.3): without the key `apk add blocktools` failed; with it,
0.1.1-r0 installed and 42 of 44 files in /usr/bin exited 0 on `--help` (`blocktools`, the Docker wrapper,
prints usage and exits 2; `recover.sh` exits non-zero); a fetched copy with one byte flipped was refused.

## Limits (what is not there or not measured)

- The repo holds one x86_64 package (0.1.1-r0); there is no arm64 build. From the next v* tag on,
  release.yml's `repos` job rebuilds and re-signs it; that job has not yet run on a real tag.
- Signed APKs are not attached to the GitHub release (they are only in the Pages repo).
- Measured: signing and `apk verify` in `alpine:3.20` containers on x86_64. `apk add` from a
  signed index measured in an Alpine 3.24 container (apk-tools v3, v2 package format). Not measured:
  arm64, a bare-metal/VM Alpine host, Alpine releases other than 3.24.3.
- The key has no expiry. Rotation means a new key name, a new `.pub` in this directory and a new Vault
  version; old packages still verify only against the old key.
