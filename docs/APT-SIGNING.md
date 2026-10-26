# apt repository and signing

blocktools has a signed apt repository for Debian and Ubuntu (amd64) at
`https://tsavo.github.io/blocktools/apt`, served by GitHub Pages from the `gh-pages` branch. This page
says how to use it, where the signing key lives, and what has been measured.

## Install

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo wget -O /etc/apt/keyrings/blocktools-archive-keyring.asc \
  https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/apt/blocktools-archive-keyring.asc
echo "deb [signed-by=/etc/apt/keyrings/blocktools-archive-keyring.asc] https://tsavo.github.io/blocktools/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/blocktools.list
sudo apt update && sudo apt install blocktools
```

Check the key before trusting it:
`gpg --show-keys /etc/apt/keyrings/blocktools-archive-keyring.asc` must show fingerprint
`08D9 04B0 EB3B CC0F 6D24  C621 607A 6605 8B6C 256E` ("BlockTools apt signing <blocktools-apt@tsavo>").
The key is trusted only for this one source (`signed-by=`); `apt-key` is not used.

## Which systems

The repository serves `blocktools 0.1.0-1`, built from the v0.1.0 release binaries, which link glibc.
The package declares `Depends: libc6 (>= 2.34)`. Most of its tools need glibc 2.34; `sealed-run`
needs glibc 2.39. Measured in containers (see Tests):

| image | glibc | apt update/install | `--help` exit 0 |
|---|---|---|---|
| debian:12 (12.15) | 2.36 | ok | 40 of 41 (`sealed-run`: GLIBC_2.39 not found) |
| ubuntu:22.04 (22.04.5) | 2.35 | ok | 40 of 41 (`sealed-run`: GLIBC_2.39 not found) |
| ubuntu:24.04 (24.04.5) | 2.39 | ok | 41 of 41 |

Man pages (`man derive`, `man blocktools`) were found on all three.

## Where the key lives

- **Private key:** RSA 4096, only in the maintainer's HashiCorp Vault, KV v2 mount `secret`, path
  `blocktools/apt-signing` (fields `private_key` armored, `key_id`, `fingerprint`). It is not in this
  repository, in CI secrets or in any runner. `scripts/secret-scan.sh` rule S-pgp fails on any OpenPGP
  private-key block in a tracked file.
- **Read access:** one AppRole, `blocktools-apt-signer`. Its policy `blocktools-apt-signer` grants `read`
  on `secret/data/blocktools/apt-signing` and nothing else; tokens have no default policy and live 5
  minutes (10 at most). Its role id and secret id sit in files mode 600 on the build host.
- **Public key:** [`packaging/apt/blocktools-archive-keyring.asc`](../packaging/apt/blocktools-archive-keyring.asc)
  (armored; apt reads armored keys in `signed-by=` when the file name ends in `.asc`). Stable URL
  `https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/apt/blocktools-archive-keyring.asc`.

## How the repository is built

`scripts/apt-sign-host.sh OUTDIR file.deb...` runs on the build **host**, never in a CI runner container.
It logs in with the AppRole, reads the key into a throwaway `GNUPGHOME` in a 0700 directory on
`/dev/shm`, revokes its token, refuses unless the Vault fingerprint equals the committed keyring's,
lays out `pool/main/b/blocktools/` and `dists/stable/main/binary-amd64/Packages(.gz)` with
`apt-ftparchive`, writes `Release` (MD5/SHA1/SHA256/SHA512), signs it as `InRelease` (clearsigned) and
`Release.gpg` (detached), and shreds the key directory in a trap. It then checks both signatures with
`gpgv` against the committed keyring only. The output directory is copied to `apt/` on `gh-pages`.

The published package was made with
`BINDIR=bin DEB_DEPENDS="libc6 (>= 2.34)" scripts/package-native.sh deb` inside the extracted v0.1.0
release tarball.

## Tests

`scripts/apt-sign-test.sh` uses a throwaway dev-mode Vault container (never the real Vault) and
throwaway GPG keys, and checks: the signed repo verifies against its keyring and not another; the script
refuses when the AppRole policy does not cover the path, and when the Vault key is not the committed
one; no PGP private-key block in output; nothing left on `/dev/shm`; and in a `debian:12` container,
`apt update` + `apt install` succeed with `signed-by`, `apt update` fails with a different key, and
fails with a tampered `Packages`. Measured on the build host (x86_64) at 9ff933a: every check ok.

With the real key, served from a local HTTP server, in debian:12, ubuntu:22.04 and ubuntu:24.04:
`apt update` with the right key ok; with a different key it fails (`NO_PUBKEY 607A66058B6C256E`); with
an edited `InRelease` it fails (`BADSIG`); `apt install blocktools` ok. From the live Pages URL, with the key
fetched from the raw GitHub URL above into `/etc/apt/keyrings/` (the install steps exactly), in the
same three images: `apt update` fetched `InRelease` and `Packages` with no warning, `apt install
blocktools` installed 0.1.0-1, `derive --help`, `chain-table --help` and `man -w blocktools` ok. The
wrong-key and tamper cases were not repeated against the live URL.

## Limits (not measured or not there)

- amd64 only; no arm64 package. Not tested on a real (non-container) Debian or Ubuntu host.
- The repository holds 0.1.0 only. Updating it is a manual host step; the release workflow does not
  build or sign the apt repository.
- The key has no expiry. Rotation means a new keyring file here and a new Vault version.
