# Release package repositories (Alpine, apt, RPM)

Served from the `gh-pages` branch at `https://tsavo.github.io/blocktools/{alpine,apt,rpm}`, x86_64 only.
Current version in all three: 0.1.1 (from tag v0.1.1). Signing keys live only in the maintainer's Vault;
see [APK-SIGNING.md](APK-SIGNING.md) and [APT-SIGNING.md](APT-SIGNING.md).

## Install

Alpine (key SHA-256 `07ca30cd9d1d599342d87514b8585326a28880d62308fe9304007b62db66c09f`):

```sh
wget -O /etc/apk/keys/blocktools@tsavo-2026.rsa.pub \
  https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/alpine/keys/blocktools@tsavo-2026.rsa.pub
echo https://tsavo.github.io/blocktools/alpine >> /etc/apk/repositories
apk update && apk add blocktools
```

Debian/Ubuntu (key fingerprint `08D9 04B0 EB3B CC0F 6D24  C621 607A 6605 8B6C 256E`): see APT-SIGNING.md.

Fedora/RHEL (key fingerprint `8C50 B7A7 95D1 D3EC C5FC  97FF B83B E907 A65A 3F3F`; packages and
`repomd.xml` are both signed, `gpgcheck=1`, `repo_gpgcheck=1`):

```sh
sudo curl -o /etc/yum.repos.d/blocktools.repo \
  https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/rpm/blocktools.repo
sudo dnf install blocktools
```

The apk payload is a static musl build of the tagged source; the deb and rpm carry the release
tarball's glibc binaries (`Depends: libc6 (>= 2.34)` on the deb; see APT-SIGNING.md for the floor).

## How a release updates them

A v* tag push runs `.github/workflows/release.yml`: `build` makes the tarball and SHA256SUMS, `publish`
creates the GitHub release, then `repos` runs `scripts/release-repos.sh build VERSION TARBALL OUTDIR` and
`scripts/release-repos.sh publish OUTDIR`. `build` refuses when Cargo.toml's version is not the tag's, or a
binary in the tarball is missing from `package-native.sh` CLIS; it builds the musl apk, the deb and the rpm,
signs them with `scripts/{apk,apt,rpm}-sign-host.sh` (read-only AppRoles, key on tmpfs, never printed), and
refuses output that contains a private-key block. `publish` refuses an unsigned build, replaces `alpine/`,
`apt/` and `rpm/` on gh-pages and pushes with the job's token.

`repos` runs on a separate runner on the Battleaxe host, labelled only `blocktools-signer` (not in a
runner container and not matched by CI jobs). Its job-started hook, `scripts/signer-runner-hook.sh`, fails
any job that is not this repo's `release.yml` on a v* tag push or a `workflow_dispatch` on main. The job
also uses the `release` environment, which deploys only from v* tags (`scripts/release-env-check.sh`).

Dry run: `gh workflow run release.yml --ref main` runs `repos-dry-run`, which builds the same packages
and layout with `REPOS_UNSIGNED=1`: no AppRole login, no signature, no push.

## Limits

- The signed path inside the workflow (`repos`) has not run on a real tag yet. The same scripts were run
  by hand on the host for v0.1.1.
- The container runners hold the host Docker socket, so the signer hook limits what the signer runner
  runs; it does not stop a container job from reaching the host through Docker.
- x86_64 only; no arm64. Old versions are not kept: each release replaces the repos.
- Whether GitHub Pages redeploys after a push made with the job token is not yet observed.
