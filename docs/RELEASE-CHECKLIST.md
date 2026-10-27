# Release checklist

What pushing a `v*` tag does, what has never been exercised, and what must be true before the tag.
Nothing here tags, publishes or signs; T says go before any tag is pushed.

## What a tag push runs (.github/workflows/release.yml)

Trigger: `push` of a tag matching `v*` (the same workflow also runs on `workflow_dispatch`; see the dry run below).

1. **build** (self-hosted runner, labels `self-hosted, Linux, X64, blocktools` unless `vars.RUNNER_LABELS`):
   installs the pinned Rust toolchain, checks required tools (`scripts/ci-require-tools.sh`), builds and tests the
   workspace with fat LTO (`cargo build/test --locked --release --workspace`), runs `scripts/check-deps.sh`,
   `scripts/secret-scan.sh` and `scripts/version-check.sh <tag>` (fails unless the tag is `v` + the workspace
   version and every version location agrees). It packages `blocktools-<tag>-linux-x86_64.tar.gz` (bin/, the
   `blocktools` wrapper, LICENSE, README, DESIGN, EXPORTS, recipes, man pages) and `SHA256SUMS`, and uploads
   them as the `release-dist` artifact.
2. **release-env**: `scripts/release-env-check.sh` fails closed unless the `release` environment only allows
   deployments from `v*` tags.
3. **publish** (tag only; needs build and release-env; environment `release`; `contents: write`): downloads
   `release-dist`, runs `sha256sum -c SHA256SUMS`, then `gh release create <tag>` with the tarball and
   `SHA256SUMS` and the notes "Linux x86_64 binaries. Verify with: sha256sum -c SHA256SUMS". There is no
   manual approval step (T, 2026-10-26). This is the step that makes the release public.
4. **repos** (tag only; needs publish; runner `self-hosted, blocktools-signer`; environment `release`):
   `sha256sum -c`, then `scripts/release-repos.sh build <version> <tarball> $RUNNER_TEMP/repos`: refuses if
   Cargo.toml's version differs or a tarball binary is missing from the package list; builds the static musl
   apk (docker `rust:alpine`), the deb and the rpm; signs them host-side through read-only Vault AppRoles
   (`scripts/apk-sign-host.sh`, `apt-sign-host.sh`, `rpm-sign-host.sh`; keys only on tmpfs); refuses output
   containing a private key block. Then `release-repos.sh publish`: refuses an unsigned build, clones
   `gh-pages`, replaces `alpine/`, `apt/` and `rpm/`, commits and pushes. Served at
   https://tsavo.github.io/blocktools/{alpine,apt,rpm}. The previous version's packages are not kept.
   The signer runner's job-started hook (`scripts/signer-runner-hook.sh`) admits only release.yml on a
   `v*` tag push or a dispatch on main.

On `workflow_dispatch` (main): build, release-env, the arm64 dry-run jobs (`dryrun-macos-arm64`,
`dryrun-linux-aarch64`: `gate.sh package`, artifacts only) and `repos-dry-run` (`REPOS_UNSIGNED=1`: builds the
packages and repository layout, signs nothing, publishes nothing). publish and repos are skipped.

## Never exercised

- The signed `repos` job has never run on a real tag (it was added after v0.1.1; v0.1.1's repositories were
  built and signed by running the same scripts by hand on the host). Its first run is the release.
- Whether GitHub Pages redeploys after the job's token push is not observed.
- Vault signing inside the runner job (the dispatch dry run is unsigned by design).
- A dispatch cannot run publish or repos; there is no dry run of `gh release create` or of the gh-pages push.

## Before the tag (each item: how it is checked)

- [ ] Green `ci` run on main at the exact commit to be tagged (`gh run list -w ci -b main`).
- [ ] Every claim in docs/claims.toml measured, stamped at a green main commit, except the families T allowed
      to stay untested (recovery-real-lost-wallet, macos-sealed / macos-remote-context-*); `python3
      scripts/claims-check.py` exit 0 at that commit.
- [ ] Versions bumped in every location (`sh scripts/version-check.sh v<version>` exit 0).
- [ ] CHANGELOG.md: the version heading carries the release date instead of "Unreleased".
- [ ] Man page headers and `--version` match (`version-check.sh` checks man1/man7 headers; `--version` of the
      built binaries prints the workspace version).
- [ ] Dispatch dry run of release.yml green at that commit (build, release-env, arm64 dry runs, repos-dry-run).
- [ ] T says go. Then: `git tag -a v<version> -m v<version> <commit> && git push origin v<version>`.
