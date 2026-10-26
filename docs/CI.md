# CI runners

Linux gate jobs (`lint`, `test`, `negatives`, `e2e`) run on four self-hosted Battleaxe runners
(`battleaxe-blocktools-1` to `battleaxe-blocktools-4`, all with labels `self-hosted, Linux, X64, blocktools, battleaxe`). The extra three come from
`docker-compose.blocktools-extra.yml` (compose project `github-runners-bt-extra`) on Battleaxe. All four
share the tool-cache volume and mount the host Docker socket. The `macos` job
stays on GitHub-hosted `macos-latest`. The release workflow (`release.yml`, tag push and workflow_dispatch only) runs on
Battleaxe too: the v0.1.0 run 40368238848 ran release-env, build and publish on `battleaxe-blocktools-1`
(measured with `gh api .../runs/40368238848/jobs`). Fork pull requests run on GitHub-hosted `ubuntu-latest`
(next section).

Release gate: the `release` environment has no required reviewer (removed 2026-10-26 on T's word) and
allows deployments only from tags matching `v*`. `scripts/release-env-check.sh` (run by the release-env job)
refuses to publish if that policy is absent, uses protected branches, or contains any branch policy or a tag
pattern not starting with `v`; `scripts/e2e.d/release-env.sh` plants each of those cases with a stub `gh`.

Timings below were measured with one runner; no timing with four runners has been measured yet.

## Pushing (scripts/verify-and-push.sh)

An agent's push used to run all four stages serially on its own machine and then CI ran them again. Since
2026-10-26 `scripts/verify-and-push.sh "msg"` runs the lint stage locally (release build plus the static
checks), commits, pushes main and waits for CI's verdict with `gh`, printing the failing job names and the
FAIL lines when it is red (exit 1), or exit 3 when a newer push cancelled the run. `GATE=full` restores the
serial local gate; `WAIT=0` returns right after the push; `scripts/verify-and-push.sh --wait [SHA]` only waits.
The heavy stages run in parallel on the four runners, so the agent is blocked for one lint stage plus one CI
run instead of the whole gate twice.

## Per-job overhead removed on 2026-10-26 (unmeasured until the next runs)

Measured on runs 40388233412..40401710490 (four runners): push to green 12-25 min, of which 7-19 min was
waiting for the previous run (`concurrency` serializes runs per ref and pushes arrived every 2.4 min), the
longest job 7-12 min, and the `cargo build --release` inside a job 0.5-1.8 min. The rest of a job was overhead:

- `Swatinem/rust-cache` save (Post step) 1.1-2.7 min per Linux job, for a target/ that the cleanup step already
  keeps on disk. It now runs on GitHub-hosted runners only (`if: runner.environment == 'github-hosted'`).
- `cargo install wasm-bindgen-cli` compiled from source on every job (0.4-1.4 min): the version check is
  now the gate, see the table above.
- The test stage ran `cargo test --workspace` twice (default features, then `--all-features`), building every
  test binary twice. It now runs `-p blocktools` at default features (the configuration bindings/wasm ships)
  and one `--workspace --all-features` pass; features are additive, so the second pass covers every other crate.
- Cargo.toml's release profile is now `lto = "thin"` (it was `lto = true`, fat): fat LTO relinked 43 binaries and
  every test binary through a whole-program pass on each change, in the gate and in every developer's
  `cargo test --release`. The shipped artifacts keep fat LTO: the Dockerfile sets `CARGO_PROFILE_RELEASE_LTO=fat`
  for the sealed image and release.yml sets it for the tarball. scripts/wasm-build.sh unsets the variable so the
  wasm bytes never depend on the caller's environment.
- `scripts/wasm-check.sh` deleted the default wasm build dir after its first build, and the job cleanup deleted
  it again, so every job's first wasm build was a clean build on top of the clean reproducibility rebuild. Both
  now keep it.

The four jobs of a run no longer compile the commit four times: ci.yml links `target` to
`$RUNNER_TOOL_CACHE/blocktools-target/<ref>` (the tool-cache volume all four runner containers share), so the
first job to take cargo's build-directory lock compiles and the other three wait for the artifacts. The dir is
per ref because the concurrency group allows one run per ref: no two commits build into one dir at once (a PR
branch gets its own dir). `.gitignore` lists `/target` as well as `/target/` so the symlink is not an untracked
file for prepush-check. Old ref dirs are not removed automatically: `du -sh /opt/hostedtoolcache/blocktools-target/*`
in a runner container, delete what no branch needs. This is a repo change only; no compose change on Battleaxe.

Measured from our own run 40270984219 (c0ece5e) with
`gh api repos/TSavo/blocktools/actions/runs/40270984219/jobs`: all four Linux jobs succeeded on
runner `battleaxe-blocktools-1` (test 4m27s, lint 1m17s, negatives 3m53s, e2e 1m33s; about 11m18s from first
start to last finish). The `macos` job failed after 2 s ("recent account payments have failed").

## Fallback to GitHub-hosted (manual override only)

Self-hosted is the default because GitHub-hosted Linux jobs currently do not start: run 40265106260
(db291f5) shows all four Linux jobs ending in 2 s with "The job was not started because recent account
payments have failed or your spending limit needs to be increased". The macOS job did start.

Set the repository variable `RUNNER_LABELS` to the JSON string `"ubuntu-latest"`
(Settings -> Secrets and variables -> Actions -> Variables). Unset it to return to the self-hosted
runner. If no self-hosted runner is online and the variable is unset, Linux jobs queue until one is.

## Security: public repo, fork pull requests

TSavo/blocktools is **public** (GitHub API, 2026-10-26). Which runner a job gets:

| Event | Linux gate jobs | macos job |
|---|---|---|
| push to this repo (branches, tags) | Battleaxe (`RUNNER_LABELS` or the self-hosted default) | macos-latest |
| pull_request from a branch of this repo | Battleaxe | macos-latest |
| pull_request from a fork (`head.repo.full_name != github.repository`) | GitHub-hosted `ubuntu-latest`, whatever `RUNNER_LABELS` says | macos-latest |
| release.yml (tag push v*, workflow_dispatch) | Battleaxe | none |

This is one `runs-on` expression in ci.yml, with no duplicated jobs. `scripts/ci-fork-check.py` (rule H-fork,
run by hygiene-check in the lint stage) parses every workflow. For each job a `pull_request` can start, it
evaluates the `runs-on` expression with a small GitHub-expression evaluator, for a fork PR and a same-repo
PR or push, with `RUNNER_LABELS` unset, set to self-hosted, and set to ubuntu-latest. It fails if a fork PR
can get any label other than a GitHub-hosted one, if a same-repo event stops getting self-hosted, if any
workflow uses `pull_request_target`, or if a pull_request job's token is not read-only. ci.yml sets
`permissions: contents: read` for every job. GitHub gives fork PRs no secrets. gate-negatives plants both
violations (H-fork, H-forkperm).

The Actions setting "require approval for all external contributors" stays on (API, 2026-10-26:
`approval_policy: all_external_contributors`). A fork PR runs nothing until a maintainer approves it.

Limits:
- A pull_request run uses the workflow file from the PR itself. A fork PR that edits
  `.github/workflows/ci.yml` can therefore put back a self-hosted `runs-on`, and ci-fork-check only checks
  this repo's own copy. The only thing that stops that PR is the approval step: read the diff
  (workflows and `scripts/` included) before you approve a fork run.
- Same-repo branches and pushes still run on the persistent Battleaxe runners, which mount the host
  Docker socket (root-equivalent on Battleaxe). Pushing needs write access.
- GitHub-hosted Linux jobs did not start on this account while billing was failing (run 40265106260).
  Until that is fixed, fork PR Linux jobs may not run at all.
- No fork PR has been run yet, and `scripts/ci-require-tools.sh` has not been checked on ubuntu-latest
  (it needs clang and lld).

## What the runner must have / what the job installs

Runner image (per SwapChan's check of Battleaxe): node 24.19.0, bun, Docker, no pnpm. Not verified by us.

| Need | Source |
|---|---|
| Rust toolchain 1.85.1 (pinned) | job installs via rustup if missing and verifies `rustc --version`; the tool-cache is shared with other runners, so it is not trusted |
| wasm32-unknown-unknown, wasm-bindgen-cli 0.2.100 | job installs only what is missing: `rustup target list --installed` (no network) gates `rustup target add`, and `wasm-bindgen --version` gates `cargo install`. Before 2026-10-26 the install ran on every job: the logs of run 40401710490 show `Installing wasm-bindgen-cli v0.2.100` compiling from source in both the test and the e2e job (0.4-1.4 min each) |
| clang, lld, python3, cc, git | must be in the runner image; `scripts/ci-require-tools.sh` fails the job listing what is missing (CI never runs apt-get or sudo). Measured: run 40269892206 failed at the old apt-get step on battleaxe-blocktools-1 (no clang/ld.lld, no working sudo) |
| node 20 | actions/setup-node |
| python3 + `cryptography`, `pyyaml` | python3 must be on the image (untested); the job pip-installs them only when `import cryptography, yaml` fails (recipes e2e skips without cryptography) |
| git, curl | must be on the image |
| shellcheck, groff, pnpm | not used by the gate |
| Docker | not used by `scripts/gate.sh`; needed only for the manual sealed-image claims (`scripts/image-size.sh`, `scripts/sealed-check.sh`) if they are ever run in CI |

## Persistent runner

The four runners are not ephemeral, and each mounts the host Docker socket (root-equivalent on Battleaxe).
They share the tool-cache volume, so the four jobs of one run can now execute in parallel on different
runners and use that cache at the same time. Each Linux job ends with an `if: always()` cleanup: git worktree
prune, git clean except target/, and removal of `$TMPDIR/blocktools-*` and `$TMPDIR/ci-gate.*`, sparing
`$TMPDIR/blocktools-wasm-build` (scripts/wasm-build.sh's build dir) so the next job's first wasm build is incremental;
wasm-check's reproducibility rebuild still runs in a fresh build dir. The cleanup
touches only that runner's checkout, so it is safe with parallel jobs as long as each runner container has
its own `/tmp`. That is the case unless the compose file mounts a shared `/tmp`; we have not verified it.
`scripts/gate.sh` creates no Docker images or containers. Workflow-level `concurrency` (`ci-<ref>`) keeps one
run per ref and, since 2026-10-26, cancels the previous commit's run when a new push arrives (see 'Queue').
The jobs inside a run execute in parallel on different runners.

## Queue (why push-to-green was 12-25 min)

Measured on runs 40388233412..40401710490: pushes arrived every 2.4 min (median), the per-ref group kept
`cancel-in-progress: false`, so every surviving run waited 7-19 min for the previous run to finish and 19 of
30 runs were cancelled while pending. `cancel-in-progress` is now true: a push to a ref cancels the run of
the commit before it, and the newest commit starts as soon as a runner is free. Consequences:

- An intermediate commit in a burst gets no verdict of its own; the next commit's run covers its changes.
  A claim or finding that cites 'measured by CI at <sha>' must cite a commit whose run completed.
- While pushes keep arriving faster than a run takes (about 7 min after the overhead removal), nothing
  finishes. A bot that waits for green before its next push gets one as soon as it waits one run-length.
- Same-repo pull requests use the PR's own ref, so they do not cancel main's run.

Checking out with `clean: false` keeps `target` between jobs (it is the per-ref symlink above), so each
stage's `cargo build --release` is incremental from the last commit built on that ref. Before this,
actions/checkout's default `git clean -ffdx` emptied target/ at the start of every job and rust-cache
restored it from GitHub's cache (0.3-0.5 min restore, 1.1-2.7 min save).

## Gate image (Dockerfile.gate)

`Dockerfile.gate` is a pinned toolchain image with exactly what `scripts/gate.sh` needs (rust 1.85.1 by
base-image digest, wasm32 target, wasm-bindgen-cli 0.2.100, clang/lld, node 20.19.5 by tarball checksum,
python3 with cryptography and pyyaml, groff, git, file) and nothing of the general-purpose runner image.
`sh scripts/gate-docker.sh [STAGE]` builds it once and runs the gate inside it with the checkout
bind-mounted at `/src` and cargo caches in named volumes. Bind mounts resolve on the Docker host: from a
Mac whose docker context is Battleaxe, point `GATE_SRC` at a checkout on Battleaxe. The sealed runtime image
is still `Dockerfile`; the two share nothing. Measured on Battleaxe (docker context from a Mac, checkout cloned on Battleaxe, branch prebip39-phrases at 420f7b1): `lint` and `test` passed in the image before the jq/openssl/safe.directory additions (lint needed jq for a man example, negatives needed git to trust the clone source); `negatives` (67 lines, all ok) and `e2e` (145 recipe examples ok, 0 skipped, "e2e: all ok") passed in the final image. Not measured: running the image on a Docker host other than Battleaxe, and the image under a non-root `--user`.
