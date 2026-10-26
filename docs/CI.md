# CI runners

Linux gate jobs (`lint`, `test`, `negatives`, `e2e`) run on four self-hosted Battleaxe runners
(`battleaxe-blocktools-1` to `battleaxe-blocktools-4`, all with labels `self-hosted, Linux, X64, blocktools, battleaxe`). The extra three come from
`docker-compose.blocktools-extra.yml` (compose project `github-runners-bt-extra`) on Battleaxe. All four
share the tool-cache volume and mount the host Docker socket. The `macos` job
stays on GitHub-hosted `macos-latest`. The release workflow (`release.yml`, tag push and workflow_dispatch only) runs on
Battleaxe too: the v0.1.0 run 40368238848 ran release-env, build and publish on `battleaxe-blocktools-1`
(measured with `gh api .../runs/40368238848/jobs`). Fork pull requests run on GitHub-hosted `ubuntu-latest`
(next section).

Timings below were measured with one runner; no timing with four runners has been measured yet.

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
| wasm32-unknown-unknown, wasm-bindgen-cli 0.2.100 | job installs (rustup target add / cargo install) |
| clang, lld, python3, cc, git | must be in the runner image; `scripts/ci-require-tools.sh` fails the job listing what is missing (CI never runs apt-get or sudo). Measured: run 40269892206 failed at the old apt-get step on battleaxe-blocktools-1 (no clang/ld.lld, no working sudo) |
| node 20 | actions/setup-node |
| python3 + `cryptography` | python3 must be on the image (untested); job pip-installs cryptography (recipes e2e skips without it) |
| git, curl | must be on the image |
| shellcheck, groff, pnpm | not used by the gate |
| Docker | not used by `scripts/gate.sh`; needed only for the manual sealed-image claims (`scripts/image-size.sh`, `scripts/sealed-check.sh`) if they are ever run in CI |

## Persistent runner

The four runners are not ephemeral, and each mounts the host Docker socket (root-equivalent on Battleaxe).
They share the tool-cache volume, so the four jobs of one run can now execute in parallel on different
runners and use that cache at the same time. Each Linux job ends with an `if: always()` cleanup: git worktree
prune, git clean except target/, and removal of `$TMPDIR/blocktools-*` and `$TMPDIR/ci-gate.*`. The cleanup
touches only that runner's checkout, so it is safe with parallel jobs as long as each runner container has
its own `/tmp`. That is the case unless the compose file mounts a shared `/tmp`; we have not verified it.
`scripts/gate.sh` creates no Docker images or containers. Workflow-level `concurrency` (`ci-<ref>`, no
cancel-in-progress) still serializes runs per ref. It does not serialize the jobs inside a run, which now
run in parallel.
