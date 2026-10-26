# CI runners

Linux gate jobs (`lint`, `test`, `negatives`, `e2e`) run on the self-hosted Battleaxe runner
(`battleaxe-blocktools-1`, labels `self-hosted, Linux, X64, blocktools, battleaxe`). The `macos` job
stays on GitHub-hosted `macos-latest`. The release workflow stays GitHub-hosted.

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

## Security rule: self-hosted only while the repo is private

A public repo lets anyone open a pull request from a fork, and `on: pull_request` would run that
code on the self-hosted runner (on Battleaxe). So: self-hosted runners are allowed only while
TSavo/blocktools is private. Before the repo is ever made public, set `RUNNER_LABELS` to
`"ubuntu-latest"` (or remove the self-hosted default from ci.yml) and remove the runner.

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

The runner is not ephemeral and mounts the host Docker socket (root-equivalent on Battleaxe). Each Linux job
ends with an `if: always()` cleanup (git worktree prune, git clean except target/, temp files).
`scripts/gate.sh` creates no Docker images or containers. Workflow-level `concurrency` serializes runs per ref;
with one runner, jobs within a run already execute one at a time.
