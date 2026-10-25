#!/bin/sh
# Every gate must pass, in order, or nothing is pushed. Usage: scripts/verify-and-push.sh "commit message"
# Stage changes by explicit path first (`git add path...`); this script never stages anything.
set -eu
# pipefail where the shell has it (dash >= 0.5.11, bash); a shell without it just lacks the extra check
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
# Expects cargo and node on PATH.
[ $# = 1 ] || { echo "usage: $0 MESSAGE" >&2; exit 2; }
sh scripts/prepush-check.sh
sh scripts/secret-scan.sh
cargo build -q --release --workspace
cargo test -q --release --workspace --no-fail-fast
cargo test -q --release --workspace --all-features --no-fail-fast
sh scripts/check-deps.sh
sh scripts/hygiene-check.sh
sh scripts/docs-check.sh
bash scripts/e2e-local.sh
sh scripts/wasm-check.sh
sh scripts/prepush-check.sh
sh scripts/secret-scan.sh
git commit -qm "$1"
git push -q origin main
git log --oneline -1
