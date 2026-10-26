#!/bin/sh
# THE gate. CI (.github/workflows/ci.yml) and scripts/verify-and-push.sh both run exactly
# this script, so they cannot diverge. hygiene-check.sh fails if ci.yml runs any command
# other than this script or a listed environment-setup step (scripts/ci-allowed-setup.txt).
# Expects cargo, node, clang/lld, wasm-bindgen and python3 on PATH.
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
cd "$(dirname "$0")/.."
step() { echo "== gate: $*"; "$@" || { echo "gate FAILED at: $*" >&2; exit 1; }; }
step sh scripts/prepush-check.sh
step sh scripts/secret-scan.sh
step cargo build -q --locked --release --workspace
step cargo test -q --locked --release --workspace --no-fail-fast
step cargo test -q --locked --release --workspace --all-features --no-fail-fast
step env RUSTDOCFLAGS='-D warnings' cargo doc -q --locked -p blocktools --no-deps
step sh scripts/check-deps.sh
step sh scripts/check-deps-regress.sh
step sh scripts/hygiene-check.sh
step sh scripts/docs-check.sh
step sh scripts/fetch-fixtures.sh
step bash scripts/e2e-local.sh
step sh scripts/wasm-check.sh
step sh scripts/prepush-check.sh
step sh scripts/secret-scan.sh
echo "gate ok"
