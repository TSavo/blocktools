#!/bin/sh
# THE gate. CI (.github/workflows/ci.yml) and scripts/verify-and-push.sh both run this script,
# so they cannot diverge. ci-gate-check.sh fails if ci.yml runs any command other than this
# script or a listed environment-setup step, or if its stage matrix differs from `--list`.
#   sh scripts/gate.sh            all stages, in order (local / verify-and-push)
#   sh scripts/gate.sh STAGE      one stage (CI runs each stage as a parallel job)
#   sh scripts/gate.sh --list     stage names
# Expects cargo, node, clang/lld, wasm-bindgen and python3 on PATH.
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
cd "$(dirname "$0")/.."
# Thin LTO for everything the gate builds natively: the shipped binaries (Dockerfile, release.yml) keep
# Cargo.toml's fat LTO; the gate only needs working binaries, and fat LTO relinks 43 binaries and every
# test binary through a whole-program pass on each change. scripts/wasm-build.sh unsets this (wasm bytes
# must not depend on the gate). GATE_LTO=fat restores the old behaviour.
export CARGO_PROFILE_RELEASE_LTO=${GATE_LTO:-thin}
STAGES="lint test negatives e2e"
step() { echo "== gate: $*"; "$@" || { echo "gate FAILED at: $*" >&2; exit 1; }; }
stage() {
  case "$1" in
  lint)
    step cargo build -q --locked --release --workspace  # docs-check (gen-man.py) runs target/release/* --help
    step sh scripts/prepush-check.sh
    step sh scripts/secret-scan.sh
    step sh scripts/check-deps.sh
    step sh scripts/check-deps-regress.sh
    step sh scripts/hygiene-check.sh
    step sh scripts/version-check.sh
    step sh scripts/fetch-fixtures.sh  # man examples (docs-check) read fixtures/external: pinned download, never a local-only copy
    step sh scripts/docs-check.sh;;
  test)
    step cargo build -q --locked --release --workspace
    # The facade at its default features (what bindings/wasm ships) reuses the build above; one all-features
    # pass covers every other crate (features are additive). Two full --workspace passes built everything twice.
    step cargo test -q --locked --release -p blocktools --no-fail-fast
    step cargo test -q --locked --release --workspace --all-features --no-fail-fast
    step env RUSTDOCFLAGS='-D warnings' cargo doc -q --locked -p blocktools --no-deps;;
  negatives)
    step cargo build -q --locked --release --workspace  # docs-check (gen-man.py) runs target/release/* --help
    step sh scripts/fetch-fixtures.sh  # gate-negatives' baseline docs-check needs them too
    step sh scripts/gate-negatives.sh;;
  e2e)
    step cargo build -q --locked --release --workspace
    step sh scripts/fetch-fixtures.sh
    # wasm-check first: it builds bindings/wasm/pkg, which recipes/paths (e2e.d/paths.sh) call.
    if [ "$(uname -s)" = Darwin ]; then  # Apple clang has no wasm32 target (secp256k1-sys C build)
      echo "skip wasm-check on macOS: wasm is verified by the Linux gate only (untested on macOS)"
    else step sh scripts/wasm-check.sh; fi
    step bash scripts/e2e-local.sh;;
  *) echo "gate: unknown stage '$1' (stages: $STAGES)" >&2; exit 2;;
  esac
  echo "gate stage $1 ok"
}
case "${1:-}" in
--list) echo "$STAGES";;
"") for s in $STAGES; do stage "$s"; done
    step sh scripts/prepush-check.sh   # tree still clean after every stage
    step sh scripts/secret-scan.sh
    echo "gate ok";;
*) stage "$1";;
esac
