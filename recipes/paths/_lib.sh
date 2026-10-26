# Shared by recipes/paths/*.sh. Not a tool. Sourced, never run alone.
#   B        directory holding the blocktools binaries (default: target/release, made absolute)
#   RPC      node or Esplora URL. Real use: your own node. Tests: scripts/mock-chain.py on 127.0.0.1.
#   W        work directory for the stage files (default: a new temp dir)
#   KEY      file holding the private key (tests: the public throwaway key 1, never a real secret)
# tx-sign and tx-broadcast ask a human to type a code on the terminal. confirm() runs them on your
# terminal; the test harness sets TTY_DRIVE to its pty driver so the gate can answer the prompt.
set -eu
B=$(cd "${B:-target/release}" && pwd); W=${W:-$(mktemp -d)}
stage() { printf '\n== %s\n' "$*" >&2; }
confirm() {  # confirm IN OUT CMD ARGS...
  i=$1 o=$2; shift 2
  if [ -n "${TTY_DRIVE:-}" ]; then python3 "$TTY_DRIVE" right "$i" "$o" "$@" >/dev/null; else "$@" < "$i" > "$o"; fi
}
# Resolved on first bt call, not at source time: the non-wasm paths (utxo-sweep, evm-sweep, ...) must run
# where bindings/wasm/pkg was never built (macOS CI skips wasm-check).
WASM_DIR=${WASM:-bindings/wasm/pkg/node}; WASM_DIR=$(cd "$WASM_DIR" 2>/dev/null && pwd || echo "$WASM_DIR")
# bt FUNCTION ARGS...: call one wasm export (bindings/wasm, built by scripts/wasm-check.sh) and print its result.
bt() { [ -f "$WASM_DIR/blocktools_wasm.js" ] || { echo "bt: $WASM_DIR/blocktools_wasm.js missing (build it: sh scripts/wasm-check.sh)" >&2; return 1; }
  node -e 'const b=require(process.argv[1]),f=process.argv[2];const r=b[f](...process.argv.slice(3));console.log(typeof r==="string"?r:JSON.stringify(r))' "$WASM_DIR/blocktools_wasm.js" "$@"; }
rpc() { curl -fsS -H 'Content-Type: application/json' --data "$2" "$1"; }   # rpc URL JSON-BODY
