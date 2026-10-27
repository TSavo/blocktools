#!/bin/sh
# Measure the wasm module (claim wasm-size): bytes and gzip -9 -n bytes of the reproducible build
# (scripts/wasm-build.sh) with names, the same with every custom section (names, producers) removed
# ("stripped"), and the number of crates in the wasm32 normal dependency tree.
set -eu
cd "$(dirname "$0")/.."
w=$(sh scripts/wasm-build.sh)
t=$(mktemp); trap 'rm -f "$t"' EXIT
python3 - "$w" "$t" <<'PY'
import sys
b = open(sys.argv[1], 'rb').read(); assert b[:8] == b'\0asm\1\0\0\0', 'not a wasm module'
out, i = bytearray(b[:8]), 8
def leb(i):
    r = s = 0
    while True:
        x = b[i]; i += 1; r |= (x & 0x7f) << s; s += 7
        if x < 0x80: return r, i
while i < len(b):
    sid = b[i]; n, j = leb(i + 1)
    if sid != 0: out += b[i:j + n]
    i = j + n
open(sys.argv[2], 'wb').write(out)
PY
gz() { gzip -9 -n -c "$1" | wc -c | tr -d ' '; }
crates=$(cd bindings/wasm && cargo tree -q --locked --target wasm32-unknown-unknown -e normal --prefix none \
  | sed -e 's/ (\*)$//' -e 's/ (.*)$//' | awk '{print $1}' | sort -u | wc -l | tr -d ' ')
echo "wasm $(wc -c < "$w" | tr -d ' ') bytes ($(gz "$w") gzip) with names; $(wc -c < "$t" | tr -d ' ') bytes ($(gz "$t") gzip) stripped; $crates crates in the wasm tree; commit $(git rev-parse HEAD)"
