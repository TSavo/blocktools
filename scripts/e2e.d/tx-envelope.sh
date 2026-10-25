#!/bin/sh
# Common signing envelope (public): chain_table + decode refuse paths + C ABI artifact.
set -eu
B=${BIN:-target/release}
T=${T:-$(mktemp -d)}
f() { echo "FAIL $1"; exit 1; }

echo '{"op":"chain_table","chain":"_"}' | $B/tx-envelope > $T/ct.json || f ct
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["status"]=="ok" and v["envelope"]=="blocktools.sign/v1" and len(v["result"])>=40' $T/ct.json || f ct-shape
echo "ok   tx-envelope: chain_table op returns registry"

echo '{"op":"decode","chain":"btc","tx":"00"}' | $B/tx-envelope > $T/bad.json || f bad
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["status"]=="error" and v["op"]=="decode"' $T/bad.json || f bad-shape

echo '{"op":"decode","chain":"xlm","tx":"00"}' | $B/tx-envelope > $T/xlm.json || f xlm
grep -q unsupported_family $T/xlm.json || f xlm-family
echo "ok   tx-envelope: decode error paths (btc refuse, xlm unsupported_family)"

# C ABI release artifact (cdylib and/or staticlib)
ok=0
for a in target/release/libblocktools_c.a target/release/libblocktools_c.so target/release/libblocktools_c.dylib; do
  [ -f "$a" ] && ok=1
done
[ "$ok" = 1 ] || f cabi-lib
echo "ok   blocktools-c: release library artifact present"
