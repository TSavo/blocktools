#!/bin/sh
# rpc sendraw shows the fee before the irreversible broadcast, against scripts/mock-bitcoind.py (a fake regtest
# bitcoind on 127.0.0.1, NOT a real node; it does not verify signatures). The tx is the mock's SPEND with a dummy
# one-byte scriptSig (OP_TRUE) so it decodes as signed: 50000 sat in, 49000 out, fee 1000 sat.
set -eu
B=${BIN:-target/release}; Bab=$(cd "$B" && pwd)
W=$(mktemp -d); trap 'kill $M1 $M2 2>/dev/null; rm -rf "$W"' EXIT
python3 scripts/mock-bitcoind.py "$W/p1" "$W/log1" & M1=$!
python3 scripts/mock-bitcoind.py "$W/p2" "$W/log2" --txindex & M2=$!
i=0; while [ ! -s "$W/p1" ] || [ ! -s "$W/p2" ]; do i=$((i+1)); [ $i -lt 100 ] || { echo "FAIL sendraw-fee: mock did not start"; exit 1; }; sleep 0.05; done
U1=http://127.0.0.1:$(cat "$W/p1"); U2=http://127.0.0.1:$(cat "$W/p2")
f() { echo "FAIL sendraw-fee: $1"; cat "$W/tty" "$W/o" 2>/dev/null; exit 1; }
jq -r .tx recipes/fixtures/rpc-decode/spend.json | python3 -c 'import sys;h=sys.stdin.read().strip();print(h[:82]+"0151"+h[84:])' > "$W/s"
D="python3 scripts/e2e-only/tty-drive.py"
sent() { cat "$1" 2>/dev/null | grep -c sendrawtransaction || true; }  # allow-true: grep -c prints 0 and exits 1 when absent
# 1. -txindex node: prevout looked up through rpc's allowlist (getrawtransaction), fee in the confirmation text
$D right "$W/s" "$W/o" "$Bab/rpc" "$U2" sendraw > "$W/tty" || f "txindex broadcast"
grep -q '^fee    : 0.00001000 btc' "$W/tty" && grep -q '^in  #0: .* 0.00050000' "$W/tty" && ! grep -q 'FEE UNKNOWN\|Type ACK' "$W/tty" \
  && grep -q '"status":"ok"' "$W/o" && echo "ok   rpc sendraw (-txindex mock): confirmation shows in 0.00050000 and fee 0.00001000, one code" || f "fee not shown"
# 2. pruned node, --prevtxs from 'rpc URL prevtxs' output: fee shown, no lookup needed
$D right "$W/s" "$W/o" "$Bab/rpc" --prevtxs recipes/fixtures/rpc-decode/prevtxs.jsonl "$U1" sendraw > "$W/tty" || f "--prevtxs broadcast"
grep -q '^fee    : 0.00001000 btc' "$W/tty" && ! grep -q 'Type ACK' "$W/tty" && echo "ok   rpc sendraw --prevtxs (pruned mock): fee 0.00001000 shown" || f "--prevtxs fee"
# 3. negative: pruned node, no prevtxs -> FEE UNKNOWN banner and a distinct ACK; the code alone sends nothing
n=$(sent "$W/log1")
if $D noack "$W/s" "$W/o" "$Bab/rpc" "$U1" sendraw > "$W/tty"; then f "unknown fee broadcast without ACK"; fi
grep -q 'FEE UNKNOWN' "$W/tty" && grep -q 'Type ACK FEE-UNKNOWN' "$W/tty" && grep -q '"status":"aborted"' "$W/tty" && [ "$(sent "$W/log1")" = "$n" ] \
  && echo "ok   rpc sendraw unknown fee: loud banner, refusing the ACK aborts, nothing sent" || f "unknown-fee ack"
# 4. the ACK plus the code does broadcast (the human accepted the stated risk)
$D right "$W/s" "$W/o" "$Bab/rpc" "$U1" sendraw > "$W/tty" || f "ack broadcast"
grep -q '"status":"ok"' "$W/o" && [ "$(sent "$W/log1")" -gt "$n" ] && echo "ok   rpc sendraw unknown fee: ACK FEE-UNKNOWN + code -> sent" || f "ack path"
