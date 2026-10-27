#!/bin/sh
# recipes/rpc-decode.md: its script block runs as written against scripts/mock-bitcoind.py (a deterministic fake
# pruned regtest bitcoind on 127.0.0.1, NOT a real node), pruned and with -txindex; plus the pipe-exit-code gotcha.
set -eu
B=${BIN:-target/release}; Bab=$(cd "$B" && pwd)
W=$(mktemp -d); trap 'kill $M1 $M2 2>/dev/null; rm -rf "$W"' EXIT
python3 scripts/mock-bitcoind.py "$W/p1" "$W/log1" & M1=$!
python3 scripts/mock-bitcoind.py "$W/p2" "$W/log2" --txindex & M2=$!
i=0; while [ ! -s "$W/p1" ] || [ ! -s "$W/p2" ]; do i=$((i+1)); [ $i -lt 100 ] || { echo "FAIL rpc-decode: mock did not start"; exit 1; }; sleep 0.05; done
U1=http://127.0.0.1:$(cat "$W/p1"); U2=http://127.0.0.1:$(cat "$W/p2")
python3 - recipes/rpc-decode.md > "$W/script.sh" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
m = re.search(r"<!-- rpc-decode: script[^>]*-->\n```sh\n(.*?)```", t, re.S)
sys.stdout.write(m.group(1))
PY
[ -s "$W/script.sh" ] || { echo "FAIL rpc-decode: script block not found in recipe"; exit 1; }
# -txindex node: the whole block succeeds and the fee is the mock's known 1000 sat
o=$(cd "$W" && U=$U2 PATH="$Bab:$PATH" bash -eu script.sh 2>&1) || { echo "FAIL rpc-decode: recipe script on -txindex mock"; echo "$o"; exit 1; }
echo "$o" | grep -q '"chain":"regtest"' && echo "$o" | grep -q '"n_tx":1' && echo "$o" | grep -q 'input_amounts_unknown' \
  && echo "$o" | grep -q '"fee":1000' && echo "$o" | grep -q '"amount":50000' && echo "$o" | grep -q '"amount":49000' \
  && echo "ok   rpc-decode recipe script (-txindex mock): fee 1000" || { echo "FAIL rpc-decode outputs"; echo "$o"; exit 1; }
# pruned node: rawtx with the block hash works, prevtxs fails with the node's -5 (rpc_error, exit 1) and stops the script
if o=$(cd "$W" && U=$U1 PATH="$Bab:$PATH" bash -eu script.sh 2>&1); then echo "FAIL rpc-decode: prevtxs succeeded on a pruned node"; exit 1; fi
echo "$o" | grep -q '"txid":"9a899cc8' && echo "$o" | grep -q '"code":-5' && echo "$o" | grep -q '"status":"rpc_error"' \
  && echo "ok   rpc-decode pruned: rawtx with blockhash ok, prevtxs needs -txindex (-5)" || { echo "FAIL rpc-decode pruned"; echo "$o"; exit 1; }
# gotchas 2, 3, 6: refused methods send nothing; a pipe masks rpc's exit code unless pipefail
n=$(wc -l < "$W/log1")
r=$(bash -c "\"$B/rpc\" \"$U1\" dumpprivkey '[\"x\"]' | cat; echo \"rc=\$? ps=\${PIPESTATUS[*]}\"" 2>"$W/err")
[ "$r" = "rc=0 ps=1 0" ] && grep -q '"status":"refused"' "$W/err" && echo "ok   rpc-decode: rpc dumpprivkey | cat exits 0, PIPESTATUS 1 0" || { echo "FAIL pipe mask: $r"; exit 1; }
r=$(bash -o pipefail -c "\"$B/rpc\" --allow-unlisted \"$U1\" dumpprivkey '[\"x\"]' 2>/dev/null | cat; echo rc=\$?")
[ "$r" = "rc=1" ] && echo "ok   rpc-decode: with pipefail (and --allow-unlisted) the pipeline exits 1" || { echo "FAIL pipefail: $r"; exit 1; }
s=$("$B/rpc" "$U1" dumpprivkey '["x"]' 2>&1 >/dev/null | jq -r .status || true)  # allow-true: rpc exits 1 by design here; status asserted next
[ "$s" = refused ] && [ "$(wc -l < "$W/log1")" = "$n" ] && echo "ok   rpc-decode: status=refused, nothing sent" || { echo "FAIL refused status/sent: $s"; exit 1; }
s=$("$B/rpc" "$U1" getblockhash '[9]' 2>&1 >/dev/null | jq -r .status || true)  # allow-true: rpc exits 1 by design here; status asserted next
[ "$s" = rpc_error ] && [ "$(wc -l < "$W/log1")" -gt "$n" ] && echo "ok   rpc-decode: status=rpc_error is the node's answer" || { echo "FAIL rpc_error status: $s"; exit 1; }
