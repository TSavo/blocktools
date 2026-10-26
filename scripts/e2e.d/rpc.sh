#!/bin/sh
# rpc against scripts/mock-chain.py on 127.0.0.1 ONLY (never a real network). Throwaway key 1.
# Round trip: rpc utxos | tx-build | tx-sign | rpc sendraw, plus eth account -> sendraw, and refusals.
set -eu
. scripts/e2e-only/portable.sh
B=${BIN:-target/release}; T=$(mktemp -d)
python3 scripts/mock-chain.py $T/port $T/log $T/exp >/dev/null 2>&1 & M=$!
trap 'kill $M 2>/dev/null || true; rm -rf "$T"' EXIT  # allow-true: the mock server may already have exited
while [ ! -s $T/port ]; do sleep 0.1; done; U=http://127.0.0.1:$(cat $T/port)
f() { echo "FAIL $1"; exit 1; }
W=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4; D=bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
$B/rpc --protocol esplora $U utxos $W > $T/u
$B/utxo-fetch --chain btc --url $U $W > $T/u2 2>/dev/null
cmp -s $T/u $T/u2 && echo "ok   rpc utxos == utxo-fetch lines (same bytes)" || f utxos
$B/tx-build --chain btc --utxos $T/u --to $D --sweep --fee-rate 5 > $T/p
python3 scripts/e2e-only/tty-drive.py right $T/k $T/s $PWD/$B/tx-sign --tx $T/p --expect-to $D >/dev/null
$B/tx-decode < $T/s | python3 -c 'import json,sys;print([json.loads(l) for l in sys.stdin if "txid" in l][0]["txid"])' > $T/exp
: > $T/log; nosid $B/rpc --protocol esplora $U sendraw < $T/s > $T/o 2>&1 || true  # allow-true: refusal asserted next
grep -q aborted $T/o && [ ! -s $T/log ] && echo "ok   rpc sendraw without terminal -> nothing sent" || f notty
python3 scripts/e2e-only/tty-drive.py right $T/s $T/o $PWD/$B/rpc --protocol esplora $U sendraw > $T/tty
grep -q '"status":"ok"' $T/o && grep -q "^/tx " $T/log && grep -q BROADCAST $T/tty && echo "ok   rpc utxos | tx-build | tx-sign | rpc sendraw (esplora mock), id matches" || f round
$B/rpc --protocol evm $U account 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf > $T/acct
grep -q '"nonce":5' $T/acct && grep -q '"chain_id":1' $T/acct && echo "ok   rpc account == utxo-fetch eth account shape" || f acct
$B/tx-build --chain eth --chain-id 1 --account $T/acct --to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF --sweep > $T/e
python3 scripts/e2e-only/tty-drive.py right $T/k $T/es $PWD/$B/tx-sign --tx $T/e --chain-id 1 --expect-to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF >/dev/null
$B/tx-decode < $T/es | python3 -c 'import json,sys;print([json.loads(l) for l in sys.stdin if "txid" in l][0]["txid"].removeprefix("0x"))' > $T/exp
python3 scripts/e2e-only/tty-drive.py right $T/es $T/o $PWD/$B/rpc --protocol evm $U sendraw >/dev/null
grep -q '"status":"ok"' $T/o && grep -q eth_sendRawTransaction $T/log && echo "ok   rpc account | tx-build | tx-sign | rpc sendraw (evm mock), id matches" || f eth
: > $T/log; for m in dumpprivkey dumpwallet walletpassphrase eth_sign personal_unlockAccount eth_sendTransaction; do
  st=0; $B/rpc $U $m '[]' >/dev/null 2>$T/err || st=$?
  [ $st = 3 ] && grep -q '"status":"refused"' $T/err || f "deny $m"
done; [ ! -s $T/log ] && echo "ok   rpc refuses key-export / unlock / wallet-sign methods, nothing sent" || f deny
kill $M 2>/dev/null; wait $M 2>/dev/null || true  # allow-true: wait returns the killed mock's signal status
