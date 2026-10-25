#!/bin/sh
# utxo-fetch + tx-broadcast against scripts/mock-chain.py on 127.0.0.1 ONLY. Throwaway key 1.
set -eu
. scripts/e2e-only/portable.sh
B=${BIN:-target/release}; T=$(mktemp -d)
python3 scripts/mock-chain.py $T/port $T/log $T/exp >/dev/null 2>&1 & M=$!
trap 'kill $M 2>/dev/null || true; rm -rf "$T"' EXIT  # allow-true: the mock server may already have exited
while [ ! -s $T/port ]; do sleep 0.1; done; U=http://127.0.0.1:$(cat $T/port)
f() { echo "FAIL $1"; exit 1; }
W=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4; D=bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
$B/utxo-fetch --chain btc --url $U $W > $T/u 2>/dev/null
grep -q '"amount":50000' $T/u && echo "ok   utxo-fetch esplora -> utxo lines" || f fetch
! $B/utxo-fetch --chain btc --url $U/bad $W >/dev/null 2>&1 && echo "ok   utxo-fetch rejects hostile txid from server" || f hostile
! $B/utxo-fetch --chain btc --url http://example.com $W >/dev/null 2>&1 && echo "ok   utxo-fetch refuses plain http to non-localhost" || f http
! $B/utxo-fetch --chain btc --url $U notanaddress >/dev/null 2>&1 && echo "ok   utxo-fetch refuses invalid address" || f addr
$B/utxo-fetch --chain eth --url $U 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf > $T/acct 2>/dev/null
grep -q '"nonce":5' $T/acct && grep -q '"chain_id":1' $T/acct && echo "ok   utxo-fetch eth json-rpc -> account file" || f eth
$B/tx-build --chain btc --utxos $T/u --to $D --sweep --fee-rate 5 > $T/p
python3 scripts/e2e-only/tty-drive.py right $T/k $T/s $PWD/$B/tx-sign --tx $T/p --expect-to $D >/dev/null
$B/tx-decode < $T/s | python3 -c 'import json,sys;print([json.loads(l) for l in sys.stdin if "txid" in l][0]["txid"])' > $T/exp
! $B/tx-broadcast --chain btc --url $U < $T/p | grep -q '"status":"ok"' && echo "ok   tx-broadcast refuses unsigned" || f unsigned
nosid $B/tx-broadcast --chain btc --url $U < $T/s | grep -q aborted && echo "ok   tx-broadcast refuses without terminal" || f notty
: > $T/log; python3 scripts/e2e-only/tty-drive.py wrong $T/s $T/o $PWD/$B/tx-broadcast --chain btc --url $U >/dev/null || true  # allow-true: nonzero exit is the expected refusal; the outcome is asserted on the next line
grep -q aborted $T/o && [ ! -s $T/log ] && echo "ok   tx-broadcast wrong code -> nothing sent" || f wrong
python3 scripts/e2e-only/tty-drive.py right $T/s $T/o $PWD/$B/tx-broadcast --chain btc --url $U > $T/tty
grep -q '"status":"ok"' $T/o && grep -q "^/tx " $T/log && grep -q BROADCAST $T/tty && echo "ok   tx-broadcast right code -> posted once, id matches" || f right
python3 scripts/e2e-only/tty-drive.py right $T/s $T/o $PWD/$B/tx-broadcast --chain btc --url $U/wrongid >/dev/null || true  # allow-true: nonzero exit is the expected refusal; the outcome is asserted on the next line
grep -q server_id_differs $T/o && echo "ok   tx-broadcast flags server id mismatch" || f mism
$B/tx-build --chain eth --chain-id 1 --account $T/acct --to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF --sweep > $T/e
python3 scripts/e2e-only/tty-drive.py right $T/k $T/es $PWD/$B/tx-sign --tx $T/e --chain-id 1 --expect-to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF >/dev/null
$B/tx-decode < $T/es | python3 -c 'import json,sys;print([json.loads(l) for l in sys.stdin if "txid" in l][0]["txid"].removeprefix("0x"))' > $T/exp
python3 scripts/e2e-only/tty-drive.py right $T/es $T/o $PWD/$B/tx-broadcast --chain eth --url $U >/dev/null
grep -q '"status":"ok"' $T/o && grep -q eth_sendRawTransaction $T/log && echo "ok   tx-broadcast eth -> eth_sendRawTransaction, id matches" || f eth2
kill $M 2>/dev/null; wait $M 2>/dev/null || true  # allow-true: wait returns the killed mock's signal status
