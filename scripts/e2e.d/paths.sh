#!/bin/sh
# recipes/paths/*.sh run end to end. Fetches are answered from saved real RPC responses
# (recipes/paths/fixtures, via scripts/e2e-only/replay-rpc.py); broadcasts go to scripts/mock-chain.py on
# 127.0.0.1 ONLY, which logs the request, and the logged body must be exactly the signed bytes.
# Keys: the public throwaway keys 1 and 0101..01. Nothing here touches a real network or a real secret.
set -eu
B=$(cd "${BIN:-target/release}" && pwd); T=$(mktemp -d); P=recipes/paths
f() { echo "FAIL paths $1"; exit 1; }
python3 scripts/e2e-only/replay-rpc.py $P/fixtures $T/rport $T/rlog >/dev/null 2>&1 & R=$!
python3 scripts/mock-chain.py $T/mport $T/mlog $T/exp >/dev/null 2>&1 & M=$!
trap 'rc=$?; kill $R $M 2>/dev/null || true; rm -rf "$T"; exit $rc' EXIT  # allow-true: servers may already have exited
while [ ! -s $T/rport ] || [ ! -s $T/mport ]; do sleep 0.1; done
RU=http://127.0.0.1:$(cat $T/rport); MU=http://127.0.0.1:$(cat $T/mport)
export B TTY_DRIVE=$PWD/scripts/e2e-only/tty-drive.py
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k1
printf '%064d' 0 | tr 0 1 | sed 's/1/01/g' | cut -c1-64 > $T/k2
txid() { $B/tx-decode < "$1" | python3 -c 'import json,sys;print([json.loads(l) for l in sys.stdin if "txid" in l][0]["txid"].removeprefix("0x"))'; }
D=bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3; E=0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF
# signatures are deterministic (RFC 6979), so a first run tells the mock which txid to answer with
for pass in 1 2; do mkdir -p $T/u$pass; : > $T/mlog
  RPC=$MU W=$T/u$pass KEY=$T/k1 sh $P/utxo-sweep.sh btc bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 $D > $T/u.out 2>&1 || [ $pass = 1 ] || { cat $T/u.out; f utxo-sweep; }
  [ $pass = 1 ] && txid $T/u1/signed.tx > $T/exp
done
S=$(python3 scripts/e2e-only/psbt-extract.py $T/u2/signed.tx); [ "$(grep "^/tx " $T/mlog)" = "/tx $S" ] && grep -q '"status":"ok"' $T/u2/sent.json && echo "ok   paths utxo-sweep: broadcast body == signed bytes" || { cat $T/mlog; f "utxo-sweep body"; }
for id in 1 8453; do for pass in 1 2; do mkdir -p $T/e$id$pass; : > $T/mlog
  RPC=$MU W=$T/e$id$pass KEY=$T/k1 sh $P/evm-sweep.sh $id 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf $E > $T/e.out 2>&1 || [ $pass = 1 ] || { cat $T/e.out; f "evm-sweep $id"; }
  [ $pass = 1 ] && txid $T/e${id}1/signed.tx > $T/exp
done
python3 - $T/mlog $T/e${id}2/signed.tx <<'PY' && echo "ok   paths evm-sweep chain $id: eth_sendRawTransaction param == signed bytes" || f "evm-sweep $id body"
import json, sys
l = [x for x in open(sys.argv[1]) if "eth_sendRawTransaction" in x]; assert len(l) == 1, l
p = json.loads(l[0].split(" ", 1)[1])["params"][0].removeprefix("0x"); s = json.load(open(sys.argv[2]))["signed_tx"].removeprefix("0x")
assert p == s, (p, s)
PY
done
mkdir -p $T/c; RPC=$RU W=$T/c KEY=$T/k2 sh $P/cosmos-send.sh cosmos1a0qwuze2h85zw7nqpsj3ga0z9geyrgwphl8j6w 1234567 7 123456 > $T/c.out 2>&1 || { cat $T/c.out; f cosmos; }
grep -q '"signature_valid":true' $T/c.out && grep -q '"signed":true' $T/c.out && echo "ok   paths cosmos-send: signed, signature_valid" || f "cosmos txid"
mkdir -p $T/b; RPC=$RU W=$T/b sh $P/utxo-inspect.sh btc bc1qevel27lv9l8qwrylu0z9rmec9cadujkkpxv2pn $D > $T/b.out 2>&1 || { cat $T/b.out; f utxo-inspect; }
grep -q '"amount":54261' $T/b.out && grep -q expected_destination_missing $T/b.out && echo "ok   paths utxo-inspect on a saved mainnet esplora response" || f "utxo-inspect out"
if [ -f bindings/wasm/pkg/node/blocktools_wasm.js ]; then
  mkdir -p $T/v; RPC=$RU W=$T/v sh $P/evm-inspect.sh 0xc0ee5b5618437369d0925560368ee87b84569ef1e6a2763983efa5fc437231ab > $T/v.out 2>&1 || { cat $T/v.out; f evm-inspect; }
  grep -q "data matches on-chain input: True" $T/v.out && grep -q chain_id_mismatch $T/v.out && echo "ok   paths evm-inspect on a saved mainnet tx" || f "evm-inspect out"
  mkdir -p $T/s; RPC=$RU W=$T/s sh $P/sol-transfer.sh HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk 9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM 1234567 > $T/s.out 2>&1 || { cat $T/s.out; f sol; }
  grep -q '"ok":true' $T/s.out && grep -q BEQY5fioukC3PmjPPbxZbH21kwueqCCVGrTLAoT2EYxV $T/s.out && echo "ok   paths sol-transfer on a saved mainnet blockhash" || f "sol out"
  mkdir -p $T/t; RPC=$RU W=$T/t sh $P/tron-transfer.sh TMxXrJ5u3Qsh7scpn4zRUzrxYtBoPCW5GM TXfrRsqwPbMi4Leb4EGB7dv5NMMWmkdRwk 1000000 > $T/t.out 2>&1 || { cat $T/t.out; f tron; }
  grep -q '"amount_sun":"1000000"' $T/t.out && grep -q '"ref_block_bytes": "31db"' $T/t.out && echo "ok   paths tron-transfer on a saved mainnet block" || f "tron out"
else echo "skip paths evm-inspect/sol/tron: wasm package not built (scripts/wasm-check.sh builds it)"; fi
