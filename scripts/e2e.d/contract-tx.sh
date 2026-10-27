#!/bin/sh
# EVM contract invocation AND creation end to end, offline + scripts/mock-chain.py on 127.0.0.1 ONLY. Throwaway key 1.
# abi-encode -> tx-build --data/--create -> tx-verify --call/--create-hash -> tx-sign (pty types the code;
# summary shows the decoded call / init code hash + new address) -> tx-decode -> tx-broadcast (mock).
set -eu
B=${BIN:-target/release}; T=$(mktemp -d)
python3 scripts/mock-chain.py $T/port $T/log $T/exp >/dev/null 2>&1 & M=$!
trap 'kill $M 2>/dev/null || true; rm -rf "$T"' EXIT  # allow-true: the mock server may already have exited
while [ ! -s $T/port ]; do sleep 0.1; done; U=http://127.0.0.1:$(cat $T/port)
f() { echo "FAIL $1"; exit 1; }
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
C=0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF; S='setValue(uint256)'
for CID in 1 8453 262144; do  # any EVM chain id (262144: an arbitrary id no table lists)
  $B/abi-encode "$S" 42 | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"])' > $T/cd
  $B/tx-build --chain eth --chain-id $CID --nonce 3 --max-fee-per-gas 2000000000 --gas 60000 --to $C --data @$T/cd > $T/u
  $B/tx-verify --chain-id $CID --expect-to $C --call "$S" < $T/u > $T/v && grep -q '"signature":"setValue(uint256)"' $T/v && grep -q '"value":"42"' $T/v || f "verify call $CID"
  echo "ok   chain $CID: tx-build --data + tx-verify --call decodes setValue(42)"
done
! $B/tx-verify --chain-id 1 --expect-to $C < $T/u > $T/v && grep -q unknown_selector $T/v && grep -q unknown_contract_call $T/v && echo "ok   tx-verify without --call flags the unknown selector" || f unknown
! $B/tx-verify --chain-id 1 --expect-to $C --call 'setValue(uint128)' < $T/u > $T/v && grep -q unknown_selector $T/v && echo "ok   tx-verify: wrong signature -> unknown_selector" || f wrongsig
$B/tx-build --chain eth --chain-id 1 --nonce 3 --max-fee-per-gas 2000000000 --gas 60000 --to $C --data "$(cat $T/cd)00" > $T/tr
! $B/tx-verify --chain-id 1 --expect-to $C --call "$S" < $T/tr > $T/v && grep -q bad_calldata $T/v && echo "ok   tx-verify: trailing calldata byte -> bad_calldata (strict re-encode)" || f trailing
! $B/tx-verify --chain-id 1 --expect-to 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf --call "$S" < $T/u >/dev/null && echo "ok   tx-verify: approved call to another contract -> refused" || f otherto
$B/tx-build --chain eth --chain-id 1 --nonce 3 --max-fee-per-gas 2000000000 --gas 60000 --to $C --data @$T/cd > $T/u
python3 scripts/e2e-only/tty-drive.py right $T/k $T/s $PWD/$B/tx-sign --tx $T/u --chain-id 1 --expect-to $C --call "$S" > $T/tty
grep -q '"status":"ok"' $T/s && grep -q 'Contract call: setValue(uint256)' $T/tty && grep -q 'arg0 (uint256): 42' $T/tty && echo "ok   tx-sign shows the decoded call and signs" || f sign
python3 scripts/e2e-only/tty-drive.py right $T/k $T/s2 $PWD/$B/tx-sign --tx $T/u --chain-id 1 --expect-to $C > $T/tty || true  # allow-true: refusal asserted next
grep -q unknown_contract_call $T/s2 && echo "ok   tx-sign without --call refuses the unknown selector" || f signunk
$B/tx-decode < $T/s | python3 -c 'import json,sys;print([json.loads(l) for l in sys.stdin if "txid" in l][0]["txid"].removeprefix("0x"))' > $T/exp
python3 scripts/e2e-only/tty-drive.py right $T/s $T/o $PWD/$B/tx-broadcast --chain eth --url $U >/dev/null
grep -q '"status":"ok"' $T/o && grep -q eth_sendRawTransaction $T/log && echo "ok   tx-broadcast contract call -> eth_sendRawTransaction (mock), id matches" || f bcast
# Creation: init code of a tiny contract (no compiler: fixed bytes).
I=600a600c600039600a6000f3602a60005260206000f3
$B/tx-build --chain eth --chain-id 1 --nonce 0 --max-fee-per-gas 2000000000 --gas 226175 --create $I > $T/c
H=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["initcode_keccak256"])' $T/c)
$B/tx-verify --chain-id 1 --create-hash $H < $T/c > $T/v && grep -q '"kind":"create"' $T/v && echo "ok   tx-verify --create-hash approves the exact init code" || f create
! $B/tx-verify --chain-id 1 --create-hash 0x$(printf '%064d' 0) < $T/c > $T/v && grep -q initcode_mismatch $T/v && echo "ok   tx-verify: other init code hash -> refused" || f createbad
! $B/tx-verify --chain-id 1 < $T/c >/dev/null && echo "ok   tx-verify: creation without --create-hash -> refused" || f createnone
A=$($B/create-address --deployer 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf --nonce 0 | python3 -c 'import json,sys;print(json.load(sys.stdin)["address"])')
python3 scripts/e2e-only/tty-drive.py right $T/k $T/cs $PWD/$B/tx-sign --tx $T/c --chain-id 1 --create-hash $H > $T/tty
grep -q '"status":"ok"' $T/cs && grep -q "New contract address: $A" $T/tty && echo "ok   tx-sign creation shows init code hash + CREATE address $A" || f csign
$B/tx-decode < $T/cs | python3 -c 'import json,sys;print([json.loads(l) for l in sys.stdin if "txid" in l][0]["txid"].removeprefix("0x"))' > $T/exp
python3 scripts/e2e-only/tty-drive.py right $T/cs $T/o $PWD/$B/tx-broadcast --chain eth --url $U >/dev/null
grep -q '"status":"ok"' $T/o && echo "ok   tx-broadcast contract creation (mock), id matches" || f cbcast
kill $M 2>/dev/null; wait $M 2>/dev/null || true  # allow-true: wait returns the killed mock's signal status
