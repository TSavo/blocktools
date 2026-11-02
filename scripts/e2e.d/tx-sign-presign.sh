#!/bin/sh
# tx-sign runs the tx-verify content step (blocktools_evm::presign::apply) before signing AND on the
# re-decoded signed bytes, deny by default, with the same opt-in flags as tx-verify. Constructed txs and
# public throwaway key 1 only. Refusals happen before any key line is read.
set -eu
. scripts/e2e-only/portable.sh
f() { echo "FAIL tx-sign-presign $1"; exit 1; }
B=${BIN:-target/release}; Bab=$(cd "$B" && pwd); T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
TOK=0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
SP=0x000000000022d473030f116ddee9f6b43ac78ba3
RCP=0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF
MAX=115792089237316195423570985008687907853269984665640564039457584007913129639935
bld() { $B/tx-build --chain eth --chain-id 1 --nonce 0 --max-fee-per-gas 1000000000 --gas 200000 --to "$1" --data "$2"; }
code() { python3 -c 'import json,sys;d=json.loads(sys.stdin.read().strip().splitlines()[-1]);print(d.get("status"),",".join(d.get("failures",[])) or d.get("error",""))'; }
# 1. unlimited approve: refused by default, signs only when spender and unlimited are asserted
bld $TOK $($B/abi-encode --raw 'approve(address,uint256)' $SP $MAX) > $T/unl
r=$($B/tx-sign --tx $T/unl --chain-id 1 --expect-to $TOK < $T/k | code)
case "$r" in "refused "*unlimited_approval*) echo "ok   tx-sign refuses an unlimited approve by default ($r)";; *) f "unl: $r";; esac
r=$($B/tx-sign --tx $T/unl --chain-id 1 --expect-to $TOK --expect-spender $RCP --expect-unlimited < $T/k | code)
case "$r" in "refused "*spender_not_expected*) echo "ok   tx-sign --expect-spender mismatch -> spender_not_expected";; *) f "sp: $r";; esac
python3 scripts/e2e-only/tty-drive.py right $T/k $T/s1 $Bab/tx-sign --tx $T/unl --chain-id 1 --expect-to $TOK --expect-spender $SP --expect-unlimited > $T/tty1 2>&1 || true  # allow-true: asserted next
grep -q '"status":"ok"' $T/s1 || { cat $T/s1 $T/tty1; f "asserted unlimited approve did not sign"; }
$B/tx-verify --chain-id 1 --expect-to $TOK --expect-spender $SP --expect-unlimited < $T/s1 > /dev/null || f "signed bytes do not pass tx-verify with the same assertions"
echo "ok   tx-sign signs an asserted unlimited approve; the signed bytes pass the same assertions (recheck)"
# 2. a multicall hiding an unlimited approve (--call lifts the selector only): refused
IN=$($B/abi-encode --raw 'approve(address,uint256)' $SP $MAX)
bld $TOK $($B/abi-encode --raw 'multicall(bytes[])' "[\"$IN\"]") > $T/mc
r=$($B/tx-sign --tx $T/mc --chain-id 1 --expect-to $TOK --call 'multicall(bytes[])' < $T/k | code)
case "$r" in "refused "*inner_calls_not_asserted*unlimited_approval*|"refused "*unlimited_approval*inner_calls_not_asserted*) echo "ok   tx-sign refuses a multicall hiding an unlimited approve";; *) f "mc: $r";; esac
r=$($B/tx-sign --tx $T/mc --chain-id 1 --expect-to $TOK --call 'multicall(bytes[])' --allow-inner-call $TOK:0x095ea7b3 < $T/k | code)
case "$r" in "refused "*unlimited_approval*) echo "ok   naming the inner call still leaves unlimited_approval";; *) f "mc2: $r";; esac
# 3. Safe delegatecall refused
Z=0x0000000000000000000000000000000000000000; MS=0x40A2aCCbd92BCA938b02010E17A5b8929b49130D
bld 0x5555555555555555555555555555555555555555 $($B/abi-encode --raw 'execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)' $MS 0 0x8d80ff0a 1 0 0 0 $Z $Z 0x) > $T/safe
r=$($B/tx-sign --tx $T/safe --chain-id 1 --expect-to 0x5555555555555555555555555555555555555555 < $T/k | code)
case "$r" in "refused "*delegatecall*) echo "ok   tx-sign refuses a Safe delegatecall";; *) f "safe: $r";; esac
# 4. bad input codes match tx-verify (exit 2)
set +e; $B/tx-sign --tx $T/unl --chain-id 1 --expect-to $TOK --expect-unlimited < $T/k > $T/bi; rc=$?; set -e
[ $rc = 2 ] && grep -q expect_unlimited_needs_expect_spender $T/bi && echo "ok   tx-sign --expect-unlimited without --expect-spender -> bad_input" || f "bad input rc=$rc $(cat $T/bi)"
# 5. --plan path: an EVM approve Plan; the content checks still apply
P=$($B/tx-plan new --chain eth --chain-id 1)
P=$(printf '%s' "$P" | $B/tx-plan approve --token $TOK --spender $SP --amount $MAX)
P=$(printf '%s' "$P" | $B/tx-plan expect-to --address $TOK)
P=$(printf '%s' "$P" | $B/tx-plan cap-fee --max 1000000000000000)
printf '%s\n' "$P" > $T/plan
echo '{"nonce":0,"gas":200000,"max_fee_per_gas":1000000000,"priority_fee":1000000000}' > $T/ctx
$B/tx-plan resolve --plan $T/plan --context $T/ctx > $T/ptx || { cat $T/ptx; f "plan resolve"; }
r=$($B/tx-sign --tx $T/ptx --plan $T/plan < $T/k | code)
case "$r" in "refused "*unlimited_approval*) echo "ok   tx-sign --plan refuses an unlimited approve by default";; *) f "plan: $r";; esac
python3 scripts/e2e-only/tty-drive.py right $T/k $T/s2 $Bab/tx-sign --tx $T/ptx --plan $T/plan --expect-spender $SP --expect-unlimited > $T/tty2 2>&1 || true  # allow-true: asserted next
grep -q '"status":"ok"' $T/s2 || { cat $T/s2 $T/tty2; f "plan + assertions did not sign"; }
echo "ok   tx-sign --plan with --expect-spender --expect-unlimited signs"
