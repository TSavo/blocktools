#!/bin/sh
# ERC-20 approve authorized by an offline --policy allow_calls entry, end to end (regression for #12).
# Before the fix, tx-verify/tx-sign added the general approve findings (token_call_not_transfer,
# has_warnings) into their own verdict and the policy merge only ADDED file findings, never lifted
# the general ones -> an explicitly allowed approve could never verify or sign. Throwaway key 1.
set -eu
B=${BIN:-target/release}; T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
C=0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF            # token contract (approve target)
SP=0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b           # spender (lowercase: no EIP-55 enforcement)
# approve(spender, 1e18): selector 0x095ea7b3
$B/abi-encode 'approve(address,uint256)' $SP 1000000000000000000 | python3 -c 'import json,sys;print(json.load(sys.stdin)["data"])' > $T/cd
$B/tx-build --chain eth --chain-id 56 --nonce 0 --max-fee-per-gas 2000000000 --gas 60000 --to $C --data @$T/cd > $T/u

# Policy that authorizes exactly this (contract, selector).
printf '{"version":1,"chains":{"eth":{"chain_id":56,"allow_calls":[{"to":"%s","selector":"0x095ea7b3"}]}}}' "$C" > $T/pol
# Policy whose allow_calls points at the wrong selector (transfer), so the approve is NOT authorized.
printf '{"version":1,"chains":{"eth":{"chain_id":56,"allow_calls":[{"to":"%s","selector":"0xa9059cbb"}]}}}' "$C" > $T/polbad

# tx-verify WITH the matching policy -> allowed, no findings.
$B/tx-verify --chain-id 56 --policy $T/pol < $T/u > $T/v || f "verify approve under policy should pass"
python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));sys.exit(0 if d.get("status")=="ok" and not d.get("findings") else 1)' $T/v || f "verify approve: expected ok [] got $(cat $T/v)"
echo "ok   tx-verify: approve authorized by allow_calls -> ok, no findings"

# tx-verify with NO policy -> the approve raises token_call_not_transfer + has_warnings.
! $B/tx-verify --chain-id 56 --expect-to $C < $T/u > $T/vn && grep -q token_call_not_transfer $T/vn && grep -q has_warnings $T/vn \
  && echo "ok   tx-verify: approve without policy -> refused (token_call_not_transfer, has_warnings)" || f "no-policy approve must refuse"

# tx-verify with a policy that allows a DIFFERENT selector -> still refused, and the approve findings stay.
! $B/tx-verify --chain-id 56 --policy $T/polbad < $T/u > $T/vb && grep -q 'policy:allow_calls' $T/vb && grep -q token_call_not_transfer $T/vb \
  && echo "ok   tx-verify: wrong allow_calls selector -> refused (policy:allow_calls, token_call_not_transfer)" || f "wrong-selector approve must refuse"

# tx-sign WITH the matching policy -> signs behind the typed code.
python3 scripts/e2e-only/tty-drive.py right $T/k $T/s $PWD/$B/tx-sign --tx $T/u --chain-id 56 --expect-to $C --policy $T/pol > $T/tty
grep -q '"status":"ok"' $T/s || f "tx-sign approve under policy should sign"
echo "ok   tx-sign: approve authorized by allow_calls signs behind the code"

# tx-sign with NO policy -> refuses the approve (never reaches the code prompt).
python3 scripts/e2e-only/tty-drive.py right $T/k $T/s2 $PWD/$B/tx-sign --tx $T/u --chain-id 56 --expect-to $C > $T/tty2 || true  # allow-true: refusal asserted next
grep -q token_call_not_transfer $T/s2 && echo "ok   tx-sign: approve without policy -> refused" || f "no-policy approve sign must refuse"

# A non-token OPAQUE contract call (unknown selector) authorized by allow_calls. THORChain
# depositWithExpiry is the real-world shape: the selector is unknown to blocktools, so the general
# check raises unknown_contract_call + a has_warnings (unknown_calldata) that the allowance must lift.
G=0x1111111111111111111111111111111111111111
GD=0xdeadbeef0000000000000000000000000000000000000000000000000000000000000001
$B/tx-build --chain eth --chain-id 56 --nonce 1 --max-fee-per-gas 1000000000 --priority-fee 1000000000 --gas 120000 --to $G --data $GD --value 0 > $T/gu
printf '{"version":1,"chains":{"eth":{"chain_id":56,"allow_calls":[{"to":"%s","selector":"0xdeadbeef"}]}}}' "$G" > $T/gpol
$B/tx-verify --chain-id 56 --policy $T/gpol < $T/gu > $T/gv || f "opaque call under policy should pass"
python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));sys.exit(0 if d.get("status")=="ok" and not d.get("failures") and not d.get("findings") else 1)' $T/gv || f "opaque call: expected ok [] got $(cat $T/gv)"
echo "ok   tx-verify: opaque unknown-selector call authorized by allow_calls -> ok, no findings"
! $B/tx-verify --chain-id 56 --expect-to $G < $T/gu > $T/gvn && grep -q unknown_contract_call $T/gvn && grep -q has_warnings $T/gvn \
  && echo "ok   tx-verify: opaque call without policy -> refused (unknown_contract_call, has_warnings)" || f "no-policy opaque call must refuse"
