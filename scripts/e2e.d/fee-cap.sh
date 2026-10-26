#!/bin/sh
# Security regression: a plain ETH transfer with a 9.99 ETH fee must be refused on every CLI path
# (tx-verify, tx-envelope verify, tx-sign) by the shared default fee cap. Throwaway key 1 only.
set -eu
f() { echo "FAIL $1"; [ -s "${2:-/dev/null}" ] && sed 's/^/  | /' "$2"; exit 1; }
B=${BIN:-target/release}; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
TX=$(cat crates/blocktools/tests/data/evm-fee-9.99eth.txt); TO=0x3535353535353535353535353535353535353535
printf %s "$TX" > $T/tx
! $B/tx-verify --chain eth --chain-id 1 --expect-to $TO < $T/tx > $T/o 2>&1 && grep -q fee_above_cap $T/o && echo "ok   fee-cap: tx-verify refuses 9.99 ETH fee" || f tx-verify $T/o
printf '{"envelope":"blocktools.sign/v1","op":"verify","chain":"eth","chain_id":1,"expect_to":"%s","tx":"%s"}' $TO "$TX" | $B/tx-envelope > $T/o 2>&1 || true  # allow-true: refusal exit asserted on the next line
grep -q fee_above_cap $T/o && grep -q '"ok":false' $T/o && echo "ok   fee-cap: tx-envelope verify refuses 9.99 ETH fee" || f tx-envelope $T/o
echo 0000000000000000000000000000000000000000000000000000000000000001 | { ! $B/tx-sign --chain eth --chain-id 1 --tx $T/tx --expect-to $TO > $T/o 2>&1 < /dev/stdin; } && grep -q fee_above_cap $T/o && ! grep -q '"status":"ok"' $T/o && echo "ok   fee-cap: tx-sign refuses 9.99 ETH fee, nothing signed" || f tx-sign $T/o
