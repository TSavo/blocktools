#!/bin/sh
# build -> decode -> verify -> sign (pty types the code) -> decode, with throwaway key 1 only.
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
D=bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3; TID=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
printf '{"txid":"%s","vout":0,"amount":50000,"address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}\n{"txid":"%s","vout":1,"amount":30000,"address":"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"}\n' $TID $TID > $T/u
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
f() { echo "FAIL $1"; exit 1; }
$B/tx-build --chain btc --utxos $T/u --to $D --sweep --fee-rate 5 --rbf > $T/p
$B/tx-decode --text < $T/p | grep -q "fee    : 0.00001350" && echo "ok   tx-build sweep fee 1350 sats" || f build
$B/tx-verify --expect-to $D < $T/p >/dev/null && echo "ok   tx-verify accepts expected destination" || f verify
! $B/tx-verify --expect-to 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH < $T/p >/dev/null && echo "ok   tx-verify rejects wrong destination" || f verify2
$B/tx-sign --tx $T/p < $T/k | grep -q "expect-to" && echo "ok   tx-sign requires --expect-to" || f expect
$B/tx-sign --tx $T/p --expect-to $D --max-fee 1000 < $T/k | grep -q fee_above_cap && echo "ok   tx-sign fee cap" || f cap
setsid $B/tx-sign --tx $T/p --expect-to $D < $T/k | grep -q aborted && echo "ok   tx-sign refuses without terminal" || f notty
python3 scripts/tty-drive.py wrong $T/k $T/o $PWD/$B/tx-sign --tx $T/p --expect-to $D >/dev/null || true
grep -q aborted $T/o && ! grep -q signed_tx $T/o && echo "ok   tx-sign wrong code -> nothing signed" || f wrong
python3 scripts/tty-drive.py right $T/k $T/o $PWD/$B/tx-sign --tx $T/p --expect-to $D > $T/tty
grep -q "TRANSACTION (btc psbt, SIGNED)" $T/tty && grep -q "Checks passed" $T/tty || f summary
$B/tx-decode --text < $T/o | grep -q "SIGNED" && $B/tx-verify --expect-to $D < $T/o >/dev/null && echo "ok   tx-sign right code -> signed, decodes, re-verifies" || f sign
