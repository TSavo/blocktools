#!/bin/sh
# build -> decode -> verify -> sign (pty types the code) -> decode, with throwaway key 1 only.
set -eu
. scripts/e2e-only/portable.sh
f() { echo "FAIL $1"; exit 1; }
B=${BIN:-target/release}; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
D=bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3; TID=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
printf '{"txid":"%s","vout":0,"amount":50000,"address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}\n' $TID > $T/u
MU="cargo run -q --offline --release -p blocktools-tx --example mock-utxo --"
$MU btc 1 30000 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH >> $T/u   # legacy input: carries prev_tx (amount proof)
# lying amount on a legacy input (prev_tx says 30000, line claims 3000) must be refused
sed 's/"amount":30000/"amount":3000/' $T/u > $T/ulie
! $B/tx-build --chain btc --utxos $T/ulie --to $D --sweep --fee-rate 5 > $T/plie 2>&1 && grep -q prev_tx $T/plie && echo "ok   tx-build refuses legacy input whose amount contradicts prev_tx" || f lie
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
$B/tx-build --chain btc --utxos $T/u --to $D --sweep --fee-rate 5 --rbf > $T/p
$B/tx-decode --text < $T/p | grep -q "fee    : 0.00001350" && echo "ok   tx-build sweep fee 1350 sats" || f build
$B/tx-verify --expect-to $D < $T/p >/dev/null && echo "ok   tx-verify accepts expected destination" || f verify
! $B/tx-verify --expect-to 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH < $T/p >/dev/null && echo "ok   tx-verify rejects wrong destination" || f verify2
# Offline policy file (docs/POLICY.md): allowlist + caps, deny by default, sha256 reported.
printf '{"version":1,"chains":{"btc":{"allow_to":["%s"],"max_value":100000,"max_fee":2000,"max_outputs":1}}}' $D > $T/pol
$B/tx-verify --chain btc --policy $T/pol < $T/p > $T/polout || true  # allow-true: the outcome is asserted on the next line
grep -q '"policy_sha256":"[0-9a-f]\{64\}"' $T/polout && grep -q '"status":"ok"' $T/polout && echo "ok   tx-verify --policy allows listed destination" || { tr -d 0-9a-f < $T/polout; f pol1; }
sed 's/"max_fee":2000/"max_fee":100/' $T/pol > $T/pol2
! $B/tx-verify --chain btc --policy $T/pol2 < $T/p | grep -q policy:max_fee && f pol2 || echo "ok   tx-verify --policy refuses fee over cap"
sed 's/"btc"/"ltc"/' $T/pol > $T/pol3
$B/tx-verify --chain btc --policy $T/pol3 < $T/p | grep -q policy:no_rule_for_chain && echo "ok   tx-verify --policy denies chain without rule" || f pol3
$B/tx-sign --tx $T/p --chain btc --expect-to $D --policy $T/pol2 < $T/k | grep '"refused"' | grep -q policy:max_fee && echo "ok   tx-sign --policy refuses before signing" || f pol4
$B/tx-sign --tx $T/p < $T/k | grep -q "expect-to" && echo "ok   tx-sign requires --expect-to" || f expect
$B/tx-sign --tx $T/p --expect-to $D --max-fee 1000 < $T/k | grep -q fee_above_cap && echo "ok   tx-sign fee cap" || f cap
nosid $B/tx-sign --tx $T/p --expect-to $D < $T/k | grep -q aborted && echo "ok   tx-sign refuses without terminal" || f notty
python3 scripts/e2e-only/tty-drive.py wrong $T/k $T/o $PWD/$B/tx-sign --tx $T/p --expect-to $D >/dev/null || true  # allow-true: nonzero exit is the expected refusal; the outcome is asserted on the next line
grep -q aborted $T/o && ! grep -q signed_tx $T/o && echo "ok   tx-sign wrong code -> nothing signed" || f wrong
# finding:R1-8 (macOS: the controlling tty comes from proc_pidinfo; these three steps run in the macos CI job).
# Terminal pinning: a pin made in one pty session refuses a code typed from a fresh pty (the
# agent-spawned-pty case). Limit: an agent that can write the pin file can re-pin; see SECURITY.md.
BLOCKTOOLS_TTY_PIN=$T/pin python3 scripts/e2e-only/tty-drive.py right /dev/null $T/pinout $PWD/$B/sealed-run pin-tty > /dev/null
grep -q pinned $T/pinout && [ "$(fmode $T/pin)" = 600 ] || f pin
BLOCKTOOLS_TTY_PIN=$T/pin python3 scripts/e2e-only/tty-drive.py right $T/k $T/o $PWD/$B/tx-sign --tx $T/p --expect-to $D > $T/tty.pin || true  # allow-true: nonzero exit is the expected refusal; the outcome is asserted on the next line
grep -q tty_session_not_pinned $T/tty.pin && ! grep -q signed_tx $T/o && echo "ok   pinned terminal: code from another pty session refused" || f pinrefuse
BLOCKTOOLS_TTY_PIN=$T/pin python3 scripts/e2e-only/tty-drive.py right /dev/null $T/o2 $PWD/$B/sealed-run human "derive --help" > /dev/null || true  # allow-true: nonzero exit is the expected refusal; the outcome is asserted on the next line
grep -q tty_session_not_pinned $T/o2 && echo "ok   pinned terminal: sealed-run human refused from another session" || f pinhuman
python3 scripts/e2e-only/tty-drive.py right $T/k $T/o $PWD/$B/tx-sign --tx $T/p --expect-to $D > $T/tty
grep -q "TRANSACTION (btc psbt, SIGNED)" $T/tty && grep -q "Checks passed" $T/tty || f summary
$B/tx-decode --text < $T/o | grep -q "SIGNED" && $B/tx-verify --expect-to $D < $T/o >/dev/null && echo "ok   tx-sign right code -> signed, decodes, re-verifies" || f sign
