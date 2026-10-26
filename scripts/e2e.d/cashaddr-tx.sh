#!/bin/sh
# finding:D1-1 follow-up. CashAddr destinations on bch: tx-build with --to CashAddr (prefixed, bare, upper case) gives the
# same bytes as the legacy address; tx-verify and tx-sign accept CashAddr --expect-to and still
# refuse a different destination. Vectors: bitcoincashorg spec/cashaddr.md. Throwaway key 1 only.
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
cargo run -q --offline --release -p blocktools-tx --example mock-utxo -- bch 1 30000 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH > $T/u
$B/tx-build --chain bch --utxos $T/u --to 1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu --sweep --fee-rate 5 > $T/legacy
for d in bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a BITCOINCASH:QPM2QSZNHKS23Z7629MMS6S4CWEF74VCWVY22GDX6A; do
  $B/tx-build --chain bch --utxos $T/u --to $d --sweep --fee-rate 5 > $T/p || f "build $d"
  cmp -s $T/p $T/legacy || f "bytes differ for $d"
  $B/tx-verify --chain bch --expect-to $d < $T/p >/dev/null || f "verify $d"
done
if $B/tx-verify --chain bch --expect-to bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq < $T/p >/dev/null 2>&1; then f "verify accepted wrong destination"; fi
if $B/tx-build --chain bch --utxos $T/u --to bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b --sweep --fee-rate 5 >/dev/null 2>&1; then f "bad checksum accepted"; fi
if $B/tx-build --chain bch --utxos $T/u --to bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t --sweep --fee-rate 5 >/dev/null 2>&1; then f "testnet accepted"; fi
python3 scripts/e2e-only/tty-drive.py right $T/k $T/o $PWD/$B/tx-sign --tx $T/p --expect-to bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a > $T/tty || f sign
grep -q "Checks passed" $T/tty || f "sign summary"
echo "cashaddr-tx ok"
