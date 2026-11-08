# Kusama (SS58 2) and Polymesh (SS58 12): key-to-addresses from the subkey docs public mnemonic gives
# the same sr25519 public key as the dot row under each prefix; an ed25519 row is emitted alongside
# (TWC dummy key 0x46×32 and derive --explain registry paths); redact keeps each row only with its
# own chain. Redacted output only.
set -eu
DM="caution juice atom organ advance problem want pledge someone senior holiday very"
for c in ksm polyx; do
  out=$(echo "$DM" | "$B/key-to-addresses" --chain $c | "$B/redact")
  echo "$out" | grep -q "\"chain\":\"$c\",\"kind\":\"sr25519\"" && ! echo "$out" | grep -Eq '"private_key":"0x' || { echo "FAIL twc-substrate $c rows"; exit 1; }
done
echo "$DM" | "$B/key-to-addresses" --chain ksm | "$B/redact" | grep -q '"address":"HRkCrbmke2XeabJ5fxJdgXWpBRPkXWfWHY8eTeCKwDdf4k6"' || { echo "FAIL twc-substrate ksm address"; exit 1; }
echo "$DM" | "$B/key-to-addresses" --chain ksm | "$B/redact" | grep -q '"kind":"ed25519"' || { echo "FAIL twc-substrate ksm ed25519 kind"; exit 1; }
DUMMY=4646464646464646464646464646464646464646464646464646464646464646
# redact reorders keys, so kind and address are not adjacent
out=$(echo "$DUMMY" | "$B/key-to-addresses" --chain ksm | "$B/redact")
echo "$out" | grep -q '"kind":"ed25519"' && echo "$out" | grep -q '"address":"Hy8mqcexg5FMwMYnQvzrUvD723qMxDjMRU9HdNCnTsMAypY"' || { echo "FAIL twc-substrate ksm dummy ed25519"; exit 1; }
out=$(echo "$DUMMY" | "$B/key-to-addresses" --chain polyx | "$B/redact")
echo "$out" | grep -q '"kind":"ed25519"' && echo "$out" | grep -q '"address":"2HqjMm2goapWvXQBqjjEdVaTZsUmunWwEq1TSToDR1pDzQ1F"' || { echo "FAIL twc-substrate polyx dummy ed25519"; exit 1; }
"$B/derive" --explain --chain ksm | grep -qF "m/44'/434'/0'/0'/0'" || { echo "FAIL twc-substrate ksm derive path"; exit 1; }
"$B/derive" --explain --chain polyx | grep -qF "m/44'/595'/0'/0'/0'" || { echo "FAIL twc-substrate polyx derive path"; exit 1; }
echo '{"tool":"x","status":"ok","chain":"btc","address":"HRkCrbmke2XeabJ5fxJdgXWpBRPkXWfWHY8eTeCKwDdf4k6"}' | "$B/redact" | grep -q HRkC && { echo "FAIL twc-substrate cross-chain redact"; exit 1; }
echo "ok  twc-substrate: ksm/polyx sr25519+ed25519 rows, redact per chain"
