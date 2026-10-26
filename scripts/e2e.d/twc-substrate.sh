# Kusama (SS58 2) and Polymesh (SS58 12): key-to-addresses from the subkey docs public mnemonic gives
# the same sr25519 public key as the dot row under each prefix; redact keeps each row only with its
# own chain; validate accepts Trust Wallet Core's published addresses. Redacted output only.
set -eu
DM="caution juice atom organ advance problem want pledge someone senior holiday very"
for c in ksm polyx; do
  out=$(echo "$DM" | "$B/key-to-addresses" --chain $c | "$B/redact")
  echo "$out" | grep -q "\"chain\":\"$c\",\"kind\":\"sr25519\"" && ! echo "$out" | grep -Eq '"private_key":"0x' || { echo "FAIL twc-substrate $c rows"; exit 1; }
done
echo "$DM" | "$B/key-to-addresses" --chain ksm | "$B/redact" | grep -q '"address":"HRkCrbmke2XeabJ5fxJdgXWpBRPkXWfWHY8eTeCKwDdf4k6"' || { echo "FAIL twc-substrate ksm address"; exit 1; }
echo '{"tool":"x","status":"ok","chain":"btc","address":"HRkCrbmke2XeabJ5fxJdgXWpBRPkXWfWHY8eTeCKwDdf4k6"}' | "$B/redact" | grep -q HRkC && { echo "FAIL twc-substrate cross-chain redact"; exit 1; }
echo "ok  twc-substrate: ksm/polyx rows, redact per chain"
