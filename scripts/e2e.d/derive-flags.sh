# derive flag system: --explain needs no stdin and emits no keys; --match prints only hits.
set -eu
out=$("$B/derive" --explain --preset recovery --chain all </dev/null)
echo "$out" | grep -q '"status":"done"' && ! echo "$out" | grep -Eq 'wif|private_key' && echo "ok  derive-explain: plan only" || { echo "FAIL derive-explain"; exit 1; }
printf 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el\nTSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK\n' > "$T/targets"
hits=$(echo '{"mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}' | "$B/seed-to-master" | "$B/derive" --preset recovery --chain all --match "$T/targets" | "$B/redact")
n=$(echo "$hits" | grep -c '"address"')
[ "$n" = 2 ] && echo "$hits" | grep -q "m/84'/0'/0'/1/0" && ! echo "$hits" | grep -Eq "$LEAK" && echo "ok  derive-match: 2 hits with paths, redacted" || { echo "FAIL derive-match: $n"; exit 1; }

# --stop-on-match: first hit ends the walk (address search). Target is BIP84 /0/0 of abandon…about.
printf 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu\nbc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el\n' > "$T/stop-targets"
stop=$(echo '{"mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}' | "$B/seed-to-master" | "$B/derive" --chain btc --address-type p2wpkh --count 20 --match "$T/stop-targets" --stop-on-match | "$B/redact")
n=$(echo "$stop" | grep -c '"address"')
# Exactly one address hit (the first), then status done — second target never reached.
[ "$n" = 1 ] && echo "$stop" | grep -q "m/84'/0'/0'/0/0" && ! echo "$stop" | grep -q "m/84'/0'/0'/1/0" && ! echo "$stop" | grep -Eq "$LEAK" && echo "ok  derive-stop-on-match: 1 hit then halt" || { echo "FAIL derive-stop-on-match: $n"; echo "$stop"; exit 1; }
# --stop-on-match without --match must fail loudly (nonzero exit is enough; help text is optional)
if echo '{"mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}' | "$B/seed-to-master" | "$B/derive" --stop-on-match --count 1 >/dev/null 2>"$T/stop-err"; then
  echo "FAIL derive-stop-requires-match: expected nonzero"; cat "$T/stop-err"; exit 1
fi
echo "ok  derive-stop-on-match: requires --match"
