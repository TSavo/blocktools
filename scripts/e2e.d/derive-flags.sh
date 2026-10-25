# derive flag system: --explain needs no stdin and emits no keys; --match prints only hits.
out=$("$B/derive" --explain --preset recovery --chain all </dev/null)
echo "$out" | grep -q '"status":"done"' && ! echo "$out" | grep -Eq 'wif|private_key' && echo "ok  derive-explain: plan only" || { echo "FAIL derive-explain"; exit 1; }
printf 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el\nTSeJkUh4Qv67VNFwY8LaAxERygNdy6NQZK\n' > "$T/targets"
hits=$(echo '{"mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}' | "$B/seed-to-master" | "$B/derive" --preset recovery --chain all --match "$T/targets" | "$B/kr-redact")
n=$(echo "$hits" | grep -c '"address"')
[ "$n" = 2 ] && echo "$hits" | grep -q "m/84'/0'/0'/1/0" && ! echo "$hits" | grep -Eq "$LEAK" && echo "ok  derive-match: 2 hits with paths, redacted" || { echo "FAIL derive-match: $n"; exit 1; }
