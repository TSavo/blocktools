# TON (test-only mnemonic generated with tonsdk, never funded): classify -> ton_mnemonic;
# key-to-addresses --chain ton = tonsdk wallet v4r2 address; a BIP39 mnemonic is not TON. Redacted output only.
set -eu
TM="elbow ramp code slogan cigar note auto solution leaf bunker process essence armed burger item blossom achieve normal vault whip switch artefact parrot coffee"
printf '%s\n' "$TM" > "$T/ton.txt"
"$B/classify" "$T/ton.txt" | grep -q '"class":"ton_mnemonic"' || { echo "FAIL ton classify"; exit 1; }
out=$(printf '%s\n' "$TM" | "$B/key-to-addresses" --chain ton | "$B/redact")
echo "$out" | grep -q '"address":"UQCCZtVXlbxxKJbbZti9ESdAkizMyK_CTl0x65osWV1TnALb"' && ! echo "$out" | grep -q 'elbow ramp' \
 && ! printf 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n' | "$B/key-to-addresses" --chain ton | grep -q '"address"' \
 && echo "ok  ton: classify, key-to-addresses = tonsdk v4r2 address, BIP39 phrase not TON" || { echo "FAIL ton"; exit 1; }
