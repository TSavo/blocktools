# Cosmos Hub (cosmjs public test mnemonic): seed-to-master | derive --chain atom must give
# cosmjs's published default address; classify echoes it as an address. Redacted output only.
M="special sign fit simple patrol salute grocery chicken wheat radar tonight ceiling"
out=$(echo "{\"mnemonic\":\"$M\"}" | "$B/seed-to-master" | "$B/derive" --chain atom --count 1 | "$B/redact")
echo "$out" | grep "cosmos1jhg0e7s6gn44tfc5k37kr04sznyhedtc9rzys5" | grep -q "m/44'/118'/0'/0/0" && ! echo "$out" | grep -Eq '"private_key":"[0-9a-f]' \
 && echo "ok  atom-derive: cosmjs default address" || { echo "FAIL atom-derive"; exit 1; }
