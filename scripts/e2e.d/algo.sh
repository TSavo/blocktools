# Algorand (py-algorand-sdk public test mnemonic): classify -> algo_mnemonic; key-to-addresses
# --chain algo gives the SDK's address; a changed word is rejected. Redacted output only.
AM="advice pudding treat near rule blouse same whisper inner electric quit surface sunny dismiss leader blood seat clown cost exist hospital century reform able sponsor"
printf '%s\n' "$AM" > "$T/algo.txt"
"$B/classify" "$T/algo.txt" | grep -q '"class":"algo_mnemonic"' || { echo "FAIL algo classify"; exit 1; }
out=$(printf '%s\n' "$AM" | "$B/key-to-addresses" --chain algo | "$B/redact")
echo "$out" | grep -q '47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU' && ! echo "$out" | grep -q 'advice' \
 && ! printf '%s\n' "${AM% sponsor} abandon" | "$B/key-to-addresses" --chain algo | grep -q '"address"' \
 && echo "ok  algo: classify, key-to-addresses = SDK address, bad checksum rejected" || { echo "FAIL algo"; exit 1; }
