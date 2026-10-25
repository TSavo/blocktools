# Cardano (public BIP39 vector): key-to-addresses --chain ada = bip_utils / pycardano base address
# at m/1852'/1815'/0'/0/0; 5 rows; mnemonic never in redacted output.
set -eu
AM="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
out=$(printf '%s\n' "$AM" | "$B/key-to-addresses" --chain ada | "$B/redact")
echo "$out" | grep -q '"address":"addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv"' \
 && [ "$(echo "$out" | grep -c '"chain":"ada"')" = 5 ] && ! echo "$out" | grep -q 'abandon' \
 && echo addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv > "$T/ada.txt" && "$B/classify" "$T/ada.txt" | grep -q '"class":"address"' \
 && echo "ok  ada: key-to-addresses = bip_utils base address, 5 rows, classify address" || { echo "FAIL ada"; exit 1; }
