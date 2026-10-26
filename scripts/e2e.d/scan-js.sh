# shellcheck shell=bash
# derive --preset scan-js --address-list + seed-to-master --passphrase-file == SwapChan SCAN_JS output
# (fixtures/scan-js, recorded from the SCAN_JS script). Public test phrase; no key material may print.
set -eu
X=$T/scanjs; mkdir -p "$X"; printf 'TREZOR\r\n\n' > "$X/pp.txt"
A="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
echo "$A" | "$B/seed-to-master" --passphrase-file "$X/pp.txt" > "$X/m.json"
[ "$(grep -c '"passphrase_index":1' "$X/m.json")" = 1 ] || { echo "FAIL scan-js passphrase_index"; exit 1; }
grep -q TREZOR "$X/m.json" && { echo "FAIL scan-js passphrase text printed"; exit 1; }
"$B/derive" --preset scan-js --address-list < "$X/m.json" > "$X/l.txt" 2>"$X/l.err"
tr '\t' ' ' < "$X/l.txt" | cmp -s - fixtures/scan-js/abandon-about-TREZOR.txt || { echo "FAIL scan-js output != SCAN_JS"; exit 1; }
awk -F'\t' 'NF!=3{exit 1}' "$X/l.txt" || { echo "FAIL scan-js list line not 3 fields"; exit 1; }
grep -q '"status":"done","count":600' "$X/l.err" || { echo "FAIL scan-js count"; exit 1; }
"$B/derive" --preset scan-js --public-only < "$X/m.json" > "$X/p.json"
grep -Eq '"(wif|xprv|seed|secret|private_key|privkey)"' "$X/p.json" && { echo "FAIL scan-js public-only leaked a key field"; exit 1; }
"$B/derive" --preset scan-js < "$X/m.json" | grep -Eq '"(wif|secret|private_key|privkey)"' || { echo "FAIL scan-js default mode must still carry keys"; exit 1; }
[ "$(grep -c '"label":"Ledger Live EVM"' "$X/p.json")" = 40 ] || { echo "FAIL scan-js Ledger Live EVM label"; exit 1; }
"$B/derive" --preset scan-js --explain | tail -1 | grep -q '"count":300' || { echo "FAIL scan-js explain 15x20"; exit 1; }
echo "$A" | "$B/seed-to-master" --passphrase-file "$X/pp.txt" --passphrase-prompt < /dev/null | grep -q bad_input || { echo "FAIL scan-js file+prompt accepted"; exit 1; }
printf '{"mnemonic":"%s","passphrase":"x"}\n' "$A" | "$B/seed-to-master" --passphrase-file "$X/pp.txt" | grep -q passphrase_file_and_stdin_passphrase || { echo "FAIL scan-js file+stdin passphrase accepted"; exit 1; }
"$B/seed-to-master" --passphrase-file "$X/none" < /dev/null >/dev/null 2>&1 && { echo "FAIL scan-js missing file accepted"; exit 1; }
true
