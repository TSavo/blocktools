# Zcash Sapling: zec-sapling -> redact keeps zs1 rows, no secrets on stdout, 0600 viewing-key file, no overwrite.
AM="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
out=$(printf '%s\n' "$AM" | "$B/zec-sapling" --count 2 --viewkey-out "$T/zec.view" | "$B/redact")
[ "$(echo "$out" | grep -Ec '"address":"zs1[a-z0-9]{75}"')" = 2 ] && ! echo "$out" | grep -Eq 'abandon|zxviews' \
 && [ "$(stat -c %a "$T/zec.view")" = 600 ] && [ "$(grep -c '"viewing_key":"zxviews1' "$T/zec.view")" = 2 ] \
 && ! printf '%s\n' "$AM" | "$B/zec-sapling" --viewkey-out "$T/zec.view" >/dev/null 2>&1 \
 && echo "ok  zec-sapling: 2 zs1 rows through redact, 0600 viewkey file, refuses overwrite" || { echo "FAIL zec-sapling"; exit 1; }
