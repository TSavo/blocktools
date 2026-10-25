# Zcash Sapling: zec-sapling -> redact keeps zs1 rows, no secrets on stdout, 0600 viewing-key file, no overwrite.
AM="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
out=$(printf '%s\n' "$AM" | "$B/zec-sapling" --count 2 --viewkey-out "$T/zec.view" | "$B/redact")
[ "$(echo "$out" | grep -Ec '"address":"zs1[a-z0-9]{75}"')" = 2 ] && ! echo "$out" | grep -Eq 'abandon|zxviews' \
 && [ "$(stat -c %a "$T/zec.view")" = 600 ] && [ "$(grep -c '"viewing_key":"zxviews1' "$T/zec.view")" = 2 ] \
 && ! printf '%s\n' "$AM" | "$B/zec-sapling" --viewkey-out "$T/zec.view" >/dev/null 2>&1 \
 && echo "ok  zec-sapling: 2 zs1 rows through redact, 0600 viewkey file, refuses overwrite" || { echo "FAIL zec-sapling"; exit 1; }
# --unified: per account one u1 (orchard+sapling+p2pkh) row and one t1 row survive redact; no secrets.
out=$(printf '%s\n' "$AM" | "$B/zec-sapling" --count 2 --unified | "$B/redact")
[ "$(echo "$out" | grep -Ec '"address":"u1[a-z0-9]{100,}"')" = 2 ] && [ "$(echo "$out" | grep -Ec '"address":"t1[1-9A-HJ-NP-Za-km-z]{33}"')" = 2 ] \
 && echo "$out" | grep -q '"address":"u1vu0zkreyef83369fn3dr94zkg2djqlcgtghxf2jmdcdmxp2z4l70dlh6yfdf5v33cteezva2c528syqtmu7uxgzss6fumh3tzjumnqh45z3yewkqplrfdz4f68aahg8x35yknyf7vjh4wy5sn4cc8edkxlef2p4q8ez6e0xuzrmr4rzff54m5t5whyzdgfg2cujtjdjlx2zqu46h7ty"' \
 && ! echo "$out" | grep -Eq 'abandon|zxviews' \
 && echo "ok  zec-sapling --unified: 2 u1 + 2 t1 rows through redact, account-0 UA matches local KAT" || { echo "FAIL zec-sapling --unified"; exit 1; }
