set -eu
. scripts/e2e-only/portable.sh
# Zcash Sapling: zec-sapling -> redact keeps zs1 rows, no secrets on stdout, 0600 viewing-key file, no overwrite.
AM="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
out=$(printf '%s\n' "$AM" | "$B/zec-sapling" --count 2 --viewkey-out "$T/zec.view" | "$B/redact")
# Counts go into variables first: macOS bash 3.2 mis-parses '{75}' inside a quoted "$(... | grep -c)" test.
re_zs='"address":"zs1[a-z0-9]{75}"'; n_zs=$(printf '%s\n' "$out" | grep -Ec "$re_zs" || true)  # allow-true: grep -c exits 1 on zero; the count is asserted
[ "$n_zs" = 2 ] && ! echo "$out" | grep -Eq 'abandon|zxviews' \
 && [ "$(fmode "$T/zec.view")" = 600 ] && [ "$(grep -c '"viewing_key":"zxviews1' "$T/zec.view")" = 2 ] \
 && ! printf '%s\n' "$AM" | "$B/zec-sapling" --viewkey-out "$T/zec.view" >/dev/null 2>&1 \
 && echo "ok  zec-sapling: 2 zs1 rows through redact, 0600 viewkey file, refuses overwrite" || { echo "FAIL zec-sapling"; exit 1; }
# --unified: per account one u1 (orchard+sapling+p2pkh) row and one t1 row survive redact; no secrets.
out=$(printf '%s\n' "$AM" | "$B/zec-sapling" --count 2 --unified | "$B/redact")
re_u1='"address":"u1[a-z0-9]{100,}"'; re_t1='"address":"t1[1-9A-HJ-NP-Za-km-z]{33}"'
n_u1=$(printf '%s\n' "$out" | grep -Ec "$re_u1" || true); n_t1=$(printf '%s\n' "$out" | grep -Ec "$re_t1" || true)  # allow-true: counts asserted below
[ "$n_u1" = 2 ] && [ "$n_t1" = 2 ] \
 && echo "$out" | grep -q '"address":"u1vu0zkreyef83369fn3dr94zkg2djqlcgtghxf2jmdcdmxp2z4l70dlh6yfdf5v33cteezva2c528syqtmu7uxgzss6fumh3tzjumnqh45z3yewkqplrfdz4f68aahg8x35yknyf7vjh4wy5sn4cc8edkxlef2p4q8ez6e0xuzrmr4rzff54m5t5whyzdgfg2cujtjdjlx2zqu46h7ty"' \
 && ! echo "$out" | grep -Eq 'abandon|zxviews' \
 && echo "ok  zec-sapling --unified: 2 u1 + 2 t1 rows through redact, account-0 UA matches local KAT" || { echo "FAIL zec-sapling --unified"; exit 1; }
