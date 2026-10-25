# Armory .wallet (gurnec/btcrecover public test wallet, scripts/fetch-fixtures.sh; skipped when absent).
# Expected addresses: hash160 of the 65-byte PUBLIC keys stored in each entry, read by an independent
# Python parser. armory-read -> key-to-addresses must hit all of them; a wrong password must fail.
set -eu
F=fixtures/external
f() { echo "FAIL $1"; exit 1; }
if [ ! -f $F/armory-wallet.wallet ]; then echo "skip armory (no fixture)"; else
python3 - $F/armory-wallet.wallet > $T/arm.want <<'PY' || f "armory expected addresses"
import hashlib, struct, sys
d = open(sys.argv[1], 'rb').read(); p = 846 + 237 + 1024
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58c(b):
    b += hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]; n = int.from_bytes(b, 'big'); s = ''
    while n: n, r = divmod(n, 58); s = A[r] + s
    return '1' * (len(b) - len(b.lstrip(b'\0'))) + s
while p < len(d):
    t = d[p]; p += 1
    if t != 0: break
    pub = d[p + 20 + 144:p + 20 + 209]; p += 20 + 237
    print(b58c(b'\0' + hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()))
PY
[ "$(wc -l < $T/arm.want)" = 100 ] || f "armory want count"
{ echo btcr-test-password; cat $F/armory-wallet.wallet; } | $B/armory-read | $B/key-to-addresses --chain btc > $T/arm.got 2>/dev/null || f "armory read"
n=0; while read -r a; do grep -q "\"$a\"" $T/arm.got && n=$((n+1)); done < $T/arm.want
[ $n = 100 ] || f "armory: $n/100 stored addresses hit"
! { echo wrong; cat $F/armory-wallet.wallet; } | $B/armory-read 2>/dev/null | grep -q '"wif"' || f "armory wrong password gave keys"
{ echo wrong; cat $F/armory-wallet.wallet; } | $B/armory-read 2>/dev/null | grep -q wrong_password || f "armory wrong_password status"
echo "ok   armory-wallet.wallet: armory-read 100 keys -> addresses = stored public keys' addresses; wrong password refused"
fi
