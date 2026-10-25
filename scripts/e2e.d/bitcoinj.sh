#!/bin/sh
# bitcoinj / MultiBit Classic .wallet and MultiBit HD mbhd.wallet.aes (btcrecover public test
# wallets, scripts/fetch-fixtures.sh; skipped when absent). Expected addresses come from the
# PUBLIC keys stored in each file, read here by an independent Python protobuf parser (for MBHD
# after Python-side outer decryption). multibit-read -> key-to-addresses / derive must hit them.
set -eu
B=${BIN:-target/release}; F=fixtures/external; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
[ -f $F/mbhd.wallet.aes ] || { echo "skip bitcoinj (no fixtures)"; exit 0; }
. scripts/e2e-only/portable.sh
have_pymod cryptography || { echo "skip bitcoinj (python3 module cryptography not installed: pip install cryptography)"; exit 0; }
python3 - $F "$T" <<'PY' || f "expected addresses"
import hashlib, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
F, T = sys.argv[1:]
def vi(b, p):
    r = s = 0
    while True:
        c = b[p]; p += 1; r |= (c & 0x7f) << s; s += 7
        if c < 0x80: return r, p
def fields(b):
    p, o = 0, []
    while p < len(b):
        k, p = vi(b, p); t = k & 7
        if t == 0: v, p = vi(b, p)
        elif t == 2: n, p = vi(b, p); v = b[p:p+n]; p += n
        else: p += 8 if t == 1 else 4; v = None
        o.append((k >> 3, v))
    return o
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def addr(pk):
    b = b"\0" + hashlib.new("ripemd160", hashlib.sha256(pk).digest()).digest()
    b += hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]; n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = A[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s
for n in ["multibit.wallet.bitcoinj.encrypted", "bitcoinj-wallet.wallet", "multibit.wallet.bitcoinj.clear"]:
    pk = [dict(fields(v))[3] for k, v in fields(open(f"{F}/{n}", "rb").read()) if k == 3][0]
    open(f"{T}/{n}.want", "w").write(addr(pk) + "\n")
b = open(f"{F}/mbhd.wallet.aes", "rb").read()
k = hashlib.scrypt("btcr-test-password".encode("utf-16-be"), salt=bytes.fromhex("3551038075a3b0c5"), n=16384, r=8, p=1, dklen=32, maxmem=1 << 30)
d = Cipher(algorithms.AES(k), modes.CBC(bytes.fromhex("a344391f538311b329548616c489723e"))).decryptor(); pt = d.update(b) + d.finalize()
want = []
for kk, v in fields(pt[:-pt[-1]]):
    if kk != 3: continue
    K = dict(fields(v))
    if K.get(1) == 4 and tuple(x for g, x in fields(K[7]) if g == 2) in [(2**31, 0, 0), (2**31, 0, 1)]: want.append(addr(K[3]))
assert len(want) == 2
open(f"{T}/mbhd.want", "w").write("\n".join(want) + "\n")
PY
for n in multibit.wallet.bitcoinj.encrypted bitcoinj-wallet.wallet multibit.wallet.bitcoinj.clear; do
  pw=btcr-test-password; [ $n = multibit.wallet.bitcoinj.clear ] && pw=
  { echo "$pw"; cat $F/$n; } | $B/multibit-read | $B/key-to-addresses --chain btc > $T/a 2>/dev/null || f "$n read"
  grep -qF "\"$(cat $T/$n.want)\"" $T/a || f "$n address"
  echo "ok   $n: multibit-read key -> address = stored public key's address"
done
{ echo btcr-test-password; cat $F/mbhd.wallet.aes; } | $B/multibit-read | $B/derive --chain btc --path "m/0'/{change}/{i}" --change 0 --index 0..1 --address-type p2pkh --compressed --match $T/mbhd.want > $T/h || f "mbhd derive"
[ "$(grep -c '"address"' $T/h)" = 2 ] || f "mbhd hits"
{ echo nope; cat $F/mbhd.wallet.aes; } | $B/multibit-read > $T/w && f "mbhd wrong pw accepted"; grep -q wrong_password $T/w || f "mbhd wrong pw status"
echo "ok   mbhd.wallet.aes: multibit-read xprv -> derive m/0'/0/0..1 hits both stored keys; wrong password refused"
printf 'btcr-test-password\n' > $T/pw; cp $F/mbhd.wallet.aes $T/mbhd.wallet.aes
BIN=$B recipes/recover.sh $T/mbhd.wallet.aes - --goal addresses --count 2 --password-file $T/pw > $T/r 2>/dev/null || f "mbhd recover.sh"
while read -r a; do grep -qF "\"$a\"" $T/r || f "mbhd recover.sh address"; done < $T/mbhd.want
echo "ok   mbhd.wallet.aes: classify (by name) -> recover.sh routes to multibit-read + derive m/0'/c/i, both stored keys found"
