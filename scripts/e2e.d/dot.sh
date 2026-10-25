# Polkadot (subkey docs public mnemonic): key-to-addresses --chain dot gives the prefix-0 address
# of subkey's published public key. Expected value is recomputed here in Python (base58 + hashlib
# blake2b SS58 checksum over the published pubkey). Redacted output only.
DM="caution juice atom organ advance problem want pledge someone senior holiday very"
exp=$(python3 -c "
import hashlib
p=bytes.fromhex('d6a3105d6768e956e9e5d41050ac29843f98561410d3a47f9dd5b3b227ab8746'); d=b'\0'+p
d+=hashlib.blake2b(b'SS58PRE'+d,digest_size=64).digest()[:2]
A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; n=int.from_bytes(d,'big'); s=''
while n: n,r=divmod(n,58); s=A[r]+s
print('1'*(len(d)-len(d.lstrip(b'\0')))+s)")
out=$(printf '%s\n' "$DM" | "$B/key-to-addresses" --chain dot | "$B/redact")
echo "$out" | grep -q "\"address\":\"$exp\"" && ! echo "$out" | grep -q '"private_key":"0x' \
 \
 && echo "ok  dot: mnemonic -> subkey pubkey's SS58 address" || { echo "FAIL dot"; exit 1; }
