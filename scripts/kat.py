#!/usr/bin/env python3
"""Independent known-answer generator (Python, shares no code with the Rust tools).
Prints first address per chain for the PUBLIC BIP39 phrase "abandon x11 about".
Used to cross-check crates/kr-core chain encoders. Needs: cryptography, pycryptodome."""
import hashlib, hmac, struct
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives import serialization as S
from Crypto.Hash import keccak
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(b, alpha=A):
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = alpha[r] + s
    return alpha[0] * (len(b) - len(b.lstrip(b"\0"))) + s
def b58c(b, alpha=A): return b58(b + hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4], alpha)
def pub(k, comp=True):
    p = ec.derive_private_key(k, ec.SECP256K1()).public_key()
    return p.public_bytes(S.Encoding.X962, S.PublicFormat.CompressedPoint if comp else S.PublicFormat.UncompressedPoint)
def h160(b): return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
def ckd(k, c, i):
    d = (b"\0" + k.to_bytes(32, "big")) if i >= 1 << 31 else pub(k)
    I = hmac.new(c, d + struct.pack(">I", i), hashlib.sha512).digest()
    return (int.from_bytes(I[:32], "big") + k) % N, I[32:]
def path(seed, p):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest(); k, c = int.from_bytes(I[:32], "big"), I[32:]
    for x in p.split("/")[1:]: k, c = ckd(k, c, int(x.rstrip("'")) + (1 << 31 if x.endswith("'") else 0))
    return k
# BIP173 reference bech32
CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def polymod(v):
    g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; c = 1
    for x in v:
        b = c >> 25; c = (c & 0x1ffffff) << 5 ^ x
        for i in range(5): c ^= g[i] if (b >> i) & 1 else 0
    return c
def segwit(hrp, prog):
    acc = bits = 0; d = [0]
    for b in prog:
        acc = acc << 8 | b; bits += 8
        while bits >= 5: bits -= 5; d.append(acc >> bits & 31)
    if bits: d.append(acc << (5 - bits) & 31)
    e = [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    m = polymod(e + d + [0] * 6) ^ 1
    return hrp + "1" + "".join(CH[x] for x in d + [m >> 5 * (5 - i) & 31 for i in range(6)])
seed = hashlib.pbkdf2_hmac("sha512", ("abandon " * 11 + "about").encode(), b"mnemonic", 2048)
k = path(seed, "m/44'/2'/0'/0/0"); print("ltc p2pkh", b58c(b"\x30" + h160(pub(k))))
k = path(seed, "m/84'/2'/0'/0/0"); print("ltc p2wpkh", segwit("ltc", h160(pub(k))))
k = path(seed, "m/44'/3'/0'/0/0"); print("doge p2pkh", b58c(b"\x1e" + h160(pub(k))))
k = path(seed, "m/44'/195'/0'/0/0"); kh = keccak.new(digest_bits=256, data=pub(k, False)[1:]).digest()
print("tron", b58c(b"\x41" + kh[12:]))
k = path(seed, "m/44'/144'/0'/0/0"); print("xrp", b58c(b"\0" + h160(pub(k)), "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"))
I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
for i in (44, 501, 0, 0):
    I = hmac.new(I[32:], b"\0" + I[:32] + struct.pack(">I", i | 1 << 31), hashlib.sha512).digest()
pk = ed25519.Ed25519PrivateKey.from_private_bytes(I[:32]).public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
print("sol", b58(pk))
