#!/usr/bin/env python3
"""Generate self-made Bitcoin Core-style SQLite descriptor wallets for tests.

Independent of the Rust code: Python's sqlite3, hashlib, and `cryptography`
(AES-256-CBC, secp256k1). Keys used are PUBLIC TEST VECTORS / throwaway only:
  * the BIP84 account m/84'/0'/0' of the public BIP39 phrase "abandon x11 about"
  * a throwaway bare key = sha256("blocktools throwaway fixture key 1")
Password of the encrypted wallet (public test password): blocktools-test-password
"""
import hashlib, hmac, os, sqlite3, struct, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization

N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58c(b):
    b = b + hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = B58[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s
def pub(k):
    return ec.derive_private_key(k, ec.SECP256K1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
def h160(b): return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()
def ckd(k, c, i):
    data = (b"\0" + k.to_bytes(32, "big")) if i >= 1 << 31 else pub(k)
    I = hmac.new(c, data + struct.pack(">I", i), hashlib.sha512).digest()
    return (int.from_bytes(I[:32], "big") + k) % N, I[32:]
def cs(b):  # CompactSize vector
    assert len(b) < 0xfd; return bytes([len(b)]) + b
def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def aes_enc(key, iv, pt):
    p = padding.PKCS7(128).padder(); pt = p.update(pt) + p.finalize()
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor(); return e.update(pt) + e.finalize()
def der(k):  # SEC1-shaped CPrivKey prefix as Core writes it
    return bytes.fromhex("308201130201010420") + k.to_bytes(32, "big") + bytes.fromhex("a081a5")

phrase = "abandon " * 11 + "about"
seed = hashlib.pbkdf2_hmac("sha512", phrase.encode(), b"mnemonic", 2048)
I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
k, c = int.from_bytes(I[:32], "big"), I[32:]
fp = h160(pub(k))[:4]
for i in (84 | 1 << 31, 0 | 1 << 31):
    k, c = ckd(k, c, i); fp_parent = fp; fp = h160(pub(k))[:4]
pk, cc, parent = None, None, None
k_parent = k
k, c = ckd(k, c, 0 | 1 << 31)            # m/84'/0'/0'
xpub = b58c(bytes.fromhex("0488B21E") + bytes([3]) + h160(pub(k_parent))[:4] + struct.pack(">I", 1 << 31) + c + pub(k))
desc = f"wpkh([73c5da0a/84h/0h/0h]{xpub}/0/*)#fixture0"
acct, acct_pub = k, pub(k)
bare = int.from_bytes(hashlib.sha256(b"blocktools throwaway fixture key 1").digest(), "big")

def wallet(path, encrypted):
    if os.path.exists(path): os.remove(path)
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE main(key BLOB PRIMARY KEY NOT NULL, value BLOB NOT NULL)")
    put = lambda k, v: db.execute("INSERT INTO main VALUES(?,?)", (k, v))
    did = hashlib.sha256(desc.encode()).digest()
    put(cs(b"walletdescriptor") + did, cs(desc.encode()) + struct.pack("<QiII", 0, 1, 0, 1000))
    put(cs(b"version"), struct.pack("<I", 210100))
    if not encrypted:
        put(cs(b"walletdescriptorkey") + did + cs(acct_pub), cs(der(acct)) + sha256d(acct_pub + der(acct)))
        put(cs(b"key") + cs(pub(bare)), cs(der(bare)) + bytes(32))
    else:
        pw, salt, rounds = b"blocktools-test-password", hashlib.sha256(b"salt").digest()[:8], 25000
        master = hashlib.sha256(b"blocktools fixture master key").digest()
        h = hashlib.sha512(pw + salt).digest()
        for _ in range(rounds - 1): h = hashlib.sha512(h).digest()
        put(cs(b"mkey") + struct.pack("<I", 1), cs(aes_enc(h[:32], h[32:48], master)) + cs(salt) + struct.pack("<II", 0, rounds) + cs(b""))
        for (kt, extra, key, p) in ((b"walletdescriptorckey", did, acct, acct_pub), (b"ckey", b"", bare, pub(bare))):
            put(cs(kt) + extra + cs(p), cs(aes_enc(master, sha256d(p)[:16], key.to_bytes(32, "big"))))
    db.commit(); db.execute("VACUUM"); db.close()

if len(sys.argv) != 2: sys.exit("usage: make-fixtures.py <output-dir>  (use a temp dir; never commit the output)")
out = sys.argv[1]
wallet(f"{out}/descriptor-plain.sqlite", False)
wallet(f"{out}/descriptor-encrypted.sqlite", True)
print("wrote", out)
