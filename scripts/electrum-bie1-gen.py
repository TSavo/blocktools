#!/usr/bin/env python3
"""Independent BIE1 vector for crates/secrets/src/electrum.rs, built with the `cryptography` package
following Electrum's public storage.py/crypto.py description (no Electrum code copied). Public
throwaway password and a fixed ephemeral scalar; the plaintext holds no secrets. Prints one line:
base64 file."""
import base64, hashlib, hmac, zlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, serialization
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PW, PLAIN = "blocktools-bie1-test", b'{"seed_version": 18, "wallet_type": "standard", "note": "blocktools BIE1 vector"}'
c = ec.SECP256K1()
priv = int.from_bytes(hashlib.pbkdf2_hmac("sha512", PW.encode(), b"", 1024), "big") % N
pub = ec.derive_private_key(priv, c).public_key()
eph = ec.derive_private_key(0x1234567890ABCDEF, c)
shared_x = eph.exchange(ec.ECDH(), pub)  # x only; rebuild the compressed point from the full point
pt = ec.derive_private_key(priv * 0x1234567890ABCDEF % N, c).public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
assert pt[1:] == shared_x
k = hashlib.sha512(pt).digest()
p = padding.PKCS7(128).padder(); m = p.update(zlib.compress(PLAIN, 1)) + p.finalize()
e = Cipher(algorithms.AES(k[16:32]), modes.CBC(k[:16])).encryptor(); ct = e.update(m) + e.finalize()
body = b"BIE1" + eph.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint) + ct
print(base64.b64encode(body + hmac.new(k[32:], body, hashlib.sha256).digest()).decode())
