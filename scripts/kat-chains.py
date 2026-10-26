#!/usr/bin/env python3
"""Independent known-answer vectors for the UTXO chain table: base58check written from scratch
here (hashlib sha256 only, no project code). Inputs are textbook public values: hash160 of the
secp256k1 generator G (= pubkey of private key 1) and private key 1 itself. Version bytes are
copied from each coin's own source (see chains.rs `source`), not from chains.rs.
usage: kat-chains.py  -> prints `name p2pkh wif_compressed` per row."""
import hashlib
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58c(b):
    b += hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
    n = int.from_bytes(b, "big"); s = ""
    while n: n, r = divmod(n, 58); s = A[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s
H160_G = bytes.fromhex("751e76e8199196d454941c45d1b3a323f1433bd6")  # BIP173 vector program
K1 = bytes(31) + b"\1"
# name: (p2pkh, wif) as decimal from source
ROWS = {"btc": (0, 128), "ltc": (48, 176), "doge": (30, 158), "qtum": (58, 128), "ftc": (14, 142), "nmc": (52, 180),
        "dash": (76, 204), "vtc": (71, 128), "dgb": (30, 128), "via": (71, 199), "mona": (50, 176), "rvn": (60, 128),
        "xpm": (23, 151), "trc": (0, 128), "mec": (50, 178), "aur": (23, 176), "bch": (0, 128), "bsv": (0, 128),
        "btg": (38, 128), "ppc": (55, 183), "nvc": (8, 136), "clam": (137, 133), "blk": (25, 153), "rdd": (61, 189),
        "pot": (55, 183), "qrk": (58, 186), "wdc": (73, 201), "anc": (23, 151),
        "bcc": (18, 146), "pivx": (30, 212), "sys": (63, 128), "firo": (82, 210)}
for n, (p, w) in ROWS.items():
    print(n, b58c(bytes([p]) + H160_G), b58c(bytes([w]) + K1 + b"\1"))
# Zcash transparent (zcash/zcash src/chainparams.cpp): 2-byte prefixes t1 = 1CB8, t3 = 1CBD.
# Printed as `zec P2PKH P2SH-of-H160_G` (no WIF line: zec is address-only here).
print("zec", b58c(bytes.fromhex("1cb8") + H160_G), b58c(bytes.fromhex("1cbd") + H160_G))
