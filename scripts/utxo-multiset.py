#!/usr/bin/env python3
"""Order-independent digest of a UTXO set, from either side of the chainstate cross-check, written
independently of the Rust reader (stdlib only):
  utxo-multiset.py dump FILE      a Core dumptxoutset file (25-27 legacy, or 28+ "utxo\\xff" header),
                                  decoded here: Coin VARINT code, compressed amount, compressed script
                                  (types 0-5 incl. uncompressed-key recovery, raw n-6)
  utxo-multiset.py jsonl          chainstate-dump JSON lines on stdin
Prints one JSON line {coins, total, full, script_amount}: `full` = sum over coins of
sha256(txid:vout:height:coinbase:amount:script) mod 2^256, `script_amount` = the same over
(scriptPubKey, amount) only (the funded multiset). Equal digests and counts on both sides = equal sets
(up to a sha256 collision). Invalid uncompressed keys (types 4/5 off the curve) are keyed as Rust
does: ff, type, x."""
import sys, json, hashlib, struct
P = 2**256 - 2**32 - 977
M = 1 << 256

def varint(f):
    n = 0
    while True:
        b = f.read(1)
        if not b: raise EOFError("truncated varint")
        c = b[0]; n = (n << 7) | (c & 0x7f)
        if c & 0x80: n += 1
        else: return n
def compact(f):
    b = f.read(1)[0]
    if b < 253: return b
    return struct.unpack({253: "<H", 254: "<I", 255: "<Q"}[b], f.read({253: 2, 254: 4, 255: 8}[b]))[0]
def amount(x):
    if x == 0: return 0
    x -= 1; e = x % 10; x //= 10
    if e < 9: d = x % 9 + 1; x //= 9; n = x * 10 + d
    else: n = x + 1
    return n * 10 ** e
def script(f):
    n = varint(f)
    if n == 0: return "76a914" + f.read(20).hex() + "88ac"
    if n == 1: return "a914" + f.read(20).hex() + "87"
    if n in (2, 3): return "21" + bytes([n]).hex() + f.read(32).hex() + "ac"
    if n in (4, 5):
        x = f.read(32); xi = int.from_bytes(x, "big")
        y2 = (pow(xi, 3, P) + 7) % P; y = pow(y2, (P + 1) // 4, P)
        if xi >= P or y * y % P != y2: return "ff" + bytes([n]).hex() + x.hex()
        if y % 2 != n - 4: y = P - y
        return "4104" + x.hex() + y.to_bytes(32, "big").hex() + "ac"
    s = f.read(n - 6)
    if len(s) != n - 6: raise EOFError("truncated script")
    return s.hex()

class Acc:
    def __init__(s): s.n = 0; s.total = 0; s.full = 0; s.sa = 0
    def add(s, txid, vout, height, cb, amt, spk):
        s.n += 1; s.total += amt
        s.full = (s.full + int.from_bytes(hashlib.sha256(f"{txid}:{vout}:{height}:{int(cb)}:{amt}:{spk}".encode()).digest(), "big")) % M
        s.sa = (s.sa + int.from_bytes(hashlib.sha256(f"{spk}:{amt}".encode()).digest(), "big")) % M
    def out(s, **kw): print(json.dumps({"coins": s.n, "total": s.total, "full": "%064x" % s.full, "script_amount": "%064x" % s.sa, **kw}))

def coin(f, a, txid, vout):
    code = varint(f); amt = amount(varint(f)); a.add(txid, vout, code >> 1, code & 1, amt, script(f))

a = Acc()
def legacy(skip):
    """Core 25-27 legacy layout; skip=4: the 0.21-24 header, which carries a u32 nChainTx after the count
    (Litecoin 0.21.x dumps). The variant is not marked in the file: try without, then with."""
    a = Acc(); f = open(sys.argv[2], "rb", buffering=1 << 20); h = f.read(40 + skip)
    base = h[:32][::-1].hex(); count = struct.unpack("<Q", h[32:40])[0]
    for _ in range(count):
        txid = f.read(32)[::-1].hex(); vout = struct.unpack("<I", f.read(4))[0]
        if vout >= 1 << 20: raise ValueError("vout out of range")  # same bound as crates/utxo
        coin(f, a, txid, vout)
    if f.read(1): raise ValueError("trailing bytes after the last coin")
    return a, base, count
if sys.argv[1] == "dump":
    f = open(sys.argv[2], "rb", buffering=1 << 20)
    if f.read(5) == b"utxo\xff":
        f.read(2 + 4); base = f.read(32)[::-1].hex(); count = struct.unpack("<Q", f.read(8))[0]; left = count
        while left:
            txid = f.read(32)[::-1].hex(); k = compact(f)
            for _ in range(k): coin(f, a, txid, compact(f)); left -= 1
        if f.read(1): raise SystemExit("trailing bytes after the last coin")
        a.out(base_blockhash=base, coins_count_header=count, header="28+")
    else:
        # Never guess: a 0.21 file can also parse to EOF as 25-27 shifted by 4 bytes (seen in CI run
        # 40577089163: same count, wrong amounts). Parse both; accept only if exactly one succeeds.
        ok = []
        for skip, name in ((0, "25-27"), (4, "0.21-24 (nChainTx u32)")):
            try: ok.append(legacy(skip) + (name,))
            except (ValueError, EOFError, struct.error, IndexError, KeyError): pass
        if len(ok) != 1: raise SystemExit(f"dump layout ambiguous or unparseable: {len(ok)} of 2 layouts parse")
        a, base, count, hdr = ok[0]
        a.out(base_blockhash=base, coins_count_header=count, header=hdr)
else:
    for l in sys.stdin:
        d = json.loads(l); a.add(d["txid"], d["vout"], d["height"], d["coinbase"], d["amount"], d["scriptpubkey_hex"])
    a.out()
