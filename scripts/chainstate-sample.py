#!/usr/bin/env python3
"""Independent (stdlib) decoder for a bounded sample of a pre-0.15 ('c' per-transaction) chainstate,
for cross-checking chainstate-dump on real data without decoding the whole set:
  chainstate-sample.py pick DIR N     take the key ranges of N evenly spaced deepest-level tables; for each,
                                      merge every live table of any level overlapping it plus the live logs
                                      (newest sequence number wins, deletions honoured), decode the 'c'
                                      records (LevelDB table, de-obfuscation, CCoins mask/compressed txouts
                                      all decoded here); print the Acc digest and the ranges (internal
                                      txid hex, inclusive)
  chainstate-sample.py filter RANGES  chainstate-dump JSON lines on stdin; digest the coins whose txid
                                      falls in a range of RANGES (the JSON line printed by `pick`)
Uncompressed (non-snappy) tables only; prints aggregates only (counts, totals, digests)."""
import sys, os, io, json, struct, importlib.util
spec = importlib.util.spec_from_file_location("um", os.path.join(os.path.dirname(os.path.abspath(__file__)), "utxo-multiset.py"))
src = open(spec.origin).read(); src = src[:src.index("\na = Acc()")]
um = {}; exec(compile(src, spec.origin, "exec"), um)
Acc, varint, amount, script = um["Acc"], um["varint"], um["amount"], um["script"]

def uv(b, p):
    n = s = 0
    while True:
        c = b[p]; p += 1; n |= (c & 0x7f) << s; s += 7
        if c < 0x80: return n, p
def sl(b, p): n, p = uv(b, p); return b[p:p + n], p + n
def records(path):
    d = open(path, "rb").read(); out = []; cur = b""; p = 0
    while p + 7 <= len(d):
        left = 32768 - p % 32768
        if left < 7: p += left; continue
        n = d[p + 4] | d[p + 5] << 8; t = d[p + 6]
        if t == 0 and n == 0: p += left; continue
        body = d[p + 7:p + 7 + n]; p += 7 + n
        if t == 1: out.append(body)
        elif t == 2: cur = body
        elif t == 3: cur += body
        elif t == 4: out.append(cur + body)
    return out
def manifest(dirp):
    m = open(os.path.join(dirp, "CURRENT")).read().strip(); files = {}; logno = 0
    for r in records(os.path.join(dirp, m)):
        p = 0
        while p < len(r):
            tag, p = uv(r, p)
            if tag == 1: _, p = sl(r, p)
            elif tag == 2: logno, p = uv(r, p)
            elif tag in (3, 4, 9): _, p = uv(r, p)
            elif tag == 5: _, p = uv(r, p); _, p = sl(r, p)
            elif tag == 6: _, p = uv(r, p); n, p = uv(r, p); files.pop(n, None)
            elif tag == 7:
                lv, p = uv(r, p); n, p = uv(r, p); _, p = uv(r, p); lo, p = sl(r, p); hi, p = sl(r, p)
                files[n] = (lv, lo[:-8], hi[:-8])
            else: raise SystemExit(f"manifest tag {tag}")
    return files, logno
def block(d, off, size):
    b = d[off:off + size + 5]
    if b[-5] != 0: raise SystemExit("compressed block: unsupported in this sampler")
    b = b[:-5]; nr = struct.unpack("<I", b[-4:])[0]; end = len(b) - 4 - 4 * nr; p = 0; key = b""; out = []
    while p < end:
        sh, p = uv(b, p); ns, p = uv(b, p); vl, p = uv(b, p)
        key = key[:sh] + b[p:p + ns]; p += ns; out.append((key, b[p:p + vl])); p += vl
    return out
def table(path):
    d = open(path, "rb").read(); ft = d[-48:]; p = 0
    _, p = uv(ft, p); _, p = uv(ft, p); io_, p = uv(ft, p); is_, p = uv(ft, p)
    for _, h in block(d, io_, is_):
        o, q = uv(h, 0); s, _ = uv(h, q)
        for ik, v in block(d, o, s): t = int.from_bytes(ik[-8:], "little"); yield ik[:-8], t >> 8, t & 0xff, v
def log_entries(dirp, logno):
    ks = []
    for f in os.listdir(dirp):
        if f.endswith(".log") and int(f[:-4]) >= logno:
            for r in records(os.path.join(dirp, f)):
                p = 12; seq = struct.unpack("<Q", r[:8])[0]
                for _ in range(struct.unpack("<I", r[8:12])[0]):
                    t = r[p]; p += 1; k, p = sl(r, p); v = b""
                    if t == 1: v, p = sl(r, p)
                    ks.append((k, seq, t, v)); seq += 1
    return ks
def coins(txid, v, a):
    f = io.BytesIO(v); varint(f); code = varint(f); cb = code & 1
    avail = [bool(code & 2), bool(code & 4)]; nz = code // 8 + (0 if code & 6 else 1)
    while nz:
        c = f.read(1)[0]; avail += [bool(c >> i & 1) for i in range(8)]; nz -= c != 0
    outs = [(i, amount(varint(f)), script(f)) for i, u in enumerate(avail) if u]
    h = varint(f)
    if f.read(1): raise SystemExit("trailing bytes in a 'c' record")
    for i, amt, spk in outs: a.add(txid, i, h, cb, amt, spk)

if sys.argv[1] == "pick":
    dirp, n = sys.argv[2], int(sys.argv[3]); files, logno = manifest(dirp)
    deep = max(lv for lv, _, _ in files.values()); logs = log_entries(dirp, logno)
    xor = None; ob = b"\x0e\x00obfuscate_key"
    for k, _, t, v in logs:
        if k == ob and t == 1: xor = v[1:]
    for fn, (lv, lo, hi) in files.items():
        if xor is None and lo <= ob <= hi:
            for k, _, t, v in table(os.path.join(dirp, f"{fn:06}.ldb")):
                if k == ob and t == 1: xor = v[1:]
    deepc = sorted((lo, hi) for lv, lo, hi in files.values() if lv == deep and lo[:1] == b"c" and hi[:1] == b"c")
    pick = sorted({deepc[i * len(deepc) // n] for i in range(n)})
    a = Acc(); ranges = []; opened = 0
    for lo, hi in pick:
        newest = {}
        def take(k, seq, t, v):
            if lo <= k <= hi and (k not in newest or newest[k][0] < seq): newest[k] = (seq, t, v)
        for fn, (lv, flo, fhi) in files.items():
            if flo <= hi and lo <= fhi:
                opened += 1
                for e in table(os.path.join(dirp, f"{fn:06}.ldb")): take(*e)
        for e in logs: take(*e)
        for k in sorted(newest):
            seq, t, v = newest[k]
            if t != 1 or k[:1] != b"c": continue
            if xor: v = bytes(x ^ xor[i % len(xor)] for i, x in enumerate(v))
            coins(k[1:][::-1].hex(), v, a)
        ranges.append([lo[1:].hex(), hi[1:].hex()])
    a.out(level=deep, tables_total=len(files), sampled_ranges=len(pick), tables_read=opened, obfuscated=xor is not None, ranges=ranges)
else:
    rs = [(bytes.fromhex(lo), bytes.fromhex(hi)) for lo, hi in json.loads(open(sys.argv[2]).read())["ranges"]]
    a = Acc()
    for l in sys.stdin:
        d = json.loads(l); k = bytes.fromhex(d["txid"])[::-1]
        if any(lo <= k <= hi for lo, hi in rs): a.add(d["txid"], d["vout"], d["height"], d["coinbase"], d["amount"], d["scriptpubkey_hex"])
    a.out()
