#!/usr/bin/env python3
"""Re-measure a docs/CHAINS.md fee-rate sample from a public explorer (network; not run by the gate).

usage: python3 scripts/fee-sample.py CHAIN

Method (the one that reproduces the CHAINS.md rows): walk blocks upward from the row's first block,
skip each block's coinbase (and Qtum coinstake), take every other tx in explorer order until N txs are
collected; per tx, fee = inputs - outputs in base units and size from the raw tx (vsize = ceil(weight/4),
witness stripped, for sat/vB rows; full size for sat/B rows). Where the explorer serves raw hex the
sha256d of the stripped tx must equal the txid (mismatches are skipped and counted); on chainz.cryptoid
the raw tx is rebuilt from the explorer JSON and checked the same way. Prints count, block range reached,
median, p10/p75/p90 (sorted[int(q*n)]) and max. Chain data is immutable, so a re-run prints the same line.
"""
import hashlib, json, os, statistics, sys, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

ROWS = {  # chain: (backend, base url, first block, last block in CHAINS.md, txs, unit)
    "dgb": ("blockbook", "https://blockbook.dgb.zelcore.io", 24444779, 24445073, 60, "vB"),
    "rvn": ("blockbook", "https://blockbook.rvn.zelcore.io", 4596227, 4596275, 60, "vB"),
    "vtc": ("blockbook", "https://blockbook.vtc.zelcore.io", 2703728, 2703858, 60, "vB"),
    "doge": ("blockbook", "https://blockbook.doge.zelcore.io", 6429664, 6429671, 100, "B"),
    "ftc": ("blockbook", "https://blockbook.feathercoin.com", 6407004, 6408299, 100, "vB"),
    "zec": ("blockbook", "https://blockbook.zec.zelcore.io", 3529835, 3529915, 200, "B"),
    "qtum": ("qtuminfo", "https://qtum.info/api", 6253698, 6255768, 100, "vB"),
    "mona": ("insight", "https://mona.insight.monaco-ex.org/insight-api-monacoin", 4142748, 4143093, 100, "vB"),
    "trc": ("insight", "https://insight.terracoin.io/api", 3325168, 3327910, 100, "B"),
    "xpm": ("cryptoid", "xpm", 7064002, 7064118, 30, "B"),
    "aur": ("cryptoid", "aur", 5913204, 5913347, 30, "B"),
    "wdc": ("cryptoid", "wdc", 11881187, 11881187, 4, "B"),
}

def get(u, raw_str=False):
    err = None
    for a in range(12):
        try:
            d = json.loads(urllib.request.urlopen(urllib.request.Request(u, headers={"User-Agent": "blocktools-fee-sample"}), timeout=30).read())
            if isinstance(d, str) and not (raw_str and len(d) == 64): raise RuntimeError(d[:80])  # cryptoid answers "busy"
            return d
        except Exception as e:
            err = e; time.sleep(3 + 3 * a)
    raise err

def varint(b, i):
    x = b[i]
    if x < 0xfd: return x, i + 1
    w = {0xfd: 2, 0xfe: 4, 0xff: 8}[x]; return int.from_bytes(b[i + 1:i + 1 + w], "little"), i + 1 + w

def vi(n): return bytes([n]) if n < 0xfd else (b"\xfd" + n.to_bytes(2, "little") if n <= 0xffff else b"\xfe" + n.to_bytes(4, "little"))
def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()[::-1].hex()

def sizes(b):
    """(vsize, total size, segwit?, txid of the witness-stripped tx) for a BTC-format tx"""
    if len(b) > 6 and b[4] == 0 and b[5] == 1:
        i = 6; n, i = varint(b, i)
        for _ in range(n): i += 36; l, i = varint(b, i); i += l + 4
        m, i = varint(b, i)
        for _ in range(m): i += 8; l, i = varint(b, i); i += l
        io = i
        for _ in range(n):
            k, i = varint(b, i)
            for _ in range(k): l, i = varint(b, i); i += l
        assert i + 4 == len(b), "trailing bytes"
        base = b[:4] + b[6:io] + b[i:]
        return -(-(len(base) * 3 + len(b)) // 4), len(b), True, sha256d(base)
    return len(b), len(b), False, sha256d(b)

def blockbook(base, h):
    p = 1
    while True:
        blk = get(f"{base}/api/v2/block/{h}?page={p}")
        for k, t in enumerate(blk["txs"]):
            if p == 1 and k == 0: continue
            tx = get(f"{base}/api/v2/tx/{t['txid']}")
            yield t["txid"], int(tx.get("fees", "0")), bytes.fromhex(tx["hex"])
        if p >= blk.get("totalPages", 1): return
        p += 1

def insight(base, h):
    bh = get(f"{base}/block-index/{h}")["blockHash"]
    for txid in get(f"{base}/block/{bh}")["tx"][1:]:
        t = get(f"{base}/tx/{txid}")
        yield txid, round(t["fees"] * 1e8), bytes.fromhex(get(f"{base}/rawtx/{txid}")["rawtx"])

def qtuminfo(base, h, pool=ThreadPoolExecutor(8), ahead={}):
    # qtum.info is slow (seconds per call): fetch blocks 16 ahead in parallel, and skip the coinbase and the
    # coinstake (tx 0 and tx 1 of a proof-of-stake block) without fetching them
    for k in range(h, h + 16):
        if k not in ahead: ahead[k] = pool.submit(get, f"{base}/block/{k}")
    blk = ahead.pop(h).result()
    txids = blk["transactions"][2 if "proof-of-stake" in blk.get("flags", "") else 1:]
    for txid, t in zip(txids, pool.map(lambda x: get(f"{base}/tx/{x}"), txids)):
        if t["isCoinbase"] or t["isCoinstake"]: continue
        yield txid, int(t["fees"]), -(-t["weight"] // 4)  # qtum.info gives weight, not hex

def cryptoid(coin, h, cache={}):
    R = "https://chainz.cryptoid.info/explorer"
    def tx(t):
        if t not in cache: cache[t] = get(f"{R}/tx.raw.dws?coin={coin}&id={t}"); time.sleep(0.6)
        return cache[t]
    sat = lambda v: round(v * 1e8)
    bh = get(f"https://chainz.cryptoid.info/{coin}/api.dws?q=getblockhash&height={h}", raw_str=True)
    for txid in get(f"{R}/block.raw.dws?coin={coin}&hash={bh}")["tx"][1:]:
        t = tx(txid); raw = t["version"].to_bytes(4, "little") + vi(len(t["vin"]))
        info = get(f"https://chainz.cryptoid.info/{coin}/api.dws?q=txinfo&t={txid}"); time.sleep(0.6)
        vin = sum(sat(i["amount"]) for i in info["inputs"])  # input values from cryptoid txinfo
        for i in t["vin"]:
            s = bytes.fromhex(i["scriptSig"]["hex"])
            raw += bytes.fromhex(i["txid"])[::-1] + i["vout"].to_bytes(4, "little") + vi(len(s)) + s + i["sequence"].to_bytes(4, "little")
        raw += vi(len(t["vout"]))
        for o in t["vout"]:
            s = bytes.fromhex(o["scriptPubKey"]["hex"]); raw += sat(o["value"]).to_bytes(8, "little") + vi(len(s)) + s
        raw += t["locktime"].to_bytes(4, "little")
        yield txid, vin - sum(sat(o["value"]) for o in t["vout"]), raw

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ROWS: sys.exit(f"usage: fee-sample.py {{{','.join(ROWS)}}}")
    chain = sys.argv[1]; kind, base, start, end, n, unit = ROWS[chain]
    src = {"blockbook": blockbook, "insight": insight, "qtuminfo": qtuminfo, "cryptoid": cryptoid}[kind]
    rates, bad, sw, last = [], 0, 0, None
    for h in range(start, end + 1):
        for txid, fee, raw in src(base, h):
            if len(rates) >= n: break
            if isinstance(raw, int): size = raw  # qtum.info vsize
            elif chain == "zec": size = len(raw)  # v4/v5 txs: not BTC format, txid is not sha256d for v5
            else:
                vs, tot, s, cid = sizes(raw)
                if cid != txid: bad += 1; continue
                sw += s; size = vs if unit == "vB" else tot
            rates.append(fee / size); last = h
        if len(rates) >= n: break
    r = sorted(rates); q = lambda x: r[min(len(r) - 1, int(x * len(r)))]
    print(f"{chain}: {len(r)} txs ({sw} segwit, {bad} txid mismatches skipped), blocks {start}-{last}; "
          f"median {statistics.median(r):,.2f} sat/{unit}; p10 {q(0.1):,.2f} p75 {q(0.75):,.2f} p90 {q(0.9):,.2f}; max {r[-1]:,.2f}; zero-fee {sum(1 for x in r if x == 0)}")

main()
sys.stdout.flush(); os._exit(0)  # do not wait for qtum prefetch threads
