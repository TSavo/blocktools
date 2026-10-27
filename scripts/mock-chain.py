#!/usr/bin/env python3
"""Fake Esplora + JSON-RPC server on 127.0.0.1 for tests. Never contacts any real network.
usage: mock-chain.py PORTFILE LOGFILE EXPECTFILE   (writes chosen port, logs every POST body)"""
import hashlib, http.server, json, os, socketserver, sys
TID = "c" * 64
UT = [{"txid": TID, "vout": 0, "value": 50000, "status": {"confirmed": True}}]
def txid(h, single=False):
    """Bitcoin txid of a raw tx hex (witness stripped), so tests need not precompute it.
    single=True: Groestlcoin's single-SHA-256 txid."""
    b = bytes.fromhex(h); i = 4
    def vi():
        nonlocal i
        n = b[i]; i += 1
        if n < 0xfd: return n
        k = {0xfd: 2, 0xfe: 4, 0xff: 8}[n]; v = int.from_bytes(b[i:i + k], "little"); i += k; return v
    seg = b[4] == 0 and b[5] == 1
    if seg: i = 6
    s0 = i; nin = vi()
    def skip(pre, post=0):  # read the varint first: `i += vi()` would use the stale i
        nonlocal i
        i += pre; n = vi(); i += n + post
    for _ in range(nin): skip(36, 4)
    for _ in range(vi()): skip(8)
    body = b[s0:i]
    if seg:
        for _ in range(nin):
            for _ in range(vi()): skip(0)
    raw = b[:4] + body + b[i:i + 4]
    if single: return hashlib.sha256(raw).digest()[::-1].hex()
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()[::-1].hex()
def keccak256(m):
    """Keccak-256 (Ethereum's, not NIST SHA3) for eth tx hashes; test helper only."""
    R = [1, 0x8082, 0x800000000000808A, 0x8000000080008000, 0x808B, 0x80000001, 0x8000000080008081, 0x8000000000008009,
         0x8A, 0x88, 0x80008009, 0x8000000A, 0x8000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
         0x8000000000008002, 0x8000000000000080, 0x800A, 0x800000008000000A, 0x8000000080008081, 0x8000000000008080,
         0x80000001, 0x8000000080008008]
    O = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
    M = (1 << 64) - 1; rot = lambda v, n: ((v << n) | (v >> (64 - n))) & M if n else v
    m = bytearray(m) + b"\x01"; m += b"\0" * (-len(m) % 136); m[-1] |= 0x80
    A = [[0] * 5 for _ in range(5)]
    for o in range(0, len(m), 136):
        for i in range(17): A[i % 5][i // 5] ^= int.from_bytes(m[o + 8 * i:o + 8 * i + 8], "little")
        for rc in R:
            C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
            D = [C[(x - 1) % 5] ^ rot(C[(x + 1) % 5], 1) for x in range(5)]
            A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
            Bm = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5): Bm[y][(2 * x + 3 * y) % 5] = rot(A[x][y], O[x][y])
            A = [[Bm[x][y] ^ (~Bm[(x + 1) % 5][y] & Bm[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
            A[0][0] ^= rc
    return b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; BECH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def spk(a):
    """scriptPubKey for a base58 (p2pkh/p2sh, any version byte) or bech32 segwit address (no checksum check: test only)."""
    if a[:3] in ("bc1", "tb1") or a.startswith("ltc1"):
        d = [BECH.index(c) for c in a[a.rindex("1") + 1:-6]]; v, acc, bits, out = d[0], 0, 0, []
        for x in d[1:]:
            acc = acc << 5 | x; bits += 5
            if bits >= 8: bits -= 8; out.append(acc >> bits & 255)
        return bytes([0x50 + v if v else 0, len(out)]) + bytes(out)
    n = 0
    for c in a: n = n * 58 + B58.index(c)
    b = n.to_bytes(25, "big")
    p2sh = b[0] in (5, 0x32, 0x16, 0xc4)
    return (b"\xa9\x14" + b[1:21] + b"\x87") if p2sh else (b"\x76\xa9\x14" + b[1:21] + b"\x88\xac")
def prev_tx(a):
    """A fake confirmed tx paying 50000 sats to address a (so prev_tx re-hashing works)."""
    s = spk(a)
    return (b"\x02\0\0\0\x01" + hashlib.sha256(a.encode()).digest() + b"\0\0\0\0\0\xff\xff\xff\xff\x01"
            + (50000).to_bytes(8, "little") + bytes([len(s)]) + s + b"\0\0\0\0").hex()
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body, ct="application/json"):
        b = body.encode(); self.send_response(code); self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith("/bad/"): return self.send(200, json.dumps([{"txid": "../x", "vout": 0, "value": 1}]))
        if self.path.endswith("/utxo"):
            if "empty" in self.path: return self.send(200, "[]")
            # MOCK_FUNDED=FILE: only the addresses listed there hold coins (one 50000-sat UTXO each,
            # txid derived from the address so inputs never collide). Unset: every address is funded.
            fund = os.environ.get("MOCK_FUNDED")
            if fund:
                a = self.path.split("/")[-2]
                if a not in open(fund).read().split(): return self.send(200, "[]")
                return self.send(200, json.dumps([{"txid": txid(prev_tx(a)), "vout": 0, "value": 50000, "status": {"confirmed": True}}]))
            return self.send(200, json.dumps(UT))
        fund = os.environ.get("MOCK_FUNDED")
        if fund and self.path.startswith("/tx/") and self.path.endswith("/hex"):
            for a in open(fund).read().split():
                if txid(prev_tx(a)) == self.path.split("/")[2]: return self.send(200, prev_tx(a), "text/plain")
        self.send(404, "nope", "text/plain")
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        open(sys.argv[2], "ab").write(self.path.encode() + b" " + b + b"\n")
        try: exp = open(sys.argv[3]).read().strip()
        except OSError: exp = ""  # the id the test computed locally
        if self.path.startswith("/wrongid"): exp = "d" * 64
        if self.path.endswith("/tx"): return self.send(200, exp or txid(b.decode().strip()), "text/plain")
        r = json.loads(b); m = r["method"]
        try: cid = open(sys.argv[3] + ".chainid").read().strip()  # the chain id a test is impersonating
        except OSError: cid = "0x1"
        res = {"eth_chainId": cid, "eth_getTransactionCount": "0x5", "eth_getBalance": "0xde0b6b3a7640000",
               "eth_gasPrice": "0x3b9aca00", "eth_maxPriorityFeePerGas": "0x5f5e100"}.get(m)
        if m == "eth_sendRawTransaction": res = "0x" + (exp or keccak256(bytes.fromhex(r["params"][0][2:])).hex())
        self.send(200, json.dumps({"jsonrpc": "2.0", "id": 1, "result": res}))
if __name__ == "__main__":
    # HTTPServer.server_bind calls socket.getfqdn(), a reverse-DNS lookup that can stall on macOS runners;
    # a plain TCP bind is all a 127.0.0.1 mock needs. The port file appears whole (rename) once bound.
    class S(http.server.HTTPServer):
        def server_bind(self):
            socketserver.TCPServer.server_bind(self); self.server_name, self.server_port = "127.0.0.1", self.server_address[1]
    s = S(("127.0.0.1", 0), H)
    with open(sys.argv[1] + ".tmp", "w") as o: o.write(str(s.server_address[1]))
    os.replace(sys.argv[1] + ".tmp", sys.argv[1]); s.serve_forever()
