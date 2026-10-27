#!/usr/bin/env python3
"""Deterministic fake bitcoind JSON-RPC on 127.0.0.1 for tests. NOT bitcoind: a scripted stand-in
that never contacts any network. It models a PRUNED node without -txindex: getrawtransaction
answers only when the block hash is given ([txid, verbose, blockhash]), like bitcoind's -5 error.
Chain: 3 regtest-shaped blocks; block 1 holds PREV (pays 50000 sat to a public test p2wpkh
address, BIP173 vector), block 2 holds SPEND (spends PREV:0, pays 49000 sat) -> fee 1000 sat.
Logs every request body to LOGFILE. usage: mock-bitcoind.py PORTFILE LOGFILE [--txindex]"""
import hashlib, http.server, json, os, socketserver, sys
def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
SPK = bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6")  # bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
def tx(prev_txid_le, vout, value):
    return (b"\x02\0\0\0" + b"\x01" + prev_txid_le + vout.to_bytes(4, "little") + b"\x00" + b"\xfd\xff\xff\xff"
            + b"\x01" + value.to_bytes(8, "little") + bytes([len(SPK)]) + SPK + b"\0\0\0\0")
PREV = tx(hashlib.sha256(b"blocktools mock coinbase").digest(), 0, 50000)
PREV_ID = dsha(PREV)[::-1].hex()
SPEND = tx(dsha(PREV), 0, 49000)
SPEND_ID = dsha(SPEND)[::-1].hex()
TXS = {PREV_ID: (PREV.hex(), 1), SPEND_ID: (SPEND.hex(), 2)}
HASH = [hashlib.sha256(b"mock block %d" % h).hexdigest() for h in range(3)]
BLOCK_TXS = {0: [], 1: [PREV_ID], 2: [SPEND_ID]}
TXINDEX = "--txindex" in sys.argv
def err(code, msg): return None, {"code": code, "message": msg}
def call(m, p):
    if not isinstance(p, (list, dict)): return err(-32600, "Params must be an array or object")
    if isinstance(p, dict): p = list(p.values())
    if m == "getblockcount": return 2, None
    if m == "getbestblockhash": return HASH[2], None
    if m == "getblockhash":
        return (HASH[p[0]], None) if p and isinstance(p[0], int) and 0 <= p[0] <= 2 else err(-8, "Block height out of range")
    if m == "getblockchaininfo":
        return {"chain": "regtest", "blocks": 2, "headers": 2, "bestblockhash": HASH[2], "verificationprogress": 1, "pruned": True, "pruneheight": 0}, None
    if m == "getblock":
        if not p or p[0] not in HASH: return err(-5, "Block not found")
        h = HASH.index(p[0]); v = p[1] if len(p) > 1 else 1
        if v == 0: return "00" * 80, None
        b = {"hash": p[0], "height": h, "confirmations": 3 - h, "time": 1700000000 + h, "nTx": len(BLOCK_TXS[h]),
             "previousblockhash": HASH[h - 1] if h else None, "tx": list(BLOCK_TXS[h])}
        if h == 0: b.pop("previousblockhash")
        return b, None
    if m == "getrawtransaction":
        t = TXS.get(p[0] if p else "")
        bh = p[2] if len(p) > 2 else None
        if t is None or (bh is not None and bh != HASH[t[1]]): return err(-5, "No such transaction found in the provided block")
        if bh is None and not TXINDEX:
            return err(-5, "No such mempool transaction. Use -txindex or provide a block hash to enable blockchain transaction queries.")
        if p[1] in (True, 1): return {"txid": p[0], "hex": t[0], "blockhash": HASH[t[1]]}, None
        return t[0], None
    if m == "sendrawtransaction":  # logs nothing to disk; answers the txid of the hex it was given
        return (dsha(bytes.fromhex(p[0]))[::-1].hex(), None) if p and isinstance(p[0], str) else err(-22, "TX decode failed")
    if m == "dumpprivkey": return "cVpF924EspNh8KjYsfhgY96mmxvT6DgdWiTYMtMjuM74hJaU5psW", None  # BIP key-1 regtest WIF, public test value
    return err(-32601, "Method not found")
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        open(sys.argv[2], "ab").write(b + b"\n")
        r = json.loads(b)
        reqs = r if isinstance(r, list) else [r]
        out = []
        for q in reqs:
            res, e = call(q.get("method"), q.get("params") or [])
            out.append({"result": res, "error": e, "id": q.get("id")})
        body = json.dumps(out if isinstance(r, list) else out[0]).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
if __name__ == "__main__":
    if sys.argv[1:2] == ["--ids"]: print(PREV_ID, SPEND_ID, HASH[1], HASH[2]); sys.exit()
    # HTTPServer.server_bind calls socket.getfqdn(), a reverse-DNS lookup that can stall on macOS runners;
    # a plain TCP bind is all a 127.0.0.1 mock needs. The port file appears whole (rename) once bound.
    class S(http.server.HTTPServer):
        def server_bind(self):
            socketserver.TCPServer.server_bind(self); self.server_name, self.server_port = "127.0.0.1", self.server_address[1]
    s = S(("127.0.0.1", 0), H)
    with open(sys.argv[1] + ".tmp", "w") as o: o.write(str(s.server_address[1]))
    os.replace(sys.argv[1] + ".tmp", sys.argv[1]); s.serve_forever()
