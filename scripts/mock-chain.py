#!/usr/bin/env python3
"""Fake Esplora + JSON-RPC server on 127.0.0.1 for tests. Never contacts any real network.
usage: mock-chain.py PORTFILE LOGFILE EXPECTFILE   (writes chosen port, logs every POST body)"""
import http.server, json, sys
TID = "c" * 64
UT = [{"txid": TID, "vout": 0, "value": 50000, "status": {"confirmed": True}}]
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, body, ct="application/json"):
        b = body.encode(); self.send_response(code); self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path.startswith("/bad/"): return self.send(200, json.dumps([{"txid": "../x", "vout": 0, "value": 1}]))
        if self.path.endswith("/utxo"):
            return self.send(200, json.dumps([] if "empty" in self.path else UT))
        self.send(404, "nope", "text/plain")
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        open(sys.argv[2], "ab").write(self.path.encode() + b" " + b + b"\n")
        try: exp = open(sys.argv[3]).read().strip()
        except OSError: exp = ""  # the id the test computed locally
        if self.path.startswith("/wrongid"): exp = "d" * 64
        if self.path.endswith("/tx"): return self.send(200, exp, "text/plain")
        r = json.loads(b); m = r["method"]
        res = {"eth_chainId": "0x1", "eth_getTransactionCount": "0x5", "eth_getBalance": "0xde0b6b3a7640000",
               "eth_gasPrice": "0x3b9aca00", "eth_maxPriorityFeePerGas": "0x5f5e100", "eth_sendRawTransaction": "0x" + exp}.get(m)
        self.send(200, json.dumps({"jsonrpc": "2.0", "id": 1, "result": res}))
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1], "w").write(str(s.server_address[1])); s.serve_forever()
