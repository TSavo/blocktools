#!/usr/bin/env python3
"""Loopback mock of monero-wallet-rpc for e2e: records request bodies to $LOG, answers fixed data.
MODE=ok (amount+fee == unlocked) or MODE=bad (sweep total mismatches)."""
import json, os, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
LOG, MODE = sys.argv[2], sys.argv[3]
R = {"get_version": {"version": 65568}, "refresh": {"blocks_fetched": 3}, "close_wallet": {}, "open_wallet": {},
     "generate_from_keys": {"address": "x"}, "restore_deterministic_wallet": {"address": "x"},
     "get_address": {"address": os.environ.get("ADDR", "")}, "get_height": {"height": 2236200},
     "get_balance": {"balance": 500000000000, "unlocked_balance": 500000000000},
     "get_transfers": {"in": [{"txid": "ab" * 32, "amount": 500000000000, "height": 2236121, "confirmations": 12}]},
     "relay_tx": {"tx_hash": "cd" * 32}}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        b = self.rfile.read(int(self.headers["Content-Length"])); open(LOG, "ab").write(b + b"\n")
        m = json.loads(b)["method"]
        if m == "sweep_all":
            res = {"amount_list": [499990000000 if MODE == "ok" else 1], "fee_list": [10000000], "tx_hash_list": ["cd" * 32], "tx_metadata_list": ["00" * 40]}
        else: res = R.get(m, {})
        out = json.dumps({"jsonrpc": "2.0", "id": "0", "result": res}).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
