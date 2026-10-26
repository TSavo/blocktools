#!/usr/bin/env python3
"""Test-only replay server on 127.0.0.1 for recipes/paths/*.sh. Never contacts any real network.
Serves saved real RPC responses from recipes/paths/fixtures/routes.json:
  {"GET /path": "file.json", "POST method": "file.json"}   (JSON-RPC POSTs match on "method")
Logs every request as one line "VERB PATH BODY" to LOGFILE so the harness can assert the bytes sent.
usage: replay-rpc.py FIXTURE_DIR PORTFILE LOGFILE"""
import http.server, json, os, sys
D, PF, LF = sys.argv[1:4]; R = json.load(open(os.path.join(D, "routes.json")))
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def reply(self, key, body=b""):
        open(LF, "ab").write(key.encode() + b" " + body + b"\n")
        f = R.get(key); data = open(os.path.join(D, f), "rb").read() if f else b'{"error":"no fixture"}'
        self.send_response(200 if f else 404); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
    def do_GET(self): self.reply("GET " + self.path)
    def do_POST(self):
        b = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try: m = json.loads(b).get("method", "")
        except ValueError: m = ""
        self.reply(("POST " + m) if m else ("POST " + self.path), b)
s = http.server.HTTPServer(("127.0.0.1", 0), H); open(PF, "w").write(str(s.server_address[1])); s.serve_forever()
