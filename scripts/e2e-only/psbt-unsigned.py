#!/usr/bin/env python3
"""psbt-unsigned.py: read tx-build JSON ({"psbt": base64}) or bare base64 on stdin, print the PSBT's
unsigned global transaction as hex. Independent of blocktools (BIP-174 global key 0x00)."""
import base64, json, sys
s = sys.stdin.read().strip(); d = base64.b64decode(json.loads(s)["psbt"] if s.startswith("{") else s)
assert d[:5] == b"psbt\xff"; i = 5
def cs():
    global i; n = d[i]; i += 1
    if n >= 0xfd: w = {0xfd: 2, 0xfe: 4, 0xff: 8}[n]; n = int.from_bytes(d[i:i + w], "little"); i += w
    return n
kl = cs(); assert d[i] == 0 and kl == 1; i += kl; vl = cs(); print(d[i:i + vl].hex())
