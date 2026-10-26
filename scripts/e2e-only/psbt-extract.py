#!/usr/bin/env python3
"""psbt-extract.py FILE: print the network tx hex of a finalized PSBT (BIP 174/144), written independently
of blocktools so the paths test can check tx-broadcast sent exactly these bytes. FILE is tx-sign output
({"psbt": base64}) or bare base64."""
import base64, json, sys
s = open(sys.argv[1]).read().strip()
b = base64.b64decode(json.loads(s)["psbt"] if s.startswith("{") else s); i = 5
def cs(b, i):
    n = b[i]
    if n < 0xfd: return n, i + 1
    w = {0xfd: 2, 0xfe: 4, 0xff: 8}[n]; return int.from_bytes(b[i+1:i+1+w], "little"), i + 1 + w
def kvmap(b, i):
    m = {}
    while True:
        k, i = cs(b, i)
        if k == 0: return m, i
        key = b[i:i+k]; i += k; v, i = cs(b, i); m.setdefault(key[0], []).append(b[i:i+v]); i += v
g, i = kvmap(b, i); tx = g[0][0]
n_in, j = cs(tx, 4); ins = []
for _ in range(n_in): ins.append(j); j += 36; l, j = cs(tx, j); j += l + 4
outs_start = j; n_out, j = cs(tx, j)
for _ in range(n_out): j += 8; l, j = cs(tx, j); j += l
outs = tx[outs_start:j]; lock = tx[j:j+4]
assert n_in < 0xfd, "test helper: under 253 inputs"
wit = []; segwit = False; res_in = bytearray([n_in])
for k in range(n_in):
    m, i = kvmap(b, i)
    ss = m.get(7, [b""])[0]; w = m.get(8, [b"\x00"])[0]
    if 8 in m: segwit = True
    res_in += tx[ins[k]:ins[k]+36] + bytes([len(ss)]) + ss + tx[ins[k]+36+1+tx[ins[k]+36]:ins[k]+36+1+tx[ins[k]+36]+4]
    wit.append(w)
r = tx[:4] + (b"\x00\x01" if segwit else b"") + res_in + outs + (b"".join(wit) if segwit else b"") + lock
print(r.hex())
