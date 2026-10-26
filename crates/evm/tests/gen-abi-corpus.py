#!/usr/bin/env python3
"""Independent ABI vectors for blocktools-evm, produced by eth_abi (ethereum/eth-abi, Python) and
eth_utils.keccak. Deterministic (fixed seed). Writes data/abi-corpus.json:
  [{"types": "(..)", "args": [json values as the Rust encoder takes them], "data": "0x.."}]
Values: ints as decimal strings, bytes as 0x-hex, addresses EIP-55, tuples/arrays as JSON arrays.
Usage: python3 crates/evm/tests/gen-abi-corpus.py   (needs: pip install eth-abi eth-utils)"""
import json, os, random
from eth_abi import encode
from eth_utils import to_checksum_address
import eth_abi
R = random.Random(1014)
SCALARS = ["uint8", "uint32", "uint256", "uint160", "int8", "int64", "int256", "address", "bool",
           "bytes1", "bytes4", "bytes20", "bytes32", "bytes", "string"]

def rtype(d=0):
    k = R.random()
    if d < 2 and k < 0.15: return "(" + ",".join(rtype(d + 1) for _ in range(R.randint(1, 3))) + ")"
    if d < 2 and k < 0.25: return rtype(d + 1) + "[]"
    if d < 2 and k < 0.32: return rtype(d + 1) + f"[{R.randint(1, 3)}]"
    return R.choice(SCALARS)

def split(s):
    out, d, cur = [], 0, ""
    for c in s:
        if c == "," and d == 0: out.append(cur); cur = ""; continue
        d += c == "("; d -= c == ")"; cur += c
    return out + [cur] if cur else out

def rval(t):
    """returns (python value for eth_abi, json value for blocktools)"""
    if t.endswith("]"):
        i = t.rindex("["); inner, n = t[:i], t[i + 1:-1]
        n = int(n) if n else R.randint(0, 3)
        pv = [rval(inner) for _ in range(n)]
        return [p for p, _ in pv], [j for _, j in pv]
    if t.startswith("("):
        pv = [rval(x) for x in split(t[1:-1])]
        return tuple(p for p, _ in pv), [j for _, j in pv]
    if t.startswith("uint"):
        m = int(t[4:]); v = R.choice([0, 1, (1 << m) - 1, R.getrandbits(m)]); return v, str(v)
    if t.startswith("int"):
        m = int(t[3:]); v = R.choice([0, -1, -(1 << (m - 1)), (1 << (m - 1)) - 1, R.getrandbits(m - 1) * R.choice([1, -1])]); return v, str(v)
    if t == "address":
        b = bytes(R.getrandbits(8) for _ in range(20)); return to_checksum_address(b), to_checksum_address(b)
    if t == "bool": v = R.random() < 0.5; return v, v
    if t == "bytes" or t.startswith("bytes"):
        n = R.randint(0, 70) if t == "bytes" else int(t[5:]); b = bytes(R.getrandbits(8) for _ in range(n)); return b, "0x" + b.hex()
    if t == "string":
        s = R.choice(["", "dave", "Hello, world!", "ünïcødé ✓", "x" * R.randint(1, 80)]); return s, s
    raise ValueError(t)

out = []
for _ in range(400):
    ts = [rtype() for _ in range(R.randint(1, 4))]
    pv = [rval(t) for t in ts]
    data = encode(ts, [p for p, _ in pv])
    out.append({"types": "(" + ",".join(ts) + ")", "args": [j for _, j in pv], "data": "0x" + data.hex()})
p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "abi-corpus.json")
json.dump({"generator": f"eth_abi {eth_abi.__version__}", "cases": out}, open(p, "w"), indent=0, ensure_ascii=False)
print(f"wrote {len(out)} cases to {p}")
