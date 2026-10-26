#!/usr/bin/env python3
"""evm-fixture.py KIND: print an unsigned EVM tx (hex) built by hand with RLP, independent of blocktools,
for the refusal-code examples. KIND: transfer | legacy-no-chain-id | approve | unknown-call | value-and-token
Public test values only (recipient 0x2B5A...6cF = address of private key 2, token = USDC mainnet)."""
import sys
def be(n): return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
def rlp(x):
    if isinstance(x, list):
        p = b"".join(rlp(i) for i in x); return (bytes([0xc0 + len(p)]) if len(p) < 56 else bytes([0xf7 + len(be(len(p)))]) + be(len(p))) + p
    if isinstance(x, int): x = be(x)
    if len(x) == 1 and x[0] < 0x80: return x
    return (bytes([0x80 + len(x)]) if len(x) < 56 else bytes([0xb7 + len(be(len(x)))]) + be(len(x))) + x
TO = bytes.fromhex("2B5AD5c4795c026514f8317c7a215E218DcCD6cF"); TOKEN = bytes.fromhex("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
def call(sel, amt): return bytes.fromhex(sel) + bytes(12) + TO + amt.to_bytes(32, "big")
k = sys.argv[1]; G = 10**9
if k == "legacy-no-chain-id": print(rlp([5, G, 21000, TO, 10**15, b""]).hex()); sys.exit()
to, val, data = {"transfer": (TO, 10**15, b""), "approve": (TOKEN, 0, call("095ea7b3", 2**256 - 1)),
    "unknown-call": (TOKEN, 0, bytes.fromhex("deadbeef")), "value-and-token": (TOKEN, 10**15, call("a9059cbb", 5))}[k]
print("02" + rlp([1, 5, G, 2 * G, 100000, to, val, data, []]).hex())
