#!/usr/bin/env python3
"""Public-data smoke test for the Python C ABI wrapper."""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
import blocktools as bt

v = bt.version()
assert v and v[0].isdigit(), v
table = bt.chain_table()
assert isinstance(table, list) and any(c.get("name") == "btc" for c in table)
btc = next(c for c in table if c["name"] == "btc")
assert btc["coin_type"] == 0 and btc["buildable"] is True
wdc = next(c for c in table if c["name"] == "wdc")
assert wdc["coin_type"] is None and wdc["buildable"] is False
env = bt.envelope({"op": "chain_table", "chain": "_"})
assert env.get("status") == "ok"
print("ok  python wrapper: version", v, "chains", len(table))
