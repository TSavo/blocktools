#!/usr/bin/env python3
"""evm-decode-check: tx-decode on each committed public mainnet raw tx must match eth_getTransactionByHash.
  python3 scripts/evm-decode-check.py [BIN]     BIN default $BIN, else target/release
Fixtures: fixtures/evm-mainnet/<name>.raw.json (eth_getRawTransactionByHash reply) and NAME.tx.json
(eth_getTransactionByHash reply), both fetched with `rpc https://ethereum-rpc.publicnode.com ...` (public data).
Every field the node returns that tx-decode decodes is compared; a node field tx-decode does not map is listed
in NODE_ONLY (block position, yParity duplicate of v, gasPrice of a typed tx = the effective price)."""
import glob, json, os, subprocess, sys
B = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BIN", "target/release")
NODE_ONLY = {"blockHash", "blockNumber", "blockTimestamp", "transactionIndex", "yParity"}
def q(x): return None if x is None else int(x, 16)
fails = 0; n = 0
for raw in sorted(glob.glob("fixtures/evm-mainnet/*.raw.json")):
    name = os.path.basename(raw)[:-9]
    node = json.load(open(raw.replace(".raw.json", ".tx.json")))["result"]
    p = subprocess.run([os.path.join(B, "tx-decode"), "--chain", "eth"], stdin=open(raw), capture_output=True, text=True)
    lines = [json.loads(l) for l in p.stdout.splitlines() if l.strip()]
    if p.returncode != 0 or len(lines) != 1: print(f"FAIL {name}: rc={p.returncode} {p.stdout.strip()[:300]}"); fails += 1; continue
    d = lines[0]; checked = []
    def eq(field, got, want):
        global fails; checked.append(field)
        if got != want: print(f"FAIL {name}: {field} decoded {got!r} != node {want!r}"); fails += 1
    t = q(node["type"])
    eq("hash", d.get("txid"), node["hash"]); eq("type", d.get("tx_type"), t)
    eq("from", (d.get("from") or "").lower(), node["from"].lower()); eq("to", (d.get("to") or "").lower() or None, node["to"])
    eq("nonce", d.get("nonce"), q(node["nonce"])); eq("gas", d.get("gas"), q(node["gas"]))
    eq("value", int(d.get("value", "-1")), q(node["value"])); eq("input", d.get("data"), node["input"])
    eq("chainId", d.get("chain_id"), q(node.get("chainId")))
    eq("v", d.get("v"), q(node["v"])); eq("r", d.get("r"), node["r"]); eq("s", d.get("s"), node["s"])
    if t in (0, 1): eq("gasPrice", int(d["gas_price"]), q(node["gasPrice"]))
    if t >= 2:
        eq("maxFeePerGas", int(d["max_fee_per_gas"]), q(node["maxFeePerGas"]))
        eq("maxPriorityFeePerGas", int(d["max_priority_fee_per_gas"]), q(node["maxPriorityFeePerGas"]))
    if t >= 1:
        eq("accessList", [(a["address"].lower(), a["storage_keys"]) for a in d["access_list"]], [(a["address"], a["storageKeys"]) for a in node["accessList"]])
    if t == 3:
        eq("maxFeePerBlobGas", int(d["max_fee_per_blob_gas"]), q(node["maxFeePerBlobGas"]))
        eq("blobVersionedHashes", d["blob_versioned_hashes"], node["blobVersionedHashes"])
    if t == 4:
        eq("authorizationList", [(a["chain_id"], a["address"].lower(), a["nonce"], a["y_parity"], a["r"], a["s"]) for a in d["authorization_list"]],
           [(x["chainId"], x["address"], q(x["nonce"]), q(x["yParity"]), x["r"], x["s"]) for x in node["authorizationList"]])
    unmapped = set(node) - NODE_ONLY - {"hash", "type", "from", "to", "nonce", "gas", "value", "input", "chainId", "v", "r", "s", "gasPrice",
        "maxFeePerGas", "maxPriorityFeePerGas", "accessList", "maxFeePerBlobGas", "blobVersionedHashes", "authorizationList"}
    if unmapped: print(f"FAIL {name}: node fields not compared: {sorted(unmapped)}"); fails += 1
    n += 1; print(f"ok   {name} {node['hash']}: {len(checked)} fields match eth_getTransactionByHash ({', '.join(checked)})")
if n == 0: print("FAIL no fixtures"); sys.exit(1)
sys.exit(1 if fails else 0)
