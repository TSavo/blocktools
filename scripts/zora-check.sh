#!/bin/sh
# Live, read-only check of Zora Network (chain id 7777777) against the official public RPC
# https://rpc.zora.energy (network table: https://nft-docs.zora.co/zora-network/network).
# Confirms rpc shortcuts (chainid, height, fee, --chain-id pin and mismatch) and that
# tx-decode --chain eth --text of a recent mainnet user tx names the chain "Zora Network".
# Skips OP-Stack deposit transactions (type 0x7e), which tx-decode refuses as not_evm.
# Needs network. Not run by the CI gate. No keys, no signing, no broadcast.
# usage: sh scripts/zora-check.sh
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
cd "$(dirname "$0")/.."
B=${BIN:-target/release}
U=${ZORA_RPC:-https://rpc.zora.energy}
f() { echo "FAIL $1"; exit 1; }

out=$($B/rpc --protocol evm "$U" chainid) || f "rpc chainid (exit $?): $out"
echo "$out" | grep -q '"chain_id":7777777' && echo "ok   rpc --protocol evm $U chainid -> 7777777" || f "chainid: $out"

out=$($B/rpc --protocol evm "$U" height) || f "rpc height (exit $?): $out"
echo "$out" | grep -q '"height":[0-9]' && echo "ok   rpc --protocol evm $U height -> $out" || f "height: $out"

out=$($B/rpc --protocol evm "$U" fee) || f "rpc fee (exit $?): $out"
echo "$out" | grep -q '"unit":"wei"' && echo "ok   rpc --protocol evm $U fee -> $out" || f "fee: $out"

out=$($B/rpc --protocol evm --chain-id 7777777 "$U" height) || f "rpc --chain-id 7777777 height (exit $?): $out"
echo "$out" | grep -q '"height":[0-9]' && echo "ok   rpc --protocol evm --chain-id 7777777 $U height" || f "pin 7777777: $out"

st=0
out=$($B/rpc --protocol evm --chain-id 1 "$U" height 2>&1) || st=$?
[ "$st" != 0 ] && echo "$out" | grep -q chain_id_mismatch && echo "ok   rpc --protocol evm --chain-id 1 $U height -> chain_id_mismatch" || f "mismatch (exit $st): $out"

T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
# Walk back from tip for a legacy / 2930 / 1559 user tx; 0x7e deposits are not_evm.
ZORA_RPC="$U" python3 - "$T" <<'PY' || f "no type 0/1/2 user tx near tip"
import json, os, subprocess, sys
url, dest = os.environ["ZORA_RPC"], sys.argv[1]
def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    out = subprocess.check_output([
        "curl", "-sS", "-m", "30", "-X", "POST", url,
        "-H", "content-type: application/json",
        "-H", "user-agent: blocktools-zora-check",
        "-d", body,
    ])
    j = json.loads(out)
    if j.get("error"):
        raise SystemExit("eth_rpc %s: %s" % (method, j["error"]))
    return j["result"]
tip = int(rpc("eth_blockNumber", []), 16)
found = None
for h in range(tip, tip - 1000, -1):
    b = rpc("eth_getBlockByNumber", [hex(h), True])
    for t in b.get("transactions") or []:
        typ = t.get("type") or "0x0"
        if int(typ, 16) in (0, 1, 2):
            found = (h, t)
            break
    if found:
        break
if not found:
    raise SystemExit("no type 0/1/2 tx in blocks %s..%s" % (tip - 999, tip))
h, t = found
txid = t["hash"]
raw = rpc("eth_getRawTransactionByHash", [txid])
open(os.path.join(dest, "raw"), "w").write(raw + "\n")
meta = {"block": h, "txid": txid, "type": t.get("type") or "0x0", "chainId": t.get("chainId"), "raw": raw}
open(os.path.join(dest, "meta.json"), "w").write(json.dumps(meta) + "\n")
print("fetched block %s type %s chainId %s tx %s" % (h, meta["type"], meta["chainId"], txid))
PY

# JSON decode must report chain_id 7777777; the text summary must name Zora Network.
$B/tx-decode --chain eth < "$T/raw" > "$T/json" || f "tx-decode json"
grep -q '"chain_id":7777777' "$T/json" && grep -q '"status":"ok"' "$T/json" || f "tx-decode json: $(cat "$T/json")"
echo "ok   tx-decode --chain eth json chain_id 7777777 ($(cat "$T/meta.json"))"

$B/tx-decode --chain eth --text < "$T/raw" > "$T/text" || f "tx-decode --text"
grep -q "7777777 = ZORA NETWORK" "$T/text" && grep -q "7777777 (Zora Network)" "$T/text" \
  && echo "ok   tx-decode --chain eth --text shows 7777777 (Zora Network)" \
  || f "tx-decode text missing Zora Network: $(cat "$T/text")"
