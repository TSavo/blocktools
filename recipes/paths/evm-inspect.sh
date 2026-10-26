#!/bin/sh
set -eu
# Path: RPC eth_getTransactionByHash -> buildEvmTransfer (rebuild unsigned) -> tx-decode -> tx-verify.  EVM.
# Shows what a token transfer someone sent really did, with blocktools' own decoder.
# usage: evm-inspect.sh TXHASH
. "$(dirname "$0")/_lib.sh"
H=$1
stage "1 fetch: the transaction from $RPC"
rpc "$RPC" "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getTransactionByHash\",\"params\":[\"$H\"]}" > $W/tx.json
stage "2 rebuild it unsigned from its fields (ERC-20 transfer(to, amount) in input)"
PLAN=$(python3 - $W/tx.json <<'PY'
import json, sys
t = json.load(open(sys.argv[1]))["result"]; i = t["input"]
assert i[:10] == "0xa9059cbb", "not an ERC-20 transfer: needs abi-decode (planned)"
print(json.dumps({"chainId": int(t["chainId"], 16), "nonce": int(t["nonce"], 16), "gas": str(int(t["gas"], 16)),
  "gasPrice": str(int(t["maxFeePerGas"], 16)), "maxPriorityFeePerGas": str(int(t["maxPriorityFeePerGas"], 16)),
  "to": "0x" + i[34:74], "value": str(int(i[74:138], 16)), "token": t["to"], "from": t["from"]}))
PY
); echo "$PLAN"
bt buildEvmTransfer "$PLAN" > $W/built.json
python3 -c 'import json,sys;b=json.load(open(sys.argv[1]));t=json.load(open(sys.argv[2]))["result"];print("data matches on-chain input:",b["data"]==t["input"]);open(sys.argv[3],"w").write(b["unsigned"])' $W/built.json $W/tx.json $W/unsigned.tx
stage "3 decode"
$B/tx-decode < $W/unsigned.tx
stage "4 verify: chain id 1 and the token recipient"
TO=$(python3 -c 'import json,sys;print(json.loads(sys.argv[1])["to"])' "$PLAN")
$B/tx-verify --chain-id 1 --expect-to "$TO" < $W/unsigned.tx
stage "4b the same tx checked as chain id 8453 (Base) is refused (exit 1)"
$B/tx-verify --chain-id 8453 --expect-to "$TO" < $W/unsigned.tx || echo "exit $?"
