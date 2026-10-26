#!/bin/sh
set -eu
# Path: RPC latest block -> tronBuildTransfer -> tronDecodeTx -> tronTxId.  Tron.  Signing: NOT BUILT.
# usage: tron-transfer.sh FROM TO AMOUNT_SUN
. "$(dirname "$0")/_lib.sh"
FROM=$1 TO=$2 AMT=$3
stage "1 fetch: latest block header from $RPC"
rpc "$RPC/wallet/getblock" '{"detail":false}' > $W/block.json
PLAN=$(python3 - $W/block.json "$FROM" "$TO" "$AMT" <<'PY'
import json, sys
b = json.load(open(sys.argv[1])); h = b["block_header"]["raw_data"]
print(json.dumps({"from": sys.argv[2], "to": sys.argv[3], "amount_sun": sys.argv[4],
  "ref_block_bytes": "%04x" % (h["number"] & 0xffff), "ref_block_hash": b["blockID"][16:32],
  "timestamp_ms": str(h["timestamp"]), "expiration_ms": str(h["timestamp"] + 60000)}))
PY
); echo "$PLAN"
stage "2 build: unsigned TRX transfer (raw_data hex)"
bt tronBuildTransfer "$PLAN" > $W/unsigned.hex; cat $W/unsigned.hex
stage "3 decode"
bt tronDecodeTx "$(cat $W/unsigned.hex)"
stage "4 txid (sha256 of raw_data)"
bt tronTxId "$(cat $W/unsigned.hex)"
stage "5 verify with expectations: NOT BUILT for Tron (FINDINGS D1-10); compare stage 3 with what you meant to send."
stage "6 sign: NOT BUILT. blocktools has no Tron signer (FINDINGS D1-9)."
