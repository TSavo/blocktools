#!/bin/sh
set -eu
# Path: RPC blockhash -> solBuildTransfer -> solDecodeTx -> solVerifyTx.  Solana.  Signing: NOT BUILT.
# usage: sol-transfer.sh FROM TO LAMPORTS
. "$(dirname "$0")/_lib.sh"
FROM=$1 TO=$2 AMT=$3
stage "1 fetch: recent blockhash from $RPC"
rpc "$RPC" '{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"finalized"}]}' > $W/bh.json
BH=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["result"]["value"]["blockhash"])' $W/bh.json); echo "blockhash $BH"
stage "2 build: unsigned transfer of $AMT lamports"
bt solBuildTransfer "{\"from\":\"$FROM\",\"to\":\"$TO\",\"blockhash\":\"$BH\",\"lamports\":\"$AMT\"}" > $W/unsigned.hex
cat $W/unsigned.hex
stage "3 decode"
bt solDecodeTx "$(cat $W/unsigned.hex)"
stage "4 verify against what you meant to send"
bt solVerifyTx "$(cat $W/unsigned.hex)" "{\"to\":\"$TO\",\"lamports\":\"$AMT\"}"
stage "5 sign: NOT BUILT. blocktools has no Solana signer (FINDINGS D1-9); sign in a wallet you trust and run stage 4 on its bytes."
