#!/bin/sh
set -eu
# Path: RPC utxos -> tx-build -> tx-verify -> tx-sign -> tx-broadcast -> RPC.  Bitcoin-style chains.
# usage: utxo-sweep.sh CHAIN FROM_ADDR TO_ADDR     (CHAIN: btc | ltc | doge)
. "$(dirname "$0")/_lib.sh"
C=$1 FROM=$2 TO=$3
stage "1 fetch: unspent outputs of $FROM from $RPC"
$B/utxo-fetch --chain $C --url "$RPC" "$FROM" > $W/utxos.jsonl
stage "2 build: unsigned sweep to $TO"
$B/tx-build --chain $C --utxos $W/utxos.jsonl --to "$TO" --sweep --fee-rate 5 > $W/unsigned.psbt
stage "3 verify: destination, fee cap, warnings"
$B/tx-verify --expect-to "$TO" < $W/unsigned.psbt
stage "4 sign: shows the tx on the terminal, signs after the typed code"
confirm $KEY $W/signed.tx $B/tx-sign --tx $W/unsigned.psbt --expect-to "$TO"
stage "5 decode the signed tx"
$B/tx-decode < $W/signed.tx
stage "6 broadcast to $RPC (asks for a code again)"
confirm $W/signed.tx $W/sent.json $B/tx-broadcast --chain $C --url "$RPC"
cat $W/sent.json
