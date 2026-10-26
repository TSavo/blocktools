#!/bin/sh
set -eu
# Path: RPC utxos -> tx-build -> tx-decode -> tx-verify (no key needed).  Bitcoin-style chains.
# Builds and checks an unsigned sweep of someone's coins: what you would sign, before any key is near.
# usage: utxo-inspect.sh CHAIN FROM_ADDR TO_ADDR
. "$(dirname "$0")/_lib.sh"
C=$1 FROM=$2 TO=$3
stage "1 fetch: unspent outputs of $FROM (segwit inputs commit to their amounts, so no prev_tx is fetched)"
$B/utxo-fetch --chain $C --url "$RPC" --no-prev-tx "$FROM" > $W/utxos.jsonl
cat $W/utxos.jsonl
stage "2 build: unsigned sweep to $TO"
$B/tx-build --chain $C --utxos $W/utxos.jsonl --to "$TO" --sweep --fee-rate 5 > $W/unsigned.psbt
stage "3 decode (plain text)"
$B/tx-decode --text < $W/unsigned.psbt
stage "4 verify the destination you expect"
$B/tx-verify --expect-to "$TO" < $W/unsigned.psbt
stage "4b verify refuses a destination you did not expect (exit 1)"
$B/tx-verify --expect-to "$FROM" < $W/unsigned.psbt || echo "exit $?"
