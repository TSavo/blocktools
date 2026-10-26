#!/bin/sh
set -eu
# Path: RPC account (nonce, balance, gas) -> tx-build -> tx-verify -> tx-sign -> tx-broadcast -> RPC.  EVM chains.
# usage: evm-sweep.sh CHAIN_ID FROM_ADDR TO_ADDR    (any EVM chain id: 1 Ethereum, 8453 Base, 42161 Arbitrum, ...)
. "$(dirname "$0")/_lib.sh"
ID=$1 FROM=$2 TO=$3
stage "1 fetch: nonce, balance, chain id and gas price of $FROM from $RPC"
$B/utxo-fetch --chain eth --url "$RPC" "$FROM" > $W/account.json
cat $W/account.json
stage "2 build: unsigned sweep to $TO on chain id $ID (check that account.json chain_id matches: tx-build does not compare them, FINDINGS D1-11)"
$B/tx-build --chain eth --chain-id $ID --account $W/account.json --to "$TO" --sweep > $W/unsigned.tx
stage "3 verify: chain id, destination, fee cap"
$B/tx-verify --chain-id $ID --expect-to "$TO" < $W/unsigned.tx
stage "4 sign: shows the tx on the terminal, signs after the typed code"
confirm $KEY $W/signed.tx $B/tx-sign --tx $W/unsigned.tx --chain-id $ID --expect-to "$TO"
stage "5 decode the signed tx"
$B/tx-decode < $W/signed.tx
stage "6 broadcast with eth_sendRawTransaction to $RPC (asks for a code again)"
confirm $W/signed.tx $W/sent.json $B/tx-broadcast --chain eth --url "$RPC"
cat $W/sent.json
