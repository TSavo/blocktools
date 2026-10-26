#!/bin/sh
set -eu
# Path: account numbers -> acct-tx build -> decode -> sign -> decode (signature check).  Cosmos Hub (atom).
# Fetch: `utxo-fetch --chain atom --url LCD ADDR` gives sequence and account_number; UNTESTED here (no saved
#   response for a funded test account), so this path takes them as arguments.
# Broadcast: NOT BUILT for Cosmos (FINDINGS D1-9). Untested human step: POST the signed tx_bytes to your
#   node's /cosmos/tx/v1beta1/txs with mode BROADCAST_MODE_SYNC.
# usage: cosmos-send.sh TO AMOUNT_UATOM SEQUENCE ACCOUNT_NUMBER     (KEY: the sender's key file)
. "$(dirname "$0")/_lib.sh"
TO=$1 AMT=$2 SEQ=$3 ACC=$4
stage "1 keys: address and public key from the key file"
$B/acct-tx keys --chain atom < $KEY > $W/keys.json; cat $W/keys.json
FROM=$(sed 's/.*"address":"\([^"]*\)".*/\1/' $W/keys.json); PK=$(sed 's/.*"pubkey":"\([0-9a-f]*\)".*/\1/' $W/keys.json)
stage "2 build: unsigned MsgSend of $AMT uatom"
$B/acct-tx build --chain atom --from $FROM --pubkey $PK --to $TO --amount $AMT --fee 5000 --gas 200000 --sequence $SEQ --account-number $ACC > $W/unsigned.json
stage "3 decode the unsigned tx"
$B/acct-tx decode --chain atom < $W/unsigned.json
stage "4 sign: shows the tx on the terminal, signs after the typed code"
confirm $KEY $W/signed.json $B/acct-tx sign --chain atom --tx $W/unsigned.json --expect-to $TO
stage "5 decode the signed tx (signature_valid)"
$B/acct-tx decode --chain atom < $W/signed.json
stage "6 broadcast: NOT BUILT for Cosmos (FINDINGS D1-9)"
