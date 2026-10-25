#!/usr/bin/env bash
# recover.sh: unknown wallet file -> classify -> right reader -> funded addresses -> sweep
# transaction to DEST -> human confirms signing -> human confirms broadcast.
#
#   recover.sh FILE DEST [--url ESPLORA|RPC] [--fee-rate N] [--count N] [--chain-id N] [--password-file F]
#
# - Secrets never touch the disk or this script's variables: keys() re-runs the reader
#   pipeline each time it is needed and pipes straight into the next tool (redact or tx-sign).
# - Only public data is stored in $W: addresses, UTXOs, the unsigned PSBT, the signed tx.
# - tx-sign and tx-broadcast each print the decoded transaction on /dev/tty and wait for a
#   typed code. Nothing is signed or sent without it.
# - Wallet passwords come from --password-file (first line), read by the tool, not by bash.
# - Bitcoin, except an Ethereum keystore, which sweeps ETH (--rpc URL, --chain-id N).
set -euo pipefail
B=${BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/release}
usage() { sed -n '4p' "$0" >&2; exit 2; }
[ $# -ge 2 ] || usage
FILE=$1 DEST=$2; shift 2
URL='' FEE=5 COUNT=10 PWF=/dev/null CID=1 CHAIN=btc
while [ $# -gt 0 ]; do case $1 in
  --url) URL=$2; shift 2 ;; --fee-rate) FEE=$2; shift 2 ;; --count) COUNT=$2; shift 2 ;; --chain-id) CID=$2; shift 2 ;;
  --password-file) PWF=$2; shift 2 ;; *) usage ;; esac; done
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
say() { echo "recover: $*" >&2; }

# 1. What is it? (public: class + fingerprint, never the secret)
class=$("$B/classify" "$FILE" | head -1 | sed -n 's/.*"class":"\([a-z0-9_]*\)".*/\1/p')
say "classified as $class"

# 2. Switch on the type: keys() prints key lines (SECRET) for tx-sign and redact.
pw_then_file() { head -n1 "$PWF" | tr -d '\n'; echo; cat "$FILE"; }   # password line, then the wallet
case $class in
  mnemonic)        keys() { "$B/seed-repair" < "$FILE" | "$B/seed-to-master" | "$B/derive" --chain btc --count "$COUNT"; } ;;
  electrum_seed)   keys() { "$B/seed-to-master" < "$FILE" | "$B/derive" --chain btc --count "$COUNT"; } ;;
  wallet_dat)      keys() { pw_then_file | "$B/dat-read" | "$B/derive" --chain btc --count "$COUNT"; } ;;
  electrum_wallet) keys() { pw_then_file | "$B/electrum-read" | "$B/seed-to-master" | "$B/derive" --chain btc --count "$COUNT"; } ;;
  multibit_key)    keys() { pw_then_file | "$B/multibit-read" | "$B/key-to-addresses" --chain btc; } ;;
  wif|hex_key|b58_key|b64_key) keys() { "$B/key-to-addresses" --chain btc < "$FILE"; } ;;
  monero_seed)     "$B/xmr-keys" < "$FILE"; say "monero: address shown; view-key funds scan and sweep are not implemented yet (docs/ROADMAP.md)"; exit 3 ;;
  xrp_seed)        "$B/xrp-tx" keys < "$FILE"; say "xrp: address shown; sweep with xrp-tx build/sign (docs/recipes/xrp.md). Balance/sequence lookup is not automated yet"; exit 3 ;;
  address|xpub|monero_address)    say "watch-only ($class): no private key here, nothing can be signed"; exit 3 ;;
  keystore_v3)     CHAIN=eth; keys() { pw_then_file | "$B/keystore-open"; } ;;
  *)               say "no reader for $class yet (see docs/ROADMAP.md)"; exit 3 ;;
esac

[ -n "$URL" ] || { [ $CHAIN = btc ] && URL=https://blockstream.info/api || URL=https://ethereum-rpc.publicnode.com; }

# 3. Public addresses only (redact strips every secret field), then ask the chain.
keys | "$B/redact" | grep -E "\"(chain|kind)\":\"$CHAIN\"" | sed -n 's/.*"address":"\([^"]*\)".*/\1/p' | sort -u > "$W/addrs"
say "$(wc -l < "$W/addrs") candidate addresses"
"$B/utxo-fetch" --chain $CHAIN --url "$URL" < "$W/addrs" > "$W/utxos"
[ -s "$W/utxos" ] || { say "no funds found"; exit 4; }

# 4. Unsigned sweep, decoded for the human.
if [ $CHAIN = btc ]; then
  say "$(wc -l < "$W/utxos") funded outputs"
  "$B/tx-build" --chain btc --utxos "$W/utxos" --to "$DEST" --sweep --fee-rate "$FEE" > "$W/psbt"
else
  "$B/tx-build" --chain eth --chain-id "$CID" --account "$W/utxos" --to "$DEST" --sweep > "$W/psbt"
fi
"$B/tx-decode" --text < "$W/psbt" >&2

# 5. Sign (human types the code on the terminal), then broadcast (human types another code).
extra=(); if [ $CHAIN = eth ]; then extra=(--chain-id "$CID"); fi
keys | "$B/tx-sign" --tx "$W/psbt" --expect-to "$DEST" "${extra[@]}" > "$W/signed"
grep -q '"status":"ok"' "$W/signed" || { cat "$W/signed"; exit 1; }
"$B/tx-broadcast" --chain $CHAIN --url "$URL" < "$W/signed"
