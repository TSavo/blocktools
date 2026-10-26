#!/usr/bin/env bash
# recover.sh: unknown wallet file -> classify -> right reader -> funded addresses -> sweep
# transaction to DEST -> human confirms signing -> human confirms broadcast.
#
#   recover.sh FILE DEST [--chain C] [--goal addresses|balance|sweep] [--url ESPLORA|RPC] [--fee-rate N] [--count N] [--chain-id N] [--password-file F]
#
# The front door for every recipe in recipes/README.md. --goal addresses prints public addresses
# only (DEST is ignored, pass -), balance also asks the chain, sweep (default) builds, signs, sends.
# --chain picks the chain for seeds and raw keys (default btc). Sweep is automated for btc, ltc, doge
# (UTXO) and eth; every other chain stops after the addresses (exit 3) and names its builder + recipe.
#
# - Secrets never touch the disk or this script's variables: keys() re-runs the reader
#   pipeline each time it is needed and pipes straight into the next tool (redact or tx-sign).
# - Only public data is stored in $W: addresses, UTXOs, the unsigned PSBT, the signed tx.
# - tx-sign and tx-broadcast each print the decoded transaction on /dev/tty and wait for a
#   typed code. Nothing is signed or sent without it.
# - Wallet passwords come from --password-file (first line), read by the tool, not by bash.
# - Bitcoin, except an Ethereum keystore, which sweeps ETH (--rpc URL, --chain-id N).
# Run as `sh recover.sh` (the man examples do): dash < 0.5.11 (Ubuntu 22.04) has no pipefail and would exit 2,
# so re-exec under bash before the first bash-only line.
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
set -euo pipefail
B=${BIN:-$(cd "$(dirname "$0")/../.." && pwd)/target/release}
usage() { sed -n '4p' "$0" >&2; exit 2; }
[ $# -ge 2 ] || usage
FILE=$1 DEST=$2; shift 2
URL='' FEE=5 COUNT=10 PWF=/dev/null CID=1 CHAIN=btc GOAL=sweep WATCH=0
while [ $# -gt 0 ]; do case $1 in
  --chain) CHAIN=$2; shift 2 ;; --goal) GOAL=$2; shift 2 ;;
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
  mnemonic)        keys() { "$B/seed-repair" < "$FILE" | "$B/seed-to-master" | "$B/derive" --chain "$CHAIN" --count "$COUNT"; } ;;
  electrum_seed)   keys() { "$B/seed-to-master" < "$FILE" | "$B/derive" --chain "$CHAIN" --count "$COUNT"; } ;;
  wallet_dat)      keys() { pw_then_file | "$B/dat-read" | "$B/derive" --chain "$CHAIN" --count "$COUNT"; } ;;
  # Electrum 2+: seed -> seed-to-master -> derive. Electrum 1.x: electrum-read emits the keys itself.
  electrum_wallet|electrum_wallet_file_encrypted) keys() { local e; e=$(pw_then_file | "$B/electrum-read" --count "$COUNT")
                            if printf '%s\n' "$e" | grep -q '"wif"'; then printf '%s\n' "$e"; else printf '%s\n' "$e" | "$B/seed-to-master" | "$B/derive" --chain "$CHAIN" --count "$COUNT"; fi; unset e; } ;;
  multibit_key)    keys() { pw_then_file | "$B/multibit-read" | "$B/key-to-addresses" --chain "$CHAIN"; } ;;
  wif|hex_key|b58_key|b64_key) keys() { "$B/key-to-addresses" --chain "$CHAIN" < "$FILE"; } ;;
  monero_seed)     "$B/xmr-keys" < "$FILE"; say "monero: address shown; scan and sweep with xmr-wallet on the host through your own loopback monero-wallet-rpc (recipes/monero.md)"; exit 3 ;;
  xrp_seed)        "$B/xrp-tx" keys < "$FILE"; say "xrp: address shown; sweep with xrp-tx build/sign (recipes/xrp.md). Balance/sequence lookup is not automated yet"; exit 3 ;;
  ton_mnemonic)    "$B/key-to-addresses" --chain ton < "$FILE" | "$B/redact"; say "ton: wallet v4r2 address shown; sweep with acct-tx build/sign --chain ton (recipes/chain-ton.md)"; exit 3 ;;
  algo_mnemonic)   "$B/key-to-addresses" --chain algo < "$FILE" | "$B/redact"; say "algo: address shown; sweep with acct-tx build/sign --chain algo (recipes/chain-algorand.md)"; exit 3 ;;
  xlm_seed)        "$B/key-to-addresses" --chain xlm < "$FILE" | "$B/redact"; say "xlm: address shown; sweep with acct-tx build/sign --chain xlm (recipes/chain-stellar.md)"; exit 3 ;;
  # BIP32 master xprv (one line): wrapped as {"xprv":...} by sed (streamed, never a shell variable) for derive.
  xprv)            keys() { sed -n '1s/^[[:space:]]*\([1-9A-Za-z]*\).*/{"status":"ok","xprv":"\1"}/p' "$FILE" | "$B/derive" --chain "$CHAIN" --count "$COUNT"; } ;;
  armory_wallet)   keys() { pw_then_file | "$B/armory-read" | "$B/key-to-addresses" --chain "$CHAIN"; } ;;
  # bitcoinj / MultiBit Classic .wallet, MultiBit HD mbhd.wallet.aes (by name): loose keys (wif) or an HD seed (xprv, MultiBit HD path m/0'/c/i).
  bitcoinj_wallet|multibit_hd_wallet) keys() { local e; e=$(pw_then_file | "$B/multibit-read")
                            if printf '%s\n' "$e" | grep -q '"wif"'; then printf '%s\n' "$e" | "$B/key-to-addresses" --chain "$CHAIN"; else printf '%s\n' "$e" | "$B/derive" --chain "$CHAIN" --path "m/0'/{change}/{i}" --change 0,1 --index "0..$((COUNT-1))" --address-type p2pkh --compressed; fi; unset e; } ;;
  xpub)            WATCH=1; keys() { "$B/xpub-addresses" --chain "$CHAIN" --count "$COUNT" --change 0,1 < "$FILE"; } ;;
  address)         WATCH=1; keys() { "$B/classify" "$FILE" | sed -n 's/.*"address":"\([^"]*\)".*/{"status":"ok","chain":"'"$CHAIN"'","address":"\1"}/p'; } ;;
  monero_address)  say "watch-only ($class): Monero balances need the view key (recipes/monero.md)"; exit 3 ;;
  keystore_v3)     CHAIN=eth; keys() { pw_then_file | "$B/keystore-open"; } ;;
  blockchain_wallet) keys() { pw_then_file | "$B/blockchain-read" | "$B/key-to-addresses" --chain "$CHAIN"; } ;;
  bip38)           keys() { pw_then_file | "$B/bip38-open" | "$B/key-to-addresses" --chain "$CHAIN"; } ;;
  *)               say "no reader for $class yet (see docs/ROADMAP.md)"; exit 3 ;;
esac

# 3. Public addresses only (redact strips every secret field), then ask the chain.
keys | "$B/redact" > "$W/red"   # reader/redact failures stop the script (pipefail)
{ grep -E "\"(chain|kind)\":\"$CHAIN\"" "$W/red" | grep '"address"' > "$W/pub"; } || [ $? -eq 1 ]  # no match = no addresses (checked below); grep errors stay fatal
sed -n 's/.*"address":"\([^"]*\)".*/\1/p' "$W/pub" | sort -u > "$W/addrs"
say "$(wc -l < "$W/addrs") candidate addresses on $CHAIN"
[ -s "$W/addrs" ] || { say "no $CHAIN addresses from this input (wrong --chain?)"; exit 4; }
if [ "$GOAL" = addresses ]; then cat "$W/pub"; exit 0; fi
next() { case $1 in
  xlm) echo "acct-tx build/sign (recipes/chain-stellar.md)" ;; algo) echo "acct-tx build/sign (recipes/chain-algorand.md)" ;;
  atom) echo "acct-tx build/sign (recipes/chain-cosmos.md)" ;; ton) echo "acct-tx build/sign (recipes/chain-ton.md)" ;;
  ada) echo "acct-tx build/sign (recipes/chain-cardano.md)" ;; dot) echo "acct-tx build/sign (recipes/chain-polkadot.md)" ;;
  xrp) echo "xrp-tx build/sign (recipes/xrp.md)" ;; grs) echo "tx-build from a UTXO list (recipes/chain-groestlcoin.md)" ;;
  zec) echo "tx-build from a UTXO list (recipes/chain-zcash-transparent.md)" ;;
  qtum) echo "tx-build from a UTXO list (recipes/chain-qtum.md)" ;;
  pot) echo "sweep is not built for pot (no reachable explorer to verify its tx format); import the key into a Potcoin wallet (recipes/chain-old-coins.md)" ;;
  sol|tron) echo "sweep is not built for $1; import the key into a $1 wallet (recipes/README.md, 'By chain')" ;;
  *) echo "tx-build from a UTXO list (recipes/chain-old-coins.md)" ;; esac; }
case $CHAIN in btc|ltc|doge|eth) ;; *)
  cat "$W/pub"; say "$CHAIN: addresses only; recover.sh automates sweep for btc/ltc/doge/eth. Next: $(next "$CHAIN")"; exit 3 ;; esac
if [ $WATCH = 1 ] && [ "$GOAL" = sweep ]; then say "watch-only ($class): no private key here, nothing can be signed"; exit 3; fi
url=(); if [ -n "$URL" ]; then url=(--url "$URL"); fi
"$B/utxo-fetch" --chain $CHAIN "${url[@]}" < "$W/addrs" > "$W/utxos"
if [ $CHAIN = eth ] && grep -q '"balance":"0"' "$W/utxos"; then : > "$W/utxos"; fi
[ -s "$W/utxos" ] || { say "no funds found"; exit 4; }
if [ "$GOAL" = balance ]; then cat "$W/utxos"; exit 0; fi
[ $WATCH = 0 ] || { say "watch-only ($class): no private key here, nothing can be signed"; exit 3; }

# 4. Unsigned sweep, decoded for the human.
if [ $CHAIN != eth ]; then
  say "$(wc -l < "$W/utxos") funded outputs"
  "$B/tx-build" --chain $CHAIN --utxos "$W/utxos" --to "$DEST" --sweep --fee-rate "$FEE" > "$W/psbt"
else
  "$B/tx-build" --chain eth --chain-id "$CID" --account "$W/utxos" --to "$DEST" --sweep > "$W/psbt"
fi
dc=eth; [ $CHAIN = eth ] || dc=$CHAIN
"$B/tx-decode" --chain $dc --text < "$W/psbt" >&2

# 5. Sign (human types the code on the terminal), then broadcast (human types another code).
extra=(--chain $CHAIN); if [ $CHAIN = eth ]; then extra=(--chain-id "$CID"); fi
keys | "$B/tx-sign" --tx "$W/psbt" --expect-to "$DEST" "${extra[@]}" > "$W/signed"
grep -q '"status":"ok"' "$W/signed" || { cat "$W/signed"; exit 1; }
"$B/tx-broadcast" --chain $CHAIN "${url[@]}" < "$W/signed"
