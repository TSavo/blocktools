# shellcheck shell=bash
# acct-tx --chain atom across Cosmos SDK chains: the Trust Wallet Core Osmosis SignTransfer_81B4 vector rebuilt
# from its inputs, signed behind the typed code, must equal TWC's tx_bytes byte for byte; chain detected from hrp.
set -eu
X=$T/twc-cosmos; mkdir -p "$X"
echo 8bbec3772ddb4df68f3186440380c301af116d1422001c1877d6f5e4dba8c8af > "$X/osmo.key"
OF=osmo1mky69cn8ektwy0845vec9upsdphktxt0en97f5; OT=osmo18s0hdnsllgcclweu9aymw4ngktr2k0rkvn7jmn
"$B/acct-tx" keys --chain atom --hrp osmo < "$X/osmo.key" | grep -q "\"address\":\"$OF\"" || { echo "FAIL twc-cosmos keys --hrp osmo"; exit 1; }
PK=$("$B/acct-tx" keys --chain atom --hrp osmo < "$X/osmo.key" | sed 's/.*"pubkey":"\([0-9a-f]*\)".*/\1/')
"$B/acct-tx" build --chain atom --from $OF --pubkey "$PK" --to $OT --amount 99800 --fee 200 --gas 200000 --sequence 0 --account-number 124703 > "$X/u.json" 2>"$X/u.err"
grep -q '"cosmos_chain":"osmosis"' "$X/u.json" || { echo "FAIL twc-cosmos chain not detected"; exit 1; }
grep -q '"denom":"uosmo"' "$X/u.json" || { echo "FAIL twc-cosmos denom"; exit 1; }
grep -q '"chain_id":"osmosis-1"' "$X/u.json" || { echo "FAIL twc-cosmos chain_id"; exit 1; }
python3 scripts/e2e-only/tty-drive.py right "$X/osmo.key" "$X/s.json" "$(cd "$B" && pwd)/acct-tx" sign --chain atom --tx "$X/u.json" --expect-to $OT > "$X/t" 2>&1
grep -q '"signed":"Co0BCooBChwvY29zbW9zLmJhbmsudjFiZXRhMS5Nc2dTZW5kEmoKK29zbW8xbWt5Njljbjhla3R3eTA4NDV2ZWM5dXBzZHBoa3R4dDBlbjk3ZjUSK29zbW8xOHMwaGRuc2xsZ2NjbHdldTlheW13NG5na3RyMmswcmt2bjdqbW4aDgoFdW9zbW8SBTk5ODAwEmQKTgpGCh8vY29zbW9zLmNyeXB0by5zZWNwMjU2azEuUHViS2V5EiMKIQLs71zkN6MCxn+VRo3ksx826RH0Z9fmpStBweE+HVY2SRIECgIIARISCgwKBXVvc21vEgMyMDAQwJoMGkAMY//Md5GRUR4lVZhk558hFS3kii9QZYoYKfg4+ac/xgNeyoiEweVDhcmEvlH1orVwjLUOnYs4ly2a/yIurYVj"' "$X/s.json" || { echo "FAIL twc-cosmos signed != TWC tx_bytes"; cat "$X/t"; exit 1; }
"$B/acct-tx" decode --chain atom < "$X/s.json" | grep -q '"signature_valid":true' || { echo "FAIL twc-cosmos decode"; exit 1; }
"$B/acct-tx" keys --chain atom --hrp inj < "$X/osmo.key" | grep -q cosmos_hrp_without_vector || { echo "FAIL twc-cosmos inj not refused"; exit 1; }
"$B/acct-tx" build --chain atom --from inj1mky69cn8ektwy0845vec9upsdphktxt0x0x0x0 --pubkey "$PK" --to $OT --amount 1 --fee 1 --gas 1 --sequence 0 --account-number 1 | grep -q cosmos_hrp_without_vector || { echo "FAIL twc-cosmos inj build not refused"; exit 1; }
CA=$("$B/acct-tx" keys --chain atom < "$X/osmo.key" | sed 's/.*"address":"\([a-z0-9]*\)".*/\1/')
"$B/acct-tx" build --chain atom --from $OF --pubkey "$PK" --to "$CA" --amount 1 --fee 1 --gas 1 --sequence 0 --account-number 1 | grep -q "wrong network" || { echo "FAIL twc-cosmos cross-hrp not refused"; exit 1; }
echo "ok   twc-cosmos (osmosis vector byte-exact, hrp detect, inj/cross-hrp refused)"
