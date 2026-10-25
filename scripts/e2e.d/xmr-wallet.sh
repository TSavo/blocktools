# xmr-wallet against a loopback mock wallet-rpc: scan from the 0600 scan request, sweep plan check,
# no relay without a TTY, remote RPC refused; seed/view key reach the RPC body but never stdout/stderr.
XS="adjust mugged vaults atlas nasty mews damp toenail suddenly toxic possible framed succeed fuzzy return demonstrate nucleus album noises peculiar virtual rowboat inorganic jester fuzzy"
TO=$(printf '%s\n' "$XS" | "$B/xmr-keys" --net stage | sed 's/.*"address":"\([^"]*\)".*/\1/')
printf '%s\n' "$XS" | "$B/xmr-keys" --net stage --scan-out "$T/xw-req.json" --restore-height 2236100 >/dev/null 2>&1
P=$((38000 + $$ % 1000)); ADDR=$TO python3 scripts/mock/xmr-rpc-mock.py $P "$T/xw.log" ok & MP=$!
P2=$((P + 1)); python3 scripts/mock/xmr-rpc-mock.py $P2 "$T/xw2.log" bad & MP2=$!
sleep 1
s=$("$B/xmr-wallet" scan --rpc http://127.0.0.1:$P --scan-req "$T/xw-req.json" 2>&1)
w=$(printf '%s\n' "$XS" | "$B/xmr-wallet" sweep --rpc http://127.0.0.1:$P --net stage --to "$TO" 2>&1)
set +e
printf '%s\n' "$XS" | "$B/xmr-wallet" sweep --rpc http://127.0.0.1:$P --net stage --to "$TO" --relay >"$T/xr.out" 2>&1; rr=$?
printf '%s\n' "$XS" | "$B/xmr-wallet" sweep --rpc http://127.0.0.1:$P2 --net stage --to "$TO" >"$T/xb.out" 2>&1; rb=$?
printf '%s\n' "$XS" | "$B/xmr-wallet" sweep --rpc http://10.0.0.1:$P --net stage --to "$TO" >/dev/null 2>&1; rremote=$?
printf '%s\n' "$XS" | "$B/xmr-wallet" sweep --rpc http://127.0.0.1:$P --to "$TO" >/dev/null 2>&1; rnet=$?
set -e
kill $MP $MP2
VK=$(sed 's/.*"viewkey":"\([0-9a-f]*\)".*/\1/' "$T/xw-req.json")
all="$s$w$(cat "$T/xr.out" "$T/xb.out")"
echo "$s" | grep -q '"kind":"scan".*' && echo "$s" | grep -q '"kind":"received"' \
 && echo "$w" | grep -q '"amount_plus_fee_equals_unlocked":true' && echo "$w" | grep -q '"relayed":false' \
 && [ $rr = 3 ] && grep -q not_confirmed "$T/xr.out" && ! grep -q relay_tx "$T/xw.log" \
 && [ $rb = 3 ] && grep -q plan_check_failed "$T/xb.out" && [ $rremote = 2 ] && [ $rnet = 2 ] \
 && grep -q '"method":"restore_deterministic_wallet"' "$T/xw.log" && grep -q "$VK" "$T/xw.log" && grep -q "adjust mugged" "$T/xw.log" \
 && ! echo "$all" | grep -Eq "adjust|mugged|$VK" \
 && echo "ok  xmr-wallet: mock rpc scan + sweep plan, no relay without TTY, mismatch/remote/wrong-net refused, no secrets out" || { echo "FAIL xmr-wallet"; echo "$s"; echo "$w"; exit 1; }
