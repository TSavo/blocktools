# sol-tron-tx: the chain is detected from the input (tx bytes or the plan's from address) and
# reported in the summary; --chain overrides; junk is refused with bad_input (exit 2).
set -eu
F=recipes/fixtures/sol-tron; S="$B/sol-tron-tx"
for c in sol tron; do
  o=$("$S" build --plan "$F/$c-plan.json"); echo "$o" | grep -q "\"chain\":\"$c\"" && echo "$o" | grep -q "\"unsigned_hex\":\"$(cat "$F/$c-transfer.txt")\"" \
    && "$S" decode < "$F/$c-transfer.txt" | grep -q "\"chain\":\"$c\"" && echo "ok  sol-tron-$c: build matches fixture, decode detects $c" || { echo "FAIL sol-tron-$c"; exit 1; }
done
"$S" verify --expect '{"lamports":"1000"}' < "$F/sol-transfer.txt" | grep -q '"ok":true' && echo "ok  sol-tron-verify" || { echo "FAIL sol-tron-verify"; exit 1; }
rc=0; "$S" verify --expect '{"lamports":"999"}' < "$F/sol-transfer.txt" 2>/dev/null || rc=$?; [ $rc = 1 ] && echo "ok  sol-tron-verify-mismatch: exit 1" || { echo "FAIL sol-tron-verify-mismatch rc=$rc"; exit 1; }
rc=0; "$S" --chain sol decode < "$F/tron-transfer.txt" 2>/dev/null || rc=$?; [ $rc = 2 ] && echo "ok  sol-tron-override: --chain sol on tron bytes refused" || { echo "FAIL sol-tron-override rc=$rc"; exit 1; }
rc=0; "$S" decode ff00ff 2>/dev/null || rc=$?; [ $rc = 2 ] && echo "ok  sol-tron-junk: exit 2" || { echo "FAIL sol-tron-junk rc=$rc"; exit 1; }
