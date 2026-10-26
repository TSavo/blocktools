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
# Tron verify: mainnet vectors (TronGrid block 87,447,813); signature recovered and must be the owner.
"$S" verify --expect '{"owner":"TLymzDFTSpmoFc51sTjLxSAAA4ALUqaAqX","to":"TZGpGvWakYvAKixs982WpEiCn8JXd4157v","amount_sun":"1"}' < "$F/tron-mainnet-trx.txt" | grep -q '"fully_signed":true,"ok":true' \
  && "$S" verify --expect '{"to":"TT8jJMVHtAjgGFrc463ZwZQnMXEr519q3u","contract":"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t","amount":"100000000000"}' < "$F/tron-mainnet-trc20.txt" | grep -q '"ok":true' \
  && echo "ok  sol-tron-tron-verify: mainnet TRX + TRC-20 signed by owner" || { echo "FAIL sol-tron-tron-verify"; exit 1; }
rc=0; "$S" verify --expect '{"amount":"1"}' < "$F/tron-mainnet-trc20.txt" 2>/dev/null || rc=$?; [ $rc = 1 ] && echo "ok  sol-tron-tron-verify-mismatch: exit 1" || { echo "FAIL sol-tron-tron-verify-mismatch rc=$rc"; exit 1; }
