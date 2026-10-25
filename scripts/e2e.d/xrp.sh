# shellcheck shell=bash
# XRP: family seed -> keys; build a Payment to an X-address (tag carried); sign behind the typed code; decode verifies.
# Seeds are the public xrpl.js ripple-keypairs fixtures. Sourced by e2e-local.sh ($B, $T set).
X=$T/xrp; mkdir -p "$X"
echo sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r > "$X/ed.seed"; echo sp5fghtJtpUorTwvof1NpDXAzNwf5 > "$X/secp.seed"
"$B/xrp-tx" keys < "$X/ed.seed" | grep -q '"address":"rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD"' || { echo "FAIL xrp keys ed25519"; exit 1; }
"$B/xrp-tx" keys < "$X/secp.seed" | grep -q '"address":"rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1"' || { echo "FAIL xrp keys secp256k1"; exit 1; }
# destination: X-address of r9cZA1... with tag 11747 (ripple-address-codec vector)
"$B/xrp-tx" build --account rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD --to X7AcgcsBL6XDcUb289X4mJ8djcdyKaLFuhLRuNXPrDeJd9A \
  --sweep --balance 30000000 --fee 12 --sequence 7 --last-ledger 9000000 > "$X/u.json" 2> "$X/u.err"
grep -q '"destination_tag":11747' "$X/u.json" && ! grep -q destination_tag_missing "$X/u.err" || { echo "FAIL xrp build tag"; cat "$X/u.json"; exit 1; }
"$B/xrp-tx" build --account rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD --to r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59 --amount 1 --fee 12 --sequence 7 2>&1 >/dev/null | grep -q "WARNING destination_tag_missing" || { echo "FAIL xrp tag warning"; exit 1; }
python3 scripts/tty-drive.py wrong "$X/ed.seed" "$X/s0.json" "$PWD/$B/xrp-tx" sign --tx "$X/u.json" --expect-to X7AcgcsBL6XDcUb289X4mJ8djcdyKaLFuhLRuNXPrDeJd9A > "$X/t0" 2>&1 || true
grep -q '"status":"aborted"' "$X/s0.json" || { echo "FAIL xrp wrong code must abort"; cat "$X/s0.json"; exit 1; }
python3 scripts/tty-drive.py right "$X/ed.seed" "$X/s.json" "$PWD/$B/xrp-tx" sign --tx "$X/u.json" --expect-to X7AcgcsBL6XDcUb289X4mJ8djcdyKaLFuhLRuNXPrDeJd9A > "$X/t" 2>&1
grep -q '"status":"ok"' "$X/s.json" || { echo "FAIL xrp sign"; cat "$X/s.json" "$X/t"; exit 1; }
"$B/xrp-tx" decode < "$X/s.json" | grep -q '"signature_valid":true' || { echo "FAIL xrp signed decode"; exit 1; }
"$B/xrp-tx" sign --tx "$X/u.json" --expect-to r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59 < "$X/secp.seed" | grep -q key_does_not_match_account || { echo "FAIL xrp wrong key accepted"; exit 1; }
"$B/xrp-tx" sign --tx "$X/u.json" --expect-to rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1 < "$X/ed.seed" | grep -q destination_mismatch || { echo "FAIL xrp expect-to"; exit 1; }
if grep -rqE "sEdSKaCy2JT7|sp5fghtJtpUor" "$X"/*.json "$X/t" "$X/u.err"; then echo "LEAK xrp seed in output"; exit 1; fi
echo "ok  xrp: seeds (secp256k1+ed25519) -> addresses; X-address tag carried; wrong code aborts; signed + verified; wrong key / wrong dest refused"
set +e; BIN=$B bash docs/recipes/recover.sh "$X/ed.seed" rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1 > "$X/r.out" 2> "$X/r.err"; rc=$?; set -e
if [ $rc = 3 ] && grep -q "classified as xrp_seed" "$X/r.err" && grep -q '"address":"rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD"' "$X/r.out"; then echo "ok  recover xrp-seed: xrp_seed -> address, stops before network"; else echo "FAIL recover xrp-seed"; cat "$X/r.out" "$X/r.err"; exit 1; fi
