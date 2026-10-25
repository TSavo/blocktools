# shellcheck shell=bash
# acct-tx (xlm, algo): build -> decode -> sign behind the typed code -> decode verifies. Keys are the public
# test seeds [1;32] / [2;32] used by crates/acct/tests/kat.rs (vectors from py-stellar-sdk / py-algorand-sdk).
X=$T/acct; mkdir -p "$X"
echo SAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC5MY > "$X/xlm.key"; echo AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQGKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXA== > "$X/algo.key"
XF=GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR; XT=GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U
AF=RKEOHXLUBHYZL7KS3MWTZOS5OLFGOCN7DWKBEG7TOSEADNAPN5OOTUNSLE; AT=QE4XODVIPULV6VVDKRTMGTD6ZTFY3CURWTXDPIS56YHVXD6JWOKORTLPBU
"$B/acct-tx" build --chain xlm --from $XF --to $XT --amount 125000000 --fee 100 --seq 123456789013 --memo-id 42 --max-time 1800000000 > "$X/xu.json" 2>/dev/null
grep -q '"txid":"6f3d9d0e3539e9080977adf0f908e25c17de3f7ba9147a0e90da34ae7d7dc1c7"' "$X/xu.json" || { echo "FAIL acct xlm build"; exit 1; }
"$B/acct-tx" build --chain xlm --from $XF --to $XT --amount 1 --fee 100 --seq 1 2>&1 >/dev/null | grep -q "WARNING memo_missing" || { echo "FAIL acct xlm memo warning"; exit 1; }
"$B/acct-tx" build --chain algo --from $AF --to $AT --sweep --fee 1000 --first-round 40000000 --last-round 40001000 > "$X/au.json" 2>"$X/au.err"
grep -q '"txid":"ZKIVMCE4N2INEZVB2VCJNA7QZVOJWIWDWD6HPBPDJ44E4QATNWKA"' "$X/au.json" && grep -q close_to "$X/au.err" || { echo "FAIL acct algo sweep build"; exit 1; }
python3 scripts/tty-drive.py wrong "$X/xlm.key" "$X/xs0.json" "$(cd "$B" && pwd)/acct-tx" sign --chain xlm --tx "$X/xu.json" --expect-to $XT > "$X/t0" 2>&1 || true
grep -q '"status":"aborted"' "$X/xs0.json" || { echo "FAIL acct wrong code must abort"; exit 1; }
for c in xlm:$XT:xu algo:$AT:au; do IFS=: read -r ch to u <<< "$c"
  python3 scripts/tty-drive.py right "$X/$ch.key" "$X/$ch-s.json" "$(cd "$B" && pwd)/acct-tx" sign --chain $ch --tx "$X/$u.json" --expect-to $to > "$X/t-$ch" 2>&1
  grep -q '"status":"ok"' "$X/$ch-s.json" || { echo "FAIL acct $ch sign"; cat "$X/t-$ch"; exit 1; }
  "$B/acct-tx" decode --chain $ch < "$X/$ch-s.json" | grep -q '"signature_valid":true' || { echo "FAIL acct $ch signed decode"; exit 1; }
  "$B/acct-tx" sign --chain $ch --tx "$X/$u.json" --expect-to $XF < "$X/$ch.key" | grep -q destination_mismatch || { echo "FAIL acct $ch expect-to"; exit 1; }
done
"$B/acct-tx" sign --chain xlm --tx "$X/xs-sign-wrongkey" --expect-to $XT < /dev/null >/dev/null 2>&1 && { echo "FAIL acct missing tx accepted"; exit 1; }
grep -q 'G0D29cAAAAQC4Y2enTepaRAPTDF9gL0XCtVvFUOHpKqEGVs6qtgz2TG' "$X/xlm-s.json" || { echo "FAIL acct xlm signature != stellar-sdk"; exit 1; }
grep -q 'gqNzaWfEQE5QP6/t0rTXTW1Ip8K2vgeO0' "$X/algo-s.json" || { echo "FAIL acct algo signature != algosdk"; exit 1; }
if grep -rqF -e "$(cat "$X/xlm.key")" -e "$(cat "$X/algo.key")" "$X"/*.json "$X"/t*; then echo "LEAK acct key in output"; exit 1; fi
echo "ok  acct-tx: xlm payment + algo close-to built (SDK txids), wrong code aborts, signed == SDK bytes, verified, wrong dest refused"
