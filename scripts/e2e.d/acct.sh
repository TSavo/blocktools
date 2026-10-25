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
for c in xlm:$XT:xu algo:$AT:au; do ch=${c%%:*}; r=${c#*:}; to=${r%%:*}; u=${r#*:}
  python3 scripts/tty-drive.py right "$X/$ch.key" "$X/$ch-s.json" "$(cd "$B" && pwd)/acct-tx" sign --chain $ch --tx "$X/$u.json" --expect-to $to > "$X/t-$ch" 2>&1
  grep -q '"status":"ok"' "$X/$ch-s.json" || { echo "FAIL acct $ch sign"; cat "$X/t-$ch"; exit 1; }
  "$B/acct-tx" decode --chain $ch < "$X/$ch-s.json" | grep -q '"signature_valid":true' || { echo "FAIL acct $ch signed decode"; exit 1; }
  "$B/acct-tx" sign --chain $ch --tx "$X/$u.json" --expect-to $XF < "$X/$ch.key" | grep -q destination_mismatch || { echo "FAIL acct $ch expect-to"; exit 1; }
done
"$B/acct-tx" sign --chain xlm --tx "$X/xs-sign-wrongkey" --expect-to $XT < /dev/null >/dev/null 2>&1 && { echo "FAIL acct missing tx accepted"; exit 1; }
grep -q 'G0D29cAAAAQC4Y2enTepaRAPTDF9gL0XCtVvFUOHpKqEGVs6qtgz2TG' "$X/xlm-s.json" || { echo "FAIL acct xlm signature != stellar-sdk"; exit 1; }
grep -q 'gqNzaWfEQE5QP6/t0rTXTW1Ip8K2vgeO0' "$X/algo-s.json" || { echo "FAIL acct algo signature != algosdk"; exit 1; }
printf '%064d' 0 | tr 0 1 | sed 's/1/01/g' | cut -c1-64 > "$X/atom.key"
CF=cosmos10xcqpzrky6eff2g52qdye53xkk9jxkvrpq6uqr; CT=cosmos1a0qwuze2h85zw7nqpsj3ga0z9geyrgwphl8j6w
"$B/acct-tx" keys --chain atom < "$X/atom.key" | grep -q "\"address\":\"$CF\"" || { echo "FAIL acct atom keys"; exit 1; }
PK=$("$B/acct-tx" keys --chain atom < "$X/atom.key" | sed 's/.*"pubkey":"\([0-9a-f]*\)".*/\1/')
"$B/acct-tx" build --chain atom --from $CF --pubkey "$PK" --to $CT --amount 1234567 --fee 5000 --gas 200000 --sequence 7 --account-number 123456 --memo 42 > "$X/cu.json"
python3 scripts/tty-drive.py right "$X/atom.key" "$X/atom-s.json" "$(cd "$B" && pwd)/acct-tx" sign --chain atom --tx "$X/cu.json" --expect-to $CT > "$X/t-atom" 2>&1
grep -q '"txid":"EA467ABCA0270EBC959BEBC2A256A7592FD3C05F985CE04F4D5D49C54ED28F03"' "$X/atom-s.json" || { echo "FAIL acct atom txid != cosmjs"; cat "$X/t-atom"; exit 1; }
"$B/acct-tx" decode --chain atom < "$X/atom-s.json" | grep -q '"signature_valid":true' || { echo "FAIL acct atom signed decode"; exit 1; }
"$B/acct-tx" sign --chain atom --tx "$X/cu.json" --expect-to $CF < "$X/atom.key" | grep -q destination_mismatch || { echo "FAIL acct atom expect-to"; exit 1; }
TF=UQDvr_S6wiD4iy6Y6x2c_8yjv-O2bs4xp9bFiQ0w39evpYZV; TT=UQAaDUFwU_NsWLK1DA5VSF80Kvlj55rB-P6K-3wxAjuMOdQl
"$B/acct-tx" build --chain ton --from $TF --to $TT --amount 1500000000 --seqno 5 --valid-until 1767225600 --comment 42 > "$X/tu.json" 2>/dev/null
python3 scripts/tty-drive.py right "$X/atom.key" "$X/ton-s.json" "$(cd "$B" && pwd)/acct-tx" sign --chain ton --tx "$X/tu.json" --expect-to EQAaDUFwU_NsWLK1DA5VSF80Kvlj55rB-P6K-3wxAjuMOYng > "$X/t-ton" 2>&1
grep -q '"signed":"te6cckEBAgEAsAAB4YgB31/pdYRB8RZdMdY7Of+ZR3/HbN2cY0+tixIaYb+vX0oC4DnmBK3Xbv0PF4xWODy1x9N0Rq24MYojMh3TvGtp6ItF2mrZdCPnBxL2MyOHIvcpGvdg0Ha7vo8HSTHMdEDAQU1NGLtKrcgAAAAAKAAcAQB0QgANBqC4Kfm2LFlahgcqpC+aFXyx881g/H9Ffb4YgR3GHKLLQXgAAAAAAAAAAAAAAAAAAAAAAAA0Mnt4ook="' "$X/ton-s.json" || { echo "FAIL acct ton boc != tonsdk"; cat "$X/t-ton"; exit 1; }
"$B/acct-tx" decode --chain ton < "$X/ton-s.json" | grep -q '"signature_valid":true' || { echo "FAIL acct ton signed decode"; exit 1; }
"$B/acct-tx" sign --chain ton --tx "$X/tu.json" --expect-to $TF < "$X/atom.key" | grep -q destination_mismatch || { echo "FAIL acct ton expect-to"; exit 1; }
"$B/acct-tx" build --chain ton --from $TF --to $TT --amount 1 --seqno 0 --valid-until 1 | grep -q seqno_0 || { echo "FAIL acct ton seqno0"; exit 1; }
AS=addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv; AD=addr1qyz85693g4fr8c55mfyxhae8j2u04pydxrgqr73vmwpx3a8927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqu2c0f9
printf '%s\n' "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" | "$B/key-to-addresses" --chain ada | head -1 | sed 's/.*"private_key":"\([0-9a-f]*\)".*/\1/' > "$X/ada.key"
"$B/acct-tx" build --chain ada --from $AS --to $AD --utxo 87dac51506d06652be02110bd1e34c2156faa5fa37253dc885da93b840b4bdec#1:5000000 --utxo 1ca4b3296f0b31b9f584e06c4dfc59119ecc408ba0395047c8d616f4c88a20c6#0:5000000 --amount 1500000 --fee 172221 --ttl 150000000 > "$X/au2.json" 2>/dev/null
python3 scripts/tty-drive.py right "$X/ada.key" "$X/ada-s.json" "$(cd "$B" && pwd)/acct-tx" sign --chain ada --tx "$X/au2.json" --expect-to $AD > "$X/t-ada" 2>&1
grep -q '"signed":"84a400828258201ca4b3296f0b31b9f584e06c4dfc59119ecc408ba0395047c8d616f4c88a20c60082582087dac51506d06652be02110bd1e34c2156faa5fa37253dc885da93b840b4bdec01018282583901047a68b1455233e294da486bf72792b8fa848d30d001fa2cdb8268f4e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d1761a0016e360825839010fdc780023d8be7c9ff3a6bdc0d8d3b263bd0cc12448c40948efbf42e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d1761a007f1263021a0002a0bd031a08f0d180a100818258207ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a5840502db032be107f0e8b98e1df645f421427796ad80c8589b723dd077935b470b28582cc8212104f44a7e4758da93d308de7b6d1e1ccab3adf2e9794105783fb03f5f6"' "$X/ada-s.json" || { echo "FAIL acct ada tx != pycardano"; cat "$X/t-ada"; exit 1; }
"$B/acct-tx" decode --chain ada < "$X/ada-s.json" | grep -q '"signature_valid":true' || { echo "FAIL acct ada signed decode"; exit 1; }
"$B/acct-tx" sign --chain ada --tx "$X/au2.json" --expect-to $AS < "$X/ada.key" | grep -q destination_mismatch || { echo "FAIL acct ada expect-to"; exit 1; }
"$B/acct-tx" build --chain ada --from $AS --to $AD --utxo 87dac51506d06652be02110bd1e34c2156faa5fa37253dc885da93b840b4bdec#1:5000000 --amount 1500000 --fee 100 --ttl 1 | grep -q fee_below_size_minimum || { echo "FAIL acct ada min fee"; exit 1; }
if grep -rqF -e "$(cat "$X/ada.key")" -e "$(cat "$X/atom.key")" -e "$(cat "$X/xlm.key")" -e "$(cat "$X/algo.key")" "$X"/*.json "$X"/t*; then echo "LEAK acct key in output"; exit 1; fi
echo "ok  acct-tx: xlm payment + algo close-to + atom MsgSend (== cosmjs) + ton v4r2 (== tonsdk) + ada (== pycardano) built (SDK txids), wrong code aborts, signed == SDK bytes, verified, wrong dest refused"
