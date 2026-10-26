# Pre-BIP39 seeds through the boundary: Electrum 1.x old 12-word seed (Electrum's test_electrum_seed_old),
# brainwallet sha256 (xkcd phrase), WarpWallet (keybase spec.json #1). Public vectors only.
set -eu
OLD='powerful random nobody notice nothing important anyway look away hidden message over'
echo "$OLD" | boundary el-old '1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo' 'seed-to-master | derive --chain btc --count 1'
grep -q 1KRW8pH6HFHZh889VDq6fEKvmrsmApwNfe "$T/el-old.jsonl" || { echo "FAIL el-old change address"; exit 1; }
grep -q '"scheme":"electrum-old"' "$T/el-old.jsonl" || { echo "FAIL el-old scheme"; exit 1; }
# the hex seed form and --preset electrum-old give the same first address; the seed value never crosses
echo acb740e454c3134901d7c8f16497cc1c | boundary el-old-hex '1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo' 'seed-to-master | derive --preset electrum-old --count 1'
if grep -q acb740e454c3134901d7c8f16497cc1c "$T/el-old-hex.jsonl"; then echo "LEAK el-old-hex seed"; exit 1; fi
echo "$OLD" | "$B/classify" | grep -q '"class":"electrum_old_seed"' || { echo "FAIL classify electrum_old_seed"; exit 1; }
# an xprv is refused under the old preset (it is not a BIP32 scheme)
echo '{"xprv":"xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"}' | "$B/derive" --preset electrum-old --count 1 | grep -q '"status":"unsupported"' || { echo "FAIL xprv under electrum-old not refused"; exit 1; }
# other chains print no old-scheme rows (btc only)
n=$(echo "$OLD" | "$B/seed-to-master" | "$B/derive" --chain eth --count 1 | grep -c '"address"' || [ $? -eq 1 ])
[ "$n" -eq 0 ] || { echo "FAIL el-old emitted $n rows for eth"; exit 1; }
echo "ok  electrum-old: Electrum 1.x vector addresses, hex form, preset, classify, xprv refused, btc only"
printf 'correct horse battery staple\n' | boundary brain '1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T' 'phrase-to-key | key-to-addresses --chain btc'
grep -q 1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8 "$T/brain.jsonl" || { echo "FAIL brain compressed address"; exit 1; }
# half pipe: the key line itself is redacted
printf 'correct horse battery staple\n' | boundary brain-half '"scheme":"brainwallet-sha256"' 'phrase-to-key'
grep -q '"private_key":"\[REDACTED\]"' "$T/brain-half.jsonl" || { echo "FAIL brain-half placeholder"; exit 1; }
printf '{"phrase":"ER8FT+HFjk0","salt":"7DpniYifN6c"}\n' | boundary warp '1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ' 'phrase-to-key --scheme warpwallet | key-to-addresses --chain btc'
# raw control: the WarpWallet spec WIF comes out of the unsealed pipe (public test vector)
printf '{"phrase":"ER8FT+HFjk0","salt":"7DpniYifN6c"}\n' | "$B/phrase-to-key" --scheme warpwallet | "$B/key-to-addresses" --chain btc | grep -q 5JfEekYcaAexqcigtFAy4h2ZAY95vjKCvS1khAkSG8ATo1veQAD || { echo "FAIL warp WIF"; exit 1; }
"$B/phrase-to-key" --scheme md5 </dev/null | grep -q bad_input || { echo "FAIL phrase-to-key bad scheme"; exit 1; }
echo "ok  phrase-to-key: brainwallet + WarpWallet vectors through the boundary, placeholders, bad scheme refused"
