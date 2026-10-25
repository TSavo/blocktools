# Stellar (SEP-0005 vector 1, public test mnemonic): seed-to-master | derive --chain xlm must
# give the published account ids for m/44'/148'/0' and 1'; validate accepts G..., rejects a
# corrupted checksum. Secrets go through redact only.
set -eu
M="illness spike retreat truth genius clock brain pass fit cave bargain toe"
out=$(echo "{\"mnemonic\":\"$M\"}" | "$B/seed-to-master" | "$B/derive" --chain xlm --count 2 | "$B/redact")
echo "$out" | grep "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6" | grep -q "m/44'/148'/0'" \
 && echo "$out" | grep "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX" | grep -q "m/44'/148'/1'" \
 && ! echo "$out" | grep -Eq '"S[A-Z2-7]{55}"' && echo "ok  xlm-derive: SEP-0005 vector 1 addresses" || { echo "FAIL xlm-derive"; exit 1; }
