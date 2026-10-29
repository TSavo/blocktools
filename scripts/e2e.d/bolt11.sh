#!/bin/sh
# BOLT11 Lightning invoice decode + byte-identical re-encode, no network, public spec test vectors.
# Decode the donation invoice (no amount) to its golden fields + the payee pubkey RECOVERED from the
# signature; decode the 2500u invoice and check the amount; re-encode byte-identically; a tampered
# checksum and a non-lightning string are rejected.
set -eu
. scripts/e2e-only/portable.sh
f() { echo "FAIL bolt11 $1"; exit 1; }
B=${BIN:-${B:-target/release}}
T=${T:-$(mktemp -d)}; mkdir -p "$T"

# Public BOLT11 spec test vectors (BOLT #11 appendix).
DON="lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql"
AMT="lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh"
NODE="03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"

# 1. Decode the donation invoice: golden fields + recovered payee.
"$B/bolt11" "$DON" > "$T/don.json" 2>&1 || { cat "$T/don.json"; f "decode donation"; }
python3 - "$T/don.json" "$NODE" <<'PY' || f "donation fields"
import json,sys
d=json.load(open(sys.argv[1])); node=sys.argv[2]
assert d["status"]=="ok", d
assert d["network"]=="mainnet", d
assert "amount_msat" not in d, "donation has no amount"
assert d["timestamp"]==1496314658, d["timestamp"]
assert d["payment_hash"]=="0001020304050607080900010203040506070809000102030405060708090102", d["payment_hash"]
assert d["description"]=="Please consider supporting this project", d["description"]
assert d["recovered_payee"]==node, d["recovered_payee"]
print("ok donation")
PY
echo "ok   bolt11: donation invoice decodes to its golden fields and recovers the spec node id"

# 2. Decode the 2500u invoice: the amount path.
"$B/bolt11" "$AMT" > "$T/amt.json" 2>&1 || { cat "$T/amt.json"; f "decode amount"; }
python3 - "$T/amt.json" "$NODE" <<'PY' || f "amount fields"
import json,sys
d=json.load(open(sys.argv[1])); node=sys.argv[2]
assert d["amount_msat"]=="250000000", d.get("amount_msat")   # 2500u BTC = 2500 * 100_000 msat
assert d["recovered_payee"]==node, d["recovered_payee"]
print("ok amount")
PY
echo "ok   bolt11: 2500u invoice decodes amount 250,000,000 msat and the same payee"

# 3. Byte-identical re-encode.
"$B/bolt11" --reencode "$DON" > "$T/re.json" 2>&1 || { cat "$T/re.json"; f "reencode"; }
grep -q '"roundtrip":true' "$T/re.json" || { cat "$T/re.json"; f "re-encode not byte-identical"; }
echo "ok   bolt11: re-encodes the invoice byte-identically"

# 4. Negatives: a tampered checksum and a non-lightning string are rejected (nonzero exit).
BAD=$(printf '%s' "$DON" | sed 's/.$/0/')   # flip the last checksum char
"$B/bolt11" "$BAD" > "$T/bad.json" 2>&1 && { cat "$T/bad.json"; f "tampered checksum must be rejected"; }
grep -q 'bad_checksum' "$T/bad.json" || { cat "$T/bad.json"; f "tampered checksum reason"; }
"$B/bolt11" bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 > "$T/notln.json" 2>&1 && { cat "$T/notln.json"; f "non-lightning string must be rejected"; }
grep -q 'not_a_lightning_invoice' "$T/notln.json" || { cat "$T/notln.json"; f "non-lightning reason"; }
echo "ok   bolt11: a tampered checksum and a non-lightning string are rejected"

echo "PASS bolt11"
