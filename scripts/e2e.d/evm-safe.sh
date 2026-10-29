#!/bin/sh
# Gnosis Safe (>=1.3.0) m-of-n execTransaction, end to end, no network, public test keys.
# `safe-tx hash` gives the EIP-712 Safe tx hash each owner signs; two of three owners sign it (the
# example `safe-owner-sign` stands in for their wallets); `safe-tx exec` orders the signatures
# ascending by owner and builds the execTransaction calldata; `safe-tx verify` recomputes the hash and
# checks the packed signatures against the owner set + threshold. Negatives: a non-owner signature, a
# short-of-threshold set, and a tampered nonce all refuse (fail closed).
set -eu
. scripts/e2e-only/portable.sh
f() { echo "FAIL evm-safe $1"; exit 1; }
B=${BIN:-${B:-target/release}}
T=${T:-$(mktemp -d)}; W="$T/evm-safe"; mkdir -p "$W"
SIGN="cargo run -q --offline --release -p blocktools-evm --example safe-owner-sign --"

SAFE=0x1111111111111111111111111111111111111111
TO=0x2222222222222222222222222222222222222222
VAL=1000000000000000000
K1=$(printf '%064x' 11); K2=$(printf '%064x' 22); K3=$(printf '%064x' 33); KX=$(printf '%064x' 99)

# 1. The Safe tx hash the owners sign.
"$B/safe-tx" hash --safe $SAFE --chain-id 1 --nonce 5 --to $TO --value $VAL > "$W/h.json" || f "hash"
grep -q '"status":"ok"' "$W/h.json" || { cat "$W/h.json"; f "hash status"; }
H=$(python3 -c 'import json;print(json.load(open("'"$W"'/h.json"))["safe_tx_hash"])')
case "$H" in 0x????????????????????????????????????????????????????????????????) : ;; *) f "safe_tx_hash is not 32 bytes" ;; esac
echo "ok   evm-safe: safe-tx hash produced the EIP-712 Safe tx hash"

# 2. Owners sign the hash (fixture stands in for each wallet); collect sigs + owner addresses.
$SIGN "$H" "$K1" > "$W/s1.json"; $SIGN "$H" "$K2" > "$W/s2.json"; $SIGN "$H" "$K3" > "$W/s3.json"; $SIGN "$H" "$KX" > "$W/sx.json"
pick() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }
SIG1=$(pick "$W/s1.json" sig); SIG3=$(pick "$W/s3.json" sig); SIGX=$(pick "$W/sx.json" sig)
O1=$(pick "$W/s1.json" owner); O2=$(pick "$W/s2.json" owner); O3=$(pick "$W/s3.json" owner)

# 3. Build the execTransaction calldata from the 2 owner signatures; they come out ascending by owner.
"$B/safe-tx" exec --safe $SAFE --chain-id 1 --nonce 5 --to $TO --value $VAL --owner-sig "$SIG1" --owner-sig "$SIG3" > "$W/ex.json" || { cat "$W/ex.json"; f "exec"; }
grep -q '"status":"ok"' "$W/ex.json" || { cat "$W/ex.json"; f "exec status"; }
CD=$(python3 -c 'import json;print(json.load(open("'"$W"'/ex.json"))["calldata"])')
python3 -c 'import json,sys
o=json.load(open("'"$W"'/ex.json"))["ordered_owners"]
assert o==sorted(o,key=lambda a:int(a,16)), ("owners not ascending",o)
assert len(o)==2, o' || f "exec did not order two owners ascending"
echo "ok   evm-safe: safe-tx exec ordered the owner signatures ascending and built the calldata"

# 4. verify accepts the calldata at threshold 2 against the real owner set.
"$B/safe-tx" verify --safe $SAFE --chain-id 1 --nonce 5 --calldata "$CD" --owner $O1 --owner $O2 --owner $O3 --threshold 2 > "$W/v.json" || { cat "$W/v.json"; f "verify"; }
grep -q '"status":"ok"' "$W/v.json" || { cat "$W/v.json"; f "verify status"; }
echo "ok   evm-safe: safe-tx verify confirms the calldata, owners, and 2-of-3 threshold"

# 5a. A non-owner signature: build with the intruder's sig, verify against the real owner set -> refused.
"$B/safe-tx" exec --safe $SAFE --chain-id 1 --nonce 5 --to $TO --value $VAL --owner-sig "$SIG1" --owner-sig "$SIGX" > "$W/exb.json" || { cat "$W/exb.json"; f "exec intruder"; }
CDB=$(python3 -c 'import json;print(json.load(open("'"$W"'/exb.json"))["calldata"])')
"$B/safe-tx" verify --safe $SAFE --chain-id 1 --nonce 5 --calldata "$CDB" --owner $O1 --owner $O2 --owner $O3 --threshold 2 > "$W/vb.json" 2>&1 && { cat "$W/vb.json"; f "a non-owner signature must be refused"; }
grep -q '"status":"refused"' "$W/vb.json" || { cat "$W/vb.json"; f "non-owner refusal reason"; }
echo "ok   evm-safe: a non-owner signature is refused (not an owner)"

# 5b. Short of threshold: the honest 2-sig calldata refuses at threshold 3.
"$B/safe-tx" verify --safe $SAFE --chain-id 1 --nonce 5 --calldata "$CD" --owner $O1 --owner $O2 --owner $O3 --threshold 3 > "$W/vc.json" 2>&1 && { cat "$W/vc.json"; f "a short-of-threshold set must be refused"; }
grep -q '"status":"refused"' "$W/vc.json" || { cat "$W/vc.json"; f "threshold refusal reason"; }
echo "ok   evm-safe: a set short of the threshold is refused"

# 5c. A tampered nonce changes the hash, so the signatures recover to non-owners -> refused.
"$B/safe-tx" verify --safe $SAFE --chain-id 1 --nonce 999 --calldata "$CD" --owner $O1 --owner $O2 --owner $O3 --threshold 2 > "$W/vd.json" 2>&1 && { cat "$W/vd.json"; f "a tampered nonce must be refused"; }
grep -q '"status":"refused"' "$W/vd.json" || { cat "$W/vd.json"; f "tamper refusal reason"; }
echo "ok   evm-safe: a tampered nonce is refused (recovers to non-owners)"

echo "PASS evm-safe"
