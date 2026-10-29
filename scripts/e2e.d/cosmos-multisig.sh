#!/bin/sh
# Cosmos legacy m-of-n multisig (LegacyAminoPubKey, SIGN_MODE_DIRECT), end to end, no network, public keys.
# A 2-of-3 MsgSend: `acct-tx multisig-build` makes the unsigned SignDoc under a LegacyAminoPubKey of three
# member secp256k1 pubkeys; two cosigners `multisig-sign` (pty) the SAME SignDoc; `multisig-combine`
# assembles their 64-byte sigs into a MultiSignature TxRaw; `multisig-decode` re-verifies every member
# signature and the CompactBitArray against the SignDoc. Negatives: a sub-threshold combine refuses, and a
# key that is not one of the members refuses to sign.
set -eu
. scripts/e2e-only/portable.sh
f() { echo "FAIL cosmos-multisig $1"; exit 1; }
B=${BIN:-${B:-target/release}}; Bab=$(cd "$B" && pwd)
T=${T:-$(mktemp -d)}; W="$T/cosmos-multisig"; mkdir -p "$W"

# Three member secret keys (1..3) and a non-member key (9); member pubkeys + a real `to` address via keys.
for i in 1 2 3 9; do printf '%064x\n' "$i" > "$W/k$i"; done
pk() { "$B/acct-tx" keys --chain atom < "$W/k$1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["pubkey"])'; }
addr() { "$B/acct-tx" keys --chain atom < "$W/k$1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["address"])'; }
P1=$(pk 1); P2=$(pk 2); P3=$(pk 3); TO=$(addr 3)
case "$TO" in cosmos1*) : ;; *) f "could not derive a cosmos recipient address" ;; esac
echo "ok   cosmos-multisig: three member pubkeys + recipient derived"

# 1. Build the 2-of-3 (signer subset = members 0 and 1), unsigned SignDoc.
"$B/acct-tx" multisig-build --chain atom --threshold 2 --pubkey "$P1" --pubkey "$P2" --pubkey "$P3" --signer 0 --signer 1 \
  --to "$TO" --amount 1000000 --fee 2000 --gas 200000 --sequence 5 --account-number 42 > "$W/build.json" 2>&1 || { cat "$W/build.json"; f "multisig-build"; }
grep -q '"status":"ok"' "$W/build.json" || { cat "$W/build.json"; f "build status"; }
FROM=$(python3 -c 'import json;print(json.load(open("'"$W"'/build.json"))["summary"]["from"])')
case "$FROM" in cosmos1*) : ;; *) f "multisig from-address not derived" ;; esac
echo "ok   cosmos-multisig: 2-of-3 LegacyAminoPubKey built ($FROM)"

# 2. Two cosigners sign the SAME SignDoc (pty, right code).
for k in 1 2; do
  python3 scripts/e2e-only/tty-drive.py right "$W/k$k" "$W/p$k.json" "$Bab/acct-tx" multisig-sign --chain atom --tx "$W/build.json" --expect-to "$TO" > "$W/tty$k" 2>&1 || true  # allow-true: outcome asserted next
  grep -q '"partial":true' "$W/p$k.json" || { cat "$W/p$k.json"; cat "$W/tty$k"; f "cosigner $k partial sign"; }
  grep -q '"status":"ok"' "$W/p$k.json" || { cat "$W/p$k.json"; f "cosigner $k status"; }
done
python3 -c 'import json;a=json.load(open("'"$W"'/p1.json"));b=json.load(open("'"$W"'/p2.json"));assert a["index"]==0 and b["index"]==1, (a["index"],b["index"])' || f "member indices not 0 and 1"
echo "ok   cosmos-multisig: two cosigners each produce a partial (members 0 and 1)"

# 3. Combine the quorum -> a MultiSignature TxRaw.
"$B/acct-tx" multisig-combine --chain atom --tx "$W/build.json" --part "$W/p1.json" --part "$W/p2.json" > "$W/signed.json" 2>&1 || { cat "$W/signed.json"; f "multisig-combine"; }
grep -q '"signed"' "$W/signed.json" || { cat "$W/signed.json"; f "combine produced no signed tx"; }
echo "ok   cosmos-multisig: combine assembled the MultiSignature TxRaw"

# 4. Decode re-verifies both member signatures and the bitarray against the SignDoc.
"$B/acct-tx" multisig-decode --chain atom < "$W/signed.json" > "$W/dec.json" 2>&1 || { cat "$W/dec.json"; f "multisig-decode"; }
python3 -c 'import json;d=json.loads(open("'"$W"'/dec.json").readline());assert d["signatures_verified"]==2 and d["signature_valid"] is True and d["threshold"]==2, d' || { cat "$W/dec.json"; f "decode did not re-verify 2 sigs over threshold 2"; }
echo "ok   cosmos-multisig: decode re-verifies 2 signatures and the bitarray (threshold 2)"

# 5a. Sub-threshold: a 2-of-3 whose chosen signer set is a single member -> combine refuses.
"$B/acct-tx" multisig-build --chain atom --threshold 2 --pubkey "$P1" --pubkey "$P2" --pubkey "$P3" --signer 0 \
  --to "$TO" --amount 1 --fee 0 --gas 100000 --sequence 0 --account-number 0 > "$W/build1.json" 2>&1 || { cat "$W/build1.json"; f "sub-threshold build"; }
python3 scripts/e2e-only/tty-drive.py right "$W/k1" "$W/q0.json" "$Bab/acct-tx" multisig-sign --chain atom --tx "$W/build1.json" --expect-to "$TO" > "$W/ttyq" 2>&1 || true  # allow-true: asserted next
"$B/acct-tx" multisig-combine --chain atom --tx "$W/build1.json" --part "$W/q0.json" > "$W/under.json" 2>&1 && { cat "$W/under.json"; f "1-of-2 must not combine"; }
grep -q 'not_enough_signatures' "$W/under.json" || { cat "$W/under.json"; f "sub-threshold refusal reason"; }
echo "ok   cosmos-multisig: a sub-threshold combine refuses (not_enough_signatures)"

# 5b. A key that is not one of the members refuses to sign.
python3 scripts/e2e-only/tty-drive.py right "$W/k9" "$W/pX.json" "$Bab/acct-tx" multisig-sign --chain atom --tx "$W/build.json" --expect-to "$TO" > "$W/ttyX" 2>&1 || true  # allow-true: a non-member key is expected to refuse
grep -q '"partial":true' "$W/pX.json" 2>/dev/null && { cat "$W/pX.json"; f "a non-member key must be refused"; }
grep -q 'key is not one of the multisig members' "$W/pX.json" || { cat "$W/pX.json"; cat "$W/ttyX"; f "non-member refusal reason"; }
echo "ok   cosmos-multisig: a non-member key is refused (key is not one of the multisig members)"

echo "PASS cosmos-multisig"
