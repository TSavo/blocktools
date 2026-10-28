#!/bin/sh
# Taproot SCRIPT-PATH m-of-n, end to end through the declarative Plan (RFC #15), no network, public keys.
# A 3-of-5 tapscript (CHECKSIGADD) under the BIP341 NUMS internal key: `taproot-multisig` builds the leaf
# + P2TR address; a mock UTXO funds it; `tx-plan input --tap-leaf-script` carries the leaf into the Plan;
# resolve -> the unsigned PSBT; `tx-plan check` passes (the signer's policy::check). Three cosigners
# `tx-sign --partial` (pty) each add ONE Schnorr tap_script_sig and emit NO signed tx; `tx-combine`
# finalizes the quorum into a script-path witness `[sigs…, leaf, control_block]` that `tx-decode` shows
# spending the P2TR input. Negatives: sub-threshold combine refuses, a key outside the leaf refuses, and
# a tampered plan assertion refuses the partial sign (pass-check <=> sign across the multi-party flow).
set -eu
. scripts/e2e-only/portable.sh
f() { echo "FAIL taproot-multisig $1"; exit 1; }
B=${BIN:-${B:-target/release}}; Bab=$(cd "$B" && pwd)
T=${T:-$(mktemp -d)}; W="$T/taproot-multisig"; mkdir -p "$W"

# Five cosigner secret keys (1..5) and their canonical compressed pubkeys (secp G multiples); the tool
# accepts compressed and drops the parity byte to x-only. A wrong key makes partial_sign find no match
# and the flow fails loudly, so the vectors are self-checking. Sign with keys 1..3 (the 3-of-5 quorum).
P1=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
P2=02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
P3=02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
P4=02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13
P5=022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4
for i in 1 2 3; do printf '%064x\n' "$i" > "$W/k$i"; done
printf '%064x\n' 9 > "$W/kX"   # a key OUTSIDE the leaf

# 1. Build the 3-of-5 script-path output: leaf + P2TR address + control block. Public, offline, keyless.
MS=$("$B/taproot-multisig" 3 --pubkey $P1 --pubkey $P2 --pubkey $P3 --pubkey $P4 --pubkey $P5 --network bitcoin) || f "taproot-multisig build"
echo "$MS" | grep -q '"status":"ok"' || { echo "$MS"; f "taproot-multisig status"; }
LEAF=$(printf '%s' "$MS" | sed 's/.*"leaf_script":"//; s/".*//')
ADDR=$(printf '%s' "$MS" | sed 's/.*"address":"//; s/".*//')
# <pk1> CHECKSIG … <M> NUMEQUAL: the leaf starts with a 32-byte key push (0x20) and ends in OP_NUMEQUAL (9c).
printf '%s' "$LEAF" | grep -q '^20.*9c$' || { echo "$LEAF"; f "leaf is not a CHECKSIGADD multisig"; }
case "$ADDR" in bc1p*) [ "${#ADDR}" -eq 62 ] || f "P2TR address is ${#ADDR} chars, expected 62" ;; *) f "address is not a bech32m P2TR" ;; esac
echo "ok   taproot-multisig: 3-of-5 script-path P2TR built ($ADDR)"

# 2. Fund the P2TR with a synthetic prev_tx, then read the UTXO fields.
cargo run -q --offline --release -p blocktools-tx --example mock-utxo -- btc 0 200000 "$ADDR" > "$W/u" || f "mock-utxo"
eval "$(python3 -c 'import json,sys
u=json.loads([l for l in open(sys.argv[1]) if l.strip()][0])
print("TXID=%s"%u["txid"]); print("VOUT=%s"%u["vout"]); print("AMT=%s"%u["amount"]); print("PREV=%s"%u.get("prev_tx",""))' "$W/u")"
echo '{"fee_rate":2}' > "$W/ctx.json"

# 3. Declarative Plan carrying the tapleaf; resolve -> PSBT; `tx-plan check` is clean.
P=$("$B/tx-plan" new --chain btc)
P=$(printf '%s' "$P" | "$B/tx-plan" input --txid "$TXID" --vout "$VOUT" --amount "$AMT" --address "$ADDR" --prev-tx "$PREV" --tap-leaf-script "$LEAF")
P=$(printf '%s' "$P" | "$B/tx-plan" output --to "$ADDR" --amount 150000)
P=$(printf '%s' "$P" | "$B/tx-plan" change --to "$ADDR")
P=$(printf '%s' "$P" | "$B/tx-plan" fee-rate --satvb 2)
P=$(printf '%s' "$P" | "$B/tx-plan" expect-to --address "$ADDR")
P=$(printf '%s' "$P" | "$B/tx-plan" cap-fee --max 50000)
printf '%s\n' "$P" > "$W/plan.json"
grep -q '"tap_leaf_script"' "$W/plan.json" || f "plan AddInput did not carry tap_leaf_script"
"$B/tx-plan" resolve --plan "$W/plan.json" --context "$W/ctx.json" > "$W/tx.json" 2>&1 || { cat "$W/tx.json"; f resolve; }
grep -q '"status":"ok"' "$W/tx.json" || { cat "$W/tx.json"; f "resolve status"; }
"$B/tx-plan" check --plan "$W/plan.json" --context "$W/ctx.json" > "$W/check.out" 2>&1 || { cat "$W/check.out"; f "tx-plan check failed on the honest taproot plan"; }
grep -q '"findings":\[\]' "$W/check.out" || { cat "$W/check.out"; f "tx-plan check not clean"; }
echo "ok   taproot-multisig: tx-plan check passes on the script-path spend"

# 4. Three cosigners Schnorr-partial-sign (pty, right code); each adds ONE sig and emits NO signed tx.
for k in 1 2 3; do
  python3 scripts/e2e-only/tty-drive.py right "$W/k$k" "$W/p$k.json" "$Bab/tx-sign" --partial --tx "$W/tx.json" --plan "$W/plan.json" > "$W/tty$k" 2>&1 || true  # allow-true: asserted next
  grep -q '"status":"ok"' "$W/p$k.json" || { cat "$W/p$k.json"; f "cosigner $k partial sign"; }
  grep -q '"added":1' "$W/p$k.json" || { cat "$W/p$k.json"; f "cosigner $k did not add exactly one sig"; }
  grep -q '"signed_tx"' "$W/p$k.json" && { cat "$W/p$k.json"; f "partial must not emit a signed tx"; }
done
echo "ok   taproot-multisig: three cosigners each add one Schnorr tap_script_sig, no finalize"

# 5. Combine the quorum -> a finalized script-path tx; tx-decode shows the P2TR input spent.
"$B/tx-combine" --psbt "$W/p1.json" --psbt "$W/p2.json" --psbt "$W/p3.json" > "$W/signed.json" 2>&1 || { cat "$W/signed.json"; f "tx-combine quorum"; }
grep -q '"status":"ok"' "$W/signed.json" || { cat "$W/signed.json"; f "combine status"; }
grep -q '"signed_tx"' "$W/signed.json" || { cat "$W/signed.json"; f "combine produced no signed tx"; }
"$B/tx-decode" --text --chain btc < "$W/signed.json" > "$W/dec.txt" 2>&1 || { cat "$W/dec.txt"; f "decode signed tx"; }
grep -qi 'p2tr' "$W/dec.txt" || { cat "$W/dec.txt"; f "decoded tx does not spend the P2TR input"; }
echo "ok   taproot-multisig: tx-combine finalizes the 3-of-5 into a script-path witness spending the P2TR input"

# 6a. Sub-threshold: combining only 2 of 3 refuses.
"$B/tx-combine" --psbt "$W/p1.json" --psbt "$W/p2.json" > "$W/under.json" 2>&1 && { cat "$W/under.json"; f "2-of-3 must not finalize"; }
grep -q 'not_enough_signatures' "$W/under.json" || { cat "$W/under.json"; f "sub-threshold refusal reason"; }
echo "ok   taproot-multisig: a sub-threshold combine refuses (not_enough_signatures)"

# 6b. A cosigner outside the leaf: partial-sign refuses.
python3 scripts/e2e-only/tty-drive.py right "$W/kX" "$W/pX.json" "$Bab/tx-sign" --partial --tx "$W/tx.json" --plan "$W/plan.json" > "$W/ttyX" 2>&1 || true  # allow-true: a non-cosigner is expected to refuse; asserted next
grep -q 'no_multisig_input_for_these_keys' "$W/pX.json" || { cat "$W/pX.json"; f "a non-cosigner key must be refused"; }
echo "ok   taproot-multisig: a key outside the leaf is refused (no_multisig_input_for_these_keys)"

# 6c. Tamper the plan's destination assertion: tx-sign --partial refuses before touching a key.
Ptamper=$(python3 -c 'import json,sys
p=json.load(open(sys.argv[1]))
for s in p["steps"]:
    if s.get("op")=="expect-to": s["address"]=sys.argv[2]
print(json.dumps(p))' "$W/plan.json" bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 2>/dev/null || echo "")
printf '%s\n' "$Ptamper" > "$W/plan.tamper.json"
python3 scripts/e2e-only/tty-drive.py right "$W/k1" "$W/pt.json" "$Bab/tx-sign" --partial --tx "$W/tx.json" --plan "$W/plan.tamper.json" > "$W/ttyt" 2>&1 || true  # allow-true: a tampered plan is expected to refuse; asserted next
grep -q '"status":"ok"' "$W/pt.json" && { cat "$W/pt.json"; f "a tampered plan assertion must refuse the partial sign"; }
echo "ok   taproot-multisig: a tampered expect-to refuses the partial sign (pass-check <=> sign)"

echo "PASS taproot-multisig"
