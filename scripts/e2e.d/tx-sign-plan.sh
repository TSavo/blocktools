#!/bin/sh
# RFC #15 end-state: a Plan's assertions BECOME tx-sign's enforced guards. A DOGE THORChain inbound
# built as a declarative Plan (tx-plan) resolves to the unsigned PSBT; `tx-plan check` passes; the SAME
# plan drives `tx-sign --plan` (pty, public key 1), which SIGNS ONLY because the resolved tx satisfies
# the plan. Then tamper the plan's assertions (wrong vault / wrong memo / fee over the CapFee) and
# `tx-sign --plan` REFUSES before any key is touched -- the invariant: pass-check <=> sign, tamper <=> refuse.
set -eu
. scripts/e2e-only/portable.sh
f() { echo "FAIL tx-sign-plan $1"; exit 1; }
B=${BIN:-${B:-target/release}}; Bab=$(cd "$B" && pwd)
T=${T:-$(mktemp -d)}; W="$T/tx-sign-plan"; mkdir -p "$W"
V=D5kTEGxmas71USKAcAaJptKjq8NJc6EK8C          # vault      = public key 2 (doge P2PKH)
A1=DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE         # change     = public key 1 (doge P2PKH)
MEMO='=:r:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu'
MEMO_HEX=$(python3 -c 'import sys;print(sys.argv[1].encode().hex())' "$MEMO")
echo 0000000000000000000000000000000000000000000000000000000000000001 > "$W/k1"
cargo run -q --offline --release -p blocktools-tx --example mock-utxo -- doge 1 500000000 "$A1" > "$W/u" || f "mock-utxo"

# The one UTXO the mock produced -> AddInput fields for the plan (txid, vout, amount, address, prev_tx).
eval "$(python3 -c 'import json,sys
u=json.loads([l for l in open(sys.argv[1]) if l.strip()][0])
print("TXID=%s"%u["txid"]); print("VOUT=%s"%u["vout"]); print("AMT=%s"%u["amount"])
print("ADDR=%s"%u["address"]); print("PREV=%s"%u.get("prev_tx",""))' "$W/u")"
echo '{"fee_rate":1000}' > "$W/ctx.json"

# 1. Build the inbound as a declarative Plan (tx-plan pipe); keep the plan JSON for --plan.
P=$("$B/tx-plan" new --chain doge)
P=$(printf '%s' "$P" | "$B/tx-plan" input --txid "$TXID" --vout "$VOUT" --amount "$AMT" --address "$ADDR" --prev-tx "$PREV")
P=$(printf '%s' "$P" | "$B/tx-plan" output --to "$V" --amount 100000000)
P=$(printf '%s' "$P" | "$B/tx-plan" change --to "$A1")
P=$(printf '%s' "$P" | "$B/tx-plan" op-return --memo "$MEMO_HEX")
P=$(printf '%s' "$P" | "$B/tx-plan" fee-rate --satvb 1000)
P=$(printf '%s' "$P" | "$B/tx-plan" expect-to --address "$V")
P=$(printf '%s' "$P" | "$B/tx-plan" expect-memo --memo "$MEMO")
P=$(printf '%s' "$P" | "$B/tx-plan" cap-fee --max 10000000)
printf '%s\n' "$P" > "$W/plan.json"

# 2. resolve -> the unsigned PSBT (the tx-sign --tx input), and `tx-plan check` passes.
"$B/tx-plan" resolve --plan "$W/plan.json" --context "$W/ctx.json" > "$W/tx.json" || { cat "$W/tx.json"; f resolve; }
grep -q '"status":"ok"' "$W/tx.json" || { cat "$W/tx.json"; f "resolve status"; }
"$B/tx-plan" check --plan "$W/plan.json" --context "$W/ctx.json" > "$W/check.out" || { cat "$W/check.out"; f "tx-plan check failed on the honest plan"; }
grep -q '"status":"ok"' "$W/check.out" && grep -q '"findings":\[\]' "$W/check.out" || { cat "$W/check.out"; f "tx-plan check not clean"; }
echo "ok   tx-sign-plan: tx-plan check passes on the honest inbound plan"

# 3. tx-sign --plan (pty, right code): signs ONLY because the resolved tx satisfies the plan's assertions.
python3 scripts/e2e-only/tty-drive.py right "$W/k1" "$W/signed.json" "$Bab/tx-sign" --tx "$W/tx.json" --plan "$W/plan.json" > "$W/tty" 2>&1 || true  # allow-true: outcome asserted next
grep -q '"status":"ok"' "$W/signed.json" || { cat "$W/signed.json"; cat "$W/tty"; f "tx-sign --plan did not sign the honest inbound"; }
grep -qF "OP_RETURN memo : $MEMO" "$W/tty" || { cat "$W/tty"; f "memo not shown on the tty summary"; }
"$B/tx-decode" --text --chain doge < "$W/signed.json" | grep -q op_return || f "signed tx has no OP_RETURN"
echo "ok   tx-sign-plan: a plan that passes tx-plan check is signed by tx-sign --plan (same assertions, by construction)"

# 4. Tamper the plan's assertions; tx-sign --plan must REFUSE before any key is touched (no tty needed).
refuses() { # <name> <expect-code> <tampered-plan>
  "$B/tx-sign" --tx "$W/tx.json" --plan "$3" < "$W/k1" > "$W/r.$1" 2>&1 || true  # allow-true: refusal asserted next
  grep -q '"status":"refused"' "$W/r.$1" && grep -q "$2" "$W/r.$1" || { cat "$W/r.$1"; f "$1 not refused ($2)"; }
  ! grep -q signed_tx "$W/r.$1" || { cat "$W/r.$1"; f "$1 leaked a signature"; }
}
# wrong recipient: assert a different vault than the one the resolved tx pays -> the real vault output is unexpected
python3 -c 'import json,sys;p=json.load(open(sys.argv[1]));[s.__setitem__("address",sys.argv[2]) for s in p["steps"] if s.get("op")=="expect-to"];json.dump(p,open(sys.argv[3],"w"))' "$W/plan.json" "$A1" "$W/plan.badto.json"
refuses badto unexpected_output "$W/plan.badto.json"
# wrong memo: assert a memo one byte off from the OP_RETURN the tx carries
python3 -c 'import json,sys;p=json.load(open(sys.argv[1]));[s.__setitem__("memo",sys.argv[2]) for s in p["steps"] if s.get("op")=="expect-memo"];json.dump(p,open(sys.argv[3],"w"))' "$W/plan.json" "${MEMO}X" "$W/plan.badmemo.json"
refuses badmemo unexpected_output "$W/plan.badmemo.json"
# fee over the CapFee: lower the cap below the resolved tx's fee
python3 -c 'import json,sys;p=json.load(open(sys.argv[1]));[s.__setitem__("max","1") for s in p["steps"] if s.get("op")=="cap-fee"];json.dump(p,open(sys.argv[2],"w"))' "$W/plan.json" "$W/plan.badfee.json"
refuses badfee fee_above_cap "$W/plan.badfee.json"
echo "ok   tx-sign-plan: tampering the plan (wrong vault / wrong memo / fee over CapFee) makes tx-sign --plan refuse, nothing signed"

# 5. tx-verify --plan agrees with the signer path: honest ok, tampered failed.
"$B/tx-verify" --plan "$W/plan.json" < "$W/tx.json" | grep -q '"status":"ok"' || f "tx-verify --plan rejected the honest inbound"
"$B/tx-verify" --plan "$W/plan.badto.json" < "$W/tx.json" > "$W/v.badto" || true  # allow-true: refusal asserted next
grep -q '"status":"failed"' "$W/v.badto" && grep -q unexpected_output "$W/v.badto" || { cat "$W/v.badto"; f "tx-verify --plan did not reject the wrong vault"; }
echo "ok   tx-sign-plan: tx-verify --plan matches tx-sign --plan (honest passes, tampered fails)"
