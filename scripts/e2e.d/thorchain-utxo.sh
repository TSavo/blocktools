#!/bin/sh
# THORChain UTXO inbound via the SHIPPED tools, node-free (synthetic UTXO): tx-build --memo builds the
# [vault, change, OP_RETURN memo] inbound, tx-envelope verify_thor_send accepts it, tx-sign (pty, public
# key 1) shows the memo and signs, tx-decode confirms the signed OP_RETURN. Negative probes (refused
# before any signing): a tx with TWO OP_RETURNs and a tx with a NON-ZERO-value OP_RETURN. Public key 1/2.
set -eu
. scripts/e2e-only/portable.sh
f() { echo "FAIL thorchain-utxo $1"; exit 1; }
B=${BIN:-${B:-target/release}}; Bab=$(cd "$B" && pwd)
T=${T:-$(mktemp -d)}; W="$T/thorchain-utxo"; mkdir -p "$W"
V=D5kTEGxmas71USKAcAaJptKjq8NJc6EK8C          # vault      = public key 2 (doge P2PKH)
A1=DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE         # taker/change = public key 1 (doge P2PKH)
MEMO='=:r:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu'
echo 0000000000000000000000000000000000000000000000000000000000000001 > "$W/k1"
cargo run -q --offline --release -p blocktools-tx --example mock-utxo -- doge 1 500000000 "$A1" > "$W/u" || f "mock-utxo"

# 1. SHIPPED build with --memo: [vault, change, OP_RETURN memo]
"$B/tx-build" --chain doge --utxos "$W/u" --to "$V" --send 100000000 --change "$A1" --fee-rate 1000 --memo "$MEMO" > "$W/tx.json" || { cat "$W/tx.json"; f build; }
grep -q '"status":"ok"' "$W/tx.json" || { cat "$W/tx.json"; f "build status"; }
PSBT=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["psbt"])' "$W/tx.json")

# 2. tx-envelope verify_thor_send accepts the honest inbound
printf '{"op":"verify_thor_send","chain":"doge","tx":"%s","vault":"%s","memo":"%s","amount":"100000000","change":"%s","taker":"%s"}' "$PSBT" "$V" "$MEMO" "$A1" "$A1" > "$W/env.json"
"$B/tx-envelope" --json "$(cat "$W/env.json")" > "$W/env.out" || true  # allow-true: outcome asserted next
grep -q '"ok":true' "$W/env.out" || { cat "$W/env.out"; f "verify_thor_send refused the honest inbound"; }

# tx-verify (the shared policy) also accepts it: the single zero-value OP_RETURN is not an unexpected output
"$B/tx-verify" --chain doge --expect-to "$V" --change "$A1" < "$W/tx.json" | grep -q '"status":"ok"' || f "tx-verify refused the honest inbound"
echo "ok   thorchain-utxo: tx-build --memo + verify_thor_send + tx-verify accept the doge inbound"

# 3. tx-sign (pty, right code) shows the memo and signs; tx-decode confirms the OP_RETURN
python3 scripts/e2e-only/tty-drive.py right "$W/k1" "$W/signed.json" "$Bab/tx-sign" --tx "$W/tx.json" --chain doge --expect-to "$V" --change "$A1" > "$W/tty" 2>&1
grep -qF "OP_RETURN memo : $MEMO" "$W/tty" || { cat "$W/tty"; f "memo not shown on the tty summary"; }
grep -q '"status":"ok"' "$W/signed.json" || { cat "$W/signed.json"; f "tx-sign did not sign the inbound"; }
"$B/tx-decode" --text --chain doge < "$W/signed.json" | grep -q op_return || f "signed tx has no OP_RETURN"
echo "ok   thorchain-utxo: pty sign shows the memo, signs, tx-decode confirms the OP_RETURN"

# 4. Negatives: build a no-memo inbound, then graft OP_RETURN outputs the shipped signer must still refuse.
"$B/tx-build" --chain doge --utxos "$W/u" --to "$V" --send 100000000 --change "$A1" --fee-rate 1000 > "$W/base.json" || f "base build"
BASE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["psbt"])' "$W/base.json")
cat > "$W/surg.py" <<'PY'
import base64, sys
def rv(b, i):
    x = b[i]; i += 1
    if x < 0xfd: return x, i
    if x == 0xfd: return int.from_bytes(b[i:i+2], 'little'), i+2
    if x == 0xfe: return int.from_bytes(b[i:i+4], 'little'), i+4
    return int.from_bytes(b[i:i+8], 'little'), i+8
def wv(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff: return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')
def opret(value, data):
    s = bytes([0x6a]) + (bytes([len(data)]) if len(data) <= 75 else bytes([0x4c, len(data)])) + data
    return value.to_bytes(8, 'little') + wv(len(s)) + s
b = base64.b64decode(sys.argv[1]); assert b[:5] == b'psbt\xff'
i = 5; glob = []
while b[i] != 0x00:
    kl, i = rv(b, i); key = b[i:i+kl]; i += kl
    vl, i = rv(b, i); val = b[i:i+vl]; i += vl
    glob.append((key, val))
i += 1; rest = b[i:]
utx = next(v for k, v in glob if k == b'\x00')
j = 0; ver = utx[j:j+4]; j += 4
nin, j = rv(utx, j); s = j
for _ in range(nin):
    j += 36; sl, j = rv(utx, j); j += sl + 4
ins = utx[s:j]
nout, j = rv(utx, j); s = j
for _ in range(nout):
    j += 8; sl, j = rv(utx, j); j += sl
outs = utx[s:j]; lock = utx[j:j+4]
extra = [(0, b'=:r:extra-memo-one'), (0, b'=:r:extra-memo-two')] if sys.argv[2] == 'two' else [(1000, b'=:r:paid-opreturn')]
newutx = ver + wv(nin) + ins + wv(nout + len(extra)) + outs + b''.join(opret(v, d) for v, d in extra) + lock
g = b''.join(wv(len(k)) + k + wv(len(newutx if k == b'\x00' else v)) + (newutx if k == b'\x00' else v) for k, v in glob) + b'\x00'
print(base64.b64encode(b'psbt\xff' + g + rest + b'\x00' * len(extra)).decode())
PY
python3 "$W/surg.py" "$BASE" two > "$W/two.b64" || f "graft two"
python3 "$W/surg.py" "$BASE" paid > "$W/paid.b64" || f "graft paid"
for case in two paid; do
  "$B/tx-sign" --tx "$W/$case.b64" --chain doge --expect-to "$V" --change "$A1" < "$W/k1" > "$W/neg.$case" 2>&1 || true  # allow-true: refusal asserted next
  grep -q '"status":"refused"' "$W/neg.$case" && grep -q unexpected_output "$W/neg.$case" || { cat "$W/neg.$case"; f "$case OP_RETURN not refused"; }
done
echo "ok   thorchain-utxo: two OP_RETURNs and a non-zero-value OP_RETURN both refused (unexpected_output)"
