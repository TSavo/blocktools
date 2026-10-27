# shellcheck shell=bash
# THORChain MsgDeposit (acct-tx --chain rune): keys, build, decode, sign behind the typed code (wrong
# code aborts, right code signs, the signature verifies), the --expect-memo guard, and a golden check
# that build + the real mainnet signature reproduce the `swapchan` THORName register TxRaw byte for byte
# (the KAT in crates/acct/tests/thorchain.rs, re-derived here through the shipped CLI). Public key 1 only.
set -eu
B=${BIN:-${B:-target/release}}
X="${T:-$(mktemp -d)}/thorchain"; mkdir -p "$X"
echo 0000000000000000000000000000000000000000000000000000000000000001 > "$X/k1"
"$B/acct-tx" keys --chain rune < "$X/k1" > "$X/keys.json"
A1=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["address"])' "$X/keys.json")
PK1=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["pubkey"])' "$X/keys.json")
[ "$A1" = thor1w508d6qejxtdg4y5r3zarvary0c5xw7ku6wp68 ] || { echo "FAIL thorchain keys ($A1)"; exit 1; }

MEMO='=:ETH.ETH:0x0000000000000000000000000000000000000001:0'
"$B/acct-tx" build --chain rune --from "$A1" --pubkey "$PK1" --amount 100000000 --memo "$MEMO" --sequence 0 --account-number 1 > "$X/u.json"
"$B/acct-tx" decode --chain rune < "$X/u.json" | grep -q '"amount_base":"100000000"' || { echo "FAIL thorchain decode"; exit 1; }
echo "ok   thorchain: keys + build/decode (MsgDeposit THOR.RUNE)"

# Wrong code -> aborted, nothing signed.
python3 scripts/e2e-only/tty-drive.py wrong "$X/k1" "$X/s0.json" "$(cd "$B" && pwd)/acct-tx" sign --chain rune --tx "$X/u.json" --expect-memo "$MEMO" > "$X/t0" 2>&1 || true  # allow-true: refusal asserted next
grep -q '"status":"aborted"' "$X/s0.json" || { echo "FAIL thorchain wrong-code must abort"; exit 1; }
# Right code -> signed, and the signed TxRaw verifies.
python3 scripts/e2e-only/tty-drive.py right "$X/k1" "$X/s1.json" "$(cd "$B" && pwd)/acct-tx" sign --chain rune --tx "$X/u.json" --expect-memo "$MEMO" > "$X/t1" 2>&1
grep -q '"status":"ok"' "$X/s1.json" || { echo "FAIL thorchain sign"; cat "$X/s1.json"; exit 1; }
"$B/acct-tx" decode --chain rune < "$X/s1.json" | grep -q '"signature_valid":true' || { echo "FAIL thorchain signature verify"; exit 1; }
echo "ok   thorchain: pty sign (wrong aborts, right signs, signature verifies)"

# --expect-memo mismatch is refused before any signing.
python3 scripts/e2e-only/tty-drive.py right "$X/k1" "$X/s2.json" "$(cd "$B" && pwd)/acct-tx" sign --chain rune --tx "$X/u.json" --expect-memo '=:ETH.ETH:0xdeadbeef:0' > "$X/t2" 2>&1 || true  # allow-true: refusal asserted next
grep -q memo_mismatch "$X/s2.json" || { echo "FAIL thorchain --expect-memo guard"; exit 1; }
echo "ok   thorchain: --expect-memo mismatch refused"

# Golden: build with the real swapchan register pubkey + params; with the mainnet signature it is the exact on-chain TxRaw.
REGMEMO='~:swapchan:THOR:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu:ETH.ETH'
"$B/acct-tx" build --chain rune --from thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu --pubkey 02db731fc490a4107583546391517f26d0196a1e8ac777560cccda03c702c86023 --amount 1105120000 --memo "$REGMEMO" --sequence 0 --account-number 157891 > "$X/reg.json"
python3 - "$X/reg.json" <<'PY' || { echo "FAIL thorchain golden TxRaw"; exit 1; }
import json, sys, base64
def flds(b):
    i = 0; o = {}
    while i < len(b):
        t = b[i]; i += 1; f = t >> 3; w = t & 7
        v = 0; sh = 0
        while True:
            x = b[i]; i += 1; v |= (x & 0x7f) << sh; sh += 7
            if not x & 0x80: break
        if w == 2:
            o.setdefault(f, []).append(b[i:i + v]); i += v
        else:
            o.setdefault(f, []).append(v)
    return o
def W(f, b):
    n = len(b); v = b""
    while n >= 0x80: v += bytes([n & 0x7f | 0x80]); n >>= 7
    return bytes([f << 3 | 2]) + v + bytes([n]) + b
sd = base64.b64decode(json.load(open(sys.argv[1]))["unsigned"]); f = flds(sd)
sig = bytes.fromhex("6126e2df96a1737fedcca08c58a84783bf2cd4651742ca84b7ecd1aed4ea7807679269a8c7c6f976ff701760ba907524aa6e9c82bc169ec41f952327baf9b6b2")
tx = W(1, f[1][0]) + W(2, f[2][0]) + W(3, sig)
REG = "CsIBCr8BChEvdHlwZXMuTXNnRGVwb3NpdBKpAQogChIKBFRIT1ISBFJVTkUaBFJVTkUSCjExMDUxMjAwMDASb346c3dhcGNoYW46VEhPUjp0aG9yMTc0anN1NWFndGd6dGNtY2x5OTZhYzltcnRmNW4yazk4ZGhtdW51OnRob3IxNzRqc3U1YWd0Z3p0Y21jbHk5NmFjOW1ydGY1bjJrOThkaG11bnU6RVRILkVUSBoU9WUOU6haBLxvHyF13BdjWmk1WKcSVwpOCkYKHy9jb3Ntb3MuY3J5cHRvLnNlY3AyNTZrMS5QdWJLZXkSIwohAttzH8SQpBB1g1RjkVF/JtAZah6Kx3dWDMzaA8cCyGAjEgQKAggBEgUQgNrECRpAYSbi35ahc3/tzKCMWKhHg78s1GUXQsqEt+zRrtTqeAdnkmmox8b5dv9wF2C6kHUkqm6cgrwWnsQflSMnuvm2sg=="
assert base64.b64encode(tx).decode() == REG, "TxRaw differs from mainnet swapchan register"
print("golden ok")
PY
echo "ok   thorchain: build + mainnet signature == swapchan register TxRaw (byte-for-byte)"
