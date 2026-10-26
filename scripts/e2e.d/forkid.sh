#!/bin/sh
# Fork-id sweep e2e (BCH/BSV fork id 0, BTG 79): build -> verify -> sign (pty types the code) ->
# decode -> re-verify, then an INDEPENDENT pure-Python check (hashlib + secp256k1 arithmetic here,
# no Rust): the signature byte is 0x41, the signature verifies under the BIP143-style fork-id
# digest with type 0x41|forkid<<8 and the proven amount, and does NOT verify under fork id 0 for
# BTG or under the plain BTC legacy sighash. tx-sign gets no --chain: it auto-detects the chain
# from the tx-build file. Throwaway key 1 only; nothing touches a network.
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap '[ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
MU="cargo run -q --offline --release -p blocktools-tx --example mock-utxo --"
run() { # chain forkid from-p2pkh to
  c=$1; fid=$2; p=$3; d=$4
  $MU $c 1 30000 $p > $T/u.$c
  $B/tx-build --chain $c --utxos $T/u.$c --to $d --sweep --fee-rate 5 > $T/p.$c || { cat $T/p.$c; f "$c build"; }
  $B/tx-verify --chain $c --expect-to $d < $T/p.$c >/dev/null || f "$c verify"
  python3 scripts/e2e-only/tty-drive.py right $T/k $T/o.$c $PWD/$B/tx-sign --tx $T/p.$c --expect-to $d > $T/tty.$c || { cat $T/o.$c; f "$c sign"; }
  grep -q "Checks passed" $T/tty.$c || f "$c summary"
  $B/tx-decode --chain $c < $T/o.$c > $T/d.$c && grep -q '"signed":true' $T/d.$c || f "$c decode"
  $B/tx-verify --chain $c --expect-to $d < $T/o.$c >/dev/null || f "$c reverify"
  python3 - $T/o.$c $T/u.$c $fid <<'PY' || f "$c independent fork-id signature check"
import hashlib, json, sys
o = [json.loads(l) for l in open(sys.argv[1]) if "signed_tx" in l][0]
u = json.loads(open(sys.argv[2]).readline()); fid = int(sys.argv[3])
H = lambda b: hashlib.sha256(hashlib.sha256(b).digest()).digest()
raw = bytes.fromhex(o["signed_tx"])
def vi(b, p):
    x = b[p]
    if x < 0xfd: return x, p + 1
    n = {0xfd: 2, 0xfe: 4, 0xff: 8}[x]; return int.from_bytes(b[p+1:p+1+n], "little"), p + 1 + n
p = 4; n, p = vi(raw, p); ins = []
for _ in range(n):
    op = raw[p:p+36]; p += 36; l, p = vi(raw, p); ss = raw[p:p+l]; p += l; seq = raw[p:p+4]; p += 4; ins.append((op, ss, seq))
n, p = vi(raw, p); o0 = p
for _ in range(n): p += 8; l, p = vi(raw, p); p += l
outs = raw[o0:p]; lock = raw[p:p+4]; ver = raw[:4]
assert len(ins) == 1
op, ss, seq = ins[0]
sig = ss[1:1+ss[0]]; pub = ss[2+ss[0]:]
assert sig[-1] == 0x41, sig[-1]
prev = bytes.fromhex(u["prev_tx"])
# amount + script of the spent output, from the proving prev_tx
q = 4; m, q = vi(prev, q)
for _ in range(m): q += 36; l, q = vi(prev, q); q += l + 4
m, q = vi(prev, q); vout = int.from_bytes(op[32:], "little")
for k in range(m):
    amt = int.from_bytes(prev[q:q+8], "little"); q += 8; l, q = vi(prev, q); spk = prev[q:q+l]; q += l
    if k == vout: break
assert H(prev)[::-1].hex() == u["txid"] and amt == 30000
def ser(b): return bytes([len(b)]) + b
def digest(ty):
    pre = ver + H(op) + H(seq) + op + ser(spk) + amt.to_bytes(8, "little") + seq + H(outs) + lock + ty.to_bytes(4, "little")
    return int.from_bytes(H(pre), "big")
def legacy():
    t = ver + b"\x01" + op + ser(spk) + seq + bytes([raw[o0-1]]) + outs + lock + (1).to_bytes(4, "little")
    return int.from_bytes(H(t), "big")
P = 2**256 - 2**32 - 977; N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798; Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    l = (3*a[0]*a[0]*pow(2*a[1], -1, P)) % P if a == b else ((b[1]-a[1])*pow(b[0]-a[0], -1, P)) % P
    x = (l*l - a[0] - b[0]) % P; return (x, (l*(a[0]-x) - a[1]) % P)
def mul(k, pt):
    r = None
    while k:
        if k & 1: r = add(r, pt)
        pt = add(pt, pt); k >>= 1
    return r
assert pub[0] in (2, 3) and len(pub) == 33
x = int.from_bytes(pub[1:], "big"); y = pow((x**3 + 7) % P, (P+1)//4, P)
if y % 2 != pub[0] % 2: y = P - y
d = sig[:-1]; assert d[0] == 0x30
rl = d[3]; r = int.from_bytes(d[4:4+rl], "big"); sl = d[5+rl]; s = int.from_bytes(d[6+rl:6+rl+sl], "big")
assert s <= N // 2, "high-s"
def ok(z):
    w = pow(s, -1, N); R = add(mul(z*w % N, (Gx, Gy)), mul(r*w % N, (x, y))); return R is not None and R[0] % N == r
assert ok(digest(0x41 | fid << 8)), "fork-id digest"
assert not ok(legacy()), "verifies under the BTC sighash: not replay-protected"
if fid: assert not ok(digest(0x41)), "BTG signature verifies with fork id 0"
PY
  echo "ok   $c fork-id sweep: build -> verify -> tty sign -> decode -> re-verify; Python: sig byte 0x41, verifies under type 0x41|$fid<<8, not under the BTC sighash"
}
run bch 0 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH 147Us9aEq2PvBC5wobBJw1yEpQEbPKzssA
run bsv 0 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH 147Us9aEq2PvBC5wobBJw1yEpQEbPKzssA
run btg 79 GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5 GLxQHGuBot1DFfPEjXqRMnK8ja2SSrhEgL
# Refusal kept: a fork-id P2PKH input without prev_tx (amount unproven) is not built (and the
# signer refuses such a PSBT with legacy_input_amount_unproven: test forkid_signer_refusals).
python3 -c 'import json,sys; d=json.loads(open(sys.argv[1]).readline()); d.pop("prev_tx"); print(json.dumps(d))' $T/u.bch > $T/np.bch
rc=0; $B/tx-build --chain bch --utxos $T/np.bch --to 147Us9aEq2PvBC5wobBJw1yEpQEbPKzssA --sweep --fee-rate 5 > $T/pn.bch || rc=$?
[ $rc = 2 ] && grep -q legacy_input_needs_prev_tx $T/pn.bch || f "bch without prev_tx: rc=$rc"
echo "ok   bch input without prev_tx: rc=2 legacy_input_needs_prev_tx (refusal kept)"
