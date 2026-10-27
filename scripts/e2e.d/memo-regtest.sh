#!/bin/sh
# THORChain memo send (SwapChan LTC/DOGE/BCH) against the REAL pinned regtest nodes (scripts/fork-pins), started
# with -acceptnonstdtxn=0 so mainnet standardness policy applies (doge/ltc regtest default to accepting non-standard).
# Per chain: fund throwaway key 1 (P2PKH), psbtmemo::build (examples/memo-sign.rs, signs with public key 1) a send
# to vault = key 2 (BCH: prefixless CashAddr, the live THORChain vault form) with change to key 1, then
#   tx-envelope verify_thor_send on the PSBT -> ok (and a memo case change -> refused with "memo"),
#   sendrawtransaction -> accepted, mined; on chain: exactly [vault == amount, change == key 1, OP_RETURN == memo
#   bytes], every input sequence 0xffffffff (non-RBF). A second tx sends exactly the chain's builder dust with a
#   memo of exactly the chain's OP_RETURN limit (80 B; bch 220 B) and must also be accepted and mined. Negative
#   probes (same coin, signed with key 1): vault output 1 below the node's dust (doge: 100000, below the builder's 1000000) -> node rejects "dust"; memo 1 byte over the
#   limit -> node rejects ("scriptpubkey" / bch "oversize-op-return"), so the builder's limits are the node's limits.
# MEMO_CHAINS="ltc doge bch" (default). Prerequisite missing: skip, or fail in CI / BLOCKTOOLS_REQUIRE_FIXTURES=1.
set -eu
B=${BIN:-${B:-target/release}}; Bab=$(cd "$B" && pwd)
T=${T:-$(mktemp -d)}; W="$T/memo-regtest"; mkdir -p "$W"
CACHE=${BLOCKTOOLS_RECOVERY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/blocktools-recovery}; mkdir -p "$CACHE"
f() { echo "FAIL memo-regtest $1"; exit 1; }
skip() { if [ "${BLOCKTOOLS_REQUIRE_FIXTURES:-}" = 1 ] || [ "${CI:-}" = true ]; then f "$1"; fi; echo "skip memo-regtest ($1)"; exit 0; }
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo "SKIP memo-regtest: release tarballs pinned for Linux x86_64 only; real-node property not measured here"; exit 0; }
cargo build -q --offline --release -p blocktools --features secrets --example memo-sign || f "build memo-sign"
MS=target/release/examples/memo-sign
# P2PKH of throwaway key N: legacy base58 (version V), script hex, prefixless CashAddr
addr() { python3 - "$1" "$2" <<'PY'
import hashlib, sys
n, v = int(sys.argv[1]), int(sys.argv[2])
p, Gx, Gy = 2**256 - 2**32 - 977, 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
def add(P, Q):
    if P is None: return Q
    l = (3 * P[0] * P[0] * pow(2 * P[1], -1, p)) if P == Q else ((Q[1] - P[1]) * pow(Q[0] - P[0], -1, p))
    x = (l * l - P[0] - Q[0]) % p; return (x, (l * (P[0] - x) - P[1]) % p)
R, Q = None, (Gx, Gy)
while n:
    if n & 1: R = add(R, Q)
    Q = add(Q, Q); n >>= 1
h = hashlib.new("ripemd160", hashlib.sha256(bytes([2 + (R[1] & 1)]) + R[0].to_bytes(32, "big")).digest()).digest()
b = bytes([v]) + h; b += hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; x = int.from_bytes(b, "big"); s = ""
while x: x, r = divmod(x, 58); s = A[r] + s
def pm(vals):
    c = 1
    for d in vals:
        c0 = c >> 35; c = ((c & 0x07ffffffff) << 5) ^ d
        for i, g in enumerate([0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]):
            if c0 >> i & 1: c ^= g
    return c ^ 1
bits = int.from_bytes(bytes([0]) + h, "big") << 2; d = [(bits >> (5 * i)) & 31 for i in reversed(range(34))]
m = pm([ord(ch) & 31 for ch in "bitcoincash"] + [0] + d + [0] * 8); d += [(m >> 5 * (7 - i)) & 31 for i in range(8)]
print("1" * (len(b) - len(b.lstrip(b"\0"))) + s, "76a914" + h.hex() + "88ac", "".join("qpzry9x8gf2tvdw0s3jn54khce6mua7l"[i] for i in d))
PY
}
jf() { python3 -c 'import sys,json; d=json.load(sys.stdin); [d:=d[int(k)] if isinstance(d,list) else d[k] for k in sys.argv[1:]]; print(d if not isinstance(d,(dict,list)) else json.dumps(d))' "$@"; }
hexs() { printf %s "$1" | od -An -v -tx1 | tr -d ' \n'; }
mine() { $C generatetoaddress 1 "$($C getnewaddress)" >/dev/null 2>&1 || $C generate 1 >/dev/null; }
send_one() { # tag amount memo
  tag=$1; amt=$2; memo=$3; mh=$(hexs "$memo")
  fund=$($C sendtoaddress "$R1" 100) || f "$c: fund"; mine
  prev=$($C getrawtransaction "$fund") || f "$c: getrawtransaction"
  vout=$($C getrawtransaction "$fund" 1 | python3 -c 'import sys,json; print([o["n"] for o in json.load(sys.stdin)["vout"] if o["scriptPubKey"]["hex"]==sys.argv[1]][0])' "$S1")
  printf '{"txid":"%s","vout":%s,"amount":10000000000,"address":"%s","prev_tx":"%s"}\n' "$fund" "$vout" "$A1" "$prev" > "$W/u.$c.$tag"
  "$MS" $c "$W/u.$c.$tag" "$V" "$amt" "$A1" "$RATE" "$mh" > "$W/s.$c.$tag" || { cat "$W/s.$c.$tag"; f "$c $tag: build/sign"; }
  psbt=$(jf psbt < "$W/s.$c.$tag"); raw=$(jf raw < "$W/s.$c.$tag")
  printf '{"op":"verify_thor_send","chain":"%s","tx":"%s","vault":"%s","memo":"%s","amount":"%s","change":"%s","taker":"%s"}' $c "$psbt" "$V" "$memo" "$amt" "$A1" "$A1" > "$W/e.$c.$tag"
  "$B/tx-envelope" --json "$(cat "$W/e.$c.$tag")" > "$W/v.$c.$tag" || true  # allow-true: result checked next
  grep -q '"ok":true' "$W/v.$c.$tag" || { cat "$W/v.$c.$tag"; f "$c $tag: verify_thor_send refused the honest PSBT"; }
  bad=$(printf %s "$memo" | tr 'T' 't')
  sed "s|\"memo\":\"$memo\"|\"memo\":\"$bad\"|" "$W/e.$c.$tag" > "$W/eb.$c.$tag"
  "$B/tx-envelope" --json "$(cat "$W/eb.$c.$tag")" > "$W/vb.$c.$tag" || true  # allow-true: result checked next
  python3 -c 'import json,sys; d=json.loads(open(sys.argv[1]).readline()); d=d.get("result",d); assert d["ok"] is False and "memo" in d["failures"]' "$W/vb.$c.$tag" || { cat "$W/vb.$c.$tag"; f "$c $tag: memo case change not refused with reason memo"; }
  if [ $tag = limits ]; then
    for o in dust:$ndust memo; do
      "$MS" $c "$W/u.$c.$tag" "$V" "$amt" "$A1" "$RATE" "$mh" $o > "$W/n.$c.${o%%:*}" || { cat "$W/n.$c.${o%%:*}"; f "$c: probe $o build"; }
      if $C sendrawtransaction "$(jf raw < "$W/n.$c.${o%%:*}")" > "$W/ne.$c.${o%%:*}" 2>&1; then f "$c: node ACCEPTED probe $o (builder limit below node limit)"; fi
      case $o in dust:*) want=dust;; memo) want='scriptpubkey|oversize-op-return';; esac
      grep -Eq "$want" "$W/ne.$c.${o%%:*}" || f "$c: probe $o refused for another reason: $(cat "$W/ne.$c.${o%%:*}")"
    done
    echo "ok   memo-regtest $c probes: vault $((ndust - 1)) rejected (dust), memo $(( ${#memo} + 1 )) B rejected"
  fi
  txid=$($C sendrawtransaction "$raw" 2>"$W/err.$c.$tag") || f "$c $tag: node refused: $(cat "$W/err.$c.$tag")"
  mine
  $C getrawtransaction "$txid" 1 > "$W/t.$c.$tag" || f "$c $tag: getrawtransaction"
  python3 - "$W/t.$c.$tag" "$S2" "$amt" "$S1" "$mh" <<'PY' || f "$c $tag: on-chain shape"
import json, sys
t = json.load(open(sys.argv[1])); s2, amt, s1, mh = sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
assert t["confirmations"] >= 1, "not mined"
o = t["vout"]; assert len(o) == 3, f"{len(o)} outputs"
assert o[0]["scriptPubKey"]["hex"] == s2 and round(float(o[0]["value"]) * 1e8) == amt, "vault output"
assert o[1]["scriptPubKey"]["hex"] == s1, "change output"
n = len(mh) // 2; push = ("%02x" % n) if n <= 75 else ("4c%02x" % n)
assert o[2]["scriptPubKey"]["hex"] == "6a" + push + mh and round(float(o[2]["value"]) * 1e8) == 0, "OP_RETURN != memo bytes"
assert all(i["sequence"] == 0xffffffff for i in t["vin"]), "RBF-signalling input"
PY
  echo "ok   memo-regtest $c $tag: amount $amt, memo ${#memo} B accepted by the node, mined, [vault, change, OP_RETURN] verified on chain ($txid)"
}
run_chain() { # chain url sha dir daemon cli rate
  RATE=$7; c=$1; url=$2; sha=$3; dir=$4; tgz=${url##*/}
  if [ ! -x "$CACHE/$dir/bin/$5" ]; then
    [ -f "$CACHE/$tgz" ] || { curl -fsSL -o "$CACHE/$tgz.part" "$url" && mv "$CACHE/$tgz.part" "$CACHE/$tgz"; } || skip "cannot download $tgz"
    echo "$sha  $CACHE/$tgz" | sha256sum -c --quiet - || { rm -f "$CACHE/$tgz"; f "$c: $tgz sha256 mismatch"; }
    tar xzf "$CACHE/$tgz" -C "$CACHE"
  fi
  D="$W/$c"; mkdir -p "$D"; port=$((19800 + $(printf %s "$c" | cksum | cut -c1-3) % 100))
  printf 'regtest=1\nserver=1\ntxindex=1\nlisten=0\nrpcport=%s\nrpcallowip=127.0.0.1\n[regtest]\nrpcport=%s\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n' $port $port > "$D/conf"
  [ $c != bch ] || echo expire=0 >> "$D/conf"
  C="$CACHE/$dir/bin/$6 -conf=$D/conf -datadir=$D"
  "$CACHE/$dir/bin/$5" -conf="$D/conf" -datadir="$D" -pid="$D/node.pid" -acceptnonstdtxn=0 -daemon >/dev/null || f "$c: $5 did not start"
  STOP="$C stop || kill \$(cat $D/node.pid)"
  i=0; until $C getblockcount >/dev/null 2>&1; do i=$((i + 1)); [ $i -lt 900 ] || f "$c: node RPC not up"; sleep 1; done
  $C getwalletinfo >/dev/null 2>&1 || $C createwallet w >/dev/null || f "$c: createwallet"
  $C generatetoaddress 110 "$($C getnewaddress)" >/dev/null 2>&1 || $C generate 110 >/dev/null || f "$c: mining"
  ver=$("$Bab/chain-table" | python3 -c 'import sys,json; [print(int(d["p2pkh"])) for d in map(json.loads,sys.stdin) if d["name"]==sys.argv[1]]' $c)
  set -- $(addr 1 "$ver"); A1=$1; S1=$2; set -- $(addr 1 111); R1=$1
  if ck=$($C getdescriptorinfo "raw($S1)" 2>/dev/null | jf checksum 2>/dev/null); then R1=$($C deriveaddresses "raw($S1)#$ck" | jf 0); fi
  set -- $(addr 2 "$ver"); V=$1; S2=$2; [ $c != bch ] || V=$3
  case $c in ltc) dust=5460 lim=80;; doge) dust=1000000 lim=80;; bch) dust=546 lim=220;; esac
  ndust=$dust; case $c in doge) ndust=100000;; esac  # node relay dust; the builder keeps the 1 DOGE wallet floor (1000000)
  send_one swap 100000000 "=:THOR.RUNE:thor1g98cy3n9mmjrpn0sxmn63lztelera37n8n67c0:0/1/0"
  send_one limits $dust "$(python3 -c 'import sys; m="=:THOR.RUNE:thor1g98cy3n9mmjrpn0sxmn63lztelera37n8n67c0:"; print(m + "0" * (int(sys.argv[1]) - len(m)))' $lim)"
  pid=$(cat "$D/node.pid"); $C stop >/dev/null || f "$c: stop"; STOP=true
  i=0; while kill -0 "$pid" 2>/dev/null; do i=$((i + 1)); [ $i -lt 60 ] || f "$c: node did not shut down"; sleep 1; done
}
STOP=true; trap 'sh -c "$STOP" >/dev/null 2>&1 || true' EXIT  # allow-true: best-effort node stop
for c in ${MEMO_CHAINS:-ltc doge bch}; do
  set -- $(cat scripts/fork-pins/$c); run_chain "$@"
done
