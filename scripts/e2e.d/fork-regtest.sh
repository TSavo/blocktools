#!/bin/sh
# Build -> sign -> broadcast against REAL Core-family fork nodes on throwaway regtest chains (not a mock).
# Release tarballs are pinned by version + sha256 (cross-checked against each project's published SHA256SUMS);
# a mismatch fails, never runs. Per chain: start the node, fund throwaway key 1 (P2PKH) from the node's
# coinbase, take the coin's prev tx from the node, then tx-build --sweep -> tx-verify -> tx-sign (pty) ->
# rpc sendraw (pty) to throwaway key 2. Requires: the node accepts the tx into its mempool (txid equal to
# tx-sign's), it is mined, the key-1 coin is spent (gettxout null) and key 2's output holds exactly
# amount minus the fee the node computed (fee within --fee-rate x (vsize + 4 B of signature-size estimate)). Negative: the same tx with one signature byte flipped is rejected by the node.
# FORK_CHAINS="ltc doge bch" (default all). Prerequisite missing (network): skip, or fail with
# BLOCKTOOLS_REQUIRE_FIXTURES=1 or in CI (CI=true; Linux x86_64), so a claim can never be stamped on a skip. Nothing committed; keys 1 and 2 are the public throwaway keys.
set -eu
B=${BIN:-${B:-target/release}}; Bab=$(cd "$B" && pwd)
T=${T:-$(mktemp -d)}; W="$T/fork-regtest"; mkdir -p "$W"
CACHE=${BLOCKTOOLS_RECOVERY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/blocktools-recovery}; mkdir -p "$CACHE"
f() { echo "FAIL fork-regtest $1"; exit 1; }
skip() { if [ "${BLOCKTOOLS_REQUIRE_FIXTURES:-}" = 1 ] || [ "${CI:-}" = true ]; then f "$1"; fi; echo "skip fork-regtest ($1)"; exit 0; }
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || skip "release tarballs pinned for Linux x86_64 only"
# chain tarball-url sha256 dir daemon cli fee-rate(sat/vB, >= the node's min relay) (sha256 = the project's signed SHA256SUMS line)
pins() { cat <<'P'
ltc https://download.litecoin.org/litecoin-0.21.4/linux/litecoin-0.21.4-x86_64-linux-gnu.tar.gz 857fc41091f2bae65c3bf0fd4d388fca915fc93a03f16dd2578ac3cc92898390 litecoin-0.21.4 litecoind litecoin-cli 10
doge https://github.com/dogecoin/dogecoin/releases/download/v1.14.9/dogecoin-1.14.9-x86_64-linux-gnu.tar.gz 4f227117b411a7c98622c970986e27bcfc3f547a72bef65e7d9e82989175d4f8 dogecoin-1.14.9 dogecoind dogecoin-cli 1000
bch https://download.bitcoincashnode.org/releases/28.0.1/linux/bitcoin-cash-node-28.0.1-x86_64-linux-gnu.tar.gz d69ee632147f886ca540cecdff5b1b85512612b4c005e86b09083a63c35b64fa bitcoin-cash-node-28.0.1 bitcoind bitcoin-cli 2

P
}
echo 0000000000000000000000000000000000000000000000000000000000000001 > "$W/k"
# base58check P2PKH of throwaway key N (compressed) under version byte V; prints address and script hex
addr() { python3 - "$1" "$2" <<'PY'
import hashlib, sys
n, v = int(sys.argv[1]), int(sys.argv[2])
p, Gx, Gy = 2**256 - 2**32 - 977, 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
def add(P, Q):
    if P is None: return Q
    if P[0] == Q[0] and P[1] != Q[1]: return None
    l = (3 * P[0] * P[0] * pow(2 * P[1], -1, p)) if P == Q else ((Q[1] - P[1]) * pow(Q[0] - P[0], -1, p))
    x = (l * l - P[0] - Q[0]) % p; return (x, (l * (P[0] - x) - P[1]) % p)
R, Q = None, (Gx, Gy)
while n:
    if n & 1: R = add(R, Q)
    Q = add(Q, Q); n >>= 1
pub = bytes([2 + (R[1] & 1)]) + R[0].to_bytes(32, "big")
h = hashlib.new("ripemd160", hashlib.sha256(pub).digest()).digest()
b = bytes([v]) + h; b += hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; x = int.from_bytes(b, "big"); s = ""
while x: x, r = divmod(x, 58); s = A[r] + s
print("1" * (len(b) - len(b.lstrip(b"\0"))) + s, "76a914" + h.hex() + "88ac")
PY
}
jf() { python3 -c 'import sys,json; d=json.load(sys.stdin); [d:=d[int(k)] if isinstance(d,list) else d[k] for k in sys.argv[1:]]; print(d if not isinstance(d,(dict,list)) else json.dumps(d))' "$@"; }
run_chain() { # chain url sha dir daemon cli rate
  RATE=$7; DMN=$5; c=$1; url=$2; sha=$3; dir=$4; tgz=${url##*/}
  if [ ! -x "$CACHE/$dir/bin/$5" ]; then
    [ -f "$CACHE/$tgz" ] || { curl -fsSL -o "$CACHE/$tgz.part" "$url" && mv "$CACHE/$tgz.part" "$CACHE/$tgz"; } || skip "cannot download $tgz"
    echo "$sha  $CACHE/$tgz" | sha256sum -c --quiet - || { rm -f "$CACHE/$tgz"; f "$c: $tgz sha256 mismatch"; }
    tar xzf "$CACHE/$tgz" -C "$CACHE"
  fi
  D="$W/$c"; mkdir -p "$D"; port=$((18800 + $(printf %s "$c" | cksum | cut -c1-3) % 100))
  printf 'regtest=1\nserver=1\ntxindex=1\nlisten=0\nrpcport=%s\nrpcallowip=127.0.0.1\n[regtest]\nrpcport=%s\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n' $port $port > "$D/conf"
  [ $c != bch ] || echo expire=0 >> "$D/conf"  # BCHN disables RPC on releases past their planned expiry; throwaway regtest only
  C="$CACHE/$dir/bin/$6 -conf=$D/conf -datadir=$D"
  "$CACHE/$dir/bin/$5" -conf="$D/conf" -datadir="$D" -daemon >/dev/null || f "$c: $5 did not start"
  STOP="$C stop"
  i=0; until $C getblockcount >/dev/null 2>&1; do i=$((i + 1)); [ $i -lt 90 ] || f "$c: node RPC not up"; sleep 1; done
  $C getwalletinfo >/dev/null 2>&1 || $C createwallet w >/dev/null || f "$c: createwallet"  # doge 1.14 and BCHN load a default wallet; ltc 0.21 has none
  $C generatetoaddress 101 "$($C getnewaddress)" >/dev/null 2>&1 || $C generate 101 >/dev/null || f "$c: mining"
  ver=$("$Bab/chain-table" | python3 -c 'import sys,json; [print(int(d["p2pkh"])) for d in map(json.loads,sys.stdin) if d["name"]==sys.argv[1]]' $c)
  set -- $(addr 1 "$ver"); A1=$1; S1=$2; set -- $(addr 1 111); R1=$1
  set -- $(addr 2 "$ver"); A2=$1; S2=$2
  fund=$($C sendtoaddress "$R1" 2.5) || f "$c: fund"
  $C generatetoaddress 1 "$($C getnewaddress)" >/dev/null 2>&1 || $C generate 1 >/dev/null
  prev=$($C getrawtransaction "$fund") || f "$c: getrawtransaction"
  vout=$($C getrawtransaction "$fund" 1 | python3 -c 'import sys,json; print([o["n"] for o in json.load(sys.stdin)["vout"] if o["scriptPubKey"]["hex"]==sys.argv[1]][0])' "$S1")
  printf '{"txid":"%s","vout":%s,"amount":250000000,"address":"%s","prev_tx":"%s"}\n' "$fund" "$vout" "$A1" "$prev" > "$W/u.$c"
  "$B/tx-build" --chain $c --utxos "$W/u.$c" --to "$A2" --sweep --fee-rate "$RATE" > "$W/p.$c" || { cat "$W/p.$c"; f "$c build"; }
  "$B/tx-verify" --chain $c --expect-to "$A2" < "$W/p.$c" > /dev/null || f "$c verify"
  python3 scripts/e2e-only/tty-drive.py right "$W/k" "$W/o.$c" "$Bab/tx-sign" --tx "$W/p.$c" --expect-to "$A2" > "$W/tty.$c" || { cat "$W/tty.$c"; f "$c sign"; }
  python3 -c 'import json,sys; print([json.loads(l) for l in open(sys.argv[1]) if "signed_tx" in l][0]["signed_tx"])' "$W/o.$c" > "$W/raw.$c"
  stxid=$($C decoderawtransaction "$(cat "$W/raw.$c")" | jf txid) || f "$c: node cannot decode the signed tx"
  # negative first: one flipped byte inside the first signature must be refused by the real node
  python3 -c 'import sys; h=open(sys.argv[1]).read().strip(); i=82+4+4+4+10; assert h[82+4:82+6]=="30"; print(h[:i]+("0" if h[i]!="0" else "1")+h[i+1:])' "$W/raw.$c" > "$W/bad.$c" || f "$c: corrupt"  # one hex digit of r in input 0's signature
  if $C sendrawtransaction "$(cat "$W/bad.$c")" > "$W/badout.$c" 2>&1; then f "$c: node ACCEPTED a tx with a corrupted signature"; fi
  grep -q "mandatory-script-verify-flag-failed" "$W/badout.$c" || f "$c: corrupted tx refused for another reason: $(cat "$W/badout.$c")"
  cookie="$D/regtest/.cookie"; [ -f "$cookie" ] || f "$c: no rpc cookie"
  python3 scripts/e2e-only/tty-drive.py right "$W/raw.$c" "$W/b.$c" "$Bab/rpc" --protocol btc --chain $c --auth-file "$cookie" "http://127.0.0.1:$port" sendraw > "$W/btty.$c" || { cat "$W/btty.$c" "$W/b.$c"; f "$c sendraw"; }
  grep -q '"status":"ok"' "$W/b.$c" && grep -q "$stxid" "$W/b.$c" || { cat "$W/b.$c"; f "$c: sendraw status/txid"; }
  $C getmempoolentry "$stxid" > "$W/me.$c" || f "$c: tx not in the node's mempool"
  set -- $(python3 -c 'import sys,json; e=json.load(open(sys.argv[1])); print(round(float(e["fees"]["base"] if "fees" in e else e["fee"])*1e8), e.get("vsize") or e["size"])' "$W/me.$c"); fee=$1; vs=$2
  [ "$fee" -gt 0 ] && [ "$fee" -le $(($RATE * (vs + 4))) ] || f "$c: node-reported fee $fee sat for $vs vB at --fee-rate $RATE"
  $C generatetoaddress 1 "$($C getnewaddress)" >/dev/null 2>&1 || $C generate 1 >/dev/null
  conf=$($C getrawtransaction "$stxid" 1 | jf confirmations); [ "$conf" -ge 1 ] || f "$c: not mined"
  [ -z "$($C gettxout "$fund" "$vout")" ] || f "$c: key-1 coin still unspent"
  got=$($C getrawtransaction "$stxid" 1 | python3 -c 'import sys,json; o=[o for o in json.load(sys.stdin)["vout"] if o["scriptPubKey"]["hex"]==sys.argv[1]]; print(round(float(o[0]["value"])*1e8) if len(o)==1 else -1)' "$S2")
  [ "$got" = $((250000000 - fee)) ] || f "$c: key-2 output $got sat, want $((250000000 - fee))"
  pid=$(cat "$D/regtest/$DMN.pid"); $C stop >/dev/null || f "$c: stop"; STOP=true
  i=0; while kill -0 "$pid" 2>/dev/null; do i=$((i + 1)); [ $i -lt 60 ] || f "$c: node did not shut down"; sleep 1; done
  echo "ok   fork-regtest $c ($dir): tx-build -> tx-verify -> tx-sign (pty) -> rpc sendraw (pty) accepted by the real node, mined, key-1 coin spent, key 2 holds $got sat (node fee $fee sat, $vs vB); corrupted signature rejected"
}
STOP=true; trap 'sh -c "$STOP" >/dev/null 2>&1 || true' EXIT  # allow-true: best-effort node stop
pins > "$W/pins"
while read -r c url sha dir d cli rate; do
  case " ${FORK_CHAINS:-ltc doge bch} " in *" $c "*) run_chain "$c" "$url" "$sha" "$dir" "$d" "$cli" "$rate";; esac
done < "$W/pins"
