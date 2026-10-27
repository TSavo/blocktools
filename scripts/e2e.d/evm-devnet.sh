#!/bin/sh
# EVM build -> verify -> sign (pty) -> broadcast against a REAL EVM-executing node (geth --dev, not a mock), issue #9.
# geth is pinned by version + sha256 in scripts/evm-pins/geth (tarball PGP-verified against the "Go Ethereum Linux
# Builder" key FDE5A1A0..9BA28146 when pinned); a mismatch fails, never runs. Two gas schedules, one throwaway devnet
# each: dev-default (geth --dev dumpgenesis as shipped: osakaTime 0, bogotaTime 0, no amsterdamTime) and amsterdam (amsterdamTime 0, the schedule Sepolia runs). Per schedule, with
# throwaway key 1 funded in genesis: CREATE the recipe's 42-contract with gas = the node's eth_estimateGas -> status 0x1,
# eth_getCode == runtime, contract-call reads 42; a store contract created and setValue(7) called (gas = estimate)
# -> status 0x1, contract-call reads 7; a plain value transfer -> status 0x1 and key 2 holds the amount;
# negative: the same CREATE with gas = estimate minus max(5%, 2000) -> mined with status 0x0 and no code. Amsterdam also replays the
# Sepolia failure: --gas 100000 -> status 0x0 (gasUsed == limit).
# Receipts are read with eth_getBlockReceipts(latest) (--dev mines one block per tx; the tx index lags at startup).
# Prerequisite missing (network): skip, or fail with BLOCKTOOLS_REQUIRE_FIXTURES=1 or in CI (CI=true; Linux x86_64).
set -eu
B=${BIN:-${B:-target/release}}; Bab=$(cd "$B" && pwd)
T=${T:-$(mktemp -d)}; W="$T/evm-devnet"; mkdir -p "$W"
CACHE=${BLOCKTOOLS_RECOVERY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/blocktools-recovery}; mkdir -p "$CACHE"
f() { echo "FAIL evm-devnet $1"; exit 1; }
skip() { if [ "${BLOCKTOOLS_REQUIRE_FIXTURES:-}" = 1 ] || [ "${CI:-}" = true ]; then f "$1"; fi; echo "skip evm-devnet ($1)"; exit 0; }
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo "SKIP evm-devnet: geth pinned for Linux x86_64 only (this host: $(uname -s)-$(uname -m)); not measured here"; exit 0; }
[ -s scripts/evm-pins/geth ] || f "pin scripts/evm-pins/geth missing"
read -r _ url sha dir bin < scripts/evm-pins/geth; tgz=${url##*/}
if [ ! -x "$CACHE/$dir/$bin" ]; then
  [ -f "$CACHE/$tgz" ] || { curl -fsSL -o "$CACHE/$tgz.part" "$url" && mv "$CACHE/$tgz.part" "$CACHE/$tgz"; } || skip "cannot download $tgz"
  echo "$sha  $CACHE/$tgz" | sha256sum -c --quiet - || { rm -f "$CACHE/$tgz"; f "$tgz sha256 mismatch"; }
  tar xzf "$CACHE/$tgz" -C "$CACHE"
fi
GETH="$CACHE/$dir/$bin"
jf() { python3 -c 'import sys,json; d=json.load(sys.stdin); [d:=d[k] for k in sys.argv[1:]]; print(d)' "$@"; }
echo 0000000000000000000000000000000000000000000000000000000000000001 > "$W/k"
K1=0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf; K2=0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF
R42=602a60005260206000f3; I42=600a600c600039600a6000f3$R42
# store contract (handwritten, no compiler): 36-byte calldata (setValue(uint256)) -> SSTORE slot0 = word; else return slot0
RS=36600414600e57600435600055005b60005460005260206000f3; IS=601a600c600039601a6000f3$RS
PIDS=; trap 'for p in $PIDS; do kill $p 2>/dev/null || true; done; rm -rf "$T"' EXIT  # allow-true: node may have exited
run() { # schedule port
  S=$1; P=$2; D="$W/$S"; U=http://127.0.0.1:$P; mkdir -p "$D"
  "$GETH" --dev dumpgenesis 2>/dev/null | python3 -c 'import json,sys
g=json.load(sys.stdin); g["alloc"]["7E5F4552091A69125d5DfCb7b8C2659029395Bdf"]={"balance":hex(10**21)}
if sys.argv[1]=="amsterdam": g["config"]["amsterdamTime"]=0
json.dump(g,open(sys.argv[2],"w"))' "$S" "$D/genesis.json"
  "$GETH" --datadir "$D/dd" init "$D/genesis.json" >/dev/null 2>&1 || f "$S: geth init"
  "$GETH" --dev --datadir "$D/dd" --http --http.addr 127.0.0.1 --http.port $P --nodiscover --maxpeers 0 --verbosity 1 > "$D/log" 2>&1 & PIDS="$PIDS $!"
  i=0; until "$B/rpc" $U chainid >/dev/null 2>&1; do i=$((i + 1)); [ $i -lt 120 ] || f "$S: node RPC not up"; sleep 0.5; done
  CID=$("$B/rpc" $U eth_chainId '[]' | python3 -c 'import sys,json;print(int(json.load(sys.stdin)["result"],16))')
  est() { "$B/rpc" $U eth_estimateGas "[$1]" | python3 -c 'import sys,json;print(int(json.load(sys.stdin)["result"],16))'; }
  send() { # unsigned-file verify-args... : verify, sign (pty), broadcast (pty); prints txid; waits for receipt to $D/rc
    u=$1; shift; "$B/tx-verify" --chain-id $CID "$@" < "$u" > "$D/v" || f "$S: tx-verify $(cat "$D/v")"
    python3 scripts/e2e-only/tty-drive.py right "$W/k" "$D/s" "$Bab/tx-sign" --tx "$u" --chain-id $CID "$@" > "$D/tty"
    grep -q '"status":"ok"' "$D/s" || f "$S: tx-sign"
    id=$("$B/tx-decode" < "$D/s" | python3 -c 'import json,sys;print([json.loads(l) for l in sys.stdin if "txid" in l][0]["txid"])')
    python3 scripts/e2e-only/tty-drive.py right "$D/s" "$D/o" "$Bab/tx-broadcast" --chain eth --url $U >/dev/null
    grep -q '"status":"ok"' "$D/o" || f "$S: tx-broadcast $(cat "$D/o")"
    i=0; until "$B/rpc" $U eth_getBlockReceipts '["latest"]' 2>/dev/null | python3 -c 'import sys,json;r=[x for x in json.load(sys.stdin)["result"] or [] if x["transactionHash"]==sys.argv[1]];assert r;print(json.dumps(r[0]))' "$id" > "$D/rc" 2>/dev/null; do
      i=$((i + 1)); [ $i -lt 60 ] || f "$S: no receipt for $id"; sleep 0.5; done
  }
  acct() { "$B/rpc" --protocol evm $U account $K1 > "$D/acct"; }
  rcst() { jf status < "$D/rc"; }
  code() { "$B/rpc" $U eth_getCode "[\"$1\",\"latest\"]" | jf result; }
  caddr() { acct; N=$(jf nonce < "$D/acct"); "$B/create-address" --deployer $K1 --nonce $N | jf address; }
  create() { # initcode gas -> builds, sends; sets A
    A=$(caddr); "$B/tx-build" --chain eth --chain-id $CID --account "$D/acct" --gas $2 --create $1 > "$D/u"
    send "$D/u" --create-hash $(jf initcode_keccak256 < "$D/u")
  }
  G=$(est "{\"from\":\"$K1\",\"data\":\"0x$I42\"}")
  create $I42 $G; [ "$(rcst)" = 0x1 ] || f "$S: create with estimate $G status $(rcst)"
  [ "$(code $A)" = 0x$R42 ] || f "$S: code at $A"
  "$B/contract-call" $U $A 'value() returns (uint256)' > "$D/cc"; grep -q '"42"' "$D/cc" || f "$S: contract-call $(cat "$D/cc")"
  echo "ok   $S: CREATE gas=eth_estimateGas $G -> status 0x1, code == runtime at $A, contract-call reads 42"
  GL=$((G - (G / 20 > 2000 ? G / 20 : 2000))); create $I42 $GL; [ "$(rcst)" = 0x0 ] && [ "$(code $A)" = 0x ] || f "$S: create below estimate not status 0"
  echo "ok   $S: same CREATE gas=$GL (estimate minus max(5%, 2000); geth estimates within a 1.5% tolerance, so estimate - 1 can still succeed) -> status 0x0, gasUsed $(jf gasUsed < "$D/rc"), no code"
  if [ $S = amsterdam ]; then create $I42 100000; [ "$(rcst)" = 0x0 ] && [ "$(jf gasUsed < "$D/rc")" = 0x186a0 ] || f "$S: 100000 replay"
    echo "ok   $S: recipe's old --gas 100000 -> status 0x0, gasUsed 0x186a0 == limit (the Sepolia failure, issue #9)"; fi
  GS=$(est "{\"from\":\"$K1\",\"data\":\"0x$IS\"}"); create $IS $GS; [ "$(rcst)" = 0x1 ] || f "$S: store create"; SA=$A
  CD=$("$B/abi-encode" 'setValue(uint256)' 7 | jf data)
  GC=$(est "{\"from\":\"$K1\",\"to\":\"$SA\",\"data\":\"$CD\"}"); acct
  "$B/tx-build" --chain eth --chain-id $CID --account "$D/acct" --gas $GC --to $SA --data $CD > "$D/u"
  send "$D/u" --expect-to $SA --call 'setValue(uint256)'; [ "$(rcst)" = 0x1 ] || f "$S: setValue status $(rcst)"
  "$B/contract-call" $U $SA 'value() returns (uint256)' > "$D/cc"; grep -q '"7"' "$D/cc" || f "$S: read-back $(cat "$D/cc")"
  echo "ok   $S: setValue(7) gas=eth_estimateGas $GC -> status 0x1, gasUsed $(jf gasUsed < "$D/rc"), contract-call reads 7 (store contract gas $GS)"
  GT=$(est "{\"from\":\"$K1\",\"to\":\"$K2\",\"value\":\"0x2386f26fc10000\"}"); acct
  "$B/tx-build" --chain eth --chain-id $CID --account "$D/acct" --gas $GT --to $K2 --send 10000000000000000 > "$D/u"
  send "$D/u" --expect-to $K2; [ "$(rcst)" = 0x1 ] || f "$S: transfer status"
  [ "$("$B/rpc" $U balance $K2 | grep -o '"balance":"*[0-9]*' | grep -o '[0-9]*$')" = 10000000000000000 ] || f "$S: key 2 balance $("$B/rpc" $U balance $K2)"
  echo "ok   $S: value transfer 0.01 ETH gas=eth_estimateGas $GT -> status 0x1, key 2 balance 10^16 wei"
}
run dev-default 18645
run amsterdam 18646
