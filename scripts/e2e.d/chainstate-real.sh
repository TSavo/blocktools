# utxo-set --chainstate against the chainstate/ LevelDB written by REAL nodes (sha256-pinned tarballs) on
# throwaway regtest chains built at test time; nothing committed. Per chain: mine, fund the compressed and
# uncompressed P2PKH of the public test brainwallet "correct horse battery staple", pay a 20-output tx
# (vout >= 2: the old per-tx layout's mask bytes), record the node's gettxoutsetinfo, STOP the node, then
# require: the chainstate files are byte-identical after reading (read-only), coins/total/best block equal
# the node's txouts/total_amount/bestblock, the funded scripts at the exact amounts, a never-funded
# phrase's scripts empty, the expected record layout seen, and wallet-finder --dump on the --write-dump
# file finds the phrase in free text (2 hits) and nothing without it. btc: Bitcoin Core 25.2 ('C'
# per-output layout; also its own dumptxoutset coin count); ltc: Litecoin 0.21.4 ('C'); doge: Dogecoin
# 1.14.9 ('c' per-tx layout). CHAINSTATE_CHAINS="btc ltc doge" (default all). Prerequisite missing
# (network): skip, or fail with BLOCKTOOLS_REQUIRE_FIXTURES=1 or in CI.
set -eu
B=${BIN:-${B:-target/release}}; Bab=$(cd "$B" && pwd)
T=${T:-$(mktemp -d)}; W="$T/chainstate-real"; mkdir -p "$W"
CACHE=${BLOCKTOOLS_RECOVERY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/blocktools-recovery}; mkdir -p "$CACHE"
f() { echo "FAIL chainstate-real $1"; exit 1; }
skip() { if [ "${BLOCKTOOLS_REQUIRE_FIXTURES:-}" = 1 ] || [ "${CI:-}" = true ]; then f "$1"; fi; echo "skip chainstate-real ($1)"; exit 0; }
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || { echo "SKIP chainstate-real: node tarballs pinned for Linux x86_64 only (this host: $(uname -s)-$(uname -m)); not measured here"; exit 0; }
J() { python3 -c "import sys,json; [print(*(json.loads(l).get(k) for k in sys.argv[1:])) for l in sys.stdin if l.strip()]" "$@"; }
Jd() { python3 -c "import sys,json; d=json.load(sys.stdin); print(d[sys.argv[1]])" "$1"; }
# regtest (version 111) address and script for each p2pkh shape of a phrase
shapes() { printf '%s\n' "$1" | "$B/phrase-to-key" | "$B/key-to-addresses" --chain btc | J kind address | grep -E '^p2pkh(-uncompressed)? ' | python3 -c '
import sys, hashlib
A = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
for l in sys.stdin:
    k, a = l.split(); n = 0
    for ch in a: n = n * 58 + A.index(ch)
    h = n.to_bytes(25, "big")[1:21]; b = bytes([111]) + h; b += hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
    x = int.from_bytes(b, "big"); s = ""
    while x: x, r = divmod(x, 58); s = A[r] + s
    print(k, s, "76a914" + h.hex() + "88ac")'; }
shapes "correct horse battery staple" > "$W/hit"; shapes "this phrase was never funded on this chain" > "$W/miss"
[ "$(wc -l < "$W/hit")" -eq 2 ] || f "expected 2 p2pkh shapes, got $(cat "$W/hit")"
fetch() { # url sha dir daemon
  tgz=${1##*/}
  if [ ! -x "$CACHE/$3/bin/$4" ]; then
    [ -f "$CACHE/$tgz" ] || { curl -fsSL -o "$CACHE/$tgz.part" "$1" && mv "$CACHE/$tgz.part" "$CACHE/$tgz"; } || skip "cannot download $tgz"
    echo "$2  $CACHE/$tgz" | sha256sum -c --quiet - || { rm -f "$CACHE/$tgz"; f "$tgz sha256 mismatch"; }
    tar xzf "$CACHE/$tgz" -C "$CACHE"
  fi
}
STOP=true; trap 'sh -c "$STOP" >/dev/null 2>&1 || true' EXIT  # allow-true: best-effort node stop
run() { # chain dir daemon cli port layout
  c=$1; L=$6; D="$W/$c"; mkdir -p "$D"; BD="$CACHE/$2/bin"
  printf 'regtest=1\nserver=1\nlisten=0\nfallbackfee=0.001\n[regtest]\nrpcport=%s\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n' $5 > "$D/conf"
  [ $c != doge ] || printf 'rpcport=%s\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\n' $5 >> "$D/conf"  # dogecoin 1.14 reads no [regtest] section
  C="$BD/$4 -conf=$D/conf -datadir=$D"
  start() {
    "$BD/$3" -conf="$D/conf" -datadir="$D" -pid="$D/node.pid" -daemon >/dev/null || f "$c: $3 did not start"
    STOP="$C stop || kill \$(cat $D/node.pid)"
    i=0; until $C getblockcount >/dev/null 2>&1; do i=$((i + 1)); [ $i -lt 300 ] || f "$c: node RPC not up"; sleep 1; done
    $C getwalletinfo >/dev/null 2>&1 || $C loadwallet w >/dev/null 2>&1 || $C createwallet w >/dev/null || f "$c: wallet"
  }
  start "$@"
  gen() { $C generatetoaddress "$1" "$($C getnewaddress)" >/dev/null 2>&1 || $C generate "$1" >/dev/null || f "$c: mining"; }
  gen 101
  : > "$W/want.$c"; n=0
  while read -r _ a s; do n=$((n + 1)); $C sendtoaddress "$a" "$n.25" >/dev/null || f "$c: fund $a"; echo "$s funded $((n * 100000000 + 25000000)) 1" >> "$W/want.$c"; done < "$W/hit"
  many() { i=0; printf '{'; while [ $i -lt 20 ]; do [ $i = 0 ] || printf ,; printf '"%s":1' "$($C getnewaddress)"; i=$((i + 1)); done; printf '}'; }
  $C sendmany "" "$(many)" >/dev/null || f "$c: sendmany"
  gen 1
  # CHAINSTATE_BULK_TXS=K (doge only): K more txs of 2000 one-DOGE outputs to random regtest P2PKH
  # addresses, for the throughput/RAM measurement (scripts/chainstate-bench.sh)
  k=0; while [ $c = doge ] && [ $k -lt "${CHAINSTATE_BULK_TXS:-0}" ]; do
    $C sendmany "" "$(python3 -c 'import os,hashlib,json
A="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def a():
    b=bytes([111])+os.urandom(20); b+=hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]; x=int.from_bytes(b,"big"); s=""
    while x: x,r=divmod(x,58); s=A[r]+s
    return s
print(json.dumps({a():1 for _ in range(2000)}))')" >/dev/null || f "$c: bulk sendmany $k"
    k=$((k + 1)); [ $((k % 10)) != 0 ] || gen 1
  done
  [ "${CHAINSTATE_BULK_TXS:-0}" = 0 ] || gen 1
  stop_read 1
  # restart: LevelDB turns the log into a table on open; then spend wallet coins held in that table, so
  # the new log's deletions and rewrites must shadow table entries
  start "$@"; $C sendmany "" "$(many)" >/dev/null || f "$c: sendmany 2"; gen 1
  stop_read 2
  [ "$tf" -gt 0 ] && [ "$lf" -gt 0 ] || f "$c: pass 2 read $tf tables + $lf logs; want both"
}
stop_read() { # pass
  P=$1
  $C gettxoutsetinfo > "$W/info.$c" || f "$c: gettxoutsetinfo"
  if [ $c != doge ]; then rm -f "$W/d.$c"; $C dumptxoutset "$W/d.$c" | Jd coins_written > "$W/written.$c"; fi
  CS="$D/regtest/chainstate"
  set +e; "$B/chainstate-dump" --chain $c --census "$CS" > /dev/null 2> "$W/lock.$c"; rc=$?; set -e
  [ $rc = 2 ] && grep -q chainstate_locked "$W/lock.$c" || f "$c: chainstate-dump on the live node's dir: rc=$rc $(cat "$W/lock.$c")"
  pid=$(cat "$D/node.pid"); $C stop >/dev/null || f "$c: stop"; STOP=true
  i=0; while kill -0 "$pid" 2>/dev/null; do i=$((i + 1)); [ $i -lt 120 ] || f "$c: node did not exit"; sleep 1; done
  [ -f "$CS/CURRENT" ] || f "$c: no chainstate at $CS"
  (cd "$CS" && sha256sum $(ls | grep -vx LOCK) ) > "$W/before.$c"
  cut -d' ' -f3 "$W/hit" | "$B/utxo-set" --chainstate "$CS" --write-dump "$W/w.$c.$P" 2> "$W/ingest.$c" | J script status value_sat outputs > "$W/got.$c" || f "$c: utxo-set --chainstate: $(cat "$W/ingest.$c")"
  (cd "$CS" && sha256sum $(ls | grep -vx LOCK) ) | cmp -s - "$W/before.$c" || f "$c: chainstate files changed by reading"
  set -- $(J coins total_sat base_blockhash per_output_keys per_tx_keys obfuscated dump_written ingest_secs peak_rss_bytes table_files log_files < "$W/ingest.$c")
  coins=$1 total=$2 best=$3 po=$4 pt=$5 obf=$6 wr=$7 secs=$8 rss=$9; shift 9; tf=$1 lf=$2
  set -- $(python3 -c 'import sys,json; d=json.load(open(sys.argv[1])); print(d["txouts"], round(float(d["total_amount"])*1e8), d["bestblock"])' "$W/info.$c")
  [ "$coins" = "$1" ] && [ "$wr" = "$1" ] || f "$c: read $coins coins (wrote $wr), node txouts $1"
  [ "$total" = "$2" ] || f "$c: total $total sat, node total_amount $2 sat"
  [ "$best" = "$3" ] || f "$c: best block $best, node $3"
  [ $c = doge ] || [ "$(cat "$W/written.$c")" = "$coins" ] || f "$c: Core dumptxoutset wrote $(cat "$W/written.$c"), chainstate read $coins"
  case $L in C) [ "$po" -gt 0 ] && [ "$pt" = 0 ] || f "$c: want per-output 'C' layout, saw C=$po c=$pt";; c) [ "$pt" -gt 0 ] && [ "$po" = 0 ] || f "$c: want per-tx 'c' layout, saw C=$po c=$pt";; esac
  [ "$obf" = True ] || f "$c: chainstate not obfuscated (expected a non-zero obfuscate_key)"
  while read -r l; do grep -qx "$l" "$W/got.$c" || f "$c: want '$l', got: $(cat "$W/got.$c")"; done < "$W/want.$c"
  cut -d' ' -f3 "$W/miss" | "$B/utxo-set" --chainstate "$CS" 2>/dev/null | J status > "$W/m.$c"
  [ "$(grep -c '^empty$' "$W/m.$c")" -eq 2 ] || f "$c: never-funded scripts reported funded: $(cat "$W/m.$c")"
  # the standalone tool: JSON lines digested by the independent Python decoder (scripts/utxo-multiset.py)
  # against Core's own dumptxoutset (btc, ltc) or against utxo-set's --write-dump (doge: no dumptxoutset)
  if [ $c != doge ]; then BIN=$B sh scripts/chainstate-vs-dump.sh "$CS" "$W/d.$c" $c > "$W/vs.$c" || f "$c: $(cat "$W/vs.$c")"; tail -1 "$W/vs.$c"
  else "$B/chainstate-dump" --chain $c "$CS" 2>/dev/null | python3 scripts/utxo-multiset.py jsonl > "$W/da.$c"; python3 scripts/utxo-multiset.py dump "$W/w.$c.$P" > "$W/db.$c"
    python3 -c 'import json,sys; a,b=(json.load(open(p)) for p in sys.argv[1:]); sys.exit(0 if all(a[k]==b[k] for k in ("coins","total","full","script_amount")) else 1)' "$W/da.$c" "$W/db.$c" || f "$c: chainstate-dump $(cat "$W/da.$c") != write-dump $(cat "$W/db.$c")"; fi
  if [ $c = doge ]; then  # pre-0.15 GetUTXOStats equivalents against the node's own gettxoutsetinfo
    "$B/chainstate-dump" --chain $c --census --hash-serialized "$CS" 2>/dev/null > "$W/hs.$c" || f "$c: --hash-serialized failed"
    python3 -c 'import json,sys; a=json.load(open(sys.argv[1])); n=json.load(open(sys.argv[2])); h=n.get("hash_serialized_2", n.get("hash_serialized")); ok=a["hash_serialized"]==h and a["bytes_serialized"]==n["bytes_serialized"] and a["transactions"]==n["transactions"]; print(("ok   chainstate-real %s pass %s hash_serialized: %s = node, bytes_serialized %s = node, %s txs" % (sys.argv[3], sys.argv[4], h, n["bytes_serialized"], n["transactions"])) if ok else "FAIL chainstate-real %s: hash_serialized/bytes/txs %s %s %s, node %s %s %s" % (sys.argv[3], a["hash_serialized"], a["bytes_serialized"], a["transactions"], h, n["bytes_serialized"], n["transactions"])); sys.exit(0 if ok else 1)' "$W/hs.$c" "$W/info.$c" $c $P || exit 1
  fi
  "$B/chainstate-dump" --chain $c --census "$CS" 2>/dev/null > "$W/cen.$c"; [ "$(J coins < "$W/cen.$c")" = "$coins" ] || f "$c: --census $(cat "$W/cen.$c")"
  "$B/chainstate-dump" --chain $c --addresses-only "$CS" 2>/dev/null | wc -l | tr -d ' ' > "$W/ac.$c"; [ "$(cat "$W/ac.$c")" = "$coins" ] || f "$c: --addresses-only gave $(cat "$W/ac.$c") lines"
  other=$([ $L = C ] && echo c || echo C)
  for bad in "--obfuscate-key none" "--era $other"; do
    set +e; "$B/chainstate-dump" --chain $c $bad "$CS" > /dev/null 2> "$W/bad.$c"; rc=$?; set -e
    [ $rc = 2 ] || f "$c: chainstate-dump $bad: rc=$rc (want 2, loud failure): $(tail -1 "$W/bad.$c")"
  done
  echo "ok   chainstate-real $c pass $P chainstate-dump: set = $([ $c = doge ] && echo "utxo-set --write-dump" || echo "Core dumptxoutset") (full + scriptPubKey/amount digests); --census, --addresses-only; live dir refused; --obfuscate-key none and --era $other fail rc 2"
  echo "ok   chainstate-real $c pass $P: $coins coins ($L layout, obfuscated, $tf tables + $lf logs) = node txouts/total/bestblock; funded p2pkh shapes exact, never-funded empty; files unchanged; ${secs}s, peak_rss $rss B"
  printf 'Shopping list. Milk!\nMy old note: correct horse battery staple. Do not lose it\n' > "$W/notes"
  set +e; "$B/wallet-finder" --dump "$W/w.$c.$P" < "$W/notes" > "$W/found.$c" 2> "$W/fsum.$c"; rc=$?; set -e
  [ $rc = 0 ] || f "$c: wallet-finder rc=$rc: $(cat "$W/fsum.$c")"
  [ "$(J passphrase < "$W/found.$c" | sort -u)" = "correct horse battery staple" ] && [ "$(J kind < "$W/found.$c" | sort | tr '\n' ' ')" = "p2pkh p2pkh-uncompressed " ] || f "$c: hits: $(cat "$W/found.$c")"
  printf 'Shopping list. Milk!\nNothing else here\n' | { set +e; "$B/wallet-finder" --dump "$W/w.$c.$P" > "$W/none.$c" 2>/dev/null; echo $? > "$W/nrc.$c"; }
  [ "$(cat "$W/nrc.$c")" = 1 ] && [ ! -s "$W/none.$c" ] || f "$c: wallet-finder without the phrase: rc=$(cat "$W/nrc.$c")"
  echo "ok   chainstate-real $c pass $P wallet-finder: phrase found (p2pkh, p2pkh-uncompressed) in the --write-dump file; none without it"
}
want() { case " ${CHAINSTATE_CHAINS:-btc ltc doge} " in *" $1 "*) return 0;; esac; return 1; }
if want btc; then fetch https://bitcoincore.org/bin/bitcoin-core-25.2/bitcoin-25.2-x86_64-linux-gnu.tar.gz 8d8c387e597e0edfc256f0bbace1dac3ad1ebf4a3c06da3e2975fda333817dea bitcoin-25.2 bitcoind; run btc bitcoin-25.2 bitcoind bitcoin-cli 18931 C; fi
for c in ltc doge; do
  want $c || continue
  set -- $(cat scripts/fork-pins/$c); fetch "$2" "$3" "$4" "$5"
  run $c "$4" "$5" "$6" $((18932 + ${#c})) $([ $c = doge ] && echo c || echo C)
done
