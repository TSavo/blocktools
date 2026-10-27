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
  if [ $c = btc ]; then rm -f "$W/d.$c"; $C dumptxoutset "$W/d.$c" | Jd coins_written > "$W/written.$c"; fi
  pid=$(cat "$D/node.pid"); $C stop >/dev/null || f "$c: stop"; STOP=true
  i=0; while kill -0 "$pid" 2>/dev/null; do i=$((i + 1)); [ $i -lt 120 ] || f "$c: node did not exit"; sleep 1; done
  CS="$D/regtest/chainstate"; [ -f "$CS/CURRENT" ] || f "$c: no chainstate at $CS"
  (cd "$CS" && sha256sum $(ls | grep -vx LOCK) ) > "$W/before.$c"
  cut -d' ' -f3 "$W/hit" | "$B/utxo-set" --chainstate "$CS" --write-dump "$W/w.$c.$P" 2> "$W/ingest.$c" | J script status value_sat outputs > "$W/got.$c" || f "$c: utxo-set --chainstate: $(cat "$W/ingest.$c")"
  (cd "$CS" && sha256sum $(ls | grep -vx LOCK) ) | cmp -s - "$W/before.$c" || f "$c: chainstate files changed by reading"
  set -- $(J coins total_sat base_blockhash per_output_keys per_tx_keys obfuscated dump_written ingest_secs peak_rss_bytes table_files log_files < "$W/ingest.$c")
  coins=$1 total=$2 best=$3 po=$4 pt=$5 obf=$6 wr=$7 secs=$8 rss=$9; shift 9; tf=$1 lf=$2
  set -- $(python3 -c 'import sys,json; d=json.load(open(sys.argv[1])); print(d["txouts"], round(float(d["total_amount"])*1e8), d["bestblock"])' "$W/info.$c")
  [ "$coins" = "$1" ] && [ "$wr" = "$1" ] || f "$c: read $coins coins (wrote $wr), node txouts $1"
  [ "$total" = "$2" ] || f "$c: total $total sat, node total_amount $2 sat"
  [ "$best" = "$3" ] || f "$c: best block $best, node $3"
  [ $c != btc ] || [ "$(cat "$W/written.$c")" = "$coins" ] || f "btc: Core dumptxoutset wrote $(cat "$W/written.$c"), chainstate read $coins"
  case $L in C) [ "$po" -gt 0 ] && [ "$pt" = 0 ] || f "$c: want per-output 'C' layout, saw C=$po c=$pt";; c) [ "$pt" -gt 0 ] && [ "$po" = 0 ] || f "$c: want per-tx 'c' layout, saw C=$po c=$pt";; esac
  [ "$obf" = True ] || f "$c: chainstate not obfuscated (expected a non-zero obfuscate_key)"
  while read -r l; do grep -qx "$l" "$W/got.$c" || f "$c: want '$l', got: $(cat "$W/got.$c")"; done < "$W/want.$c"
  cut -d' ' -f3 "$W/miss" | "$B/utxo-set" --chainstate "$CS" 2>/dev/null | J status > "$W/m.$c"
  [ "$(grep -c '^empty$' "$W/m.$c")" -eq 2 ] || f "$c: never-funded scripts reported funded: $(cat "$W/m.$c")"
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
