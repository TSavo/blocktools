# utxo-set and wallet-finder against a dumptxoutset file written by the REAL Bitcoin Core 25.2 (sha256-pinned
# tarball, as scripts/recovery-gen.sh), on a throwaway regtest chain built at test time; nothing committed.
# Funds the five address shapes of the public test brainwallet "correct horse battery staple" (one of them
# twice), mines, dumps, then requires: utxo-set reports each shape funded with the exact amount Core sent
# (the twice-funded one summed), a never-funded phrase's five addresses empty, the ingest coin count equal
# to Core's coins_written; wallet-finder finds all five from free text and finds nothing without the phrase.
# Prerequisite missing (network): skip, or fail with BLOCKTOOLS_REQUIRE_FIXTURES=1.
set -eu
B=${BIN:-${B:-target/release}}
T=${T:-$(mktemp -d)}; W="$T/utxo-real"; mkdir -p "$W"
f() { echo "FAIL utxo-real $1"; exit 1; }
CACHE=${BLOCKTOOLS_RECOVERY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/blocktools-recovery}; mkdir -p "$CACHE"
CORE=bitcoin-25.2-x86_64-linux-gnu.tar.gz; CORE_SHA=8d8c387e597e0edfc256f0bbace1dac3ad1ebf4a3c06da3e2975fda333817dea
skip() { if [ "${BLOCKTOOLS_REQUIRE_FIXTURES:-}" = 1 ]; then f "$1"; fi; echo "skip utxo-real ($1)"; exit 0; }
[ "$(uname -s)-$(uname -m)" = Linux-x86_64 ] || skip "Core 25.2 tarball pinned for Linux x86_64 only"
if [ ! -x "$CACHE/bitcoin-25.2/bin/bitcoind" ]; then
  [ -f "$CACHE/$CORE" ] || { curl -fsSL -o "$CACHE/$CORE.part" "https://bitcoincore.org/bin/bitcoin-core-25.2/$CORE" && mv "$CACHE/$CORE.part" "$CACHE/$CORE"; } || skip "cannot download $CORE"
  echo "$CORE_SHA  $CACHE/$CORE" | sha256sum -c --quiet - || { rm -f "$CACHE/$CORE"; f "$CORE sha256 mismatch"; }
  tar xzf "$CACHE/$CORE" -C "$CACHE"
fi
BD="$CACHE/bitcoin-25.2/bin"; D="$W/core"; mkdir -p "$D"
C="$BD/bitcoin-cli -regtest -datadir=$D -rpcport=18766"
"$BD/bitcoind" -regtest -datadir="$D" -rpcport=18766 -connect=0 -listen=0 -dnsseed=0 -daemon -fallbackfee=0.0001 -noprinttoconsole
trap '$C stop >/dev/null 2>&1 || true' EXIT
i=0; until $C getblockcount >/dev/null 2>&1; do i=$((i + 1)); [ $i -lt 60 ] || f "bitcoind did not start"; sleep 1; done
$C -named createwallet wallet_name=w >/dev/null
$C generatetoaddress 101 "$($C getnewaddress)" >/dev/null
J() { python3 -c "import sys,json; [print(*(json.loads(l).get(k) for k in sys.argv[1:])) for l in sys.stdin if l.strip()]" "$@"; }
Jd() { python3 -c "import sys,json; print(json.load(sys.stdin)[sys.argv[1]])" "$1"; }
addrs() { printf '%s\n' "$1" | "$B/phrase-to-key" | "$B/key-to-addresses" --chain btc | J kind address | grep -v '^None'; }
addrs "correct horse battery staple" > "$W/hit"
addrs "this phrase was never funded on this chain" > "$W/miss"
[ "$(wc -l < "$W/hit")" -eq 5 ] || f "expected five address shapes, got $(wc -l < "$W/hit")"
# scripts for the five shapes, from utxo-set itself on a dump taken before any funding (all empty)
$C dumptxoutset "$W/d0.dat" >/dev/null
cut -d' ' -f2 "$W/hit" | "$B/utxo-set" --dump "$W/d0.dat" 2>/dev/null | J status script > "$W/s0"
[ "$(grep -c '^empty ' "$W/s0")" -eq 5 ] || f "addresses funded before funding: $(cat "$W/s0")"
# fund shape n with n*0.001 + 0.00012345 BTC; the second shape (p2pkh-uncompressed) also gets 0.5 BTC
n=0; : > "$W/want"
while read -r _ s; do
  n=$((n + 1)); amt=$(printf '0.%03d12345' "$n")
  d=$($C getdescriptorinfo "raw($s)" | Jd checksum); a=$($C deriveaddresses "raw($s)#$d" | python3 -c 'import sys,json; print(json.load(sys.stdin)[0])')
  $C sendtoaddress "$a" "$amt" >/dev/null
  sat=$((n * 100000 + 12345)); outs=1
  if [ $n = 2 ]; then $C sendtoaddress "$a" 0.5 >/dev/null; sat=$((sat + 50000000)); outs=2; fi
  echo "$s $sat $outs" >> "$W/want"
done < "$W/s0"
$C generatetoaddress 1 "$($C getnewaddress)" >/dev/null
$C dumptxoutset "$W/d1.dat" | Jd coins_written > "$W/written"
cut -d' ' -f2 "$W/hit" | "$B/utxo-set" --dump "$W/d1.dat" 2> "$W/ingest" | J script status value_sat outputs > "$W/got"
[ "$(J coins < "$W/ingest")" = "$(cat "$W/written")" ] || f "ingested $(J coins < "$W/ingest") coins, Core wrote $(cat "$W/written")"
while read -r s sat outs; do grep -qx "$s funded $sat $outs" "$W/got" || f "script $s: want funded $sat sat in $outs outputs, got: $(grep "^$s " "$W/got")"; done < "$W/want"
cut -d' ' -f2 "$W/miss" | "$B/utxo-set" --dump "$W/d1.dat" 2>/dev/null | J status > "$W/m"
[ "$(grep -c '^empty$' "$W/m")" -eq 5 ] || f "never-funded phrase reported funded: $(cat "$W/m")"
echo "ok   utxo-real utxo-set: Core 25.2 dumptxoutset ($(cat "$W/written") coins) read; 5 shapes funded at Core's exact amounts (one summed over 2 outputs); 5 never-funded addresses empty"
printf 'Shopping list. Milk!\nMy old note: correct horse battery staple. Do not lose it\n' > "$W/notes"
set +e; "$B/wallet-finder" --dump "$W/d1.dat" < "$W/notes" > "$W/found" 2> "$W/fsum"; rc=$?; set -e
[ $rc = 0 ] || f "wallet-finder rc=$rc on text containing the phrase: $(cat "$W/fsum")"
[ "$(J passphrase < "$W/found" | sort -u)" = "correct horse battery staple" ] || f "wrong phrase in hits: $(cat "$W/found")"
[ "$(wc -l < "$W/found")" -eq 5 ] || f "expected 5 hits, got $(wc -l < "$W/found")"
grep -Eq 'wif|private_key|xprv|"secret' "$W/found" && f "wallet-finder output carries a key field"
J kind address < "$W/found" | sort > "$W/fk"; sort "$W/hit" | cmp -s - "$W/fk" || f "hit addresses differ from key-to-addresses"
printf 'Shopping list. Milk!\nNothing else here\n' | { set +e; "$B/wallet-finder" --dump "$W/d1.dat" > "$W/none" 2>/dev/null; echo $? > "$W/nrc"; }
[ "$(cat "$W/nrc")" = 1 ] && [ ! -s "$W/none" ] || f "wallet-finder without the phrase: rc=$(cat "$W/nrc") out=$(cat "$W/none")"
echo "ok   utxo-real wallet-finder: phrase found in free text, all 5 shapes with balances, no key fields; text without it: no hits, exit 1"
