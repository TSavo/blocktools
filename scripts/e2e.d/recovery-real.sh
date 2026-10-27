# Synthetic end-to-end recovery against wallets written by the REAL third-party software, generated at
# test time by scripts/recovery-gen.sh (Bitcoin Core 25.2, Electrum 4.5.8, eth-account 0.13.4,
# python-mnemonic 0.21): fresh throwaway keys every run, never committed. Each case damages what a user
# remembers (seed typo / swap / missing word / unknown word, or a password known only as tokens), runs our
# toolchain, and requires the address the GENERATOR printed. Not a real lost wallet.
# Prerequisites missing (network, python3 venv): skip, or fail with BLOCKTOOLS_REQUIRE_FIXTURES=1.
set -eu
B=${BIN:-${B:-target/release}}
T=${T:-$(mktemp -d)}; G="$T/recovery"; mkdir -p "$G"
f() { echo "FAIL recovery-real $1"; exit 1; }
set +e; sh scripts/recovery-gen.sh "$G" > "$T/gen.log" 2>&1; rc=$?; set -e
if [ $rc = 3 ] && [ "${BLOCKTOOLS_REQUIRE_FIXTURES:-}" != 1 ]; then echo "skip recovery-real (third-party generators unavailable; see $T/gen.log)"; exit 0; fi
[ $rc = 0 ] || { tail -5 "$T/gen.log"; f "recovery-gen rc=$rc"; }
PY="${BLOCKTOOLS_RECOVERY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/blocktools-recovery}/venv/bin/python3"

# seed <name> <scheme> <want> <seedfile> <damage> [preset]: seed-repair -> seed-to-master -> derive --match
seed() {
  s=$(date +%s)
  d=$("$PY" scripts/recovery-gen/damage.py "$5" < "$4")
  [ "$d" != "$(cat "$4")" ] || f "$1: damage did nothing"
  echo "$d" | "$B/seed-repair" --scheme "$2" --max 1000000 > "$T/cand"
  n=$(wc -l < "$T/cand"); n=$((n + 0))
  "$B/seed-to-master" < "$T/cand" | "$B/derive" --chain btc ${6:+--preset $6} --count 3 --match "$3" --stop-on-match --public-only > "$T/hit"
  a=$(grep -o '"address":"[^"]*"' "$T/hit" | head -1 | cut -d'"' -f4)
  [ -n "$a" ] && grep -qxF "$a" "$3" || f "$1: generator's address not reached"
  echo "ok   recovery-real seed $1: generator's address reached; $n checksum-valid candidates; $(( $(date +%s) - s ))s"
}
for k in typo swap missing unknown; do seed bip39-$k bip39 "$G/bip.want" "$G/bip39.seed" $k; done
for k in typo missing; do seed electrum-$k electrum "$G/electrum-fileenc.want" "$G/electrum-fileenc.seed" $k electrum; done

# pw <name> <tokens> <rules> <wallet> <want-file> <opener pipeline>: pw-candidates -> try each in order
pw() {
  s=$(date +%s); printf '%s\n' $2 > "$T/tok"; want=$(head -1 "$5")
  "$B/pw-candidates" --rules "$3" --max 100000 "$T/tok" > "$T/pws"
  i=0; hit=
  while IFS= read -r p; do
    i=$((i + 1))
    if { printf '%s\n' "$p"; cat "$4"; } | sh -c "$6" > "$T/o" 2>/dev/null && grep -qF "$want" "$T/o"; then hit=1; break; fi
  done < "$T/pws"
  [ -n "$hit" ] || f "$1: password not recovered"
  while read -r a; do grep -qF "$a" "$T/o" || f "$1: generator address $a missing"; done < "$5"
  echo "ok   recovery-real password $1: opened at attempt $i of $(wc -l < "$T/pws" | tr -d ' '); all $(wc -l < "$5" | tr -d ' ') generator addresses found; $(( $(date +%s) - s ))s"
}
# Passwords (throwaway, set by recovery-gen.sh): Core Horsebattery7, Electrum Horsebatetry7 (typo), keystore Horse7.
pw core-25.2-legacy-bdb "horse battery" case,digit "$G/core-legacy.dat" "$G/core-legacy.want" "$B/dat-read"
pw core-25.2-descriptor-sqlite "horse battery" case,digit "$G/core-desc.dat" "$G/core-desc.want" "$B/dat-read | $B/derive --chain btc --count 3 --public-only"
pw electrum-4.5.8-file-encrypted "horse battery" case,swap,digit "$G/electrum-fileenc" "$G/electrum-fileenc.want" "$B/electrum-read | $B/seed-to-master | $B/derive --preset electrum --chain btc --count 3 --public-only"
pw electrum-4.5.8-keystore-encrypted "horse battery" case,swap,digit "$G/electrum-keyenc" "$G/electrum-keyenc.want" "$B/electrum-read | $B/seed-to-master | $B/derive --preset electrum --chain btc --count 3 --public-only"
pw eth-account-0.13.4-scrypt "horse" case,digit "$G/eth.json" "$G/eth.want" "$B/keystore-open"
# control: a wrong password does not open the Core wallet (the loop above is not vacuous)
{ echo Horsebattery8; cat "$G/core-legacy.dat"; } | "$B/dat-read" > "$T/o" 2>/dev/null && grep -qF "$(head -1 "$G/core-legacy.want")" "$T/o" && f "wrong password opened core-legacy"
echo "ok   recovery-real control: wrong password does not open the Core 25.2 wallet"
rm -rf "$G"
