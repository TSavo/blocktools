#!/bin/sh
# --chain-spec FILE / BLOCKTOOLS_CHAIN_SPEC: a process-only, unverified chain row every UTXO tool
# accepts. Measured here, offline, throwaway keys 1/2 only:
#  - ftc and ltc re-described by a spec under another name ("ftx", "ltx", allow_collision) give
#    byte-identical addresses (key-to-addresses, derive), PSBT (tx-build) and signed tx (tx-sign)
#    to the built-in verified rows; the only differences are the chain name and the spec markers.
#  - bcc via spec ("bcs") derives the same addresses as the built-in unverified bcc row; classify
#    detects them; tx-build refuses (postime sign kind: spec_unsupported_sign).
#  - each tool refuses only the step that needs a missing field, with a stable code.
#  - negatives: malformed, name collision, byte collision, secret in file, unknown field.
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap '[ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
f() { echo "FAIL chain-spec: $1"; exit 1; }
MU="cargo run -q --offline --release -p blocktools-tx --example mock-utxo --"
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
echo 0000000000000000000000000000000000000000000000000000000000000002 > $T/k2
H='"format":"blocktools-chain-spec/1"'
echo "{$H,\"name\":\"ftx\",\"ticker\":\"FTC\",\"p2pkh\":14,\"p2sh\":5,\"wif\":142,\"hrp\":\"fc\",\"slip44\":8,\"checksum\":\"sha256d\",\"sign\":\"standard\",\"decimals\":8,\"allow_collision\":true}" > $T/ftc.spec
echo "{$H,\"name\":\"ltx\",\"ticker\":\"LTC\",\"p2pkh\":48,\"p2sh\":50,\"wif\":176,\"hrp\":\"ltc\",\"slip44\":2,\"checksum\":\"sha256d\",\"sign\":\"standard\",\"decimals\":8,\"allow_collision\":true}" > $T/ltc.spec
echo "{$H,\"name\":\"bcs\",\"ticker\":\"BCC\",\"p2pkh\":18,\"p2sh\":85,\"wif\":146,\"checksum\":\"sha256d\",\"sign\":\"postime\",\"decimals\":8,\"allow_collision\":true}" > $T/bcc.spec
addr() { python3 -c 'import json,sys;print([json.loads(l) for l in sys.stdin if "\"kind\":\"p2pkh\"" in l][0]["address"])'; }
field() { python3 -c 'import json,sys;print([json.loads(l) for l in open(sys.argv[1]) if sys.argv[2] in l][0][sys.argv[2]])' "$@"; }
M=$(echo '{"mnemonic":"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"}' | $B/seed-to-master | head -1)
same() { # built-in spec-name spec-file : addresses, PSBT, signed tx identical
  c=$1; s=$2; S="--chain-spec $T/$c.spec"
  $B/key-to-addresses --chain $c < $T/k | sed "s/\"$c\"/\"X\"/" > $T/ka.$c
  $B/key-to-addresses $S --chain $s < $T/k | sed "s/\"$s\"/\"X\"/" > $T/kb.$c
  [ -s $T/ka.$c ] && cmp -s $T/ka.$c $T/kb.$c || f "$c key-to-addresses differs"
  echo "$M" | $B/derive --chain $c --count 3 | sed "s/\"$c\"/\"X\"/" > $T/da.$c
  echo "$M" | BLOCKTOOLS_CHAIN_SPEC=$T/$c.spec $B/derive --chain $s --count 3 | sed "s/\"$s\"/\"X\"/" > $T/db.$c
  grep -q '"address"' $T/da.$c && cmp -s $T/da.$c $T/db.$c || f "$c derive differs (env var)"
  A=$(addr < $T/ka.$c); D=$($B/key-to-addresses --chain $c < $T/k2 | addr)
  $MU $c 1 30000 $A > $T/u.$c
  $B/tx-build --chain $c --utxos $T/u.$c --to $D --sweep --fee-rate 5 > $T/pa.$c || f "$c build"
  $B/tx-build $S --chain $s --utxos $T/u.$c --to $D --sweep --fee-rate 5 > $T/pb.$c || f "$s build"
  [ "$(field $T/pa.$c psbt)" = "$(field $T/pb.$c psbt)" ] || f "$c psbt differs"
  grep -q '"chain_spec":"unverified chain spec"' $T/pb.$c || f "$s build marker"
  $B/tx-verify $S --chain $s --expect-to $D < $T/pb.$c > $T/v.$c || f "$s verify"
  grep -q '"chain_spec":"unverified chain spec"' $T/v.$c || f "$s verify marker"
  $B/tx-decode $S --chain $s < $T/pb.$c | grep -q '"chain_spec":"unverified chain spec"' || f "$s decode marker"
  $B/tx-decode $S --chain $s --text < $T/pb.$c | grep -q "unverified chain spec: $s" || f "$s decode banner"
  python3 scripts/e2e-only/tty-drive.py right $T/k $T/oa.$c $PWD/$B/tx-sign --tx $T/pa.$c --expect-to $D > $T/ta.$c || f "$c sign"
  python3 scripts/e2e-only/tty-drive.py right $T/k $T/ob.$c $PWD/$B/tx-sign $S --tx $T/pb.$c --expect-to $D > $T/tb.$c || f "$s sign"
  grep -q "unverified chain spec: $s" $T/tb.$c || f "$s sign confirmation banner"
  ! grep -q "unverified chain spec" $T/ta.$c || f "$c built-in shows spec banner"
  [ "$(field $T/oa.$c signed_tx)" = "$(field $T/ob.$c signed_tx)" ] || f "$c signed tx differs"
  $B/tx-verify $S --chain $s --expect-to $D < $T/ob.$c >/dev/null || f "$s reverify"
  # default fee cap still applies: 1 input at 2000 sat/vB is over the 100,000 floor
  $MU $c 1 2000000 $A > $T/ub.$c
  $B/tx-build $S --chain $s --utxos $T/ub.$c --to $D --sweep --fee-rate 2000 > $T/pc.$c || f "$s build high fee"
  ! $B/tx-verify $S --chain $s --expect-to $D < $T/pc.$c > $T/vc.$c || f "$s fee over cap accepted"
  grep -q fee $T/vc.$c || f "$s refused for a reason other than fee: $(cat $T/vc.$c)"
  echo "ok   $s spec == built-in $c: key-to-addresses, derive, PSBT, signed tx; markers + banner; fee cap"
}
same ftc ftx
same ltc ltx
S="--chain-spec $T/bcc.spec"
$B/key-to-addresses --chain bcc < $T/k | sed 's/"bcc"/"X"/' > $T/ka.bcc
$B/key-to-addresses $S --chain bcs < $T/k | sed 's/"bcs"/"X"/' > $T/kb.bcc
cmp -s $T/ka.bcc $T/kb.bcc || f "bcc addresses differ"
A=$(addr < $T/kb.bcc)
echo $A | $B/classify $S | grep -q '"chain":"bcs"' || f "classify/detect spec chain"
echo $A | $B/classify | grep -q '"class":"unknown"' || f "classify without spec"
$MU ftc 1 30000 6pQiLg4eJbM2bP9CZemnccDzwB3kz2Ae1x > $T/u.x
r=$($B/tx-build $S --chain bcs --utxos $T/u.x --to $A --sweep --fee-rate 5 || true); echo "$r" | grep -q '"error":"spec_unsupported_sign"' || f "bcs build: $r"
echo "ok   bcs spec == built-in bcc addresses; classify detects; tx-build refuses spec_unsupported_sign"
# missing fields: refuse only the step that needs them
D=$($B/key-to-addresses --chain ftc < $T/k2 | addr)
sed 's/"wif":142,//' $T/ftc.spec > $T/nowif.spec; sed 's/"p2pkh":14,//' $T/ftc.spec > $T/nopkh.spec
$B/key-to-addresses --chain-spec $T/nowif.spec --chain ftx < $T/k | grep -q '"missing":"spec_missing_wif"' || f "nowif addresses"
$B/tx-build --chain-spec $T/nowif.spec --chain ftx --utxos $T/u.ftc --to $D --sweep --fee-rate 5 > /dev/null || f "nowif build should pass"
r=$($B/tx-sign --chain-spec $T/nowif.spec --tx $T/pb.ftc --expect-to $D < $T/k || true); echo "$r" | grep -q '"error":"spec_missing_wif"' || f "nowif sign: $r"
for t in key-to-addresses derive; do r=$(echo "$M" | $B/$t --chain-spec $T/nopkh.spec --chain ftx || true); echo "$r" | grep -q '"error":"spec_missing_p2pkh"' || f "$t nopkh: $r"; done
echo "ok   missing fields: wif -> addresses ok, build ok, sign spec_missing_wif; p2pkh -> spec_missing_p2pkh"
neg() { echo "$1" > $T/n.spec; r=$($B/key-to-addresses --chain-spec $T/n.spec < $T/k || true); echo "$r" | grep -q "\"error\":\"$2\"" || f "negative $2: $r"; }
neg '{' spec_malformed
neg "{$H,\"name\":\"ftc\",\"checksum\":\"sha256d\",\"allow_collision\":true}" spec_name_collision
neg "{$H,\"name\":\"zzz\",\"p2pkh\":0,\"checksum\":\"sha256d\"}" spec_byte_collision
neg "{$H,\"name\":\"zzz\",\"checksum\":\"sha256d\",\"title\":\"N1LYBvAjrq6XNUt5Xm3p3iSALhXdYRWE7jTWTWCSix24zWLX171A\"}" spec_contains_secret
neg "{$H,\"name\":\"zzz\",\"checksum\":\"sha256d\",\"bogus\":1}" spec_unknown_field
neg "{$H,\"name\":\"zzz\",\"checksum\":\"groestl\"}" spec_unsupported_checksum
for t in tx-build tx-verify tx-sign tx-decode classify derive chain-table; do r=$($B/$t --chain-spec $T/n.spec < /dev/null || true); echo "$r" | grep -q spec_unsupported_checksum || f "$t ignores bad spec: $r"; done
echo "ok   negatives: malformed, name/byte collision, secret, unknown field, checksum; every tool refuses a bad spec"
