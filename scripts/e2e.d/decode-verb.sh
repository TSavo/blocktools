#!/bin/sh
# One decode verb: `tx-decode --chain C` gives byte-identical stdout and the same exit status as the chain's own
# decoder (acct-tx decode, sol-tron-tx decode, xrp-tx decode) on a tx those tools build from public test keys/plans.
set -eu
B=${BIN:-target/release}; X=$(mktemp -d); trap 'rm -rf "$X"' EXIT
f() { echo "FAIL $1"; exit 1; }
same() {  # same NAME CHAIN INPUT -- DIRECT-CMD...
  n=$1; c=$2; i=$3; shift 4
  set +e; "$@" < "$i" > "$X/a" 2>/dev/null; ra=$?; "$B/tx-decode" --chain "$c" < "$i" > "$X/b" 2>/dev/null; rb=$?; set -e
  [ -s "$X/a" ] && cmp -s "$X/a" "$X/b" && [ $ra = $rb ] || f "$n: tx-decode --chain $c differs from $* (rc $ra vs $rb)"
  echo "ok   tx-decode --chain $c == $(basename "$1") decode (rc $ra, $(wc -c < "$X/a") bytes): $n"
}
"$B/acct-tx" build --chain xlm --from GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR --to GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U \
  --amount 125000000 --fee 100 --seq 123456789013 --memo-id 42 --max-time 1800000000 > "$X/xlm" 2>/dev/null
same "xlm unsigned payment" xlm "$X/xlm" -- "$B/acct-tx" decode --chain xlm
"$B/acct-tx" build --chain algo --from RKEOHXLUBHYZL7KS3MWTZOS5OLFGOCN7DWKBEG7TOSEADNAPN5OOTUNSLE --to QE4XODVIPULV6VVDKRTMGTD6ZTFY3CURWTXDPIS56YHVXD6JWOKORTLPBU \
  --sweep --fee 1000 --first-round 40000000 --last-round 40001000 > "$X/algo" 2>/dev/null
same "algo unsigned sweep" algo "$X/algo" -- "$B/acct-tx" decode --chain algo
for c in sol tron; do same "$c transfer fixture" $c recipes/fixtures/sol-tron/$c-transfer.txt -- "$B/sol-tron-tx" decode --chain $c; done
"$B/xrp-tx" build --account rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD --to X7AcgcsBL6XDcUb289X4mJ8djcdyKaLFuhLRuNXPrDeJd9A \
  --sweep --balance 30000000 --fee 12 --sequence 7 --last-ledger 9000000 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["unsigned"])' > "$X/xrp"
same "xrp unsigned payment" xrp "$X/xrp" -- "$B/xrp-tx" decode
echo zz > "$X/bad"; same "malformed input: same error, same exit" xrp "$X/bad" -- "$B/xrp-tx" decode
