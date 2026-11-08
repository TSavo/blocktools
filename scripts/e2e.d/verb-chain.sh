#!/bin/sh
# Parent verbs take --chain: delegated builds match the backend byte-for-byte; missing
# signers/verifiers/broadcasters fail closed (issue #11).
set -eu
B=${BIN:-target/release}; X=$(mktemp -d); trap 'rm -rf "$X"' EXIT
f() { echo "FAIL $1"; exit 1; }
same_out() {  # same NAME -- PARENT-CMD --- BACKEND-CMD
  n=$1; shift
  # split on ---
  parent=""; backend=""
  saw=0
  for a in "$@"; do
    if [ "$a" = "---" ]; then saw=1; continue; fi
    if [ $saw -eq 0 ]; then parent="$parent $a"; else backend="$backend $a"; fi
  done
  # shellcheck disable=SC2086
  set +e; eval "$parent" > "$X/p" 2>"$X/pe"; rp=$?; eval "$backend" > "$X/b" 2>"$X/be"; rb=$?; set -e
  [ -s "$X/b" ] && cmp -s "$X/p" "$X/b" && [ $rp = $rb ] || f "$n: parent differs from backend (rc $rp vs $rb)"
  echo "ok   $n (rc $rp, $(wc -c < "$X/p") bytes)"
}
expect_err() {  # expect_err NAME CODE -- CMD...
  n=$1; code=$2; shift 2
  set +e; "$@" > "$X/o" 2>"$X/e"; rc=$?; set -e
  grep -q "\"$code\"" "$X/o" "$X/e" || f "$n: expected $code in output (rc $rc): $(cat "$X/o" "$X/e")"
  [ "$rc" = 2 ] || f "$n: expected exit 2, got $rc"
  echo "ok   $n ($code, exit $rc)"
}

same_out "xlm build" \
  "$B/tx-build" --chain xlm --from GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR --to GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U --amount 125000000 --fee 100 --seq 123456789013 --memo-id 42 --max-time 1800000000 \
  --- \
  "$B/acct-tx" build --chain xlm --from GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR --to GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U --amount 125000000 --fee 100 --seq 123456789013 --memo-id 42 --max-time 1800000000

same_out "xrp build" \
  "$B/tx-build" --chain xrp --account rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD --to X7AcgcsBL6XDcUb289X4mJ8djcdyKaLFuhLRuNXPrDeJd9A --sweep --balance 30000000 --fee 12 --sequence 7 --last-ledger 9000000 \
  --- \
  "$B/xrp-tx" build --account rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD --to X7AcgcsBL6XDcUb289X4mJ8djcdyKaLFuhLRuNXPrDeJd9A --sweep --balance 30000000 --fee 12 --sequence 7 --last-ledger 9000000

printf '%s\n' '{"from":"EWy75VpRJLEeT9HyrsfLowpCzbKawHyCLnJEP15FhSeu","to":"DVh2QqxkWQvdYm8ijvxNMJpQDpkmVDLSdZfeeTpc3Pzq","blockhash":"BQfVAy4fAiU42cTCWXJsVY7Xg4kqByngTWVecs1cEsDc","lamports":"14209386001"}' > "$X/sol.plan"
same_out "sol build" \
  "$B/tx-build" --chain sol --plan "$X/sol.plan" \
  --- \
  "$B/sol-tron-tx" build --chain sol --plan "$X/sol.plan"

printf '%s\n' '{"from":"TMxXrJ5u3Qsh7scpn4zRUzrxYtBoPCW5GM","to":"TXfrRsqwPbMi4Leb4EGB7dv5NMMWmkdRwk","ref_block_bytes":"86ec","ref_block_hash":"05d9f8c360a410c4","expiration_ms":"1710640770000","timestamp_ms":"1710640711685","amount_sun":"1"}' > "$X/tron.plan"
same_out "tron build" \
  "$B/tx-build" --chain tron --plan "$X/tron.plan" \
  --- \
  "$B/sol-tron-tx" build --chain tron --plan "$X/tron.plan"

expect_err "tx-build xmr" xmr_requires_wallet_rpc "$B/tx-build" --chain xmr
expect_err "tx-sign sol" signing_not_available "$B/tx-sign" --chain sol
expect_err "tx-sign tron" signing_not_available "$B/tx-sign" --chain tron
expect_err "tx-sign xmr" xmr_requires_wallet_rpc "$B/tx-sign" --chain xmr
expect_err "tx-verify xrp" verify_not_available "$B/tx-verify" --chain xrp
expect_err "tx-verify xlm" verify_not_available "$B/tx-verify" --chain xlm
expect_err "tx-verify xmr" xmr_requires_wallet_rpc "$B/tx-verify" --chain xmr
expect_err "tx-broadcast sol" broadcast_not_available "$B/tx-broadcast" --chain sol
expect_err "tx-build zec stays here (not zec-sapling)" "zec: only --sweep is supported" "$B/tx-build" --chain zec
