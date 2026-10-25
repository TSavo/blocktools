#!/bin/sh
# Sweep e2e for GRS (single-SHA-256 txid/sighash, Groestl base58 checksum), LTC and DOGE:
# build -> verify -> sign (pty types the code via tty-drive.py) -> decode -> re-verify.
# Throwaway key 1 only; nothing touches a network. For GRS the decoded txid must equal the
# single-SHA-256 txid computed here in Python (and differ from the sha256d one).
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap '[ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
f() { echo "FAIL $1"; exit 1; }
echo 0000000000000000000000000000000000000000000000000000000000000001 > $T/k
TID=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
sweep() { # chain from-addr-segwit-or-empty from-p2pkh to
  c=$1; w=$2; p=$3; d=$4
  { [ -n "$w" ] && printf '{"txid":"%s","vout":0,"amount":50000,"address":"%s"}\n' $TID $w; printf '{"txid":"%s","vout":1,"amount":30000,"address":"%s"}\n' $TID $p; } > $T/u.$c
  $B/tx-build --chain $c --utxos $T/u.$c --to $d --sweep --fee-rate 5 > $T/p.$c || f "$c build"
  $B/tx-verify --chain $c --expect-to $d < $T/p.$c >/dev/null || f "$c verify"
  python3 scripts/tty-drive.py right $T/k $T/o.$c $PWD/$B/tx-sign --tx $T/p.$c --expect-to $d > $T/tty.$c || f "$c sign"
  grep -q "Checks passed" $T/tty.$c || f "$c summary"
  $B/tx-decode --chain $c < $T/o.$c > $T/d.$c && grep -q '"signed":true' $T/d.$c || f "$c decode"
  $B/tx-verify --chain $c --expect-to $d < $T/o.$c >/dev/null || f "$c reverify"
  echo "ok   $c sweep: build -> verify -> tty sign -> decode signed -> re-verify"
}
sweep grs grs1qw508d6qejxtdg4y5r3zarvary0c5xw7k3k4sj5 Ffqz14cyvZYJavD76t6oHNDJnGiWcZMVxR Fob4maNwBGVRPmMcRLS6qtTJfKeySAMsWq
python3 -c 'import json,sys;print([json.loads(l) for l in open(sys.argv[1]) if "signed_tx" in l][0]["signed_tx"])' $T/o.grs > $T/raw.grs
$B/tx-decode --chain grs < $T/raw.grs > $T/dr.grs || f "grs decode raw"
python3 - "$T/o.grs" "$T/dr.grs" <<'PY' || f "grs txid"
import hashlib, importlib.util, json, sys
s = importlib.util.spec_from_file_location("m", "scripts/mock-chain.py"); m = importlib.util.module_from_spec(s); s.loader.exec_module(m)
raw = [json.loads(l) for l in open(sys.argv[1]) if "signed_tx" in l][0]["signed_tx"]
dec = [json.loads(l) for l in open(sys.argv[2]) if '"txid"' in l][0]["txid"]
assert dec == m.txid(raw, single=True) and dec != m.txid(raw), (dec,)
PY
echo "ok   grs signed txid = single-SHA-256 (not sha256d)"
sweep ltc ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9 LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ MR8UQSBr5ULwWheBHznrHk2jxyxkHQu8vB
sweep doge "" DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE DJRU7MLhcPwCTNRZ4e8gJzDebtG1H5M7pc
