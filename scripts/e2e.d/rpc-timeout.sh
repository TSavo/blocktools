#!/bin/sh
# rpc --timeout and the slow-method default, against scripts/mock-bitcoind.py (a fake bitcoind on 127.0.0.1, NOT
# a real node) holding the HTTP request open (MOCK_SLOW). Measures the 30 s default timeout; checks status
# "timeout" (with timeout_secs) is distinct from http_error; dumptxoutset stays behind --allow-unlisted.
set -eu
B=${BIN:-target/release}
W=$(mktemp -d); P=""; trap 'kill $P 2>/dev/null; rm -rf "$W"' EXIT
start() { # NAME SLOW METHODS
  MOCK_SLOW=$2 MOCK_SLOW_METHODS=$3 python3 scripts/mock-bitcoind.py "$W/$1.p" "$W/$1.log" 2>"$W/$1.err" & P="$P $!"
}
touch "$W/r.log"; start d 40 getblockcount; start s 33 dumptxoutset; start t 5 dumptxoutset; start r 0 none
i=0; for m in d s t r; do while [ ! -s "$W/$m.p" ]; do i=$((i+1)); [ $i -lt 600 ] || { echo "FAIL rpc-timeout: mock $m did not start"; cat "$W/$m.err"; exit 1; }; sleep 0.05; done; done
u() { echo "http://127.0.0.1:$(cat "$W/$1.p")"; }
now() { python3 -c 'import time; print(time.monotonic())'; }
# 1. default timeout, measured: a plain read the mock holds for 40 s
(t0=$(now); "$B/rpc" --protocol btc "$(u d)" getblockcount >"$W/d.out" 2>"$W/d.stderr" && echo 0 >"$W/d.rc" || echo $? >"$W/d.rc"; t1=$(now)
 python3 -c "print(round($t1 - $t0, 1))" >"$W/d.secs") &
D=$!
# 2. slow-method default: dumptxoutset answered after 33 s (past the 30 s default) still succeeds
("$B/rpc" --protocol btc --allow-unlisted "$(u s)" dumptxoutset '["/data/utxo.dat"]' >"$W/s.out" 2>"$W/s.stderr" && echo 0 >"$W/s.rc" || echo $? >"$W/s.rc") &
S=$!
# 3. explicit --timeout 2 against a 5 s dumptxoutset: status timeout, timeout_secs 2, exit 1, not http_error
t0=$(now); if "$B/rpc" --protocol btc --allow-unlisted --timeout 2 "$(u t)" dumptxoutset '["/data/utxo.dat"]' >/dev/null 2>"$W/t.err"; then echo "FAIL rpc-timeout: --timeout 2 succeeded"; exit 1; else rc=$?; fi; t1=$(now)
e=$(python3 -c "print(round($t1 - $t0, 1))")
[ $rc = 1 ] && jq -e '.status == "timeout" and .timeout_secs == 2 and .timeout_source == "--timeout"' "$W/t.err" >/dev/null \
  && python3 -c "import sys; sys.exit(not 1.5 <= $e <= 4.5)" && echo "ok   rpc-timeout: --timeout 2 -> status timeout, timeout_secs 2, exit 1 after ${e}s" || { echo "FAIL rpc-timeout --timeout 2 (rc=$rc, ${e}s)"; cat "$W/t.err"; exit 1; }
# 4. dumptxoutset is not in the read allowlist: refused without --allow-unlisted, nothing sent; deny-list unchanged
n=$(wc -l < "$W/r.log")
"$B/rpc" --protocol btc "$(u r)" dumptxoutset '["/data/utxo.dat"]' 2>"$W/r.err" >/dev/null && { echo "FAIL rpc-timeout: dumptxoutset sent without --allow-unlisted"; exit 1; } || true  # allow-true: exit 1 expected, asserted next
jq -e '.status == "refused" and .code == "method_not_allowlisted"' "$W/r.err" >/dev/null && [ "$(wc -l < "$W/r.log")" = "$n" ] \
  && echo "ok   rpc-timeout: dumptxoutset refused (method_not_allowlisted) without --allow-unlisted, nothing sent" || { echo "FAIL rpc-timeout allowlist"; cat "$W/r.err"; exit 1; }
"$B/rpc" --protocol btc --allow-unlisted --timeout 600 "$(u r)" dumpprivkey '["x"]' 2>"$W/r2.err" >/dev/null && { echo "FAIL dumpprivkey sent"; exit 1; } || true  # allow-true: asserted next
grep -q '"status":"refused"' "$W/r2.err" && [ "$(wc -l < "$W/r.log")" = "$n" ] && echo "ok   rpc-timeout: dumpprivkey still refused with --allow-unlisted --timeout 600" || { echo "FAIL deny-list"; exit 1; }
"$B/rpc" --timeout 86401 "$(u r)" getblockcount 2>"$W/b.err" >/dev/null && { echo "FAIL --timeout 86401 accepted"; exit 1; } || true  # allow-true: asserted next
grep -q '"status":"bad_input"' "$W/b.err" && echo "ok   rpc-timeout: --timeout 86401 is bad_input" || { echo "FAIL timeout range"; exit 1; }
wait $D $S
[ "$(cat "$W/d.rc")" = 1 ] && jq -e '.status == "timeout" and .timeout_secs == 30 and .timeout_source == "default"' "$W/d.stderr" >/dev/null \
  && python3 -c "import sys; sys.exit(not 29 <= $(cat "$W/d.secs") <= 34)" \
  && echo "ok   rpc-timeout: default timeout measured $(cat "$W/d.secs") s (status timeout, timeout_secs 30)" || { echo "FAIL rpc-timeout default (rc=$(cat "$W/d.rc"), $(cat "$W/d.secs")s)"; cat "$W/d.stderr"; exit 1; }
[ "$(cat "$W/s.rc")" = 0 ] && jq -e '.result.coins_written == 2' "$W/s.out" >/dev/null \
  && echo "ok   rpc-timeout: dumptxoutset answered after 33 s succeeds under the slow-method default (3600 s)" || { echo "FAIL rpc-timeout slow default (rc=$(cat "$W/s.rc"))"; cat "$W/s.stderr" "$W/s.out"; exit 1; }
