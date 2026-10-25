# dat-read through the boundary (sourced by e2e-local.sh). Wallets generated into $T, never committed.
python3 scripts/make-fixtures.py "$T" >/dev/null
W="$T/descriptor-encrypted.sqlite"
{ echo keyrescue-test-password; cat "$W"; } | boundary dat-full 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu' 'dat-read | derive --count 3'
grep -q 13M3vwLduvWviNdwLqrsLYBf6KLNq1cyYM "$T/dat-full.jsonl" || { echo "FAIL dat-full: bare key missing"; exit 1; }
{ echo keyrescue-test-password; cat "$W"; } | boundary dat-half '"tool":"dat-read"' 'dat-read'
{ echo wrong; cat "$W"; } | boundary dat-wrongpw 'wrong_password' 'dat-read'
