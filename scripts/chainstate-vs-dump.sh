# Cross-check: chainstate-dump on a stopped node's chainstate/ (or a copy) against that node's own
# dumptxoutset taken at the same height. Prints both digests (scripts/utxo-multiset.py) and
# "ok   chainstate-vs-dump: identical ..." or FAIL. Usage: sh scripts/chainstate-vs-dump.sh CHAINSTATE_DIR DUMP_FILE CHAIN
set -eu
[ $# = 3 ] || { echo "usage: chainstate-vs-dump.sh CHAINSTATE_DIR DUMP_FILE CHAIN" >&2; exit 2; }
B=${BIN:-${B:-target/release}}; S=$(dirname "$0")
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
"$B/chainstate-dump" --chain "$3" "$1" 2> "$T/sum" | python3 "$S/utxo-multiset.py" jsonl > "$T/a" &
python3 "$S/utxo-multiset.py" dump "$2" > "$T/b"; wait $! || { echo "FAIL chainstate-vs-dump: chainstate-dump: $(tail -1 "$T/sum")"; exit 1; }
echo "chainstate: $(cat "$T/a") $(tail -1 "$T/sum")"; echo "dump:       $(cat "$T/b")"
python3 - "$T/a" "$T/b" "$T/sum" <<'P'
import json, sys
a, b, s = (json.loads(open(p).read().strip().splitlines()[-1]) for p in sys.argv[1:4])
same = all(a[k] == b[k] for k in ("coins", "total", "full", "script_amount")) and b["coins"] == b["coins_count_header"]
best = s.get("best_block") == b["base_blockhash"]
print(("ok   chainstate-vs-dump: identical" if same else "FAIL chainstate-vs-dump: differ") + f" {a['coins']} vs {b['coins']} coins; best block {'=' if best else '!='} dump base")
sys.exit(0 if same and best else 1)
P
