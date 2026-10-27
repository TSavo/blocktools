#!/bin/sh
# Measures utxo-set / wallet-finder on a synthetic Core-25 dumptxoutset (crates/utxo/examples/synth-dump.rs):
# ingest coins/sec and peak RSS (VmHWM), bloom false-positive rate over never-funded queries, and
# wallet-finder candidates/sec (sha256 and warpwallet). Needs about 1.4 GB of disk and 1 GB of RAM at N=20000000.
# Usage: sh scripts/utxo-bench.sh [N] [QUERIES]    (prints JSON lines, then "utxo-bench ok")
set -eu
export LC_ALL=C
N=${1:-20000000}; Q=${2:-1000000}
cd "$(dirname "$0")/.."
cargo build -q --release -p utxo-set -p wallet-finder
cargo build -q --release -p blocktools-utxo --example synth-dump
B=target/release; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
"$B/examples/synth-dump" "$N" "$T/s.dat" "$Q" "$T/q.txt"
echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //'), $(nproc) threads, $(uname -sm)"
"$B/utxo-set" --dump "$T/s.dat" --stats
"$B/utxo-set" --dump "$T/s.dat" < "$T/q.txt" 2>/dev/null > "$T/q.out"
python3 - "$T/q.out" "$Q" <<'PY'
import json, sys
n = funded = passed = 0
for l in open(sys.argv[1]):
    d = json.loads(l); n += 1; funded += d["status"] == "funded"; passed += d["bloom"] == "pass"
assert n == int(sys.argv[2]), n
print(json.dumps({"queries": n, "bloom_pass": passed, "fpr": passed / n, "reported_funded": funded}))
assert funded == 0
PY
cat README.md DESIGN.md docs/*.md > "$T/text.txt"
rc=0; "$B/wallet-finder" --dump "$T/s.dat" < "$T/text.txt" > "$T/f.out" 2> "$T/f.err" || rc=$?
[ "$rc" = 1 ] && [ ! -s "$T/f.out" ] || { echo "wallet-finder sha256: unexpected rc=$rc or hits"; exit 1; }
tail -n 1 "$T/f.err"
rc=0; "$B/wallet-finder" --dump "$T/s.dat" --scheme warpwallet --limit 200 < "$T/text.txt" > "$T/w.out" 2> "$T/w.err" || rc=$?
[ "$rc" = 1 ] && [ ! -s "$T/w.out" ] || { echo "wallet-finder warpwallet: unexpected rc=$rc or hits"; exit 1; }
tail -n 1 "$T/w.err"
echo "utxo-bench ok"
