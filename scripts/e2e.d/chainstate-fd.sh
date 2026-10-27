#!/bin/sh
# Regression: chainstate-dump on a synthetic chainstate of 203 LevelDB tables (200 level-1 + 3
# overlapping level-0) under `ulimit -n 64` reads every coin (the pre-48affb6 reader opened every table
# at once and failed with EMFILE, os error 24). The fixture is built by tools/chainstate-dump/tests/many_tables.rs.
set -eu
f() { echo "FAIL $1"; [ -s "${2:-/dev/null}" ] && sed 's/^/  | /' "$2"; exit 1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cargo test -q --release -p chainstate-dump --test many_tables > "$T/o" 2>&1 || f "chainstate-fd: many_tables under ulimit -n 64" "$T/o"
grep -q 'test result: ok. 1 passed' "$T/o" || f "chainstate-fd: many_tables did not run" "$T/o"
echo "ok   chainstate-fd: 203 tables read under ulimit -n 64 (coins 200, total 216622)"
