#!/bin/sh
cd /Users/tsavo/bt-main/.claude/worktrees/agent-a34839a79334f35c2
echo "=== workspace build ==="
cargo build --release --workspace --locked 2>&1 | grep -vE "Compiling|Fresh" | grep -iE "error|warning:" || echo "build clean"
echo "=== gen-man ==="
python3 scripts/gen-man.py 2>&1 | grep -vE "^$" | sed -n '1,2p'
echo "=== gen-man --check (ignore groff) ==="
python3 scripts/gen-man.py --check 2>&1 | grep -ivE "groff not installed" | sed -n '1,4p'; echo "(blank above=man ok)"
echo "=== unit tests ==="
cargo test --release -p blocktools-evm -p blocktools-plan 2>&1 | grep -E "test result: FAILED|[1-9][0-9]* failed|error\[" | sed -n '1,6p'; echo "(blank above=tests ok)"
echo "=== check-deps (safe-tx) ==="
sh scripts/check-deps.sh 2>&1 | grep -iE "safe-tx|FAIL" | sed -n '1,4p'
echo "=== coverage ==="
python3 scripts/coverage.py >/dev/null 2>&1 && echo "coverage ok" || echo "coverage FAIL"
echo "=== hygiene ==="
sh scripts/hygiene-check.sh >/dev/null 2>&1 && echo "hygiene ok" || sh scripts/hygiene-check.sh 2>&1 | grep -iE "FAIL" | sed -n '1,4p'
echo "=== docs-check (real fails only) ==="
sh scripts/docs-check.sh 2>&1 | grep -iE "FAIL" | grep -vE "shallow clone|groff not installed" | sed -n '1,6p'; echo "(blank above=docs ok)"
echo "=== secret-scan ==="
sh scripts/secret-scan.sh >/dev/null 2>&1 && echo "secret-scan ok" || sh scripts/secret-scan.sh 2>&1 | grep -iE "UNLISTED|FAIL" | sed -n '1,4p'
echo "=== evm-safe e2e ==="
BIN=target/release sh scripts/e2e.d/evm-safe.sh 2>&1 | grep -E "PASS|FAIL" | sed -n '1,2p'
echo "ALLDONE"
