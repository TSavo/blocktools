#!/bin/sh
# Fails if a workflow runs anything other than scripts/gate.sh or an exact line from
# scripts/ci-allowed-setup.txt. Multi-line `run: |` blocks are refused (fail closed).
# Usage: sh scripts/ci-gate-check.sh [workflow.yml]   (default .github/workflows/ci.yml)
set -eu
cd "$(dirname "$0")/.."
wf=${1:-.github/workflows/ci.yml}
allow=scripts/ci-allowed-setup.txt
[ -f "$wf" ] || { echo "FAIL ci-gate: no $wf"; exit 1; }
rc=0; n=0
runs=$(sed -n 's/^[[:space:]]*-\{0,1\}[[:space:]]*run:[[:space:]]*//p' "$wf")
[ -n "$runs" ] || { echo "FAIL ci-gate: $wf has no run: steps"; exit 1; }
printf '%s\n' "$runs" > "${TMPDIR:-/tmp}/ci-gate.$$"
while IFS= read -r r; do
  n=$((n+1))
  case "$r" in '|'*|'>'*) echo "FAIL ci-gate: multi-line run: block in $wf"; rc=1; continue;; esac
  grep -vE '^#' "$allow" | grep -qxF -- "$r" || { echo "FAIL ci-gate: $wf runs a command not in gate.sh/allowlist: $r"; rc=1; }
done < "${TMPDIR:-/tmp}/ci-gate.$$"
rm -f "${TMPDIR:-/tmp}/ci-gate.$$"
grep -qE '^[[:space:]]*-?[[:space:]]*run:[[:space:]]*sh scripts/gate.sh$' "$wf" || { echo "FAIL ci-gate: $wf never runs scripts/gate.sh"; rc=1; }
[ $rc = 0 ] && echo "ok   ci-gate: $wf runs only gate.sh + $((n-1)) setup steps"
exit $rc
