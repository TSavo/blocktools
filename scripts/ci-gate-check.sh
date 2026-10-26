#!/bin/sh
# finding:R2-10 (docs/FINDINGS.md)
# Fails if a workflow runs anything other than scripts/gate.sh or an exact line from
# scripts/ci-allowed-setup.txt. Multi-line `run: |` blocks are refused (fail closed).
# Usage: sh scripts/ci-gate-check.sh [workflow.yml]   (default .github/workflows/ci.yml)
set -eu
cd "$(dirname "$0")/.."
wf=${1:-.github/workflows/ci.yml}
allow=scripts/ci-allowed-setup.txt
[ -f "$wf" ] || { echo "FAIL ci-gate: no $wf"; exit 1; }
# Every workflow must parse as YAML (a flow mapping holding ${{ }} once killed CI at the workflow level).
for y in .github/workflows/*.yml; do
  python3 -c 'import sys, yaml; d = yaml.safe_load(open(sys.argv[1])); assert isinstance(d, dict) and "jobs" in d, "no jobs"' "$y" 2>"${TMPDIR:-/tmp}/ci-yaml.$$" \
    || { echo "FAIL ci-gate: $y is not valid workflow YAML: $(tail -n 2 "${TMPDIR:-/tmp}/ci-yaml.$$" | tr '\n' ' ')"; rm -f "${TMPDIR:-/tmp}/ci-yaml.$$"; exit 1; }  # rule:G-yaml
  if command -v actionlint >/dev/null 2>&1; then actionlint "$y" || { echo "FAIL ci-gate: actionlint $y"; exit 1; }; fi
done
rm -f "${TMPDIR:-/tmp}/ci-yaml.$$"
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
if grep -qE '^[[:space:]]*-?[[:space:]]*run:[[:space:]]*sh scripts/gate.sh \$\{\{ matrix.stage \}\}$' "$wf"; then
  # staged: the matrix must list exactly gate.sh's stages, so no stage (check) can be dropped in CI
  want=$(sh scripts/gate.sh --list | tr ' ' '\n' | sort | tr '\n' ' ')
  got=$(sed -n 's/^[[:space:]]*stage:[[:space:]]*\[\(.*\)\][[:space:]]*$/\1/p' "$wf" | tr -d ' ' | tr ',' '\n' | sort | tr '\n' ' ')
  [ "$want" = "$got" ] || { echo "FAIL ci-gate: $wf stage matrix [$got] != gate.sh --list [$want]"; rc=1; }  # rule:G-stages
elif ! grep -qE '^[[:space:]]*-?[[:space:]]*run:[[:space:]]*sh scripts/gate.sh$' "$wf"; then
  echo "FAIL ci-gate: $wf never runs scripts/gate.sh"; rc=1
fi
[ $rc = 0 ] && echo "ok   ci-gate: $wf runs only gate.sh + $((n-1)) setup steps"
exit $rc
