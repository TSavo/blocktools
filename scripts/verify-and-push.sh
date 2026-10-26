#!/bin/sh
# Lint locally, push, then wait for CI's verdict. The heavy stages (test, negatives, e2e) run on the four
# Battleaxe runners in parallel; before 2026-10-26 this script ran all four stages serially on the agent's
# machine and CI repeated them, so every push cost the agent the whole gate twice.
#   scripts/verify-and-push.sh "commit message"     lint stage here, commit, push main, wait for CI (default)
#   GATE=full scripts/verify-and-push.sh "msg"       every stage here before pushing (the old behaviour)
#   WAIT=0    scripts/verify-and-push.sh "msg"       push and return without waiting for CI
#   scripts/verify-and-push.sh --wait [SHA]          only wait for CI on SHA (default HEAD) and report
# Stage changes by explicit path first (`git add path...`); this script never stages anything.
# Exit codes: 0 pushed and CI green; 1 a gate stage or CI failed; 2 usage / not on main; 3 CI gave no verdict
# (cancelled by a newer push, or not finished after 30 min).
set -eu
# pipefail where the shell has it (dash >= 0.5.11, bash); a shell without it just lacks the extra check
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
# Expects cargo and node on PATH; gh (GitHub CLI, logged in) for the CI wait.

wait_ci() {  # wait_ci SHA: poll the ci workflow run for SHA; print its verdict and the failing lines.
  sha=$1
  command -v gh >/dev/null 2>&1 || { echo "verify-and-push: gh not installed; CI runs at https://github.com/TSavo/blocktools/actions (commit $sha)"; return 3; }
  i=0; url=""
  while [ $i -lt 90 ]; do  # 90 x 20 s = 30 min
    line=$(gh api -X GET repos/{owner}/{repo}/actions/runs -f head_sha="$sha" -f event=push \
      --jq '[.workflow_runs[] | select(.name == "ci")] | .[0] | [.status // "", .conclusion // "", .html_url // "", (.id // "" | tostring)] | @tsv' 2>/dev/null || true)  # allow-true: a transient API error is retried on the next poll
    status=$(printf '%s' "$line" | cut -f1); concl=$(printf '%s' "$line" | cut -f2); url=$(printf '%s' "$line" | cut -f3); id=$(printf '%s' "$line" | cut -f4)
    if [ "$status" = completed ]; then
      case "$concl" in
        success) echo "verify-and-push: CI green  $url"; return 0;;
        cancelled) echo "verify-and-push: CI cancelled (a newer push superseded $sha; no verdict for this commit)  $url"; return 3;;
        *) echo "verify-and-push: CI $concl  $url"
           gh api "repos/{owner}/{repo}/actions/runs/$id/jobs" --jq '.jobs[] | select(.conclusion != "success" and .conclusion != null) | "  job \(.name): \(.conclusion)"' 2>/dev/null || true  # allow-true: diagnostics only; the verdict above already failed
           # --log-failed lines are "job<TAB>step<TAB>timestamp message": drop the prefix, keep FAIL/error lines once each
           gh run view "$id" --log-failed 2>/dev/null | cut -f3- | sed 's/^[0-9][0-9-]*T[0-9:.]*Z //' \
             | grep -E '(^|[^_A-Z])FAIL( |:|$)|gate FAILED|##\[error\]|panicked at|^error(\[E[0-9]+\]|:)' | awk '!seen[$0]++' | sed -n 1,40p || true  # allow-true: diagnostics only; grep finds nothing on an unusual log
           return 1;;
      esac
    fi
    [ $i = 0 ] && echo "verify-and-push: waiting for CI on $sha (${status:-not queued yet}; WAIT=0 skips this)"
    sleep 20; i=$((i+1))
  done
  echo "verify-and-push: CI not finished after 30 min  ${url:-https://github.com/TSavo/blocktools/actions}"; return 3
}

if [ "${1:-}" = --wait ]; then wait_ci "$(git rev-parse "${2:-HEAD}")"; exit $?; fi
[ $# = 1 ] || { echo "usage: $0 MESSAGE | $0 --wait [SHA]" >&2; exit 2; }
# Must be on main: a detached HEAD would commit locally while `git push origin main` pushes nothing new.
[ "$(git symbolic-ref -q HEAD)" = refs/heads/main ] || { echo "verify-and-push: not on branch main (detached HEAD?)" >&2; exit 2; }
case "${GATE:-lint}" in
  full) sh scripts/gate.sh;;
  lint) sh scripts/gate.sh lint;;
  *) echo "verify-and-push: GATE must be lint or full" >&2; exit 2;;
esac
git commit -qm "$1"
git push -q origin HEAD:refs/heads/main
[ "$(git rev-parse HEAD)" = "$(git ls-remote origin refs/heads/main | cut -f1)" ] || { echo "verify-and-push: remote main is not HEAD after push" >&2; exit 1; }
git log --oneline -1
[ "${WAIT:-1}" = 0 ] && exit 0
wait_ci "$(git rev-parse HEAD)"
