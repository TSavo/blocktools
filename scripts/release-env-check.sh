#!/bin/sh
# finding:R2-6: the release workflow may publish only when its "release" environment has a
# required-reviewers protection rule with at least one reviewer. Asks GitHub (gh api), fails closed:
# no environment, no rule, no reviewers, or an API error all refuse. release.yml runs this before
# publish; run it by hand to see the live setting:  sh scripts/release-env-check.sh [OWNER/REPO]
set -eu
GH=${BLOCKTOOLS_GH:-gh}
repo=${1:-${GH_REPO:-$($GH repo view --json nameWithOwner --jq .nameWithOwner)}}
env=${BLOCKTOOLS_RELEASE_ENV:-release}
j=$($GH api "repos/$repo/environments/$env") || { echo "FAIL release-env: cannot read environment '$env' of $repo (missing, or token lacks access)"; exit 1; }  # rule:R-env neg-exempt: needs the GitHub API; planted by stub gh in scripts/e2e.d/release-env.sh
n=$(printf '%s' "$j" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(sum(len(r.get("reviewers") or []) for r in d.get("protection_rules") or [] if r.get("type")=="required_reviewers"))') \
  || { echo "FAIL release-env: unreadable API response"; exit 1; }  # rule:R-env neg-exempt: needs the GitHub API; planted by stub gh in scripts/e2e.d/release-env.sh
[ "$n" -gt 0 ] || { echo "FAIL release-env: environment '$env' of $repo has no required reviewers; a tag push would publish unreviewed (Settings -> Environments -> $env -> Required reviewers)"; exit 1; }  # rule:R-reviewers neg-exempt: needs the GitHub API; planted by stub gh in scripts/e2e.d/release-env.sh
echo "ok   release-env: '$env' of $repo requires review ($n reviewer(s))"
