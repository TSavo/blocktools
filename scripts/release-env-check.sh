#!/bin/sh
# finding:R2-6: the release workflow may publish only when its "release" environment restricts
# deployments to version tags: deployment_branch_policy.custom_branch_policies on, protected_branches
# off, and every deployment policy is a tag policy whose pattern starts with "v" (no branch policy,
# so no branch or PR ref can deploy). Required reviewers are not required (T, 2026-10-26: no manual
# approval click). Asks GitHub (gh api), fails closed: no environment, no policy, a branch policy, a
# non-v tag pattern, or an API error all refuse. release.yml runs this before publish; run it by
# hand to see the live setting:  sh scripts/release-env-check.sh [OWNER/REPO]
set -eu
GH=${BLOCKTOOLS_GH:-gh}
repo=${1:-${GH_REPO:-$($GH repo view --json nameWithOwner --jq .nameWithOwner)}}
env=${BLOCKTOOLS_RELEASE_ENV:-release}
j=$($GH api "repos/$repo/environments/$env") || { echo "FAIL release-env: cannot read environment '$env' of $repo (missing, or token lacks access)"; exit 1; }  # rule:R-env neg-exempt: needs the GitHub API; planted by stub gh in scripts/e2e.d/release-env.sh
p=$($GH api "repos/$repo/environments/$env/deployment-branch-policies") || { echo "FAIL release-env: cannot read deployment policies of '$env'"; exit 1; }  # rule:R-env neg-exempt: needs the GitHub API; planted by stub gh in scripts/e2e.d/release-env.sh
r=$(printf '%s\n%s' "$j" "$p" | python3 -c '
import json,sys
a,b=sys.stdin.read().split("\n",1)
d=json.loads(a); pol=d.get("deployment_branch_policy")
if not pol or not pol.get("custom_branch_policies") or pol.get("protected_branches"): print("no custom tag-only deployment policy"); sys.exit()
ps=json.loads(b).get("branch_policies") or []
if not ps: print("custom policy has no entries"); sys.exit()
for x in ps:
    if x.get("type")!="tag": print("policy %r is not a tag policy" % x.get("name")); sys.exit()
    if not str(x.get("name","")).startswith("v"): print("tag policy %r does not start with v" % x.get("name")); sys.exit()
print("ok " + ",".join(x["name"] for x in ps))') || { echo "FAIL release-env: unreadable API response"; exit 1; }  # rule:R-env neg-exempt: needs the GitHub API; planted by stub gh in scripts/e2e.d/release-env.sh
case $r in ok\ *) ;; *) echo "FAIL release-env: environment '$env' of $repo: $r; a non-tag ref could publish (Settings -> Environments -> $env -> Deployment branches and tags: tag v*)"; exit 1;; esac  # rule:R-reviewers neg-exempt: needs the GitHub API; planted by stub gh in scripts/e2e.d/release-env.sh
echo "ok   release-env: '$env' of $repo deploys only from tags (${r#ok })"
