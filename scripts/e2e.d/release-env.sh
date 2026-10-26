# finding:R2-6: release-env-check.sh, with a stub gh: no policy, protected-branches policy, empty
# custom policy, a branch policy, a non-v tag, a mixed tag+branch list and API errors are refused;
# a tag-only v* policy passes. The live repo setting is not tested here (release.yml runs it).
set -eu
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
printf '#!/bin/sh\ncase "$2" in */deployment-branch-policies) f=$STUB.p;; *) f=$STUB;; esac\n[ -s "$f" ] || exit 1\ncat "$f"\n' > $T/gh; chmod +x $T/gh
chk() { STUB=$T/j BLOCKTOOLS_GH=$T/gh sh scripts/release-env-check.sh o/r; }
C='{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
bad() { printf '%s' "$1" > $T/j; printf '%s' "$2" > $T/j.p; chk >/dev/null && { echo "FAIL release-env accepted: $3"; exit 1; }; :; }
bad '{"deployment_branch_policy":null,"protection_rules":[{"type":"required_reviewers","reviewers":[{"reviewer":{"login":"x"}}]}]}' '{"branch_policies":[]}' "no policy (reviewers only)"
bad '{"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}' '{"branch_policies":[]}' "protected branches"
bad "$C" '{"branch_policies":[]}' "empty custom policy"
bad "$C" '{"branch_policies":[{"name":"main","type":"branch"}]}' "branch policy"
bad "$C" '{"branch_policies":[{"name":"v*","type":"branch"}]}' "v* branch policy"
bad "$C" '{"branch_policies":[{"name":"*","type":"tag"}]}' "non-v tag pattern"
bad "$C" '{"branch_policies":[{"name":"v*","type":"tag"},{"name":"*","type":"branch"}]}' "tag plus branch"
bad '' '{"branch_policies":[{"name":"v*","type":"tag"}]}' "environment API error"
bad "$C" '' "policies API error"
printf '%s' "$C" > $T/j; echo '{"branch_policies":[{"name":"v*","type":"tag"}]}' > $T/j.p
chk | grep -q "deploys only from tags (v\*)" || { echo "FAIL release-env refused a v* tag-only policy"; exit 1; }
echo "ok   release-env: no-policy, branch, non-v, mixed and API-error cases refused; v* tag-only passes"
