# finding:R2-6: release-env-check.sh, with a stub gh: no rule, empty reviewers and an API error are
# refused; one required reviewer passes. The live repo setting is not tested here (release.yml runs it).
set -eu
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
printf '#!/bin/sh\n[ -s "$STUB" ] || exit 1\ncat "$STUB"\n' > $T/gh; chmod +x $T/gh
chk() { STUB=$T/j BLOCKTOOLS_GH=$T/gh sh scripts/release-env-check.sh o/r; }
echo '{"name":"release","protection_rules":[]}' > $T/j
chk >/dev/null && { echo "FAIL release-env accepted no protection rules"; exit 1; }
echo '{"protection_rules":[{"type":"required_reviewers","reviewers":[]}]}' > $T/j
chk >/dev/null && { echo "FAIL release-env accepted zero reviewers"; exit 1; }
: > $T/j; chk >/dev/null && { echo "FAIL release-env accepted an API error"; exit 1; }
echo '{"protection_rules":[{"type":"wait_timer","wait_timer":5},{"type":"required_reviewers","reviewers":[{"type":"User","reviewer":{"login":"x"}}]}]}' > $T/j
chk | grep -q "requires review (1 reviewer" || { echo "FAIL release-env refused one required reviewer"; exit 1; }
echo "ok   release-env: unprotected, empty-reviewer and API-error cases refused; one reviewer passes"
