#!/bin/sh
# Enforces docs/FINDINGS.md: every fixed finding has a commit (ancestor of HEAD) and a guard file
# that carries the token finding:<id>. Open findings are printed. Unknown statuses fail.
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
export LC_ALL=C
cd "$(dirname "$0")/.."
# A shallow clone (CI checkout default fetch-depth 1) has no history, so every fixed-in check would
# misreport. Refuse up front with the real cause.
[ "$(git rev-parse --is-shallow-repository 2>/dev/null)" != true ] || { echo "FAIL findings: shallow clone, commit history unavailable (use actions/checkout fetch-depth: 0 or git fetch --unshallow)"; exit 1; }  # rule:F-shallow
F=${1:-docs/FINDINGS.md}
[ -f "$F" ] || { echo "FAIL findings: no $F"; exit 1; }  # rule:F-file
rc=0; nf=0; no=0
rows=$(grep -E '^\| [A-Z][0-9]+-[0-9]+ \|' "$F" || [ $? -eq 1 ])
[ -n "$rows" ] || { echo "FAIL findings: no rows in $F"; exit 1; }  # rule:F-rows
dups=$(printf '%s\n' "$rows" | awk -F'|' '{gsub(/ /,"",$2); print $2}' | sort | uniq -d)
[ -z "$dups" ] || { echo "FAIL findings: duplicate ids: $dups"; rc=1; }  # rule:F-dup
printf '%s\n' "$rows" | awk -F'|' '{for(i=2;i<=6;i++){gsub(/^ +| +$/,"",$i)}; print $2 "\t" $4 "\t" $5 "\t" $6}' > "${TMPDIR:-/tmp}/findings.$$"
while IFS="$(printf '\t')" read -r id st c g; do
  case "$st" in
    fixed) nf=$((nf+1))
      [ "$c" != - ] && git merge-base --is-ancestor "$c" HEAD 2>/dev/null || { echo "FAIL findings: $id fixed-in '$c' is not a commit in HEAD's history"; rc=1; }  # rule:F-commit
      [ "$g" != - ] && [ -f "$g" ] || { echo "FAIL findings: $id is fixed but has no guard file ('$g')"; rc=1; continue; }  # rule:F-guard
      grep -qF "finding:$id" "$g" || { echo "FAIL findings: guard $g does not carry finding:$id"; rc=1; } ;;  # rule:F-token
    open) no=$((no+1)); echo "open $id" ;;
    *) echo "FAIL findings: $id has unknown status '$st'"; rc=1 ;;  # rule:F-status
  esac
done < "${TMPDIR:-/tmp}/findings.$$"
rm -f "${TMPDIR:-/tmp}/findings.$$"
[ $rc = 0 ] && echo "findings ok ($nf fixed and guarded, $no open)"
exit $rc
