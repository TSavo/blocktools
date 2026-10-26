#!/bin/sh
# Pre-push check (review G, 2026-10-25). Changes are staged by explicit path, never `git add -A`.
# Fails on: untracked, non-ignored files (stage them by name or .gitignore them); unstaged edits
# to tracked files (the commit would not be what was tested); any tracked or staged binary file;
# any tracked file over 2 MB.
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
export LC_ALL=C
cd "$(dirname "$0")/.."
rc=0
u=$(git ls-files -o --exclude-standard)
[ -z "$u" ] || { echo "FAIL untracked files (stage by explicit path or .gitignore):"; echo "$u"; rc=1; }  # rule:P-untracked
git diff --quiet || { echo "FAIL unstaged changes to tracked files:"; git diff --name-only; rc=1; }  # rule:P-unstaged
for f in $(git ls-files); do
  [ -f "$f" ] || continue
  s=$(wc -c < "$f")
  [ "$s" -le 2097152 ] || { echo "FAIL large file ($s bytes): $f"; rc=1; }  # rule:P-large
  [ "$s" -eq 0 ] || grep -qI . "$f" || { echo "FAIL binary file tracked: $f"; rc=1; }  # rule:P-binary
done
[ $rc = 0 ] && echo "prepush ok"
exit $rc
