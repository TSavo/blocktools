#!/bin/sh
# Repo hygiene (security review 2026-10-25): actions pinned by commit SHA, no build artifacts tracked,
# release publishing behind an environment.
set -eu
export LC_ALL=C
cd "$(dirname "$0")/.."
rc=0
bad=$(grep -hE '^\s*-?\s*uses:' .github/workflows/*.yml | grep -vE 'uses: [^@]+@[0-9a-f]{40}( |$)' || true)
[ -z "$bad" ] || { echo "FAIL unpinned actions:"; echo "$bad"; rc=1; }
art=$(git ls-files | grep -E '\.(whl|tar\.gz|zip|so|dylib|exe)$' || true)
[ -z "$art" ] || { echo "FAIL tracked build artifacts:"; echo "$art"; rc=1; }
grep -q 'environment: release' .github/workflows/release.yml || { echo "FAIL release publish has no environment"; rc=1; }
[ $rc = 0 ] && echo "hygiene ok"
exit $rc
