#!/bin/sh
# Repo hygiene (security review 2026-10-25): actions pinned by commit SHA, no build artifacts tracked,
# release publishing behind an environment.
set -eu
# pipefail where the shell has it (dash >= 0.5.11, bash); a shell without it just lacks the extra check
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
export LC_ALL=C
cd "$(dirname "$0")/.."
rc=0
bad=$(grep -hE '^\s*-?\s*uses:' .github/workflows/*.yml | grep -vE 'uses: [^@]+@[0-9a-f]{40}( |$)' || [ $? -eq 1 ])
[ -z "$bad" ] || { echo "FAIL unpinned actions:"; echo "$bad"; rc=1; }
art=$(git ls-files | grep -E '\.(whl|tar\.gz|zip|so|dylib|exe)$' || [ $? -eq 1 ])
[ -z "$art" ] || { echo "FAIL tracked build artifacts:"; echo "$art"; rc=1; }
grep -q 'environment: release' .github/workflows/release.yml || { echo "FAIL release publish has no environment"; rc=1; }
# Swallowed errors: every `|| true` / `|| :` in a script needs an `allow-true:` reason on its line.
sw=$(git ls-files 'scripts/*.sh' 'scripts/**/*.sh' 'recipes/*.sh' | xargs grep -nE '\|\|[[:space:]]*(true|:)([[:space:];)]|$)' | grep -v 'allow-true:' || [ $? -eq 1 ])
[ -z "$sw" ] || { echo "FAIL unjustified || true (add '# allow-true: reason' or make it fail loudly):"; echo "$sw"; rc=1; }
# Strict mode: every script runs with set -eu.
for f in $(git ls-files 'scripts/*.sh' 'scripts/**/*.sh' 'recipes/*.sh'); do
  grep -qE '^set -eu' "$f" || { echo "FAIL $f: no 'set -eu'"; rc=1; }
done
[ $rc = 0 ] && echo "hygiene ok"
exit $rc
