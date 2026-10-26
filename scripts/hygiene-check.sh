#!/bin/sh
# Repo hygiene (security review 2026-10-25): actions pinned by commit SHA, no build artifacts tracked,
# release publishing behind an environment.
set -eu
# pipefail where the shell has it (dash >= 0.5.11, bash); a shell without it just lacks the extra check
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
export LC_ALL=C
cd "$(dirname "$0")/.."
rc=0
bad=$(grep -hE '^[[:space:]]*-?[[:space:]]*uses:' .github/workflows/*.yml | grep -vE 'uses: [^@]+@[0-9a-f]{40}( |$)' || [ $? -eq 1 ])
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

# Portable shell: reject known GNU/BSD skew that broke Mac e2e.
# Patterns below intentionally avoid naming the banned tokens in comments/messages so this file is self-clean.
# wc: string-equality against a decimal (BSD pads with spaces). Prefer arithmetic or -eq/-ge.
# POSIX classes only ([[:space:]], never \s): macOS git grep -E does not know \s, which made this inert there.
WC_PAT='\[[[:space:]]+"\$\(wc [^]]+\)"[[:space:]]*=[[:space:]]*[0-9]+'
SED_PAT='(^|[^[:alnum:]_-])sed[[:space:]]+-i[[:space:]]+[^[:space:]'\''"]'
# Self-test: each rule must fire on a planted bad line via the same git grep engine (property, not the word).
st=$(mktemp -d); w=wc; sd=sed
printf '[ "$(%s -l < f)" = 100 ]\n' "$w" > "$st/a"; printf '%s -i s/a/b/ f\n' "$sd" > "$st/b"
(cd "$st" && git grep --no-index -qE "$WC_PAT" -- a) || { echo "FAIL hygiene self-test: wc rule does not match on this git"; rc=1; }
(cd "$st" && git grep --no-index -qE "$SED_PAT" -- b) || { echo "FAIL hygiene self-test: sed rule does not match on this git"; rc=1; }
rm -rf "$st"
bad=$(git grep -nE "$WC_PAT" -- scripts recipes ':!scripts/hygiene-check.sh' || [ $? -eq 1 ])
[ -z "$bad" ] || { echo "FAIL BSD-unsafe wc string compare (use arithmetic \$((\$(wc …))) or -eq):"; echo "$bad"; rc=1; }
# in-place sed without backup ext (BSD needs an empty ext arg or a .bak suffix).
bad=$(git grep -nE "$SED_PAT" -- scripts recipes ':!scripts/hygiene-check.sh' || [ $? -eq 1 ])
[ -z "$bad" ] || { echo "FAIL GNU-only in-place sed (use a .bak suffix or a temp file):"; echo "$bad"; rc=1; }
bad=$(git grep -nE 'readlink[[:space:]]+-f[[:space:]]' -- scripts recipes ':!scripts/hygiene-check.sh' || [ $? -eq 1 ])
[ -z "$bad" ] || { echo "FAIL GNU-only readlink -f:"; echo "$bad"; rc=1; }
# bare GNU stat format without a BSD fallback on the same line (e2e-only/portable.sh is exempt).
bad=$(git grep -nE 'stat[[:space:]]+-c' -- scripts recipes ':!scripts/hygiene-check.sh' | grep -vE 'stat -f|allow-bsd:|portable\.sh' || [ $? -eq 1 ])
[ -z "$bad" ] || { echo "FAIL GNU-only stat -c (pair with stat -f or # allow-bsd:):"; echo "$bad"; rc=1; }
[ $rc = 0 ] && echo "hygiene ok"
exit $rc
