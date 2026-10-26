#!/bin/sh
# Docs-versus-code checks that can be automated (security review 2026-10-25).
set -eu
# pipefail where the shell has it (dash >= 0.5.11, bash); a shell without it just lacks the extra check
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
export LC_ALL=C
cd "$(dirname "$0")/.."
rc=0; D="README.md DESIGN.md docs/SECURITY.md"
# 1. every tool is documented somewhere in README/DESIGN/EXPORTS/recipes
for t in tools/*/; do n=$(basename "$t")
  grep -qw -- "$n" README.md DESIGN.md EXPORTS.md docs/*.md recipes/*.md 2>/dev/null || { echo "FAIL tool $n not documented"; rc=1; }
done
# 2. no hand-written test counts (they go stale; CI is the source of truth)
if grep -nEi '[0-9]+ (rust )?(unit )?tests pass|[0-9]+ end-to-end checks' $D; then echo "FAIL hard-coded test counts above"; rc=1; fi
# 3. a built tool is never called "planned"
for t in tools/*/; do n=$(basename "$t")
  if grep -nE "\*\*$n\*\* \(planned" $D; then echo "FAIL $n exists but is called planned"; rc=1; fi
done
# 4. host-side network tools are never shipped in the sealed image or allowed by sealed-run
for n in utxo-fetch tx-broadcast xmr-wallet; do
  grep -q "$n" Dockerfile || { echo "FAIL Dockerfile does not exclude $n"; rc=1; }
  grep -q "\"$n\"" tools/sealed-run/src/main.rs && { echo "FAIL sealed-run allows $n"; rc=1; }
done
# 5. "never hand-rolled" claims must not coexist with in-tree crypto unless SECURITY.md lists it
if grep -qiE 'never hand-roll' $D && grep -q 'fn scrypt_raw' crates/secrets/src/keystore.rs && ! grep -q 'scrypt_raw' docs/SECURITY.md; then
  echo "FAIL in-tree scrypt_raw not disclosed in SECURITY.md"; rc=1; fi
# 6. man pages are generated from --help + doc headers and must be current (needs release binaries)
python3 scripts/gen-man.py --check || rc=1

# 7. first-class docs guides exist and are non-empty
for f in docs/DOCS-READINESS.md docs/getting-started.md docs/cookbook.md docs/troubleshooting.md docs/library-api.md bindings/wasm/README.md; do
  [ -s "$f" ] || { echo "FAIL missing or empty $f"; rc=1; }
done
# 8. every man1 page has the required section headers (names may contain spaces)
while IFS= read -r s; do
  [ -n "$s" ] || continue
  for m in man/man1/*.1; do
    grep -q "^\.SH $s$" "$m" || { echo "FAIL $m missing .SH $s"; rc=1; }
  done
done <<'SECTIONS'
NAME
SYNOPSIS
DESCRIPTION
OPTIONS
INPUT/OUTPUT
EXIT STATUS
EXAMPLES
SECURITY NOTES
SEE ALSO
SECTIONS
grep -q '^\.SH NAME$' man/man7/blocktools.7 || { echo "FAIL man7 missing NAME"; rc=1; }
# 9. packaging scripts install man pages under share/man
grep -q 'share/man' scripts/package-dist.sh || { echo "FAIL package-dist missing share/man"; rc=1; }
grep -q 'share/man' scripts/package-native.sh || { echo "FAIL package-native missing share/man"; rc=1; }
[ $rc = 0 ] && echo "docs-check ok"
exit $rc
