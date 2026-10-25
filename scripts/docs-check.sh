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
[ $rc = 0 ] && echo "docs-check ok"
exit $rc
