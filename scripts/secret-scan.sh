#!/bin/sh
# Pre-push scan of tracked files for key-shaped strings that are NOT known public test vectors.
# Every allowed hit must carry the marker "public test vector" / "throwaway" on the same or the previous line,
# or be listed in scripts/public-vectors.txt.
set -eu
cd "$(dirname "$0")/.."
pat='xprv[1-9A-HJ-NP-Za-km-z]{100,}|\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b|\b[0-9a-f]{64}\b'
hits=$(git ls-files -co --exclude-standard | grep -vE '^(scripts/public-vectors.txt|Cargo.lock)$' | xargs grep -EnoI "$pat" 2>/dev/null || true)
rc=0
echo "$hits" | while IFS= read -r h; do
  [ -n "$h" ] || continue
  v=${h##*:}
  grep -qxF "$v" scripts/public-vectors.txt 2>/dev/null || { echo "UNLISTED secret-shaped string: $h"; exit 1; }
done || rc=1
grep -rInE "/Users/|/home/[a-z]+/|@gmail|\.local\b" $(git ls-files -co --exclude-standard) | grep -v "^scripts/secret-scan.sh" && { echo "personal path/email found"; rc=1; }
[ $rc = 0 ] && echo "secret-scan ok"
exit $rc
