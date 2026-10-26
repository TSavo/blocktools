#!/bin/sh
# Pre-push scan of tracked files for key-shaped strings that are NOT known public test vectors.
# Every allowed hit must carry the marker "public test vector" / "throwaway" on the same or the previous line,
# or be listed in scripts/public-vectors.txt. bip341-wallet.json is a verbatim copy of
# bitcoin/bips bip-0341/wallet-test-vectors.json (public) and is skipped whole.
set -eu
# pipefail where the shell has it (dash >= 0.5.11, bash); a shell without it just lacks the extra check
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
cd "$(dirname "$0")/.."
pat='xprv[1-9A-HJ-NP-Za-km-z]{100,}|\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b|\b[0-9a-f]{64}\b'
# git grep: exit 1 = no match (fine), anything higher = error (fatal). Needs git built with PCRE (for \b).
hits=$(git grep -PnoI --untracked --exclude-standard -e "$pat" -- . ':!scripts/public-vectors.txt' ':!Cargo.lock' ':!bindings/wasm/Cargo.lock' ':!crates/tx/tests/vectors/bip341-wallet.json' || [ $? -eq 1 ])
rc=0
echo "$hits" | while IFS= read -r h; do
  [ -n "$h" ] || continue
  v=${h##*:}
  grep -qxF "$v" scripts/public-vectors.txt 2>/dev/null || { echo "UNLISTED secret-shaped string: $h"; exit 1; }  # rule:S-key
done || rc=1  # rule:S-key
grep -rInE "/Users/|/home/[a-z]+/|@gmail|\.local\b" $(git ls-files -co --exclude-standard) | grep -v "^scripts/secret-scan.sh" && { echo "personal path/email found"; rc=1; }  # rule:S-path
# No wallet-like files in the repo (fixtures are generated at test time; see docs/FIXTURES.md).  # rule:S-walletname
for f in $(git ls-files -co --exclude-standard); do
  case "${f##*/}" in
    *.dat|*.sqlite|*.sqlite3|*.db|*.wallet|*.key|*.keys|*.aes.json|UTC--*|wallet*|*keystore*.json|*.bdb) echo "wallet-like file name: $f"; rc=1; continue ;;  # rule:S-walletname
  esac
  [ -f "$f" ] || continue
  [ "$(wc -c < "$f")" -ge 16 ] || continue   # too short to carry either magic (od would fail)
  if [ "$(head -c 15 "$f")" = "SQLite format 3" ]; then echo "SQLite file: $f"; rc=1; fi  # rule:S-sqlite
  m=$(od -An -tx1 -j12 -N4 "$f" | tr -d ' \n')
  case "$m" in 62310500|00053162) echo "Berkeley DB file: $f"; rc=1 ;; esac  # rule:S-bdb
done
[ $rc = 0 ] && echo "secret-scan ok"
exit $rc
