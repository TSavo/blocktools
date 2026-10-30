#!/bin/sh
# Every CLI the release tarball ships must be in scripts/package-native.sh CLIS, else the release `repos` job
# fails after the GitHub release is already published (v0.3.0: bolt11 et al. missing, release run 40848964388).
# This is the one copy of that guard: release-repos.sh calls it on the release tarball's bin/, and the gate
# (lint) calls it with no argument, which builds the same tarball (scripts/package-dist.sh) from BIN.
#   sh scripts/clis-check.sh [BINDIR]
set -eu
cd "$(dirname "$0")/.."
clis=$(sed -n 's/^CLIS="\(.*\)"/\1/p' scripts/package-native.sh)
[ -n "$clis" ] || { echo "FAIL clis-check: no CLIS= line in scripts/package-native.sh"; exit 1; }
tmp=
if [ $# -gt 0 ]; then bindir=$1
else
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
  DIST_OUT="$tmp/dist" sh scripts/package-dist.sh clis-check >/dev/null
  mkdir "$tmp/x" && tar -C "$tmp/x" -xzf "$tmp/dist/clis-check.tar.gz"
  bindir=$tmp/x/clis-check/bin
fi
[ -d "$bindir" ] || { echo "FAIL clis-check: no bin dir $bindir"; exit 1; }
rc=0; n=0
for f in "$bindir"/*; do
  [ -e "$f" ] || { echo "FAIL clis-check: $bindir is empty"; exit 1; }
  b=$(basename "$f"); n=$((n+1))
  case " $clis " in *" $b "*) ;; *) echo "FAIL clis-check: $b ships in the tarball but is not in package-native.sh CLIS"; rc=1;; esac  # rule:R-clis
done
[ $rc -eq 0 ] && echo "ok   clis-check: all $n tarball CLIs are in package-native.sh CLIS"
exit $rc
