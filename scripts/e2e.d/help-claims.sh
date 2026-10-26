#!/bin/sh
# Every tool's --help claim matches the sealed-run allowlist (crates/io/sealed-tools.txt) and the host-tool
# list (crates/io/host-tools.txt): each built tool is in exactly one list; allowlisted tools say "run it
# sealed" and sealed-run accepts them; host tools say they cannot run sealed and sealed-run refuses them
# (unsupported, exit 2); the Dockerfile ships exactly the allowlist.
set -eu
B=${BIN:-target/release}; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
f() { echo "FAIL help-claims: $1"; exit 1; }
grep -v '^#' crates/io/sealed-tools.txt | sort > $T/sealed
grep -v '^#' crates/io/host-tools.txt | cut -d' ' -f1 | sort > $T/host
for d in tools/*/Cargo.toml; do basename "$(dirname "$d")"; done | sort > $T/all
[ -z "$(comm -12 $T/sealed $T/host)" ] || f "in both lists: $(comm -12 $T/sealed $T/host | tr '\n' ' ')"
sort $T/sealed $T/host > $T/listed; echo sealed-run >> $T/listed; sort -o $T/listed $T/listed
[ "$(cat $T/all)" = "$(cat $T/listed)" ] || f "tools vs lists differ: $(comm -3 $T/all $T/listed | tr '\n\t' '  ')"
n=0
while read -r t; do
  h=$("$B/$t" --help) || f "$t --help failed"
  echo "$h" | grep -q UNCLASSIFIED && f "$t unclassified"
  o=$("$B/sealed-run" agent "$t --help" </dev/null 2>&1) && rc=0 || rc=$?
  if grep -qx "$t" $T/sealed; then
    echo "$h" | grep -q "run it sealed and offline" || f "$t is allowlisted but --help does not say run it sealed"
    echo "$o" | grep -q '"status":"unsupported"' && f "sealed-run refuses allowlisted $t"
  else
    echo "$h" | grep -q "sealed-run refuses it" || f "$t is a host tool but --help does not say sealed-run refuses it"
    echo "$h" | grep -q "run it sealed" && f "$t is a host tool but --help says run it sealed"
    { [ $rc = 2 ] && echo "$o" | grep -q '"status":"unsupported"'; } || f "sealed-run ran host tool $t (rc=$rc)"
  fi
  n=$((n+1))
done <<EOT
$(grep -vx sealed-run $T/all)
EOT
"$B/sealed-run" --help | grep -q "This is the sealed boundary" || f "sealed-run --help"
grep -q 'for n in sealed-run $(grep -v .^#. crates/io/sealed-tools.txt)' Dockerfile || f "Dockerfile does not ship exactly crates/io/sealed-tools.txt"
echo "ok   help-claims: $n tools; --help sealed/host claim matches the sealed-run allowlist; Dockerfile ships the allowlist"
