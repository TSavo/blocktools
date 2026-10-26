#!/bin/sh
# One version: the workspace Cargo.toml. Fails if bindings/wasm (Cargo.toml, package.json), any
# internal path-dep pin, a man page header or a packaging script disagrees or hardcodes a version.
# With a tag argument (release.yml passes $GITHUB_REF_NAME) it also fails unless tag = v<version>.
#   sh scripts/version-check.sh [vX.Y.Z]
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd); cd "$root"
v=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
[ -n "$v" ] || { echo "FAIL version-check: no version in Cargo.toml"; exit 1; }
rc=0
w=$(sed -n 's/^version = "\(.*\)"/\1/p' bindings/wasm/Cargo.toml | head -1); [ "$w" = "$v" ] || { echo "FAIL version-check: bindings/wasm/Cargo.toml $w != $v"; rc=1; }
p=$(python3 -c 'import json;print(json.load(open("bindings/wasm/package.json"))["version"])'); [ "$p" = "$v" ] || { echo "FAIL version-check: package.json $p != $v"; rc=1; }
bad=$(git ls-files '*Cargo.toml' | xargs grep -nE 'path *= *"' | grep -E 'version *= *"' | grep -v "version = \"$v\"" || [ $? -eq 1 ])
[ -z "$bad" ] || { echo "FAIL version-check: internal pins not $v:"; echo "$bad"; rc=1; }
bad=$(grep -L "\"blocktools $v\"" man/man1/*.1 man/man7/*.7 || [ $? -eq 1 ])
[ -z "$bad" ] || { echo "FAIL version-check: man headers not $v: $bad"; rc=1; }
bad=$(grep -nE '[0-9]+\.[0-9]+\.[0-9]+-(1|r0)|^ver=[0-9]' scripts/package-native.sh scripts/package-test.sh scripts/package-dist.sh 2>/dev/null || [ $? -eq 1 ])
[ -z "$bad" ] || { echo "FAIL version-check: packaging scripts hardcode a version:"; echo "$bad"; rc=1; }
if [ $# -gt 0 ]; then [ "$1" = "v$v" ] || { echo "FAIL version-check: tag $1 != v$v"; rc=1; }; fi
[ $rc -eq 0 ] && echo "ok   version-check: $v everywhere${1:+, tag $1}"
exit $rc
