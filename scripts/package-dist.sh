#!/bin/sh
# Build linux dist tarball (same shape as .github/workflows/release.yml).
# Usage: scripts/package-dist.sh [NAME]
# BIN (default target/release) = where the built CLIs are; DIST_OUT (default dist) = output dir.
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
name=${1:-blocktools-dry-run-linux-x86_64}
bin=${BIN:-${CARGO_TARGET_DIR:-target}/release}; out=${DIST_OUT:-dist}
rm -rf "$out/$name"
mkdir -p "$out/$name/bin" "$out/$name/share/man/man1" "$out/$name/share/man/man7" "$out/$name/man"
for f in "$bin"/*; do
  [ -f "$f" ] && [ -x "$f" ] || continue
  case "$f" in *.d|*.so|*.rlib) continue ;; esac
  base=$(basename "$f")
  case "$base" in build*|*-*parity*|gen*) continue ;; esac
  cp "$f" "$out/$name/bin/"
done
[ -f blocktools ] && cp blocktools "$out/$name/"
cp LICENSE README.md DESIGN.md EXPORTS.md "$out/$name/"
cp -r recipes "$out/$name/"
cp man/man1/*.1 "$out/$name/share/man/man1/"
cp man/man7/*.7 "$out/$name/share/man/man7/"
cp -r man/man1 "$out/$name/man/"
cp -r man/man7 "$out/$name/man/"
tar -C "$out" -czf "$out/$name.tar.gz" "$name"
(cd "$out" && sha256sum "$name.tar.gz" > SHA256SUMS)
echo "wrote $out/$name.tar.gz bins=$(ls "$out/$name/bin" | wc -l) man1=$(ls "$out/$name/share/man/man1" | wc -l)"
