#!/bin/sh
# Build linux dist tarball (same shape as .github/workflows/release.yml).
# Usage: scripts/package-dist.sh [NAME]
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
name=${1:-blocktools-dry-run-linux-x86_64}
rm -rf "dist/$name"
mkdir -p "dist/$name/bin" "dist/$name/share/man/man1" "dist/$name/share/man/man7" "dist/$name/man"
for f in target/release/*; do
  [ -f "$f" ] && [ -x "$f" ] || continue
  case "$f" in *.d|*.so|*.rlib) continue ;; esac
  base=$(basename "$f")
  case "$base" in build*|*-*parity*|gen*) continue ;; esac
  cp "$f" "dist/$name/bin/"
done
[ -f blocktools ] && cp blocktools "dist/$name/"
cp LICENSE README.md DESIGN.md EXPORTS.md "dist/$name/"
cp -r recipes "dist/$name/"
cp man/man1/*.1 "dist/$name/share/man/man1/"
cp man/man7/*.7 "dist/$name/share/man/man7/"
cp -r man/man1 "dist/$name/man/"
cp -r man/man7 "dist/$name/man/"
tar -C dist -czf "dist/$name.tar.gz" "$name"
(cd dist && sha256sum "$name.tar.gz" > SHA256SUMS)
echo "wrote dist/$name.tar.gz bins=$(ls "dist/$name/bin" | wc -l) man1=$(ls "dist/$name/share/man/man1" | wc -l)"
