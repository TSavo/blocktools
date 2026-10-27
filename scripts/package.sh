#!/bin/sh
# Package target/release into dist/blocktools-<ref>-<os>-<arch>.tar.gz + SHA256SUMS, then smoke-test the
# tarball: unpack it elsewhere, check every binary is built for this host's arch, and run a public BIP84 vector
# through the packaged seed-to-master | derive. Same layout as release.yml's linux-x86_64 package.
# Usage: sh scripts/package.sh [ref-name]   (default: the Cargo.toml version)   Builds nothing itself.
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
cd "$(dirname "$0")/.."
f() { echo "FAIL package: $*"; exit 1; }
ref=${1:-v$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}
case "$(uname -s)" in Linux) os=linux;; Darwin) os=macos;; *) f "unsupported OS $(uname -s)";; esac
arch=$(uname -m); [ "$arch" != arm64 ] || arch=aarch64
case "$arch" in x86_64|aarch64) ;; *) f "unsupported arch $arch";; esac
if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum "$@"; }; else sha() { shasum -a 256 "$@"; }; fi
name=$(echo "blocktools-$ref-$os-$arch" | tr '/' '-')
rm -rf "dist/$name" "dist/$name.tar.gz"; mkdir -p "dist/$name/bin"
for b in target/release/*; do
  [ -f "$b" ] && [ -x "$b" ] && case "$b" in *.d|*.so|*.rlib|*.dylib|*.a) ;; *) cp "$b" "dist/$name/bin/";; esac
done
n=$(ls "dist/$name/bin" | wc -l | tr -d ' '); [ "$n" -ge 40 ] || f "only $n binaries in target/release (build first)"
cp blocktools LICENSE README.md DESIGN.md EXPORTS.md "dist/$name/"
cp -r recipes "dist/$name/"
mkdir -p "dist/$name/share/man/man1" "dist/$name/share/man/man7" "dist/$name/man"
cp man/man1/*.1 "dist/$name/share/man/man1/"; cp man/man7/*.7 "dist/$name/share/man/man7/"
cp -r man/man1 "dist/$name/man/"; cp -r man/man7 "dist/$name/man/"
tar -C dist -czf "dist/$name.tar.gz" "$name"
(cd dist && sha "$name.tar.gz" > "SHA256SUMS-$os-$arch" && cat "SHA256SUMS-$os-$arch")
# smoke test from the tarball, not from target/
S=$(mktemp -d); trap 'rm -rf "$S"' EXIT
tar -C "$S" -xzf "dist/$name.tar.gz"; P="$S/$name/bin"
# executable format + machine from the header (ELF e_machine 62/183, Mach-O 64-bit cputype x86_64/arm64)
fmt=$(python3 - "$arch" "$P"/* <<'PYEOF'
import struct, sys
want, seen, bad = sys.argv[1], set(), []
for b in sys.argv[2:]:
    h = open(b, "rb").read(20)
    if h[:4] == b"\x7fELF": k = ("ELF", {62: "x86_64", 183: "aarch64"}.get(struct.unpack("<H", h[18:20])[0], "?"))
    elif h[:4] == b"\xcf\xfa\xed\xfe": k = ("Mach-O", {0x01000007: "x86_64", 0x0100000c: "aarch64"}.get(struct.unpack("<I", h[4:8])[0], "?"))
    else: k = ("?", "?")
    seen.add(k)
    if k[1] != want: bad.append(b.rsplit("/", 1)[-1] + "=" + "/".join(k))
if bad: print("wrong arch: " + " ".join(bad), file=sys.stderr); sys.exit(1)
print(" ".join("/".join(k) for k in sorted(seen)))
PYEOF
) || f "binaries not built for $arch"
# BIP84 test vector (public): abandon x11 about -> m/84'/0'/0'/0/0 bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
echo "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \
  | "$P/seed-to-master" | "$P/derive" --chain btc --count 1 --public-only > "$S/d" || f "packaged derive failed"
grep -q '"address":"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"' "$S/d" || f "packaged derive: BIP84 vector not reproduced"
dep=
if [ $os = linux ] && command -v objdump >/dev/null 2>&1; then
  dep=" glibc>=$(objdump -T "$P"/* 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sort -t. -k1,1 -k2,2n -k3,3n -u | tail -1 | cut -d_ -f2)"
elif [ $os = macos ]; then
  dep=" minos $(otool -l "$P/derive" | awk '/LC_BUILD_VERSION/{f=1} f&&/minos/{print $2; exit}')"
fi
echo "ok   package $name: $n binaries, all $fmt,$dep; packaged derive reproduces the BIP84 vector"
