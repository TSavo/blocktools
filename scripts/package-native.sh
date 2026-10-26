#!/bin/sh
# Build DEB / RPM / APK from target/release (or MUSL_TARGET for apk).
# Usage:
#   scripts/package-native.sh deb
#   scripts/package-native.sh rpm
#   scripts/package-native.sh apk   # uses MUSL_BINDIR (default target/x86_64-unknown-linux-musl/release)
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
ver=0.1.0
kind=${1:?kind: deb|rpm|apk}
CLIS="acct-tx armory-read bip38-open blockchain-read chain-table classify dat-read derive electrum-read key-to-addresses keystore-open multibit-read pw-candidates read-file redact sealed-run seed-repair seed-to-master tx-broadcast tx-build tx-decode tx-envelope tx-sign tx-verify utxo-fetch xmr-keys xmr-wallet xpub-addresses xrp-tx zec-sapling"

stage() {
  dest=$1; bindir=$2
  rm -rf "$dest"
  mkdir -p "$dest/usr/bin" "$dest/usr/share/man/man1" "$dest/usr/share/man/man7" "$dest/usr/share/doc/blocktools"
  for t in $CLIS; do
    [ -x "$bindir/$t" ] && cp "$bindir/$t" "$dest/usr/bin/"
  done
  [ -f blocktools ] && cp blocktools "$dest/usr/bin/blocktools" && chmod +x "$dest/usr/bin/blocktools"
  [ -f recipes/recover.sh ] && cp recipes/recover.sh "$dest/usr/bin/" && chmod +x "$dest/usr/bin/recover.sh"
  [ -f LICENSE ] && cp LICENSE "$dest/usr/share/doc/blocktools/"
  for f in man/man1/*.1; do gzip -n -c "$f" > "$dest/usr/share/man/man1/$(basename "$f").gz"; done
  gzip -n -c man/man7/blocktools.7 > "$dest/usr/share/man/man7/blocktools.7.gz"
}

case "$kind" in
deb)
  stage /tmp/blocktools-deb-rebuild target/release
  mkdir -p /tmp/blocktools-deb-rebuild/DEBIAN
  cat > /tmp/blocktools-deb-rebuild/DEBIAN/control <<EOF
Package: blocktools
Version: ${ver}-1
Section: utils
Priority: optional
Architecture: amd64
Maintainer: TSavo <noreply@example.com>
Description: blocktools offline chain utilities
 Binaries + man pages. DANGEROUS: audit before use with real funds.
EOF
  dpkg-deb --root-owner-group --build /tmp/blocktools-deb-rebuild "/tmp/blocktools_${ver}-1_amd64.deb"
  echo "wrote /tmp/blocktools_${ver}-1_amd64.deb"
  ;;
rpm)
  stage /tmp/blocktools-rpm-root target/release
  # Build via rpmbuild in a fedora container when host lacks rpmbuild
  if command -v rpmbuild >/dev/null 2>&1; then
    echo "rpmbuild on host not wired; use docker fedora (see docs)"
    exit 1
  fi
  echo "RPM: use prior dry-run artifact or docker fedora+rpmbuild; see docs/DOCS-READINESS.md"
  ;;
apk)
  bindir=${MUSL_BINDIR:-target/x86_64-unknown-linux-musl/release}
  stage /tmp/bt-apk "$bindir"
  echo "APK payload staged at /tmp/bt-apk; build with alpine abuild (see docs)"
  ;;
*) echo "unknown kind $kind"; exit 1 ;;
esac
