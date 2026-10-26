#!/bin/sh
# Build DEB / RPM / APK from target/release (or MUSL_TARGET for apk).
# Default payload is the static musl build so one package runs on any glibc (Debian 12, Fedora 40, Alpine).
# Usage:
#   scripts/package-native.sh deb
#   scripts/package-native.sh rpm
#   scripts/package-native.sh apk   # uses MUSL_BINDIR (default target/x86_64-unknown-linux-musl/release)
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
ver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)  # one version: scripts/version-check.sh
ver=${PKG_VERSION:-$ver}  # e.g. PKG_VERSION=0.1.1_pre20261026 for an untagged pre-release apk (sorts below 0.1.1)
kind=${1:?kind: deb|rpm|apk}
CLIS="acct-tx armory-read bip38-open blockchain-read chain-table classify dat-read derive electrum-read key-to-addresses keystore-open multibit-read pw-candidates read-file redact rpc sealed-run seed-repair seed-to-master tx-broadcast tx-build tx-decode tx-envelope tx-sign tx-verify utxo-fetch xmr-keys xmr-wallet xpub-addresses xrp-tx zec-sapling sig-hash abi-decode abi-encode create-address abi-inspect bytecode-inspect typed-data-verify sol-tron-tx msg-verify msg-sign phrase-to-key"

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
  stage /tmp/blocktools-deb-rebuild "${BINDIR:-target/x86_64-unknown-linux-musl/release}"
  mkdir -p /tmp/blocktools-deb-rebuild/DEBIAN
  cat > /tmp/blocktools-deb-rebuild/DEBIAN/control <<EOF
Package: blocktools
Version: ${ver}-1
Section: utils
Priority: optional
Architecture: amd64
${DEB_DEPENDS:+Depends: $DEB_DEPENDS
}Maintainer: TSavo <noreply@example.com>
Description: blocktools offline chain utilities
 Binaries + man pages. DANGEROUS: audit before use with real funds.
EOF
  dpkg-deb --root-owner-group --build /tmp/blocktools-deb-rebuild "/tmp/blocktools_${ver}-1_amd64.deb"
  echo "wrote /tmp/blocktools_${ver}-1_amd64.deb"
  ;;
rpm)
  stage /tmp/blocktools-rpm-root "${BINDIR:-target/x86_64-unknown-linux-musl/release}"
  rm -rf /tmp/blocktools-rpmbuild; mkdir -p /tmp/blocktools-rpmbuild/SPECS
  cat > /tmp/blocktools-rpmbuild/SPECS/blocktools.spec <<EOF
Name: blocktools
Version: ${ver}
Release: 1
Summary: blocktools offline chain utilities
License: see LICENSE
BuildArch: x86_64
AutoReqProv: no
%description
Binaries + man pages. DANGEROUS: audit before use with real funds.
%install
cp -a /stage/. %{buildroot}/
%files
/usr/bin/*
/usr/share/man/man1/*
/usr/share/man/man7/*
/usr/share/doc/blocktools
EOF
  ${DOCKER:-docker} run --rm -v /tmp/blocktools-rpm-root:/stage:ro -v /tmp/blocktools-rpmbuild:/out fedora:40 sh -euc '
    dnf -q -y install rpm-build >/dev/null
    rpmbuild -bb --define "_topdir /tmp/rb" --define "__strip /bin/true" --define "debug_package %{nil}" /out/SPECS/blocktools.spec >/dev/null
    cp /tmp/rb/RPMS/x86_64/*.rpm /out/'
  cp /tmp/blocktools-rpmbuild/blocktools-${ver}-1.x86_64.rpm /tmp/
  echo "wrote /tmp/blocktools-${ver}-1.x86_64.rpm"
  ;;
apk)
  bindir=${MUSL_BINDIR:-target/x86_64-unknown-linux-musl/release}
  stage /tmp/bt-apk "$bindir"
  rm -rf /tmp/bt-apkbuild; mkdir -p /tmp/bt-apkbuild
  cat > /tmp/bt-apkbuild/APKBUILD <<EOF
pkgname=blocktools
pkgver=${ver}
pkgrel=0
pkgdesc="blocktools offline chain utilities"
url="https://github.com/TSavo/blocktools"
arch="x86_64"
depends="bash"  # recipes/recover.sh is #!/usr/bin/env bash; the CLIs are static musl
license="custom"
options="!check !strip !tracedeps"
source=""
package() { mkdir -p "\$pkgdir"; cp -a /stage/. "\$pkgdir"/; }
EOF
  ${DOCKER:-docker} run --rm -v /tmp/bt-apk:/stage:ro -v /tmp/bt-apkbuild:/out alpine:3.20 sh -euc '
    apk add -q abuild >/dev/null
    adduser -D -h /work b; addgroup b abuild
    cp /out/APKBUILD /work/; chown -R b /work
    # THROWAWAY build key: abuild always signs. Release signing is scripts/apk-sign-host.sh (docs/APK-SIGNING.md).
    su b -c "abuild-keygen -a -n >/dev/null 2>&1"; cp /work/.abuild/*.pub /etc/apk/keys/
    su b -c "cd /work && abuild -d -P /work/pkgs >/dev/null 2>&1"
    find /work/pkgs -name "*.apk" -exec cp {} /out/ \;'
  cp -f /tmp/bt-apkbuild/blocktools-${ver}-r0.apk /tmp/ && chmod 644 /tmp/blocktools-${ver}-r0.apk
  echo "wrote /tmp/blocktools-${ver}-r0.apk"
  if [ "${APK_SIGN_HOST:-0}" = 1 ]; then scripts/apk-sign-host.sh /tmp/blocktools-${ver}-r0.apk; fi  # host only, see docs/APK-SIGNING.md
  ;;
*) echo "unknown kind $kind"; exit 1 ;;
esac
