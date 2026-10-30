#!/bin/sh
# Build the signed Alpine/apt/RPM repositories for one release and (optionally) publish them to gh-pages.
# Runs on the Battleaxe HOST (the blocktools-signer runner, or by hand), never in a runner container:
# signing goes through scripts/{apk,apt,rpm}-sign-host.sh and their read-only AppRoles. See docs/RELEASE-REPOS.md.
#   scripts/release-repos.sh build   VERSION TARBALL OUTDIR   # VERSION like 0.1.1 (no leading v)
#   scripts/release-repos.sh publish OUTDIR                   # replaces alpine/ apt/ rpm/ on gh-pages
# REPOS_UNSIGNED=1 (dry run): build the same packages and layout but sign nothing and touch no AppRole.
# apk: static musl build of this checkout (docker rust:alpine). deb/rpm: the release tarball's glibc bin/.
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
DOCKER=${DOCKER:-docker}
cmd=${1:-}
case $cmd in
build)
  [ $# -eq 4 ] || { echo "usage: $0 build VERSION TARBALL OUTDIR" >&2; exit 2; }
  ver=$2; tgz=$3; out=$4
  case $ver in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "release-repos: bad version '$ver'" >&2; exit 2;; esac
  cver=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
  [ "$cver" = "$ver" ] || { echo "release-repos: Cargo.toml says $cver, asked for $ver; refusing" >&2; exit 1; }
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
  tar -C "$tmp" -xzf "$tgz"
  bindir=$(echo "$tmp"/blocktools-*/bin); [ -d "$bindir" ] || { echo "release-repos: no bin/ in $tgz" >&2; exit 1; }
  # Every shipped CLI must be in the package list (phrase-to-key before 0.1.1, bolt11 et al. in 0.3.0).
  # Same script the gate runs on every push (lint), so a missing CLI fails CI, not the release.
  sh scripts/clis-check.sh "$bindir" >&2 || { echo "release-repos: tarball CLIs not all in package-native.sh CLIS" >&2; exit 1; }
  clis=$(sed -n 's/^CLIS="\(.*\)"/\1/p' scripts/package-native.sh)
  # No host bind mounts: on Battleaxe the daemon is Docker Desktop, whose VM does not see the WSL2 distro's
  # paths (a -v mount of the checkout arrives empty: "could not find Cargo.toml in /src", release run
  # 40591364666). The sources go in as a tar stream on stdin; the musl binaries come back as a tar on stdout.
  mb=target/x86_64-unknown-linux-musl/release; mkdir -p "$mb"
  git ls-files -z --cached --others --exclude-standard | tar --null -T - --owner=0 --group=0 -cf - \
    | $DOCKER run -i --rm rust:alpine sh -euc 'exec 3>&1 1>&2
      mkdir /src && cd /src && tar -xf - && cargo build --release --locked --target x86_64-unknown-linux-musl >&2
      cd target/x86_64-unknown-linux-musl/release && tar -cf - >&3 $(for t in '"$clis"'; do [ -f "$t" ] && echo "$t"; done)' \
    | tar -C "$mb" -xf -
  rm -rf "$out"; mkdir -p "$out/alpine" "$out/rpm"
  BINDIR=$bindir DEB_DEPENDS="libc6 (>= 2.34)" PKG_VERSION=$ver sh scripts/package-native.sh deb >&2
  BINDIR=$bindir PKG_VERSION=$ver sh scripts/package-native.sh rpm >&2
  PKG_VERSION=$ver sh scripts/package-native.sh apk >&2
  apk=/tmp/blocktools-$ver-r0.apk deb=/tmp/blocktools_$ver-1_amd64.deb rpm=/tmp/blocktools-$ver-1.x86_64.rpm
  if [ "${REPOS_UNSIGNED:-0}" = 1 ]; then
    echo "release-repos: REPOS_UNSIGNED=1: packages built, nothing signed (dry run)"
    mkdir -p "$out/alpine/x86_64" "$out/apt/pool/main/b/blocktools"
    cp "$apk" "$out/alpine/x86_64/"; cp "$deb" "$out/apt/pool/main/b/blocktools/"; cp "$rpm" "$out/rpm/"
  else
    sh scripts/apk-sign-host.sh "$apk"
    sh scripts/apk-repo-build.sh "$out/alpine" "$apk"
    sh scripts/apt-sign-host.sh "$out/apt" "$deb"
    cp "$rpm" "$out/rpm/"; sh scripts/rpm-sign-host.sh "$out/rpm"
  fi
  cp packaging/rpm/RPM-GPG-KEY-blocktools "$out/rpm/"
  if grep -rlq "PRIVATE KEY" "$out"; then echo "release-repos: PRIVATE KEY block in $out; refusing" >&2; exit 1; fi
  echo "release-repos: built $out for $ver"; find "$out" -type f -name "blocktools*" | sed "s|^$out/||"
  ;;
publish)
  [ $# -eq 2 ] || { echo "usage: $0 publish OUTDIR" >&2; exit 2; }
  out=$(CDPATH= cd -- "$2" && pwd)
  [ "${REPOS_UNSIGNED:-0}" != 1 ] || { echo "release-repos: refusing to publish an unsigned (dry-run) build" >&2; exit 1; }
  for f in alpine/x86_64/APKINDEX.tar.gz apt/dists/stable/InRelease rpm/repodata/repomd.xml.asc; do
    [ -s "$out/$f" ] || { echo "release-repos: $out/$f missing; not a signed build" >&2; exit 1; }
  done
  if grep -rlq "PRIVATE KEY" "$out"; then echo "release-repos: PRIVATE KEY block in $out; refusing" >&2; exit 1; fi
  url=${REPOS_REMOTE:-https://github.com/${GITHUB_REPOSITORY:-TSavo/blocktools}}
  w=$(mktemp -d); trap 'rm -rf "$w"' EXIT INT TERM HUP
  if [ -n "${GH_TOKEN:-}" ]; then
    # token goes through a credential helper reading the env, never argv or the remote URL
    git -c credential.helper= -c "credential.helper=!f() { echo username=x-access-token; echo password=\$GH_TOKEN; }; f" clone -q -b gh-pages "$url" "$w/p"
  else git clone -q -b gh-pages "$url" "$w/p"; fi
  cd "$w/p"; git rm -rq --ignore-unmatch alpine apt rpm; cp -r "$out/alpine" "$out/apt" "$out/rpm" .
  git add -A
  if git diff --cached --quiet; then echo "release-repos: gh-pages already has this content"; exit 0; fi
  git -c user.name="${GIT_AUTHOR_NAME:-blocktools-release}" -c user.email="${GIT_AUTHOR_EMAIL:-TSavo@users.noreply.github.com}" \
    commit -qm "repos: $(ls alpine/x86_64/*.apk | xargs -n1 basename | tr '\n' ' ')(signed host-side)"
  if [ -n "${GH_TOKEN:-}" ]; then
    git -c credential.helper= -c "credential.helper=!f() { echo username=x-access-token; echo password=\$GH_TOKEN; }; f" push -q origin gh-pages
  else git push -q origin gh-pages; fi
  echo "release-repos: pushed gh-pages $(git rev-parse --short HEAD)"
  ;;
*) echo "usage: $0 build VERSION TARBALL OUTDIR | publish OUTDIR" >&2; exit 2;;
esac
