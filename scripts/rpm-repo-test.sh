#!/bin/sh
# End-to-end test of a signed blocktools dnf/yum repository in real distro containers.
#   scripts/rpm-repo-test.sh REPO_DIR [image...]      serve REPO_DIR over local http (busybox httpd)
#   RPM_REPO_URL=https://.../rpm scripts/rpm-repo-test.sh - [image...]   test a live URL (positive only)
# Per image: dnf installs blocktools with gpgcheck=1 repo_gpgcheck=1, rpm -K is OK, man pages are
# installed, and a few CLIs answer --help (glibc 2.34+ needed: expected to FAIL on EL8, reported as such).
# Negative (local mode, first image): no trusted key, a different key, a tampered RPM and a tampered
# repomd.xml must all make the install fail. Needs docker.
set -eu
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
D=${DOCKER:-docker}; src=${1:?REPO_DIR or -}; shift
[ $# -gt 0 ] || set -- fedora:latest
PUB=${RPM_SIGN_PUB:-$root/packaging/rpm/RPM-GPG-KEY-blocktools}
id=$$; net=bt-rpmtest-$id; t=$(mktemp -d)
fin() { $D rm -f bt-rpmsrv-$id >/dev/null 2>&1 || true; $D network rm $net >/dev/null 2>&1 || true; rm -rf "$t"; }  # allow-true: may already be gone
trap fin EXIT INT TERM
$D network create $net >/dev/null
if [ "$src" = - ]; then
  base=${RPM_REPO_URL:?set RPM_REPO_URL}; keyurl=${RPM_KEY_URL:-$base/RPM-GPG-KEY-blocktools}
else
  mkdir -p "$t/srv/good" "$t/srv/badrpm" "$t/srv/badmd"
  cp -r "$src"/. "$t/srv/good/"; cp "$PUB" "$t/srv/RPM-GPG-KEY-blocktools"
  $D run --rm -v "$t:/t" alpine:3.20 sh -c 'apk add -q gnupg >/dev/null 2>&1; export GNUPGHOME=$(mktemp -d)
    gpg --batch --pinentry-mode loopback --passphrase "" --quick-gen-key "throwaway other <other@throwaway>" rsa2048 sign never >/dev/null 2>&1
    gpg --batch --armor --export > /t/srv/RPM-GPG-KEY-other; chmod -R a+rX /t/srv'
  cp -r "$src"/. "$t/srv/badrpm/"; f=$(ls "$t/srv/badrpm"/*.rpm | head -1)
  sz=$(wc -c < "$f"); printf 'X' | dd of="$f" bs=1 seek=$((sz - 4096)) conv=notrunc 2>/dev/null   # flip a payload byte
  cp -r "$src"/. "$t/srv/badmd/"; sed -i 's#<revision>#<revision>9#' "$t/srv/badmd/repodata/repomd.xml"
  $D run -d --rm --name bt-rpmsrv-$id --network $net -v "$t/srv:/srv:ro" busybox httpd -f -p 8080 -h /srv >/dev/null
  base=http://bt-rpmsrv-$id:8080/good; keyurl=http://bt-rpmsrv-$id:8080/RPM-GPG-KEY-blocktools
fi
repo() { printf '[blocktools]\nname=blocktools\nbaseurl=%s\nenabled=1\ngpgcheck=1\nrepo_gpgcheck=1\ngpgkey=%s\n' "$1" "$2"; }
fail=0
for img in "$@"; do
  repo "$base" "$keyurl" > "$t/blocktools.repo"
  out=$($D run --rm --network $net -v "$t/blocktools.repo:/etc/yum.repos.d/blocktools.repo:ro" "$img" sh -c '
    . /etc/os-release; echo "os: $PRETTY_NAME; rpm $(rpm --version | cut -d" " -f3); glibc $(ldd --version | head -1 | sed "s/.* //")"
    dnf -y -q install blocktools >/tmp/dnf.log 2>&1 && echo "install: ok" || { echo "install: FAIL"; tail -5 /tmp/dnf.log; exit 0; }
    rpm -q --qf "pkgsig: %{SIGPGP:pgpsig}%{RSAHEADER:pgpsig}\n" blocktools | sed "s/(none)//g"
    echo "man: $(rpm -ql blocktools | grep -c "/usr/share/man/")"
    for c in derive tx-decode key-to-addresses sealed-run; do
      if /usr/bin/$c --help >/dev/null 2>/tmp/e; then echo "help $c: ok"; else echo "help $c: FAIL $(head -1 /tmp/e)"; fi
    done' 2>&1)
  echo "== $img"; echo "$out" | sed 's/^/   /'
  echo "$out" | grep -q "install: ok" || fail=1
done
if [ "$src" != - ]; then
  img=$1; neg() {
    repo "$2" "$3" > "$t/neg.repo"
    if $D run --rm --network $net -v "$t/neg.repo:/etc/yum.repos.d/blocktools.repo:ro" "$img" dnf -y -q install blocktools >"$t/neglog" 2>&1
    then echo "FAIL $1: install succeeded"; fail=1; else echo "ok   $1: install refused ($(grep -iE "error|fail|not signed|signature|checksum|mismatch|nokey|bad" "$t/neglog" | head -1 | sed "s/^ *//" | cut -c1-120))"; fi; }
  s=http://bt-rpmsrv-$id:8080
  neg "no key" "$base" "$s/nonexistent-key"
  neg "different key" "$base" "$s/RPM-GPG-KEY-other"
  neg "tampered rpm" "$s/badrpm" "$keyurl"
  neg "tampered repomd.xml" "$s/badmd" "$keyurl"
fi
exit $fail
