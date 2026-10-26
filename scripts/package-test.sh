#!/bin/sh
# Build DEB/RPM/APK and install-test each in a clean container:
# every CLI runs --help, every man page is installed, man7 present.
# Usage: DOCKER="sudo docker" scripts/package-test.sh [deb rpm apk]
set -eu
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd); cd "$root"
D=${DOCKER:-docker}; export DOCKER="$D"
CLIS=$(sed -n 's/^CLIS="\(.*\)"/\1/p' scripts/package-native.sh)
nman=$(ls man/man1/*.1 | wc -l); nman=$((nman))
check='set -eu; fail=0
for t in $CLIS; do command -v $t >/dev/null || { echo "missing $t"; fail=1; continue; }
  $t --help >/dev/null 2>&1 || { echo "help failed $t"; fail=1; }
  [ -f /usr/share/man/man1/$t.1.gz ] || { echo "no man $t"; fail=1; }; done
n=$(ls /usr/share/man/man1/*.1.gz | wc -l); [ $((n)) -eq $NMAN ] || { echo "man1 count $n != $NMAN"; fail=1; }
[ -f /usr/share/man/man7/blocktools.7.gz ] || { echo "no blocktools.7"; fail=1; }
[ -x /usr/bin/blocktools ] || { echo "no wrapper"; fail=1; }
exit $fail'
for k in ${*:-deb rpm apk}; do
  sh scripts/package-native.sh $k >/dev/null
  case $k in
  deb) f=/tmp/blocktools_0.1.0-1_amd64.deb img=debian:bookworm-slim inst="rm -f /etc/dpkg/dpkg.cfg.d/docker; dpkg -i /p/pkg.$k >/dev/null";;
  rpm) f=/tmp/blocktools-0.1.0-1.x86_64.rpm img=fedora:40 inst="sed -i.bak /tsflags=nodocs/d /etc/dnf/dnf.conf; rpm -i /p/pkg.$k";;
  apk) f=/tmp/blocktools-0.1.0-r0.apk img=alpine:3.20 inst="apk add -q --allow-untrusted /p/pkg.$k";;
  esac
  mkdir -p /tmp/pt; rm -f /tmp/pt/pkg.*; cp "$f" /tmp/pt/pkg.$k
  $D run --rm -e CLIS="$CLIS" -e NMAN="$nman" -v /tmp/pt:/p:ro $img sh -c "$inst && $check" \
    && echo "package-test $k ok ($(wc -c < "$f" | tr -d ' ') bytes, $(echo $CLIS | wc -w | tr -d ' ') CLIs, $nman man1)" \
    || { echo "package-test $k FAIL"; exit 1; }
done
