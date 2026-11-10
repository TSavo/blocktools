#!/bin/sh
# Install-test the live signed package repos in throwaway containers: alpine:latest (apk), ubuntu:24.04 (apt),
# fedora:latest (dnf). Each container adds the repo key/config from this repo's main branch, installs blocktools
# pinned to VERSION, prints the OS and installed package version, then runs every /usr/bin file of the package
# with --help and prints "RESULT <ok> of <n> executables run; <name>=<exit> ...".
# Needs a Docker engine and network (not run by the CI gate). No secrets: public keys and public packages only.
# usage: sh scripts/pkg-install.sh VERSION      (e.g. 0.5.0; BLOCKTOOLS_DOCKER='sudo docker' to use sudo)
set -eu
V=${1:?usage: pkg-install.sh VERSION}
D=${BLOCKTOOLS_DOCKER:-docker}
RAW=https://raw.githubusercontent.com/TSavo/blocktools/main/packaging
count='n=0; ok=0; bad=""; for f in $BINS; do n=$((n+1)); rc=0; "$f" --help >/dev/null 2>&1 || rc=$?; if [ "$rc" = 0 ]; then ok=$((ok+1)); else bad="$bad $(basename "$f")=$rc"; fi; done; echo "RESULT $ok of $n executables run;$bad"'
echo "=== alpine"
rc=0; $D run --rm alpine:latest sh -euc '. /etc/os-release; echo "os $PRETTY_NAME"; wget -qO /etc/apk/keys/blocktools@tsavo-2026.rsa.pub '"$RAW"'/alpine/keys/blocktools@tsavo-2026.rsa.pub && echo https://tsavo.github.io/blocktools/alpine >> /etc/apk/repositories && apk update -q && apk add -q "blocktools='"$V"'-r0" && echo "pkg $(apk list --installed blocktools 2>/dev/null | head -1)"; BINS=$(apk info -L blocktools | grep usr/bin/ | sed "s|^|/|"); '"$count" || rc=$?
echo "ALPINE_EXIT=$rc"
echo "=== apt ubuntu:24.04"
rc=0; $D run --rm ubuntu:24.04 bash -euc '. /etc/os-release; echo "os $PRETTY_NAME"; apt-get update -qq >/dev/null && apt-get install -y -qq wget ca-certificates >/dev/null && install -d -m 0755 /etc/apt/keyrings && wget -qO /etc/apt/keyrings/blocktools-archive-keyring.asc '"$RAW"'/apt/blocktools-archive-keyring.asc && echo "deb [signed-by=/etc/apt/keyrings/blocktools-archive-keyring.asc] https://tsavo.github.io/blocktools/apt stable main" > /etc/apt/sources.list.d/blocktools.list && apt-get update -qq >/dev/null && apt-get install -y -qq "blocktools='"$V"'-1" >/dev/null && echo "pkg $(dpkg-query -W blocktools)"; BINS=$(dpkg -L blocktools | grep "^/usr/bin/"); '"$count" || rc=$?
echo "APT_EXIT=$rc"
echo "=== rpm fedora:latest"
rc=0; $D run --rm fedora:latest bash -euc '. /etc/os-release; echo "os $PRETTY_NAME"; curl -fsSo /etc/yum.repos.d/blocktools.repo '"$RAW"'/rpm/blocktools.repo && dnf -y -q install "blocktools-'"$V"'" >/dev/null 2>&1 && echo "pkg $(rpm -q blocktools)"; BINS=$(rpm -ql blocktools | grep "^/usr/bin/"); '"$count" || rc=$?
echo "RPM_EXIT=$rc"
echo DONE
