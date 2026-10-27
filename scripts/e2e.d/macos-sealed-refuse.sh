# scripts/macos-sealed-check.sh fails closed (exit 2, no sealed-check run) off macOS, on a remote engine and on
# a stopped engine. Fake docker: `context inspect` answers FAKE_EP, `version` fails unless FAKE_UP=1.
set -eu
T=${T:-$(mktemp -d)}; f() { echo "FAIL macos-sealed-refuse $1"; exit 1; }
mkdir -p "$T/ms" && cat > "$T/ms/docker" <<'EOS'
#!/bin/sh
case "$1" in context) echo "$FAKE_EP";; version) [ "${FAKE_UP:-}" = 1 ] && echo linux/arm64 0 || exit 1;; *) echo RAN;; esac
EOS
chmod +x "$T/ms/docker"
chk() { want=$1; shift; o=$(env -u DOCKER_HOST BLOCKTOOLS_DOCKER="$T/ms/docker" "$@" sh scripts/macos-sealed-check.sh 2>&1) && f "passed: $*"
  rc=0; env -u DOCKER_HOST BLOCKTOOLS_DOCKER="$T/ms/docker" "$@" sh scripts/macos-sealed-check.sh >/dev/null 2>&1 || rc=$?
  [ $rc = 2 ] || f "rc $rc (want 2): $*"; echo "$o" | grep -q "$want" || f "no '$want': $o"; echo "$o" | grep -q RAN && f "docker ran: $*"; return 0; }
if [ "$(uname -s)" != Darwin ]; then
  chk 'not macOS' env FAKE_EP=unix:///var/run/docker.sock FAKE_UP=1
  echo "ok   macos-sealed-refuse: refuses off macOS (remote/stopped-engine cases run on the macos job)"; exit 0
fi
for ep in ssh://battleaxe tcp://10.0.0.2:2375; do chk 'not a local unix socket' env FAKE_EP=$ep FAKE_UP=1; done
chk 'not a local unix socket' env DOCKER_HOST=ssh://battleaxe FAKE_EP=unix:///x FAKE_UP=1
chk 'not running' env FAKE_EP=unix:///var/run/docker.sock
echo "ok   macos-sealed-refuse: ssh/tcp engines, DOCKER_HOST=ssh and a stopped local engine refused (exit 2) before any container"
