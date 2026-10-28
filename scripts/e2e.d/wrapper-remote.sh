# ./blocktools refuses a remote docker engine (./in and ./secrets would be copied to the remote host).
# Fake docker binary: answers `context inspect` with FAKE_HOST, otherwise records that it was asked to run.
set -eu
T=${T:-$(mktemp -d)}; W="$PWD/blocktools"
f() { echo "FAIL wrapper-remote $1"; exit 1; }
mkdir -p "$T/wr" && cat > "$T/wr/docker" <<'EOS'
#!/bin/sh
case "$1" in context) echo "${FAKE_HOST:-unix:///var/run/docker.sock}";; cp) cat >/dev/null;; run) echo RAN;; esac
EOS
chmod +x "$T/wr/docker"
run() { (cd "$T/wr" && env -u DOCKER_HOST BLOCKTOOLS_DOCKER="$T/wr/docker" "$@" sh "$W" run 'derive --help' 2>&1); }
[ "$(run env)" = RAN ] || f "local unix engine refused"
for h in ssh://battleaxe tcp://10.0.0.2:2375; do
  o=$(run env FAKE_HOST=$h) && f "$h not refused"
  echo "$o" | grep -q 'engine is remote' || f "$h: no message"
  echo "$o" | grep -q RAN && f "$h: docker run happened"
done
o=$(run env DOCKER_HOST=tcp://h:2375) && f "DOCKER_HOST tcp not refused"
[ "$(run env FAKE_HOST=ssh://b BLOCKTOOLS_ALLOW_REMOTE=1)" = RAN ] || f "explicit override ignored"
echo "ok   wrapper-remote: ssh/tcp engines and DOCKER_HOST refused before docker run; local and explicit override run"
