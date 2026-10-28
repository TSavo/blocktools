# ./blocktools refuses a remote docker engine (./in and ./secrets would be copied to the remote host).
# Fake docker binary: answers `context inspect` with FAKE_HOST, otherwise records that it was asked to run.
set -eu
T=${T:-$(mktemp -d)}; W="$PWD/blocktools"
f() { echo "FAIL wrapper-remote $1"; exit 1; }
mkdir -p "$T/wr" && cat > "$T/wr/docker" <<'EOS'
#!/bin/sh
case "$1" in context) echo "${FAKE_HOST:-unix:///var/run/docker.sock}";; create) echo cid;; inspect) echo true;; exec) cat >/dev/null;; start) echo RAN;; esac
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
[ "$(run env FAKE_HOST=tcp://h:2375 BLOCKTOOLS_ALLOW_REMOTE=1)" = RAN ] || f "=1 + tcp context not allowed"
[ "$(run env DOCKER_HOST=tcp://h:2375 BLOCKTOOLS_ALLOW_REMOTE=1)" = RAN ] || f "=1 + tcp DOCKER_HOST not allowed"
echo "ok   wrapper-remote: ALLOW_REMOTE=1 runs ssh/tcp (context and DOCKER_HOST)"
o=$(run env DOCKER_HOST=ssh://b) && f "unset + ssh DOCKER_HOST not refused"
echo "$o" | grep -q RAN && f "unset + ssh DOCKER_HOST: docker run happened"
[ "$(run env FAKE_HOST=ssh://b BLOCKTOOLS_ALLOW_REMOTE=ssh)" = RAN ] || f "=ssh + ssh context not allowed"
[ "$(run env DOCKER_HOST=ssh://b BLOCKTOOLS_ALLOW_REMOTE=ssh)" = RAN ] || f "=ssh + ssh DOCKER_HOST not allowed"
echo "ok   wrapper-remote: ALLOW_REMOTE=ssh runs ssh:// (context and DOCKER_HOST); unset refuses ssh DOCKER_HOST"
for e in "FAKE_HOST=tcp://h:2375" "DOCKER_HOST=tcp://h:2375" "FAKE_HOST=http://h" "DOCKER_HOST=https://h"; do
  o=$(run env $e BLOCKTOOLS_ALLOW_REMOTE=ssh) && f "=ssh + $e not refused"
  echo "$o" | grep -q 'permits only ssh://' || f "=ssh + $e: no message"
  echo "$o" | grep -q RAN && f "=ssh + $e: docker run happened"
  rc=0; run env $e BLOCKTOOLS_ALLOW_REMOTE=ssh >/dev/null || rc=$?; [ "$rc" = 4 ] || f "=ssh + $e: exit $rc, want 4"
done
o=$(run env FAKE_HOST=tcp://h BLOCKTOOLS_ALLOW_REMOTE=yes) && f "=yes treated as allow"
echo "ok   wrapper-remote: ALLOW_REMOTE=ssh refuses tcp/http(s) (context and DOCKER_HOST) with exit 4; other values allow nothing"
echo "ok   wrapper-remote: ssh/tcp engines and DOCKER_HOST refused before docker run; local and explicit override run"
