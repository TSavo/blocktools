# Portable helpers for the e2e scripts (Linux and macOS). Sourced, not executed.
# fmode FILE: octal permission bits (GNU stat -c / BSD stat -f).
fmode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
# nosid CMD...: run CMD in a new session with no controlling terminal (setsid(1) is not on macOS).
nosid() {
  if command -v setsid >/dev/null 2>&1 && [ -z "${E2E_NO_SETSID:-}" ]; then setsid "$@"
  else python3 -c 'import os,sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "$@"; fi
}
# have_pymod MOD: true if python3 can import MOD (checks that need it print "skip ..." otherwise).
have_pymod() { python3 -c "import $1" >/dev/null 2>&1; }
