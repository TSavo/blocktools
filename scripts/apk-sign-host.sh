#!/bin/sh
# Sign blocktools APKs with the release key held in Vault. Runs on the Battleaxe HOST, never inside a
# runner container: the runners take every same-repo push and hold the host Docker socket, so they get no
# AppRole for this key. See docs/APK-SIGNING.md.
#   scripts/apk-sign-host.sh /tmp/blocktools-X.Y.Z-r0.apk [...]
# The private key never reaches stdout, stderr, argv or the repo: it goes Vault -> 0600 file on tmpfs
# (/dev/shm) -> read-only bind into a one-shot Alpine container for abuild-sign, and is removed by a trap.
# Afterwards every APK is checked with apk verify against the repo public key ONLY.
set -eu
set +x
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8222}
SECRET_PATH=${APK_SIGN_SECRET_PATH:-secret/data/blocktools/apk-signing}
CRED_DIR=${APK_SIGN_CRED_DIR:-$HOME/.config/blocktools-apk-signer}
KEY_NAME=${APK_SIGN_KEY_NAME:-blocktools@tsavo-2026.rsa}
PUB=${APK_SIGN_PUB:-$root/packaging/alpine/keys/$KEY_NAME.pub}
DOCKER=${DOCKER:-docker}
[ $# -ge 1 ] || { echo "usage: $0 file.apk..." >&2; exit 2; }
[ -r "$PUB" ] || { echo "apk-sign: public key $PUB missing" >&2; exit 1; }
for c in role-id secret-id; do
  [ -r "$CRED_DIR/$c" ] || { echo "apk-sign: $CRED_DIR/$c not readable; refusing (no fallback key)" >&2; exit 1; }
done
umask 077
tmp=$(mktemp -d /dev/shm/bt-apksign.XXXXXX)
cleanup() { if [ -d "$tmp" ]; then shred -u "$tmp"/* 2>/dev/null || rm -f "$tmp"/*; rmdir "$tmp"; fi; return 0; }
trap cleanup EXIT INT TERM HUP
# AppRole login; ids go to curl on stdin, never argv.
jq -n --rawfile r "$CRED_DIR/role-id" --rawfile s "$CRED_DIR/secret-id" \
  "{role_id:(\$r|rtrimstr(\"\n\")), secret_id:(\$s|rtrimstr(\"\n\"))}" \
  | curl -sf --max-redirs 0 -X POST -d @- "$VAULT_ADDR/v1/auth/approle/login" > "$tmp/login" \
  || { echo "apk-sign: AppRole login refused or vault unreachable at $VAULT_ADDR" >&2; exit 1; }
printf "X-Vault-Token: %s\n" "$(jq -r .auth.client_token "$tmp/login")" > "$tmp/hdr"
shred -u "$tmp/login" 2>/dev/null || rm -f "$tmp/login"
curl -sf --max-redirs 0 -H @"$tmp/hdr" "$VAULT_ADDR/v1/$SECRET_PATH" > "$tmp/secret" \
  || { echo "apk-sign: this role may not read $SECRET_PATH (or it is missing); refusing" >&2; exit 1; }
curl -sf --max-redirs 0 -X POST -H @"$tmp/hdr" "$VAULT_ADDR/v1/auth/token/revoke-self" >/dev/null 2>&1 || true  # allow-true: token expires in 5m anyway
jq -j .data.data.private_key "$tmp/secret" > "$tmp/$KEY_NAME"
name=$(jq -r .data.data.key_name "$tmp/secret")
shred -u "$tmp/secret" "$tmp/hdr" 2>/dev/null || rm -f "$tmp/secret" "$tmp/hdr"
[ "$name" = "$KEY_NAME" ] || { echo "apk-sign: vault key_name does not match $KEY_NAME; refusing" >&2; exit 1; }
grep -q "PRIVATE KEY" "$tmp/$KEY_NAME" || { echo "apk-sign: vault secret is not a PEM key; refusing" >&2; exit 1; }
cp "$PUB" "$tmp/$KEY_NAME.pub"
work=$(mktemp -d); cid=""
cleanup2() {
  cleanup
  [ -z "$cid" ] || $DOCKER rm -f "$cid" >/dev/null 2>&1 || true  # allow-true: the signing container may already be gone
  rm -rf "$work"
  return 0
}
trap cleanup2 EXIT INT TERM HUP
for a in "$@"; do cp "$a" "$work/"; done
# scripts/apk-sign-pkg.py drops the build-time throwaway signature and signs the control member.
# No host bind mounts: the engine may be Docker Desktop (Windows), which cannot bind-mount the WSL2
# host paths -- they arrive empty. Start a one-shot container with a tmpfs key dir, stream the private
# key in over `docker exec` stdin (RAM only -- never a volume or the container's on-disk layer), then
# `docker cp` the public signer + APKs in, sign (output suppressed so nothing about the key can reach a
# log), and `docker cp` the signed APKs back out. Afterwards verify with ONLY the repo public key.
cid=$($DOCKER run -d --tmpfs /k:mode=0700 alpine:3.20 sleep 300) \
  || { echo "apk-sign: could not start signing container" >&2; exit 1; }
$DOCKER exec -i "$cid" sh -c 'cat > /k/'"$KEY_NAME" < "$tmp/$KEY_NAME"
$DOCKER exec -i "$cid" sh -c 'cat > /k/'"$KEY_NAME.pub" < "$tmp/$KEY_NAME.pub"  # tmpfs: must stream (docker cp lands under the mount)
$DOCKER cp "$root/scripts/apk-sign-pkg.py" "$cid:/sign.py" >/dev/null
$DOCKER exec "$cid" mkdir -p /apks
for a in "$@"; do $DOCKER cp "$work/$(basename "$a")" "$cid:/apks/$(basename "$a")" >/dev/null; done
$DOCKER exec "$cid" sh -euc "
  apk add -q python3 openssl >/dev/null 2>&1
  python3 /sign.py /k/$KEY_NAME $KEY_NAME.pub /apks/*.apk >/dev/null 2>&1" \
  || { echo "apk-sign: signing failed" >&2; exit 1; }
for a in "$@"; do $DOCKER cp "$cid:/apks/$(basename "$a")" "$work/$(basename "$a")" >/dev/null; done
$DOCKER rm -f "$cid" >/dev/null 2>&1; cid=""
cleanup
"$root/scripts/apk-verify.sh" "$PUB" "$work"/*.apk
for a in "$@"; do cp -f "$work/$(basename "$a")" "$a"; done
rm -rf "$work"
echo "apk-sign: signed and verified $# apk(s) with $KEY_NAME"
