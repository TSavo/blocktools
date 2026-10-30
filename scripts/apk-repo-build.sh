#!/bin/sh
# Build an Alpine apk repository from already-signed APKs (scripts/apk-sign-host.sh) and sign its
# APKINDEX.tar.gz with the same Vault key. Runs on the Battleaxe HOST only. See docs/APK-SIGNING.md.
#   scripts/apk-repo-build.sh OUTDIR file.apk...   -> OUTDIR/<arch>/{*.apk,APKINDEX.tar.gz} + OUTDIR/KEY.pub
# The private key goes Vault -> 0600 file on tmpfs -> read-only bind into a one-shot Alpine container for
# abuild-sign; abuild-sign output is suppressed and the key is removed by a trap. Every APK is verified
# with the repo public key before indexing, and the result is checked with apk update trusting ONLY it.
set -eu
set +x
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8222}
SECRET_PATH=${APK_SIGN_SECRET_PATH:-secret/data/blocktools/apk-signing}
CRED_DIR=${APK_SIGN_CRED_DIR:-$HOME/.config/blocktools-apk-signer}
KEY_NAME=${APK_SIGN_KEY_NAME:-blocktools@tsavo-2026.rsa}
PUB=${APK_SIGN_PUB:-$root/packaging/alpine/keys/$KEY_NAME.pub}
ARCH=${APK_ARCH:-x86_64}
DOCKER=${DOCKER:-docker}
[ $# -ge 2 ] || { echo "usage: $0 outdir file.apk..." >&2; exit 2; }
out=$1; shift
[ -r "$PUB" ] || { echo "apk-repo: public key $PUB missing" >&2; exit 1; }
"$root/scripts/apk-verify.sh" "$PUB" "$@" >/dev/null || { echo "apk-repo: an input APK is not signed by $KEY_NAME; refusing" >&2; exit 1; }
for c in role-id secret-id; do
  [ -r "$CRED_DIR/$c" ] || { echo "apk-repo: $CRED_DIR/$c not readable; refusing (no fallback key)" >&2; exit 1; }
done
mkdir -p "$out/$ARCH"; out=$(CDPATH= cd -- "$out" && pwd)
for a in "$@"; do cp -f "$a" "$out/$ARCH/"; done
cp -f "$PUB" "$out/$KEY_NAME.pub"; chmod 644 "$out/$KEY_NAME.pub" "$out/$ARCH"/*.apk
umask 077
tmp=$(mktemp -d /dev/shm/bt-apkrepo.XXXXXX); cid=""
cleanup() {
  if [ -d "$tmp" ]; then shred -u "$tmp"/* 2>/dev/null || rm -f "$tmp"/*; rmdir "$tmp"; fi
  [ -z "$cid" ] || $DOCKER rm -f "$cid" >/dev/null 2>&1 || true  # allow-true: the indexing container may already be gone
  return 0
}
trap cleanup EXIT INT TERM HUP
jq -n --rawfile r "$CRED_DIR/role-id" --rawfile s "$CRED_DIR/secret-id" \
  "{role_id:(\$r|rtrimstr(\"\n\")), secret_id:(\$s|rtrimstr(\"\n\"))}" \
  | curl -sf --max-redirs 0 -X POST -d @- "$VAULT_ADDR/v1/auth/approle/login" > "$tmp/login" \
  || { echo "apk-repo: AppRole login refused or vault unreachable at $VAULT_ADDR" >&2; exit 1; }
printf "X-Vault-Token: %s\n" "$(jq -r .auth.client_token "$tmp/login")" > "$tmp/hdr"
shred -u "$tmp/login" 2>/dev/null || rm -f "$tmp/login"
curl -sf --max-redirs 0 -H @"$tmp/hdr" "$VAULT_ADDR/v1/$SECRET_PATH" > "$tmp/secret" \
  || { echo "apk-repo: this role may not read $SECRET_PATH; refusing" >&2; exit 1; }
curl -sf --max-redirs 0 -X POST -H @"$tmp/hdr" "$VAULT_ADDR/v1/auth/token/revoke-self" >/dev/null 2>&1 || true  # allow-true: token expires in 5m anyway
jq -j .data.data.private_key "$tmp/secret" > "$tmp/$KEY_NAME"
name=$(jq -r .data.data.key_name "$tmp/secret")
shred -u "$tmp/secret" "$tmp/hdr" 2>/dev/null || rm -f "$tmp/secret" "$tmp/hdr"
[ "$name" = "$KEY_NAME" ] || { echo "apk-repo: vault key_name does not match $KEY_NAME; refusing" >&2; exit 1; }
grep -q "PRIVATE KEY" "$tmp/$KEY_NAME" || { echo "apk-repo: vault secret is not a PEM key; refusing" >&2; exit 1; }
cp "$PUB" "$tmp/$KEY_NAME.pub"
# No host bind mounts (the engine may be Docker Desktop, which cannot mount WSL2 paths): stream the
# key into a tmpfs over `docker exec` stdin (RAM only), `docker cp` the public key + APKs in, build and
# sign the index, then `docker cp` the signed APKINDEX.tar.gz back out.
cid=$($DOCKER run -d --tmpfs /k:mode=0700 alpine:3.20 sleep 300) \
  || { echo "apk-repo: could not start indexing container" >&2; exit 1; }
$DOCKER exec -i "$cid" sh -c 'cat > /k/'"$KEY_NAME" < "$tmp/$KEY_NAME"
$DOCKER exec -i "$cid" sh -c 'cat > /k/'"$KEY_NAME.pub" < "$tmp/$KEY_NAME.pub"  # tmpfs: must stream (docker cp lands under the mount)
$DOCKER exec "$cid" mkdir -p /r
for a in "$out/$ARCH"/*.apk; do $DOCKER cp "$a" "$cid:/r/$(basename "$a")" >/dev/null; done
$DOCKER exec "$cid" sh -euc "
  apk add -q abuild >/dev/null 2>&1
  cp /k/$KEY_NAME.pub /etc/apk/keys/
  cd /r && rm -f APKINDEX.tar.gz
  apk index -q --rewrite-arch $ARCH -o APKINDEX.tar.gz *.apk >/dev/null 2>&1
  abuild-sign -q -k /k/$KEY_NAME -p $KEY_NAME.pub APKINDEX.tar.gz >/dev/null 2>&1" \
  || { echo "apk-repo: index build or signing failed" >&2; exit 1; }
$DOCKER cp "$cid:/r/APKINDEX.tar.gz" "$out/$ARCH/APKINDEX.tar.gz" >/dev/null \
  || { echo "apk-repo: index not produced" >&2; exit 1; }
chmod 644 "$out/$ARCH/APKINDEX.tar.gz"
$DOCKER rm -f "$cid" >/dev/null 2>&1; cid=""
cleanup
[ -s "$out/$ARCH/APKINDEX.tar.gz" ] || { echo "apk-repo: index not built" >&2; exit 1; }
# Check: an Alpine container trusting ONLY the repo key accepts the index; one with no key rejects it.
# No key here, so docker cp the public repo + key into a created container, then start it (needs network
# for Alpine main/community to resolve the bash dependency).
vid=$($DOCKER create alpine:3.20 sh -euc "
  cp /$KEY_NAME.pub /etc/apk/keys/
  echo /repo >> /etc/apk/repositories  # keep Alpine main/community for dependencies (bash)
  if apk update 2>&1 | grep -q UNTRUSTED; then echo 'apk-repo: index UNTRUSTED with repo key' >&2; exit 1; fi
  apk add -q --simulate blocktools >/dev/null 2>&1 || { echo 'apk-repo: blocktools not installable with repo key' >&2; exit 1; }
  rm -f /etc/apk/keys/blocktools*
  apk update 2>&1 | grep -q UNTRUSTED || { echo 'apk-repo: index not flagged UNTRUSTED with NO key' >&2; exit 1; }
  if apk add -q --simulate blocktools >/dev/null 2>&1; then echo 'apk-repo: blocktools installable with NO key' >&2; exit 1; fi")
$DOCKER cp "$out" "$vid:/repo" >/dev/null
$DOCKER cp "$PUB" "$vid:/$KEY_NAME.pub" >/dev/null
$DOCKER start -a "$vid" && vrc=0 || vrc=$?
$DOCKER rm -f "$vid" >/dev/null 2>&1 || true  # allow-true: the verify container may already be gone
[ "$vrc" = 0 ] || exit 1
echo "apk-repo: $out/$ARCH: $# apk(s), APKINDEX.tar.gz signed with $KEY_NAME and checked"
