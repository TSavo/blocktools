#!/bin/sh
# Sign blocktools RPMs and build a signed dnf/yum repository with the RPM GPG key held in Vault. Runs on the
# Battleaxe HOST, never inside a runner container (same reasoning as apk-sign-host.sh). See docs/RPM-SIGNING.md.
#   scripts/rpm-sign-host.sh REPO_DIR        # REPO_DIR holds the *.rpm files; repodata/ is (re)built there
# Key path: Vault -> 0600 file on tmpfs (/dev/shm) -> read-only bind into a one-shot Fedora container whose
# GNUPGHOME is a tmpfs. rpmsign --addsign each RPM, createrepo_c, detached armored repodata/repomd.xml.asc.
# Then every RPM is checked with rpm -K, and repomd.xml.asc with gpgv, against the repo public key ONLY.
set -eu
set +x
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8222}
SECRET_PATH=${RPM_SIGN_SECRET_PATH:-secret/data/blocktools/rpm-signing}
CRED_DIR=${RPM_SIGN_CRED_DIR:-$HOME/.config/blocktools-rpm-signer}
PUB=${RPM_SIGN_PUB:-$root/packaging/rpm/RPM-GPG-KEY-blocktools}
IMG=${RPM_SIGN_IMAGE:-blocktools-rpmsign:f40}
DOCKER=${DOCKER:-docker}
[ $# -eq 1 ] && [ -d "$1" ] || { echo "usage: $0 REPO_DIR (containing *.rpm)" >&2; exit 2; }
repo=$(CDPATH= cd -- "$1" && pwd)
ls "$repo"/*.rpm >/dev/null 2>&1 || { echo "rpm-sign: no .rpm in $repo" >&2; exit 2; }
[ -r "$PUB" ] || { echo "rpm-sign: public key $PUB missing" >&2; exit 1; }
for c in role-id secret-id; do
  [ -r "$CRED_DIR/$c" ] || { echo "rpm-sign: $CRED_DIR/$c not readable; refusing (no fallback key)" >&2; exit 1; }
done
# Signing runs with --network none, so the tools are baked into a local image first (no key involved).
$DOCKER image inspect "$IMG" >/dev/null 2>&1 || printf 'FROM fedora:40\nRUN dnf -q -y install rpm-sign createrepo_c gnupg2 && dnf clean all\n' \
  | $DOCKER build -q -t "$IMG" - >/dev/null || { echo "rpm-sign: could not build $IMG" >&2; exit 1; }
umask 077
tmp=$(mktemp -d /dev/shm/bt-rpmsign.XXXXXX)
work=; cid=""
cleanup() {
  if [ -d "$tmp" ]; then shred -u "$tmp"/* 2>/dev/null || rm -f "$tmp"/*; rmdir "$tmp"; fi
  [ -z "$work" ] || rm -rf "$work"
  [ -z "$cid" ] || $DOCKER rm -f "$cid" >/dev/null 2>&1 || true
  return 0
}
trap cleanup EXIT INT TERM HUP
jq -n --rawfile r "$CRED_DIR/role-id" --rawfile s "$CRED_DIR/secret-id" \
  "{role_id:(\$r|rtrimstr(\"\n\")), secret_id:(\$s|rtrimstr(\"\n\"))}" \
  | curl -sf --max-redirs 0 -X POST -d @- "$VAULT_ADDR/v1/auth/approle/login" > "$tmp/login" \
  || { echo "rpm-sign: AppRole login refused or vault unreachable at $VAULT_ADDR" >&2; exit 1; }
printf "X-Vault-Token: %s\n" "$(jq -r .auth.client_token "$tmp/login")" > "$tmp/hdr"
shred -u "$tmp/login" 2>/dev/null || rm -f "$tmp/login"
curl -sf --max-redirs 0 -H @"$tmp/hdr" "$VAULT_ADDR/v1/$SECRET_PATH" > "$tmp/secret" \
  || { echo "rpm-sign: this role may not read $SECRET_PATH (or it is missing); refusing" >&2; exit 1; }
curl -sf --max-redirs 0 -X POST -H @"$tmp/hdr" "$VAULT_ADDR/v1/auth/token/revoke-self" >/dev/null 2>&1 || true  # allow-true: token expires in 5m anyway
jq -j .data.data.private_key "$tmp/secret" > "$tmp/key.asc"
fpr=$(jq -r .data.data.fingerprint "$tmp/secret")
shred -u "$tmp/secret" "$tmp/hdr" 2>/dev/null || rm -f "$tmp/secret" "$tmp/hdr"
grep -q "BEGIN PGP PRIVATE KEY BLOCK" "$tmp/key.asc" || { echo "rpm-sign: vault secret is not an armored PGP key; refusing" >&2; exit 1; }
work=$(mktemp -d)
cp "$repo"/*.rpm "$work/"
cp "$PUB" "$work/pub.asc"
# No host bind mounts (the engine may be Docker Desktop, which cannot mount WSL2 paths): the key goes
# into a container tmpfs over `docker exec` stdin (RAM only), the public key + RPMs via `docker cp`;
# sign + build repodata offline (--network none), then `docker cp` the signed RPMs + repodata back.
# Run as root in the ephemeral, offline (--network none) container: the old --user existed only so
# bind-mounted outputs were host-owned; `docker cp` out is written as the host user regardless. /k and
# the GNUPGHOME are tmpfs (RAM only). Outputs are copied back out below, so container ownership is moot.
cid=$($DOCKER run -d --network none -e HOME=/gnupg \
  --tmpfs /k:mode=0700 --tmpfs /gnupg:mode=0700 -e GNUPGHOME=/gnupg -e FPR="$fpr" "$IMG" sleep 300) \
  || { echo "rpm-sign: could not start signing container" >&2; exit 1; }
$DOCKER exec -i "$cid" sh -c 'cat > /k/key.asc' < "$tmp/key.asc"
$DOCKER exec "$cid" mkdir -p /r
for f in "$work"/*.rpm "$work/pub.asc"; do $DOCKER cp "$f" "$cid:/r/$(basename "$f")" >/dev/null; done
$DOCKER exec "$cid" sh -euc '
  command -v rpmsign createrepo_c >/dev/null 2>&1 || exit 3
  gpg --batch --import /k/key.asc >/dev/null 2>&1
  gpg --batch --with-colons --list-secret-keys | grep -q "^fpr:::::::::$FPR:" || exit 4
  gpg --batch --with-colons --import-options show-only --import /r/pub.asc | grep -q "^fpr:::::::::$FPR:" || exit 5
  rpmsign --define "_gpg_name $FPR" --addsign /r/*.rpm >/dev/null 2>&1
  createrepo_c -q --general-compress-type=gz /r >/dev/null
  gpg --batch --yes --local-user "$FPR" --armor --detach-sign -o /r/repodata/repomd.xml.asc /r/repodata/repomd.xml >/dev/null 2>&1' \
  2>/dev/null || { rc=$?; $DOCKER rm -f "$cid" >/dev/null 2>&1; cid=""
    { [ "$rc" = 125 ] || [ "$rc" = 3 ]; } && echo "rpm-sign: image $IMG needs rpm-sign and createrepo_c " >&2
    { [ "$rc" = 4 ] || [ "$rc" = 5 ]; } && echo "rpm-sign: vault key fingerprint does not match $PUB; refusing" >&2
    echo "rpm-sign: signing failed (rc $rc)" >&2; exit 1; }
for f in "$work"/*.rpm; do $DOCKER cp "$cid:/r/$(basename "$f")" "$f" >/dev/null; done
rm -rf "$work/repodata"; $DOCKER cp "$cid:/r/repodata" "$work/repodata" >/dev/null
$DOCKER rm -f "$cid" >/dev/null 2>&1; cid=""
shred -u "$tmp/key.asc" 2>/dev/null || rm -f "$tmp/key.asc"; rmdir "$tmp"
RPM_VERIFY_IMAGE=$IMG "$root/scripts/rpm-verify.sh" "$PUB" "$work"
rm -f "$work/pub.asc"
rm -rf "$repo/repodata"; cp -f "$work"/*.rpm "$repo/"; cp -r "$work/repodata" "$repo/"
chmod -R go+rX "$repo"   # public repo content; the umask above is for the key only
echo "rpm-sign: signed and verified $(ls "$work"/*.rpm | wc -l) rpm(s) and repodata with $fpr"
