#!/bin/sh
# Build and sign the blocktools apt repository with the GPG key held in Vault. Runs on the Battleaxe
# HOST, never inside a runner container (same reasoning as scripts/apk-sign-host.sh). See docs/APT-SIGNING.md.
#   scripts/apt-sign-host.sh OUTDIR file.deb [...]
# Writes OUTDIR/pool/main/b/blocktools/*.deb and OUTDIR/dists/stable/{Release,InRelease,Release.gpg,
# main/binary-amd64/Packages(.gz)}. The private key goes Vault -> 0600 file in a throwaway GNUPGHOME on
# tmpfs (/dev/shm), never stdout, stderr, argv or the repo, and a trap shreds it. Afterwards InRelease and
# Release.gpg are checked with gpgv against the repo public keyring ONLY.
set -eu
set +x
if (set -o pipefail) 2>/dev/null; then set -o pipefail; fi
root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
VAULT_ADDR=${VAULT_ADDR:-http://127.0.0.1:8222}
SECRET_PATH=${APT_SIGN_SECRET_PATH:-secret/data/blocktools/apt-signing}
CRED_DIR=${APT_SIGN_CRED_DIR:-$HOME/.config/blocktools-apt-signer}
KEYRING=${APT_SIGN_KEYRING:-$root/packaging/apt/blocktools-archive-keyring.asc}
SUITE=${APT_SUITE:-stable}
[ $# -ge 2 ] || { echo "usage: $0 OUTDIR file.deb..." >&2; exit 2; }
out=$1; shift
[ -r "$KEYRING" ] || { echo "apt-sign: public keyring $KEYRING missing" >&2; exit 1; }
for c in role-id secret-id; do
  [ -r "$CRED_DIR/$c" ] || { echo "apt-sign: $CRED_DIR/$c not readable; refusing (no fallback key)" >&2; exit 1; }
done
umask 077
tmp=$(mktemp -d /dev/shm/bt-aptsign.XXXXXX)
cleanup() {
  if [ -d "$tmp" ]; then
    GNUPGHOME=$tmp/g gpgconf --kill all >/dev/null 2>&1 || true  # allow-true: agent may not be running
    find "$tmp" -type f -exec shred -u {} + 2>/dev/null || true  # allow-true: rm below is the fallback
    rm -rf "$tmp"
  fi
  return 0
}
trap cleanup EXIT INT TERM HUP
jq -n --rawfile r "$CRED_DIR/role-id" --rawfile s "$CRED_DIR/secret-id" \
  "{role_id:(\$r|rtrimstr(\"\n\")), secret_id:(\$s|rtrimstr(\"\n\"))}" \
  | curl -sf --max-redirs 0 -X POST -d @- "$VAULT_ADDR/v1/auth/approle/login" > "$tmp/login" \
  || { echo "apt-sign: AppRole login refused or vault unreachable at $VAULT_ADDR" >&2; exit 1; }
printf "X-Vault-Token: %s\n" "$(jq -r .auth.client_token "$tmp/login")" > "$tmp/hdr"
shred -u "$tmp/login" 2>/dev/null || rm -f "$tmp/login"
curl -sf --max-redirs 0 -H @"$tmp/hdr" "$VAULT_ADDR/v1/$SECRET_PATH" > "$tmp/secret" \
  || { echo "apt-sign: this role may not read $SECRET_PATH (or it is missing); refusing" >&2; exit 1; }
curl -sf --max-redirs 0 -X POST -H @"$tmp/hdr" "$VAULT_ADDR/v1/auth/token/revoke-self" >/dev/null 2>&1 || true  # allow-true: token expires in 5m anyway
jq -j .data.data.private_key "$tmp/secret" > "$tmp/key"
fp=$(jq -r .data.data.fingerprint "$tmp/secret")
shred -u "$tmp/secret" "$tmp/hdr" 2>/dev/null || rm -f "$tmp/secret" "$tmp/hdr"
grep -q "BEGIN PGP PRIVATE KEY BLOCK" "$tmp/key" || { echo "apt-sign: vault secret is not an armored PGP key; refusing" >&2; exit 1; }
# The Vault key must be the one whose public half is committed.
pubfp=$(gpg --batch --no-default-keyring --with-colons --show-keys "$KEYRING" 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
[ "$fp" = "$pubfp" ] || { echo "apt-sign: vault fingerprint does not match $KEYRING; refusing" >&2; exit 1; }
mkdir -m 700 "$tmp/g"; export GNUPGHOME=$tmp/g
gpg --batch --quiet --import "$tmp/key" >/dev/null 2>&1 || { echo "apt-sign: key import failed" >&2; exit 1; }
shred -u "$tmp/key" 2>/dev/null || rm -f "$tmp/key"
# Repository layout (unsigned parts).
pool=$out/pool/main/b/blocktools; bin=$out/dists/$SUITE/main/binary-amd64
mkdir -p "$pool" "$bin"; chmod 755 "$out" "$out/pool" "$out/pool/main" "$out/pool/main/b" "$pool" "$out/dists" "$out/dists/$SUITE" "$out/dists/$SUITE/main" "$bin"
for d in "$@"; do cp "$d" "$pool/"; chmod 644 "$pool/$(basename "$d")"; done
(cd "$out" && apt-ftparchive packages pool > "dists/$SUITE/main/binary-amd64/Packages")
gzip -9nkf "$bin/Packages"
(cd "$out/dists/$SUITE" && apt-ftparchive \
  -o APT::FTPArchive::Release::Origin=blocktools -o APT::FTPArchive::Release::Label=blocktools \
  -o APT::FTPArchive::Release::Suite="$SUITE" -o APT::FTPArchive::Release::Codename="$SUITE" \
  -o APT::FTPArchive::Release::Architectures=amd64 -o APT::FTPArchive::Release::Components=main \
  release . > Release.new && mv Release.new Release)
rel=$out/dists/$SUITE
rm -f "$rel/InRelease" "$rel/Release.gpg"
gpg --batch --quiet --local-user "$fp" --digest-algo SHA512 --clearsign -o "$rel/InRelease" "$rel/Release" 2>/dev/null \
  && gpg --batch --quiet --local-user "$fp" --digest-algo SHA512 --armor --detach-sign -o "$rel/Release.gpg" "$rel/Release" 2>/dev/null \
  || { echo "apt-sign: signing failed" >&2; exit 1; }
chmod 644 "$rel/Release" "$rel/InRelease" "$rel/Release.gpg" "$bin/Packages" "$bin/Packages.gz"
cleanup; unset GNUPGHOME
# Verify with ONLY the committed public key (dearmored to a temp keyring for gpgv).
kr=$(mktemp); gpg --batch --yes --dearmor -o "$kr" "$KEYRING" 2>/dev/null || cp "$KEYRING" "$kr"; KEYRING=$kr
gpgv --keyring "$KEYRING" "$rel/InRelease" >/dev/null 2>&1 || { echo "apt-sign: InRelease does not verify against $KEYRING" >&2; exit 1; }
gpgv --keyring "$KEYRING" "$rel/Release.gpg" "$rel/Release" >/dev/null 2>&1 || { echo "apt-sign: Release.gpg does not verify against $KEYRING" >&2; exit 1; }
rm -f "$kr"
echo "apt-sign: signed and verified $out/dists/$SUITE ($# deb(s)) with $fp"
