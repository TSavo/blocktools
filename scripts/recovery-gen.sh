#!/bin/sh
# Write throwaway wallets with the REAL third-party software into OUTDIR (a temp dir; never commit them).
#   Bitcoin Core 25.2 (bitcoincore.org tarball, sha256 pinned below = its SHA256SUMS line; signature not checked)
#   Electrum 4.5.8 (download.electrum.org sdist, sha256 pinned), eth-account 0.13.4, python-mnemonic 0.21 (pip, pinned)
# Electrum's libsecp256k1 is loaded from coincurve 21.0.0's bundled build (same upstream library), so no
# system package is needed. Downloads are cached in $BLOCKTOOLS_RECOVERY_CACHE (default $XDG_CACHE_HOME or ~/.cache, /blocktools-recovery).
# Outputs: core-legacy.dat core-desc.dat electrum-fileenc electrum-keyenc eth.json (wallets) and, per wallet,
# *.want = addresses printed by the generator itself; bip39.seed + bip.want (Core deriveaddresses on the
# python-mnemonic xprv); electrum-*.seed. Exit 3 = a prerequisite is missing (network, python3 venv).
set -eu
O=$(cd "$1" && pwd); ROOT=$(cd "$(dirname "$0")/.." && pwd)
CACHE=${BLOCKTOOLS_RECOVERY_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/blocktools-recovery}; mkdir -p "$CACHE"
CORE=bitcoin-25.2-x86_64-linux-gnu.tar.gz; CORE_SHA=8d8c387e597e0edfc256f0bbace1dac3ad1ebf4a3c06da3e2975fda333817dea
EL=Electrum-4.5.8.tar.gz; EL_SHA=dd8595a138132dee87cee76ce760a1d622fc2fd65d3b6ac7df7e53b7fb6ea7e8
get() { [ -f "$CACHE/$1" ] || curl -fsSL -o "$CACHE/$1.part" "$2" && { [ ! -f "$CACHE/$1.part" ] || mv "$CACHE/$1.part" "$CACHE/$1"; }
  echo "$3  $CACHE/$1" | sha256sum -c --quiet - || { rm -f "$CACHE/$1"; echo "recovery-gen: $1 sha256 mismatch" >&2; exit 1; }; }
get $CORE https://bitcoincore.org/bin/bitcoin-core-25.2/$CORE $CORE_SHA || exit 3
get $EL https://download.electrum.org/4.5.8/$EL $EL_SHA || exit 3
V="$CACHE/venv"
if [ ! -x "$V/bin/electrum" ]; then
  python3 -m venv "$V" || exit 3
  "$V/bin/pip" -q install eth-account==0.13.4 mnemonic==0.21 cryptography coincurve==21.0.0 "$CACHE/$EL" || exit 3
  cp "$V"/lib/python3*/site-packages/coincurve/_libsecp256k1*.so "$(echo "$V"/lib/python3*/site-packages/electrum)/libsecp256k1.so.2"
fi
PY="$V/bin/python3"
[ -x "$CACHE/bitcoin-25.2/bin/bitcoind" ] || tar xzf "$CACHE/$CORE" -C "$CACHE"
BD="$CACHE/bitcoin-25.2/bin"; D="$O/core"; mkdir -p "$D"
C="$BD/bitcoin-cli -datadir=$D -rpcport=18765"
"$BD/bitcoind" -datadir="$D" -rpcport=18765 -connect=0 -listen=0 -dnsseed=0 -daemon -keypool=3 -noprinttoconsole
trap '$C stop >/dev/null 2>&1 || :' EXIT  # allow-true: daemon may already be stopped
$C -rpcwait createwallet legacy false false "" false false >/dev/null
{ $C -rpcwallet=legacy getnewaddress "" legacy; $C -rpcwallet=legacy getnewaddress "" bech32; } > "$O/core-legacy.want"
$C -rpcwallet=legacy encryptwallet Horsebattery7 >/dev/null
$C createwallet desc false false "" false true >/dev/null
$C -rpcwallet=desc getnewaddress "" bech32 > "$O/core-desc.want"
$C -rpcwallet=desc encryptwallet Horsebattery7 >/dev/null
"$PY" -c "from mnemonic import Mnemonic as M;m=M('english');w=m.generate(128);open('$O/bip39.seed','w').write(w+'\n');open('$O/bip39.xprv','w').write(m.to_hd_master_key(m.to_seed(w,'')))"
XP=$(cat "$O/bip39.xprv"); rm "$O/bip39.xprv"
CK=$($C getdescriptorinfo "wpkh($XP/84h/0h/0h/0/*)" | "$PY" -c 'import json,sys;print(json.load(sys.stdin)["checksum"])')
$C deriveaddresses "wpkh($XP/84h/0h/0h/0/*)#$CK" "[0,2]" | "$PY" -c 'import json,sys;print("\n".join(json.load(sys.stdin)))' > "$O/bip.want"
$C stop >/dev/null; trap - EXIT; i=0; while [ -f "$D/bitcoind.pid" ] && [ $i -lt 30 ]; do sleep 1; i=$((i + 1)); done
cp "$D/legacy/wallet.dat" "$O/core-legacy.dat"; cp "$D/desc/wallet.dat" "$O/core-desc.dat"; rm -rf "$D"
"$PY" "$ROOT/scripts/recovery-gen/electrum_gen.py" "$O" Horsebatetry7; rm -rf "$O/edir"
"$PY" -c "
import json;from eth_account import Account as A;a=A.create()
open('$O/eth.json','w').write(json.dumps(A.encrypt(a.key,'Horse7')));open('$O/eth.want','w').write(a.address+'\n')
# eth-keyfile drops leading zero IV bytes (~1 in 256 keystores): always also write one such file.
while True:
  j=A.encrypt(a.key,'Horse7',kdf='pbkdf2',iterations=1000)
  if len(j['crypto']['cipherparams']['iv'])<32: break
open('$O/eth-shortiv.json','w').write(json.dumps(j))"
echo "recovery-gen ok: $(ls "$O" | wc -l | tr -d ' ') files in $O"
