#!/bin/sh
# Fetch public third-party TEST wallets (btcrecover project, GPL-2.0; NOT committed here)
# into fixtures/external/, each pinned by sha256. Their passwords are public test
# passwords ("btcr-test-password"). They hold no real funds. Tests that need them
# are skipped when the files are absent.
set -eu
cd "$(dirname "$0")/.."
B=https://raw.githubusercontent.com/3rdIteration/btcrecover/master/btcrecover/test/test-wallets
D=fixtures/external; mkdir -p "$D"
while read -r sum f; do
  [ -n "$f" ] || continue
  [ -f "$D/$f" ] || curl -sSfL "$B/$f" -o "$D/$f"
  echo "$sum  $D/$f" | sha256sum -c --quiet - || { echo "HASH MISMATCH $f"; rm -f "$D/$f"; exit 1; }
done <<'LIST'
564a16c3b08bbd4c997a4e21ff9eac9323abb6eed8e7d1f0edf32c0d49165b7b bitcoincore-0.20.1-wallet.dat
b66de372458f8b0e92715446c6f698674f89231adacde61ab2493281c3c0a754 bitcoincore-0.21.1-wallet.dat
45608f442c49e0ee386dad545fe77a53025314f51fb0e2c932bb46f795f8b9a3 bitcoincore-wallet.dat
30747b7523bb34b2787d501093d718e396de1d3cb9186d8385dad4cd419db3da electrum-wallet
7e4203e91d3ab8076b0cdf1af6db9f1fb369c4f53566d7da4b7b4f9071720aea electrum2-loosekey-wallet
95d756d4291d4c65eeba75034dcfa58edbd016210f5b5c3b5af825d9d7d6ba90 electrum2-wallet
bd50a60769963c73cbc0f83ea2c4a1f424e33d337aa7ff24c6661d3d81b0ccc1 electrum27-wallet
8b64dbec7feaee7a245aa8473895e330ee5b74f20a4e3a17d25dc2051cf1b721 electrum28-wallet
14cf0506e383a3e42f008d6993f326fc3c0e35bdc29aa4ea65986c20b36bacea electrum41-wallet
85e79eec8d3d70ee6166ddfda853d721494473ab934b9a918fb1fb8319384d92 electrum4_4_3_unencrypted
a259d090e66e380d895175a7beb22d8356b470af72af0c2e0273edf1b0cdfdc7 multibit-wallet.key
3f5c1f6e824d50e85cb8eab5b616ab55e1f22945f8d859f8650e3a75012682f1 multibit-wallet.key.privkeys.txt
2b14b9c99d2095c42b477e1a8d6071a39fe7fd70ac34c2c4fa768b2c3713fd62 multibit.wallet.bitcoinj.clear
050f408e2ab8146866b851923892a71e37af35ce02f454d4957a3e2146133961 multibit.wallet.bitcoinj.encrypted
d1a67482ec75853b1cb84c4d8c4d65c3a3b7535dc15d8441121c3d1db79503ae multibit.wallet.bitcoinj.encrypted.txt
ae67c31362bb46ce54cd81d905f386a3161875d3679d765a2c9eda1907cda2e6 bitcoinj-wallet.wallet
05406a8604202edd7cae85530137542df38b99084d300d8defcbb8948f513f68 mbhd.wallet.aes
LIST
echo "fixtures ok: $(ls "$D" | wc -l) files in $D"
