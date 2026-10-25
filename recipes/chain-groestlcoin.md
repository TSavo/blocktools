# Chain: Groestlcoin

`--chain grs`. Same pipeline as Bitcoin, with three differences that the tools handle:
base58 addresses and WIF use a Groestl-512 double-hash checksum (so a Bitcoin-checksummed `3…`
is NOT a valid GRS address); txids and signature hashes (legacy and BIP143) use single SHA-256;
the bech32 HRP is `grs`. SLIP-44 coin 17. Taproot (grs1p…) addresses are derived and can be paid to, but
spending a GRS taproot input is refused.

<!-- e2e: expect=grs1qrm2uggqj846nljryvmuga56vtwfey0dtnc4z55 ; expect=Fpzstx4fKWhqZYbVVmuncuhbEmgecqPTgg -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain grs --count 1'

Sweep: build → verify → sign → decode is covered by scripts/e2e.d/sweep-alt.sh (127.0.0.1 only,
key 1, pty-typed code), and the signature hashes are checked against real Groestlcoin mainnet
transactions in crates/tx/tests/grs.rs.
Taproot address for key 1 (BIP341 vector; Groestlcoin ships the same bip341_wallet_vectors.json):

<!-- e2e: expect=grs1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sswdv5ep ; expect=grs1qw508d6qejxtdg4y5r3zarvary0c5xw7k3k4sj5 -->
    ./blocktools run 'key-to-addresses --chain grs < /in/key.hex'

Offline sweep, p2wpkh (key 1) -> p2tr (key 2):

<!-- e2e: expect=grs1pet7ep3czdu9k4wvdlz2fp5p8x2yp7t6ttyqg2c6cmh0lgeuu9las566mlv -->
    ./blocktools run 'tx-build --chain grs --utxos /in/u-grs.json --to grs1pet7ep3czdu9k4wvdlz2fp5p8x2yp7t6ttyqg2c6cmh0lgeuu9las566mlv --sweep --fee-rate 5 | tx-decode --chain grs'

GRS xpubs (and tpubs) carry the Groestl-512 checksum. They are accepted only with `--chain grs`, and classify reports them
as `xpub`. Example: a Groestl-checksummed tpub from Groestlcoin/eclair commit f52fbf9:

<!-- e2e: expect=grs1qs5em33g0gktaxxw8fd8mkfsdvvr8rf04h682zq ; expect=FhK2H7a26Xyy9tLqejgH5rD4q2cXqVmjXP -->
    ./blocktools run 'xpub-addresses --chain grs --change 0 --count 1 < /in/grs-tpub.txt'

UNVERIFIED: the addresses above. The vector checks only the checksum, not addresses derived from this tpub (and it is a
testnet key shown with mainnet prefixes). Compare against your GRS wallet's first receive address.
UNTESTED against a live GRS network or explorer.
