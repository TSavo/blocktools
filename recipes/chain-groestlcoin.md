# Chain: Groestlcoin

`--chain grs`. Same pipeline as Bitcoin, with three differences that the tools handle:
base58 addresses and WIF use a Groestl-512 double-hash checksum (so a Bitcoin-checksummed `3…`
is NOT a valid GRS address); txids and signature hashes (legacy and BIP143) use single SHA-256;
the bech32 HRP is `grs`. SLIP-44 coin 17. Taproot is off.

<!-- e2e: expect=grs1qrm2uggqj846nljryvmuga56vtwfey0dtnc4z55 ; expect=Fpzstx4fKWhqZYbVVmuncuhbEmgecqPTgg -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain grs --count 1'

Sweep: build → verify → sign → decode is covered by scripts/e2e.d/sweep-alt.sh (127.0.0.1 only,
key 1, pty-typed code), and the signature hashes are checked against real Groestlcoin mainnet
transactions in crates/tx/tests/grs.rs.
Not supported: GRS xpubs with a Groestl checksum (`deriveFromXpub` takes Bitcoin-checksummed xpubs only).
UNTESTED against a live GRS network or explorer.
