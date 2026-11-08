# BitConnect archival verification (2026-11-08 PST)

**Bitcoin-style fork: yes. Supported-chain promotion: no.** This checks the existing `bcc`
row, not a new row. No release or claim restamp is implied.

## Source parameters

Re-read [bitconnectcoin/bitconnectcoin at 3ab3d19](https://github.com/bitconnectcoin/bitconnectcoin/tree/3ab3d19):

- `src/base58.h:279-280`: mainnet P2PKH 18, P2SH 85. Use the enum, not the stale preceding
  comment saying P2PKH 25. `:408` sets WIF to 128 + 18 = 146.
- `src/base58.h:136/152`, `src/util.h:450-457`: Base58Check uses double SHA-256.
- `src/main.h:438-465`: version 1, **32-bit nTime immediately after nVersion**, then vin, vout,
  nLockTime. This is Bitcoin-style UTXO serialization with an extra timestamp, not Bitcoin's
  unchanged transaction format. `src/script.cpp:1190-1191` hashes the serialized transaction
  plus hash type, so nTime participates in the legacy sighash.
- `src/main.cpp:2545-2586`: genesis timestamp/message and asserted Merkle root.
- [SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md): no BitConnect
  allocation; 268 BCC is **BCChain**. Do not substitute it or claim BIP44 coin type 0.

## Surviving mainnet data

The old [Cryptoid transaction link](https://chainz.cryptoid.info/bcc/tx.dws?0fd7da348079d91726641adf9902ee0b29461cf4885ede4cd5c54a45c8afe0ba)
now returned the generic explorer directory, not transaction bytes. A Wayback CDX lookup timed
out; that is not proof no archive exists. The replacement `chainconnect.network` fetch returned
an explorer repository README rather than a usable live RPC endpoint.

A public [bootstrap release](https://github.com/bitconnectCore/bitconnect-blockchain-bootstrap/releases/tag/1.0)
survives: [bitconnect.zip](https://github.com/bitconnectCore/bitconnect-blockchain-bootstrap/releases/download/1.0/bitconnect.zip),
952185431 bytes, SHA-256
`fa28f1c06e1ce1b4d66db10046806d4e4d71298e224e6a30412ca1b0ff183992`, matching the
publisher's checksum. Only public `bitconnect/blk0001.dat` was parsed; no wallet or executable
was opened. The release describes a height-1083000 snapshot; this check only reads through 1337.

Independent published anchors in the [chainConnect README](https://github.com/ThebCC/chainConnect.network)
match the archive:

- Genesis block: `00000d3bd95c47fa17c47e1e2732d7072a6c4014a2fa93873124418a8fd9a300`.
- Genesis transaction: `2bf84615b1764b410285da38aa6a724b84ddd62b4a5dcec70a4c1bbaf6a09c09`.
- Height 1337 block: `0000000000d9a46c3126e02b128234d38be28397b13363c9dedf1dbc177dc687`.
- Height 1337 transaction: `97536cabf065a9818448ee8566df1d2a0bdfb7e2e6d51f85084b912579bf81b4`.
- Its P2PK output maps to `8VX7ER5ksnLH3iu5chm4yvJTgkMRy7SoKD` with P2PKH version 18.
  This independently checks an address, not just a synthetic generator-key KAT.

The extractor checks all 1338 block Merkle roots and header links from genesis through 1337,
with scrypt header hashes matching both published block anchors. It does **not** perform a full
node consensus replay or establish current chain availability.

## Checked-in vectors

`crates/tx/tests/data/bcc_mainnet.json` contains public raw bytes for the genesis, height-1337
coinbase, a height-59 P2PKH spend, and its previous transaction:

- Spend: `0cf3db13a15f261a7a3c3ecfc2d225fe324acadee1ecb3533a7d68dabf8cc4a1`.
- Previous transaction: `58de1e8cb0e29d49b475e6c1fa6cea3529c16859ee71e5cd5ff20db6d252a09b`.

All four round-trip with nTime at bytes 4..8 and SHA256d txids match. The spend's SIGHASH_ALL
signature verifies against its actual previous output **including nTime**; excluding nTime
fails. The public key also hashes to that output's P2PKH script. This confirms the historical
wire/sighash layout, not merely a plausible timestamp. P2SH and WIF bytes remain source-backed;
these vectors do not independently exercise a P2SH spend or a WIF import.

The test deliberately uses the existing PPC-layout parser as a reference. It does not add `bcc`
to the decoder layout table, POS_SWEEP allowlist, or signer. `verified` stays false: this pass
does not relax the registry's source/SLIP-44/independent-KAT gate, invent an allocated BIP44
coin type, or validate a dedicated BCC build/sign lifecycle. Address recovery in the synthetic
recipe is still distinct from supported signing. `tx-build --chain bcc` still exits 2 with
`unverified chain parameters: not supported`; auto-detect still excludes BCC.

## Reproduce

Download the public ZIP above (do not run bundled software), then:

```sh
python3 scripts/extract-bcc-vectors.py bitconnect.zip > bcc_mainnet.json
cmp bcc_mainnet.json crates/tx/tests/data/bcc_mainnet.json
cargo test -p blocktools-tx --test pos
cargo test -p blocktools-tx --features secrets --test pos
cargo test -p blocktools --test coins
cargo test -p blocktools-core every_utxo_row_matches_independent_vector
```

The extractor checks the archive checksum before parsing and never extracts wallet data.
The raw bytes are archival evidence, not synthetic fixtures or broadcast candidates.
