# Message-signature test vectors: provenance

Vectors used by `crates/blocktools/tests/msg_chains.rs` (msg-verify / wasm `msgVerify`, `msgVerifyOpts`).
Only public test keys appear. Anything without a published vector is marked UNTESTED.

| Chain / format | Source | What is checked | Status |
|---|---|---|---|
| Tron signMessageV2 | Trust Wallet Core `tests/chains/Tron/TronMessageSignerTests.cpp`, commit 2a8aa02011ec42b43689667682fa99ae905418d5 (public test key 75065f…, address TWWb9EjUWai17YEVB7FR8hreupYJKG9sMR) | 2 signatures ("Hello World" and the longer message) recover to the address | vector-tested |
| Solana raw | Trust Wallet Core `tests/chains/Solana/SolanaMessageSigner.cpp` and `rust/tw_tests/tests/chains/solana/solana_message_sign.rs` (`MessageType_raw`), same commit (pubkey ee6d61a8…06f9 = H3imdwa5VQMB5V6yBNyrWwPdSKs4k9Pcpsu4diogoAcg, "Hello world") | ed25519 signature verifies | vector-tested |
| Solana offchain-v0 | anza-xyz/solana-sdk `offchain-message/src/lib.rs` tests, commit 001c6d916887bd4690bc181d257e2d7553015549, (serialization and hash of the v0 preamble + message) | serialized bytes hash to the published values HG5JydBG… and 6GXTveat… | layout vector-tested; signature UNTESTED (no published `solana sign-offchain-message` signature used) |
| Cosmos ADR-036 | cosmos-sdk ADR-036 (status: Draft) for the sign doc | self round-trip with a dummy key; the spec's own JSON example is refused (its signer address has an invalid bech32 checksum and its signature does not verify for the corrected address) | UNTESTED against wallet output |
| Ethereum / Bitcoin | Trust Wallet Core EthMessageSigner / BitcoinMessageSigner (`crates/tx/tests/twc_message.rs`) | unchanged | vector-tested |

msg-sign (`scripts/e2e.d/msg-chains-sign.sh`) uses the same sources: the Tron key 75065f… and the Solana key
44f480ca27711895586074a14c552e58cc52e66a58edb6c58cf9b9b7295d4a2d (TWC `SolanaMessageSigner.cpp`, same commit, public test key)
must reproduce the published signatures byte for byte. Solana offchain-v0 and Cosmos ADR-036 (dummy key 0x46 x32,
cosmos1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0emlrvp) are only checked by msg-verify on the same machine: UNTESTED.

Deferred (no unambiguous published spec plus vector here): Tezos (Micheline formatting), Sui (intent + BCS +
blake2b), TON, StarkEx, Trust Wallet Core's 85-byte Solana off-chain layout, Ethermint eth_secp256k1 keys, Tron v 0/1.
