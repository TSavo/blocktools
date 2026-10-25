# Chain: TON

Addresses and keys only. A TON wallet's 24-word phrase uses the BIP39 word list but its own
checksum and key derivation (it is NOT a BIP39 mnemonic): `classify` reports `ton_mnemonic`,
`key-to-addresses --chain ton` gives the wallet v4r2 address (Tonkeeper / Tonhub / TON Wallet
default for years), workchain 0, non-bounceable form `UQ...` (the same account as `EQ...`).

<!-- e2e: expect=UQCCZtVXlbxxKJbbZti9ESdAkizMyK_CTl0x65osWV1TnALb -->
    ./blocktools run 'key-to-addresses --chain ton < /in/ton-mnemonic.txt'

`private_key` is the hex ed25519 seed, redacted by `redact`. If the funds are not at the v4r2
address the wallet may be v3r2, v5r1 or W5: NOT BUILT, nor password-protected TON phrases,
testnet, jettons, transfers or balance lookup.
