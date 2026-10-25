# Chain: Polkadot

Addresses and keys only. The BIP39 mnemonic goes straight to `key-to-addresses --chain dot`
(Substrate does not use the BIP39 seed: the key comes from the mnemonic's entropy). Root sr25519
account only, the polkadot.js / subkey default for an imported phrase; SS58 prefix 0 (`1...`).

<!-- e2e: expect=15rRgsWxz4H5LTnNGcCFsszfXD8oeAFd8QRsR6MbQE2f6XFF -->
    ./blocktools run 'key-to-addresses --chain dot < /in/dot-mnemonic.txt'

The key is printed as `private_key` = 0x-hex mini-secret (subkey/polkadot.js "raw seed"), redacted by `redact`.
NOT BUILT: derivation paths (`//hard`, `/soft`), mnemonic password, ed25519 or ecdsa Substrate
accounts, Kusama and parachain prefixes, transfers, balance lookup.
