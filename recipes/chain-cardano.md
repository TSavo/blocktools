# Chain: Cardano

Addresses and keys only. A Shelley-era wallet phrase (Yoroi, Eternl, Lace, Daedalus Shelley;
12/15/24 BIP39 words) goes to `key-to-addresses --chain ada`: Icarus master key from the BIP39
entropy, CIP-1852 payment keys m/1852'/1815'/0'/0/0..4 and stake key m/1852'/1815'/0'/2/0,
mainnet base addresses `addr1q...`.

<!-- e2e: expect=addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv -->
    ./blocktools run 'key-to-addresses --chain ada < /in/ada-mnemonic.txt'

`private_key` is the hex extended payment key (kL||kR), redacted by `redact`.
NOT BUILT: Ledger / Trezor master-key derivations (different from Icarus for 24 words), Byron
addresses (Ae2.../DdzFF...) and legacy Daedalus, spending passphrase, accounts > 0, change
addresses, transfers and balance lookup. Look the addresses up on a block explorer.
