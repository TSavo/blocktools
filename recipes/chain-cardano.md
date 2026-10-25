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
addresses. Look the addresses up on a block explorer, or use utxo-fetch below.

## Transfers (payment / sweep)

    utxo-fetch --chain ada addr1...SOURCE       # Koios: one line per UTxO with "utxo":"TXID#IX:LOVELACE"
    acct-tx build --chain ada --from addr1...SOURCE --to addr1...DEST \
        --utxo TXID#IX:LOVELACE [--utxo ...] (--amount LOVELACE | --sweep) --fee 180000 --ttl SLOT > unsigned.json
    acct-tx decode --chain ada < unsigned.json  # review
    acct-tx sign --chain ada --tx unsigned.json --expect-to addr1...DEST > signed.json
    # signed.json "signed" is hex CBOR (cardano-cli cborHex); submit it from a networked host.

The secret for sign is the 128-hex `private_key` from key-to-addresses (the row whose address is
`--from`); sign refuses a key whose hash is not the from address's payment part. Change (inputs -
amount - fee) goes back to `--from`; change between 0 and 1 ADA is refused. build refuses a fee below
44*size+155381 lovelace; TTL is an absolute slot (current tip slot + e.g. 7200).
KAT: signed tx bytes == pycardano 0.19.2 for payment-with-change and sweep (abandon...about vector).
Lookup tested live against Koios on an empty address only.
NOT BUILT: UTxOs carrying native assets / tokens (utxo-fetch flags them; never pass them), multi-asset
outputs, staking/delegation certificates, withdrawals, metadata, Byron inputs, protocol-parameter fetch
(fee constants are hardcoded mainnet values), testnet.

## Worked sweep (tested)

Unsigned sweep for abandon...about account 0, address 0 -> address 1, one 5 ADA UTxO. Inside `./blocktools run` write the UTxO as `TXID.IX:LOVELACE` (the boundary refuses `#`), decoded through the agent boundary. Only public fields come back (from, to, amount, fee in base
units, signed=false). Signing is the TTY step above (`acct-tx sign ... --expect-to`). It is a human-typed code, so
recipe-check can't run it here; scripts/e2e.d/acct.sh drives it through a pty.

<!-- e2e: expect="amount":4827779 ; expect="fee":172221 ; expect="signed":false -->
    ./blocktools run 'acct-tx build --chain ada --from addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv --to addr1qyz85693g4fr8c55mfyxhae8j2u04pydxrgqr73vmwpx3a8927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqu2c0f9 --utxo 87dac51506d06652be02110bd1e34c2156faa5fa37253dc885da93b840b4bdec.1:5000000 --sweep --fee 172221 --ttl 150000000 | acct-tx decode --chain ada'

