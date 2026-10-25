# Input: Armory `.wallet`

`classify` reports `armory_wallet`. Password in `secrets/armory.pw` (first line; empty for an unencrypted
wallet). `armory-read` prints one uncompressed `wif` per stored address (with `chain_index`); every key is
checked against the public key stored in the file, so a wrong password gives `wrong_password`, never a key.

<!-- e2e: expect=1H29eJEsQCtwCRc737gZyD7HtpxxdQNQzv ; expect=18zF746CL38EVzpcwUTnW7fpQcohhaSt2X ; needs=armory.wallet -->
    ./blocktools run 'read-file /secrets/armory.pw /in/armory.wallet | armory-read | key-to-addresses --chain btc'

Status: tested on the gurnec/btcrecover public test wallet only (scripts/e2e.d/armory.sh: all 100 stored
addresses). Untested: unencrypted wallets, wallets from other Armory versions, paper backups (root key +
chaincode) — those are not read. Watching-only, multisig/lockbox and testnet wallets are refused.
