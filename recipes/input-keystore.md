# Input: Ethereum keystore JSON (UTC--... file, MyEtherWallet, Geth)

Password in `secrets/keystore.pw`. Test vector: the Web3 Secret Storage spec's scrypt example (password `testpassword`).

<!-- e2e: expect="class":"keystore_v3" -->
    ./blocktools run 'classify /in/keystore.json'

<!-- e2e: expect=0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b -->
    ./blocktools run 'read-file /secrets/keystore.pw /in/keystore.json | keystore-open'

Sweep: `recipes/recover.sh in/keystore.json 0xDEST --password-file secrets/keystore.pw --chain-id 1`
(see chain-ethereum.md). ERC-20 tokens need a gas top-up first (`tx-build --topup`).

## Presale wallet (2014 Ethereum crowdsale JSON: `encseed`, `ethaddr`, `email`, `btcaddr`)

classify reports `eth_presale`; keystore-open reads it with the same input (password line, then the JSON)
and recover.sh sweeps it like a keystore. Algorithm as in go-ethereum `accounts/keystore/presale.go`:
an AES-128 key from PBKDF2-HMAC-SHA256 with the password as its own salt; `encseed` = IV || AES-128-CBC(seed); private key = keccak256(seed). The format has no MAC: a wrong password gives
`wrong_password` because the padding fails or the derived address is not `ethaddr`.
Test vectors: go-ethereum's `TestImportPreSaleKey` file (password `foo`, address
0xd4584b5F6229b7BE90727b0FC8C6b91BB427821f) and one generated independently in Python
(crates/secrets/src/keystore.rs tests; e2e: scripts/e2e.d/recover.sh `presale`).
