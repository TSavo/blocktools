# Input: Ethereum keystore JSON (UTC--... file, MyEtherWallet, Geth)

Password in `secrets/keystore.pw`. Test vector: the Web3 Secret Storage spec's scrypt example (password `testpassword`).

<!-- e2e: expect="class":"keystore_v3" -->
    ./blocktools run 'classify /in/keystore.json'

<!-- e2e: expect=0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b -->
    ./blocktools run 'read-file /secrets/keystore.pw /in/keystore.json | keystore-open'

Sweep: `recipes/recover.sh in/keystore.json 0xDEST --password-file secrets/keystore.pw --chain-id 1`
(see chain-ethereum.md). ERC-20 tokens need a gas top-up first (`tx-build --topup`).
