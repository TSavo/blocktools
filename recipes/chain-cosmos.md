# Chain: Cosmos Hub

Addresses and keys only. Path `m/44'/118'/0'/0/{i}` (secp256k1, Keplr/cosmjs default); the
recovery preset also tries `m/44'/118'/{i}'/0/0` and `m/44'/118'/{account}'/{i}`. Address =
bech32 `cosmos1...` of hash160(compressed pubkey); the key is 32-byte hex (`private_key`, redacted).

<!-- e2e: expect=cosmos1jhg0e7s6gn44tfc5k37kr04sznyhedtc9rzys5 -->
    ./blocktools run 'seed-repair < /in/atom-mnemonic.txt | seed-to-master | derive --chain atom --count 1'

NOT BUILT: other Cosmos-SDK chains (Osmosis, Juno, ... use other bech32 prefixes; Terra, Kava,
Injective, Evmos use other coin types or keccak addresses), transfers, balance lookup.
