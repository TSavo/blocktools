# Input: MultiBit Classic `.key` export

Password in `secrets/multibit.pw`. Test file: the btcrecover MultiBit fixture.

<!-- e2e: expect="class":"multibit_key" ; needs=multibit.key -->
    ./blocktools run 'classify /in/multibit.key'

<!-- e2e: expect=166UVSG9WX81Pkp9f8o4htYV9M3KBqXHdV ; needs=multibit.key -->
    ./blocktools run 'read-file /secrets/multibit.pw /in/multibit.key | multibit-read | key-to-addresses --chain btc'

MultiBit HD (BIP32 wallets, `m/0'/{change}/{i}`): if you have the 12 words, use input-seed-phrase.md with
`derive --preset legacy-hd`. Reading the encrypted `mbhd.wallet.aes` and bitcoinj `.wallet` files is
not built yet (classify detects `bitcoinj_wallet`).
