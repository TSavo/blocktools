# Input: MultiBit Classic `.key` export

Password in `secrets/multibit.pw`. Test file: the btcrecover MultiBit fixture.

<!-- e2e: expect="class":"multibit_key" ; needs=multibit.key -->
    ./blocktools run 'classify /in/multibit.key'

<!-- e2e: expect=166UVSG9WX81Pkp9f8o4htYV9M3KBqXHdV ; needs=multibit.key -->
    ./blocktools run 'read-file /secrets/multibit.pw /in/multibit.key | multibit-read | key-to-addresses --chain btc'

MultiBit HD (BIP32 wallets, `m/0'/{change}/{i}`): if you have the 12 words, use input-seed-phrase.md with
`derive --preset legacy-hd`. Without the words, `multibit-read` opens `mbhd.wallet.aes` (password line,
then the file) and prints the BIP32 master `xprv`; pipe it to
`derive --chain btc --path "m/0'/{change}/{i}" --change 0,1 --address-type p2pkh --compressed`.
bitcoinj / MultiBit Classic `.wallet` protobufs (classify: `bitcoinj_wallet`) go through the same
`multibit-read` and print `wif` lines (empty first line for an unencrypted wallet). Tested on the
btcrecover public test wallets only (scripts/e2e.d/bitcoinj.sh).
