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

## bitcoinj / MultiBit Classic `.wallet` (tested)

Encrypted wallet (btcrecover fixture). Its first key's address matches btcrecover's own key list for this wallet:

<!-- e2e: expect="class":"bitcoinj_wallet" ; needs=bitcoinj.wallet -->
    ./blocktools run 'classify /in/bitcoinj.wallet'

<!-- e2e: expect=19VvSJ13F5LYWV9rhywnjUA8v5n3pPaxeA ; needs=bitcoinj.wallet -->
    ./blocktools run 'read-file /secrets/multibit.pw /in/bitcoinj.wallet | multibit-read | key-to-addresses --chain btc'

Unencrypted copy of the same wallet (empty password line):

<!-- e2e: expect=19VvSJ13F5LYWV9rhywnjUA8v5n3pPaxeA ; needs=bitcoinj-clear.wallet -->
    ./blocktools run 'read-file /secrets/empty.pw /in/bitcoinj-clear.wallet | multibit-read | key-to-addresses --chain btc'

The front door routes `bitcoinj_wallet` the same way (wif lines -> key-to-addresses, an HD seed -> derive m/0'/c/i):

<!-- e2e: expect=19VvSJ13F5LYWV9rhywnjUA8v5n3pPaxeA ; needs=bitcoinj.wallet -->
    recipes/recover.sh /in/bitcoinj.wallet - --goal addresses --password-file /secrets/multibit.pw

MultiBit HD `mbhd.wallet.aes` has no magic bytes; classify recognises it by file name (`*.wallet.aes`, binary,
block-aligned) as `multibit_hd_wallet` and recover.sh routes it like a bitcoinj HD seed. Renamed files need the
host pipeline above (`multibit-read | derive --path "m/0'/{change}/{i}" ...`); `./blocktools run` refuses `'` and
`{}` in arguments. Covered by scripts/e2e.d/bitcoinj.sh (btcrecover's mbhd fixture, both addresses matched).
