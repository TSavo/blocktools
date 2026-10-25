# Input: Electrum (seed phrase or wallet file)

## Electrum 2.x+ seed phrase

Electrum seeds are not BIP39: the version is hashed into the words. `seed-to-master` tries both,
and `derive` picks Electrum's paths (`m/{change}/{i}` standard, `m/0'/{change}/{i}` segwit).

<!-- e2e: expect="class":"electrum_seed" -->
    ./blocktools run 'classify /in/electrum-seed.txt'

<!-- e2e: expect=1NNkttn1YvVGdqBW4PR6zvc3Zx3H5owKRf -->
    ./blocktools run 'seed-to-master < /in/electrum-seed.txt | derive --chain btc --count 1'

## Electrum wallet file (`~/.electrum/wallets/...`)

The password goes in `secrets/electrum.pw` (first line, can be empty). `read-file` joins the password and
the file because the sealed image has no shell. Test file: the btcrecover Electrum 4.4.3 fixture.

<!-- e2e: expect=bc1qsz0dhew357cj6eznmcawgyf44jzpgcax2lvfvm ; needs=electrum-wallet -->
    ./blocktools run 'read-file /secrets/electrum.pw /in/electrum-wallet | electrum-read | seed-to-master | derive --chain btc --count 1'

## Electrum 1.x wallet file (2011–2014, `seed_version: 4`, a Python dict)

`classify` reports `electrum_wallet`. `electrum-read` decrypts the 32-hex-char seed and derives the
"old" scheme keys itself (uncompressed P2PKH, receive `m/0/i` and change `m/1/i`, `--count N` per branch).
It refuses the file unless the derived master public key equals the file's `master_public_key`.
The tested vector is btcrecover's Electrum 1.x wallet. Its first receive and change addresses match the address
lists Electrum wrote into that file.

<!-- e2e: expect="scheme":"electrum-old" ; expect=1Ev9vpNwcSSZntyd86FxWox1r23jyc1Kqv ; expect=1CNATKB22T45VT5CtUk8mPjedHpbwd4vU8 ; needs=electrum1-wallet -->
    ./blocktools run 'read-file /secrets/electrum.pw /in/electrum1-wallet | electrum-read --count 1'

<!-- e2e: expect=179dvQyWSyEHwcyugmjNQGtoEXvQCqbPaa ; fund=179dvQyWSyEHwcyugmjNQGtoEXvQCqbPaa ; needs=electrum1-wallet -->
    recipes/recover.sh /in/electrum1-wallet - --goal balance --password-file /secrets/electrum.pw

The full sweep of this wallet runs in e2e (mock chain, both codes typed). NOT BUILT: the 12-word *old* Electrum
mnemonic (1626-word list) as a typed seed. Only the wallet file is read.

## Electrum "encrypt file" wallets (BIE1)

A whole-file-encrypted wallet starts with `QklFMQ` (base64 of `BIE1`). electrum-read decrypts it with the wallet
password (the same password then opens any field-encrypted seed inside), so recover.sh routes it like any Electrum
wallet. Checked against btcrecover's Electrum 2.8 and 4.1 encrypted test wallets and an independent python vector.
NOT BUILT: `BIE2` files (password derived from a hardware wallet xpub); electrum-read says `unsupported_bie2`.

<!-- e2e: expect="address" ; needs=electrum-bie1-wallet -->
    recipes/recover.sh /in/electrum-bie1-wallet - --goal addresses --password-file /secrets/electrum.pw

A file that decrypts but has no keystore is refused:

<!-- e2e: expect="status":"unsupported" -->
    ./blocktools run 'read-file /secrets/bie1.pw /in/electrum-bie1-nokeys | electrum-read'
