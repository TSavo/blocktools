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

Old (1.x, hex-seed) Electrum wallets and `--preset electrum-old` are not built yet; see docs/ROADMAP.md.
