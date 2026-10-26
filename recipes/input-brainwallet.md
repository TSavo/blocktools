# Input: a brainwallet phrase (pre-BIP39 "passphrase -> key")

Before seed words (2011-2015) people typed any sentence into brainwallet.org or bitaddress.org's *Brain Wallet*
tab and got a key: **the private key is SHA-256 of the phrase bytes**, no checksum, no stretching. Keybase's
WarpWallet (2014) hardened that with scrypt and PBKDF2 and an e-mail salt. `phrase-to-key` does both;
`key-to-addresses` then prints the addresses, compressed and uncompressed (brainwallet.org used uncompressed).

The phrase is used **byte for byte**: spaces, case and punctuation all matter, and every phrase yields a key, so a
wrong phrase gives a wrong (empty) address rather than an error. Check the address against the one you funded.

<!-- e2e: expect=1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T ; expect=1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8 -->
    ./blocktools run 'phrase-to-key < /in/brainwallet.txt | key-to-addresses --chain btc'

(The vector is the xkcd "correct horse battery staple" brainwallet, drained in 2013: 1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T.)

WarpWallet needs the e-mail (salt) too, so the input is a JSON line `{"phrase":"...","salt":"you@example.com"}`;
the salt may be empty. scrypt N=2^18 is memory-hungry (a quarter gigabyte) and takes about a second per phrase. Vector: keybase/warpwallet
`test/spec.json` #1 (1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ).

<!-- e2e: expect=1J32CmwScqhwnNQ77cKv9q41JGwoZe2JYQ -->
    ./blocktools run 'phrase-to-key --scheme warpwallet < /in/warpwallet.json | key-to-addresses --chain btc'

`--scheme all` tries both. Other chains: `key-to-addresses` without `--chain` prints every chain, but brainwallets
were a Bitcoin habit; an ETH brainwallet (sha256 of a phrase as the key) is the same bytes, so `--chain eth` works.

NOT BUILT: Electrum's or Armory's own passphrase stretching (those are wallet files: see input-electrum.md,
input-armory.md), "sha256 twice" or salted home-made variants, and the brainwallet.org *Armory* and *Electrum*
tabs. `recover.sh` cannot classify a free-text phrase (any sentence is one), so use the pipeline above.
