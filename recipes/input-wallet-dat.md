# Input: Bitcoin Core `wallet.dat` (and old-coin clients built on Bitcoin Core)

Works for legacy Berkeley DB wallets and SQLite descriptor wallets. The passphrase goes in
`secrets/wallet.pw` (first line; leave it empty if the wallet is unencrypted).

<!-- e2e: expect="class":"wallet_dat" -->
    ./blocktools run 'classify /in/wallet.dat'

Descriptor wallet (test vector: the BIP84 spec phrase imported into Core 24, encrypted):

<!-- e2e: expect=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu -->
    ./blocktools run 'read-file /secrets/wallet.pw /in/wallet.dat | dat-read | derive --chain btc --count 1'

Front door, balance only:

<!-- e2e: expect=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu ; fund=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu -->
    recipes/recover.sh /in/wallet.dat - --goal balance --password-file /secrets/wallet.pw

## Old-coin clients (Litecoin, Dogecoin, Peercoin, Namecoin, Feathercoin ... before descriptors)

These clients are forks of Bitcoin Core and store keys in the same Berkeley DB format, so `dat-read` reads
their keys and `key-to-addresses --chain <coin>` encodes them for that coin. See chain-old-coins.md.
Test file: the btcrecover legacy `wallet.dat` fixture, shown as Peercoin.

<!-- e2e: expect="chain":"ppc" ; expect=PJLEi1miUeB4kzcbHdhL6hZeciKcvBRHzk ; needs=old-client-wallet.dat -->
    ./blocktools run 'read-file /secrets/multibit.pw /in/old-client-wallet.dat | dat-read | key-to-addresses --chain ppc'

UNTESTED: no wallet.dat made by an actual altcoin client is in the test set. The format is the same, but
a client that changed the key-record layout would fail here.
