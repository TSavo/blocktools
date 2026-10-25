# Input: an xpub/ypub/zpub or a bare address (watch-only)

An extended *public* key or an address can't sign anything. You can still list the addresses and check balances.

<!-- e2e: expect="class":"xpub" -->
    ./blocktools run 'classify /in/xpub.txt'

ypub/zpub are converted (SLIP-132) and pick their script type. Test vector: the BIP84 spec account zpub.

<!-- e2e: expect=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu ; expect=bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el -->
    ./blocktools run 'xpub-addresses --chain btc --change 0,1 --count 1 < /in/xpub.txt'

<!-- e2e: expect=bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el ; fund=bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el -->
    recipes/recover.sh /in/xpub.txt - --goal balance --count 2

Asking to sweep refuses (exit 3) and nothing is built or sent:

<!-- e2e: rc=3 ; expect=watch-only -->
    recipes/recover.sh /in/address.txt bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
