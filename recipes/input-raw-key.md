# Input: a raw private key (hex, WIF, base58, base64)

`key-to-addresses` tries every encoding that gives 32 bytes and prints addresses on every chain,
compressed and uncompressed. Test vector: private key 1 (a public, famously drained key).

<!-- e2e: expect="class":"hex_key" -->
    ./blocktools run 'classify /in/key.hex'

<!-- e2e: expect=1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH ; expect=1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm ; expect=bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 ; expect=0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf ; expect=TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC -->
    ./blocktools run 'key-to-addresses < /in/key.hex'

<!-- e2e: expect=1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH -->
    ./blocktools run 'key-to-addresses --chain btc < /in/key.wif'

Front door (only the chain you name):

<!-- e2e: expect=LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ -->
    recipes/recover.sh /in/key.hex - --chain ltc --goal addresses
