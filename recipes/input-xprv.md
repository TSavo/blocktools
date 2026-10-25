# Input: a BIP32 master private key (xprv)

A one-line `xprv…` (for example exported from a wallet's "show master private key"). The test input is the
BIP84 spec mnemonic's root key (abandon ×11 about) in xprv form. BIP84 gives bc1qcr8te4… as its first receive address.

<!-- e2e: expect="class":"xprv" -->
    ./blocktools run 'classify /in/xprv.txt'

<!-- e2e: expect=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu -->
    recipes/recover.sh /in/xprv.txt - --goal addresses --count 1

recover.sh wraps the line as `{"xprv":…}` with sed, streamed (never in a shell variable), and pipes it into
`derive --chain C`, so `--chain` and the presets in derive.md apply. Sweep is the same as for a seed (goal-sweep.md).
NOT BUILT: yprv/zprv/tprv lines (derive takes the xprv form only; convert the version bytes yourself) UNTESTED: account-level xprvs (derive applies its path from the
key it is given; use `derive --path` to match).
