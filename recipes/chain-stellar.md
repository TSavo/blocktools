# Chain: Stellar

Addresses and keys only. SEP-0005 path `m/44'/148'/{i}'` (SLIP-10 ed25519, all hardened); the
recovery preset also tries `m/44'/148'/{account}'/{i}'` and `m/44'/148'/{i}'/0'`. Addresses are
StrKey `G...`; secrets are StrKey `S...` (field `private_key`, always redacted).

<!-- e2e: expect=GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6 -->
    ./blocktools run 'seed-repair < /in/xlm-mnemonic.txt | seed-to-master | derive --chain xlm --count 1'

A Stellar secret seed (`S...`) is classified as `xlm_seed`; `key-to-addresses --chain xlm` gives its account id.

<!-- e2e: expect="class":"xlm_seed" -->
    ./blocktools run 'classify /in/xlm-seed.txt'

<!-- e2e: expect=GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6 -->
    ./blocktools run 'key-to-addresses --chain xlm < /in/xlm-seed.txt'

NOT BUILT: XLM payments/sweep, balance lookup, muxed (M...) accounts, memo handling.
UNTESTED: wallets that use non-SEP-0005 paths beyond the three tried by the recovery preset.
