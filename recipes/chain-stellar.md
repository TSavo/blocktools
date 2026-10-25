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

## Payments and sweep (acct-tx)

    utxo-fetch --chain xlm G...   # host-side: Horizon: native balance, next_seq, subentry_count
    acct-tx build --chain xlm --from G... --to G... --amount STROOPS --fee 100 --seq NEXT_SEQ --memo-id N > u.json
    acct-tx build --chain xlm --from G... --to G... --sweep --fee 100 --seq NEXT_SEQ > u.json   # AccountMerge
    acct-tx decode --chain xlm < u.json
    acct-tx sign --chain xlm --tx u.json --expect-to G... < secret.txt > signed.json   # typed code on /dev/tty

One native Payment or one AccountMerge per transaction, memo none/id/text, optional max time. The sweep is an
AccountMerge: it moves the whole balance including the reserve and deletes the account; Stellar refuses it while the
account has trustlines, offers or other subentries (check `subentry_count`). A missing memo is warned about, because
exchanges credit deposits by memo. KAT: unsigned and signed envelopes and hashes byte-equal to py-stellar-sdk 16.1.1
(crates/acct/tests/kat.rs, scripts/e2e.d/acct.sh).

NOT BUILT: broadcast (submit the `signed` base64 to Horizon `POST /transactions` yourself), muxed (M...) accounts,
non-native assets, multi-op transactions, fee-bump. UNTESTED: a real network submit; `utxo-fetch` was run once against
horizon.stellar.org (2026-10-25) and is not in CI.
UNTESTED: wallets that use non-SEP-0005 paths beyond the three tried by the recovery preset.

## Worked sweep (tested)

Unsigned sweep for the SEP-0005 vector-1 accounts 0 -> 1 (AccountMerge), decoded through the agent boundary. Only public fields come back (from, to, amount, fee in base
units, signed=false). Signing is the TTY step above (`acct-tx sign ... --expect-to`). It is a human-typed code, so
recipe-check can't run it here; scripts/e2e.d/acct.sh drives it through a pty.

<!-- e2e: expect="to":"GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX" ; expect="fee":100 ; expect="signed":false -->
    ./blocktools run 'acct-tx build --chain xlm --from GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6 --to GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX --sweep --fee 100 --seq 123456789013 | acct-tx decode --chain xlm'

