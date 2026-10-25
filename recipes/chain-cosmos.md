# Chain: Cosmos Hub

Addresses and keys only. Path `m/44'/118'/0'/0/{i}` (secp256k1, Keplr/cosmjs default); the
recovery preset also tries `m/44'/118'/{i}'/0/0` and `m/44'/118'/{account}'/{i}`. Address =
bech32 `cosmos1...` of hash160(compressed pubkey); the key is 32-byte hex (`private_key`, redacted).

<!-- e2e: expect=cosmos1jhg0e7s6gn44tfc5k37kr04sznyhedtc9rzys5 -->
    ./blocktools run 'seed-repair < /in/atom-mnemonic.txt | seed-to-master | derive --chain atom --count 1'

NOT BUILT: other Cosmos-SDK chains (Osmosis, Juno, ... use other bech32 prefixes; Terra, Kava,
Injective, Evmos use other coin types or keccak addresses), IBC/other denoms, multi-message txs, broadcast.

## Transfers (acct-tx)

    utxo-fetch --chain atom cosmos1...    # host-side: balance_uatom, account_number, sequence, pubkey
    acct-tx keys --chain atom < key.txt   # public only: address + pubkey (needed by build if the account never signed)
    acct-tx build --chain atom --from cosmos1... --pubkey HEX --to cosmos1... --amount UATOM --fee 5000 --gas 200000 \
        --sequence N --account-number N --memo TAG > u.json        # or --sweep --balance UATOM (amount = balance - fee)
    acct-tx decode --chain atom < u.json
    acct-tx sign --chain atom --tx u.json --expect-to cosmos1... < key.txt > signed.json   # typed code on /dev/tty

One bank MsgSend in uatom, SIGN_MODE_DIRECT. Unsigned = SignDoc (base64), signed = TxRaw plus the SignDoc. Decode refuses
other messages, extra coins, timeout/granter/extension fields, and a from address that does not match the signer key.
A missing memo is warned about. KAT: body, auth_info, signed TxRaw and txid byte-equal to @cosmjs/proto-signing
(crates/acct/tests/kat.rs, scripts/e2e.d/acct.sh). Gas is not estimated: pass it yourself (200000 covers a plain send).
UNTESTED: a real network submit; `utxo-fetch --chain atom` was run once against cosmos-rest.publicnode.com (2026-10-25), not in CI.

## Worked sweep (tested)

Unsigned sweep for key 1's account (balance 1 ATOM, sweep = balance - fee), decoded through the agent boundary. Only public fields come back (from, to, amount, fee in base
units, signed=false). Signing is the TTY step above (`acct-tx sign ... --expect-to`). It is a human-typed code, so
recipe-check can't run it here; scripts/e2e.d/acct.sh drives it through a pty.

<!-- e2e: expect="amount":995000 ; expect="fee":5000 ; expect="to":"cosmos1jhg0e7s6gn44tfc5k37kr04sznyhedtc9rzys5" ; expect="signed":false -->
    ./blocktools run 'acct-tx build --chain atom --from cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c --pubkey 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 --to cosmos1jhg0e7s6gn44tfc5k37kr04sznyhedtc9rzys5 --sweep --balance 1000000 --fee 5000 --gas 200000 --sequence 7 --account-number 123456 | acct-tx decode --chain atom'

Address check for key 1. The boundary drops the 33-byte `pubkey` (long hex looks secret to redact), so read `--pubkey` from
plain `acct-tx keys --chain atom < key.txt` on your own machine. That output is public only.

<!-- e2e: expect=cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c ; expect="tool":"acct-tx" -->
    ./blocktools run 'acct-tx keys --chain atom < /in/key.hex'
