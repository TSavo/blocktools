# Chain: TON

Addresses and keys only. A TON wallet's 24-word phrase uses the BIP39 word list but its own
checksum and key derivation (it is NOT a BIP39 mnemonic): `classify` reports `ton_mnemonic`,
`key-to-addresses --chain ton` gives the wallet v4r2 address (Tonkeeper / Tonhub / TON Wallet
default for years), workchain 0, non-bounceable form `UQ...` (the same account as `EQ...`).

<!-- e2e: expect=UQCCZtVXlbxxKJbbZti9ESdAkizMyK_CTl0x65osWV1TnALb -->
    ./blocktools run 'key-to-addresses --chain ton < /in/ton-mnemonic.txt'

`private_key` is the hex ed25519 seed, redacted by `redact`. If the funds are not at the v4r2
address the wallet may be v3r2, v5r1 or W5: NOT BUILT, nor password-protected TON phrases,
testnet, jettons or the seqno-0 deploy message.

## Transfers (acct-tx, deployed v4r2 wallets)

    utxo-fetch --chain ton UQ...           # host-side (toncenter v2): balance_nanoton, seqno, wallet_type, account_state
    acct-tx build --chain ton --from UQ.. --to UQ..|EQ.. --amount NANOTON --seqno N --valid-until UNIX --comment TAG > u.json
    acct-tx build --chain ton --from UQ.. --to UQ.. --sweep --seqno N --valid-until UNIX > u.json   # send mode 128: whole balance
    acct-tx decode --chain ton < u.json
    acct-tx sign --chain ton --tx u.json --expect-to UQ.. < key.txt > signed.json   # 24 TON words or 64-hex seed; typed code on /dev/tty

The bounce flag follows the --to form (EQ.. bounceable, UQ.. not; raw 0:hex is refused). A sweep keeps the wallet deployed
with ~0 balance (mode 128, not 128+32). Fees are taken by the network from the balance, so they are not in the message.
`valid_until` must be in the future when it is broadcast (the tool has no clock check). seqno 0 (undeployed wallet) is refused.
Output: base64 BOC (crc32c, no index) plus `pubkey` and the external-message hash (`msg_hash`; explorers' transaction hash differs).
KAT: unsigned signing hash, signed BOC and message hash byte-equal to tonsdk 1.0.15 WalletV4ContractR2 (crates/acct/tests/kat.rs,
scripts/e2e.d/acct.sh). UNTESTED: a real broadcast; `utxo-fetch --chain ton` was run once against toncenter.com (2026-10-25), not in CI.
NOT BUILT: broadcast, deploy (StateInit) message, comments over 120 bytes (snake cells), jettons/NFTs, v3r2/v5r1 wallets.
