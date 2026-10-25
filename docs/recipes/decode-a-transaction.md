# Decode a transaction before you sign or broadcast it

> ⚠️ DANGEROUS: use at your own risk. Code that handles keys and signs transactions should
> always be read and audited by you before you trust it with real funds. Used incorrectly,
> it can destroy your money.

`tx-decode` shows what a transaction actually does. It is offline, holds no keys, and
works on signed and unsigned transactions.

```sh
tx-decode --text < tx.txt                 # human summary
tx-decode < tx.txt                        # JSON lines (summary, then inputs/outputs)
tx-decode --chain ltc --text < tx.txt     # Litecoin/Dogecoin address encoding
```

The input can be hex or base64, a raw Bitcoin tx, a PSBT, an EVM legacy or EIP-1559 tx, or
a JSON line with `psbt`, `tx`, `unsigned_tx` or `signed_tx`.

Example (Bitcoin block 170, a public transaction; the vector is in `crates/kr-tx/tests/vectors/`):

```
=== TRANSACTION (btc btc-tx, SIGNED) ===
in  #0: (unknown address) (amount unknown)
OUT #0: 1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3 10.00000000 [p2pk]
OUT #1: 12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S 40.00000000 [p2pk]
fee    : UNKNOWN (input amounts not in this data)
WARNINGS: input_amounts_unknown
```

A raw transaction doesn't carry its input amounts, so the fee is unknown. A PSBT with UTXO
data shows the fee and fee rate.

## The sequence for every send (no exceptions)

1. **Build** the unsigned tx (`tx-build`, offline, from UTXO/nonce files).
2. **Decode the exact bytes you will sign:** `tx-decode --text < unsigned.txt`.
3. **Read it yourself.** Check every output address character by character against where
   you meant to send, the amount, the fee, and (for EVM) the chain id and token. Stop on any
   warning you don't understand.
4. **Sign** (`tx-sign`). It prints the same summary again on your terminal and only
   signs after you type the code it shows.
5. **Decode the signed output:** `tx-decode --text < signed.txt`. The outputs, fee and
   (EVM) `from` must match step 2.
6. **Broadcast** (host only).

Warnings worth stopping for: `high_fee*`, `unlimited_approve`/`token_approve` (you're
granting spending rights, not sending), `no_chain_id` (replayable on other chains),
`unknown_calldata`, `nonstandard_output`, `utxo_txid_mismatch`, `contract_creation`.
