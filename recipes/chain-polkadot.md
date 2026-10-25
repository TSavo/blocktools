# Chain: Polkadot

Addresses and keys only. The BIP39 mnemonic goes straight to `key-to-addresses --chain dot`
(Substrate does not use the BIP39 seed: the key comes from the mnemonic's entropy). Root sr25519
account only, the polkadot.js / subkey default for an imported phrase; SS58 prefix 0 (`1...`).

<!-- e2e: expect=15rRgsWxz4H5LTnNGcCFsszfXD8oeAFd8QRsR6MbQE2f6XFF -->
    ./blocktools run 'key-to-addresses --chain dot < /in/dot-mnemonic.txt'

The key is printed as `private_key` = 0x-hex mini-secret (subkey/polkadot.js "raw seed"), redacted by `redact`.
NOT BUILT: derivation paths (`//hard`, `/soft`), mnemonic password, ed25519 or ecdsa Substrate
accounts, Kusama and parachain prefixes. Balance and transfers: see below.

## Transfers (Polkadot Asset Hub) - UNVERIFIED

Since the November 2025 Asset Hub migration, DOT balances live on Polkadot Asset Hub, so transfers
are built for Asset Hub (Balances pallet index 10). No official signed-extrinsic test vector exists
(sr25519 signatures are randomised; the payload depends on the runtime's extensions), so this is
shipped **unverified**. What was checked:
- call bytes and signing payload == py-substrate-interface 1.7.11 (metadata-driven) for
  transfer_keep_alive and transfer_all; its signed extrinsic decodes, verifies and re-encodes byte-equal;
- live, once: our signed mortal extrinsics (payment and sweep) passed
  `TaggedTransactionQueue_validate_transaction` on Asset Hub up to the fee check (`Invalid::Payment`
  on the empty test account; a corrupted signature returns `BadProof`). Nothing was broadcast.

    utxo-fetch --chain dot 1...SOURCE     # free balance, nonce, spec/tx version, finalized block number + hash
    acct-tx build --chain dot --from 1...SOURCE --to 1...DEST (--amount PLANCK | --sweep) \
        --nonce N --block-number N --block-hash HASH [--period 64] [--tip PLANCK] [--spec V --tx-version V] > unsigned.json
    acct-tx decode --chain dot < unsigned.json
    acct-tx sign --chain dot --tx unsigned.json --expect-to 1...DEST > signed.json   # secret: 0x mini-secret or mnemonic
    # signed.json "signed" is the 0x extrinsic for author_submitExtrinsic, from a networked host.

1 DOT = 10^10 planck. `--amount` uses transfer_keep_alive (cannot reap the sender); `--sweep` is
transfer_all(keep_alive=false), which empties and reaps the account (frozen/reserved funds stay).
The fee is computed by the runtime and taken from the sender. The era defaults to mortal, 64 blocks.
Layout tested against spec 2005000 / tx version 15; other versions warn (a wrong layout is rejected
by the node as BadProof, it cannot redirect funds).
NOT BUILT: relay-chain transfers, paying fees in other assets, CheckMetadataHash mode 1 (Ledger
generic app), ed25519/ecdsa accounts, derivation paths, Kusama, staking/unbonding (bonded DOT
needs unbond + 28 days before it can be swept), vesting, proxies/multisig.

## Worked sweep (tested)

Unsigned sweep for the test mnemonic (transfer_all; the layout itself is UNVERIFIED, see above), decoded through the agent boundary. Only public fields come back (from, to, amount, fee in base
units, signed=false). Signing is the TTY step above (`acct-tx sign ... --expect-to`). It is a human-typed code, so
recipe-check can't run it here; scripts/e2e.d/acct.sh drives it through a pty.

<!-- e2e: expect="from":"15rRgsWxz4H5LTnNGcCFsszfXD8oeAFd8QRsR6MbQE2f6XFF" ; expect="to":"14E5nqKAp3oAJcmzgZhUD2RcptBeUBScxKHgJKU4HPNcKVf3" ; expect="signed":false -->
    ./blocktools run 'acct-tx build --chain dot --from 15rRgsWxz4H5LTnNGcCFsszfXD8oeAFd8QRsR6MbQE2f6XFF --to 14E5nqKAp3oAJcmzgZhUD2RcptBeUBScxKHgJKU4HPNcKVf3 --sweep --nonce 7 --block-number 22273316 --block-hash 88f4f46ebfaa624519daaa82d9f52ffbf0045df9bb7c032d964a1f195e178043 | acct-tx decode --chain dot'

