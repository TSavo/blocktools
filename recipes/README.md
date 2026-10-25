# Recipes

**Front door:** `recipes/recover.sh FILE DEST [--chain C] [--goal addresses|balance|sweep]`. It classifies the
input, picks the reader, lists public addresses, checks balances and sweeps, with a typed code before
signing and another before broadcast. Exit codes: 0 done, 3 stopped on purpose (watch-only, or a chain without a
sweep here), 4 no funds, 1/2 error.

**Every example marked as tested runs in e2e** (`scripts/recipe-check.py`). It runs exactly as written, through
the real sealed agent boundary, on public dummy vectors, against a 127.0.0.1 mock chain, and fails on any secret in
stdout. Anything a recipe calls UNTESTED or NOT BUILT is exactly that.

**The sealed image has no shell.** It is `FROM scratch`: static tools and `sealed-run`. You can't
`docker run -it ... sh`. Run pipelines with `./blocktools run '<pipeline>'` (agent-safe, redacted output),
or `./blocktools reveal '<pipeline>'` (a human at a terminal types a code, and keys are shown). The grammar is
`tool args [< /in/file] | tool args | ...`. There are no `$VARS`, globs, `;`, `&&` or redirects except `<`. Files go
in `./in` (mounted read-only at `/in`), passwords in `./secrets` (at `/secrets`). Use `read-file a b` to
join a password file and a wallet. Network steps (`utxo-fetch`, `tx-broadcast`) and `recover.sh` run on the host
and see addresses and signed transactions only.

## By input
| You have | Recipe | Status |
|---|---|---|
| 12–24 word BIP39 phrase (typos ok) | [input-seed-phrase.md](input-seed-phrase.md) | built, tested |
| Electrum seed / wallet file | [input-electrum.md](input-electrum.md) | built, tested; Electrum 1.x not built |
| Bitcoin Core / old-client `wallet.dat` | [input-wallet-dat.md](input-wallet-dat.md) | built, tested; real altcoin-client file untested |
| MultiBit Classic `.key` | [input-multibit.md](input-multibit.md) | built, tested; MultiBit HD / bitcoinj `.wallet` built, tested on public test wallets |
| Raw key (hex, WIF, base58, base64) | [input-raw-key.md](input-raw-key.md) | built, tested |
| Ethereum keystore JSON | [input-keystore.md](input-keystore.md) | built, tested |
| xpub / ypub / zpub / address (watch-only) | [input-xpub-address.md](input-xpub-address.md) | built, tested |
| XRP family seed (`s...`, `sEd...`) | [xrp.md](xrp.md) | built, tested |
| Algorand 25-word mnemonic | [chain-algorand.md](chain-algorand.md) | addresses only, tested |
| Stellar secret (`S...`) | [chain-stellar.md](chain-stellar.md) | addresses only, tested |
| Monero 25 words | [monero.md](monero.md) | keys/address; scan + sweep via host `xmr-wallet` (stagenet-tested) |
| Don't know | [input-unknown.md](input-unknown.md) | classify |

## By chain
| Chain | Addresses | Balance | Sweep | Recipe |
|---|---|---|---|---|
| Bitcoin | ✅ | ✅ | ✅ | [chain-bitcoin.md](chain-bitcoin.md) |
| Litecoin, Dogecoin | ✅ | ✅ | ✅ (mock chain only) | [chain-litecoin-dogecoin.md](chain-litecoin-dogecoin.md) |
| Groestlcoin | ✅ (incl. Groestl-checksum xpub, grs1p; real-wallet xpub untested) | ✗ | ✅ (e2e, no live network; p2tr spend refused) | [chain-groestlcoin.md](chain-groestlcoin.md) |
| Ethereum / EVM | ✅ | ✅ | ✅ ETH, ERC-20 | [chain-ethereum.md](chain-ethereum.md) |
| XRP | ✅ | manual | ✅ Payment (xrp-tx) | [xrp.md](xrp.md) |
| Qtum | ✅ | ✗ | ✗ | [chain-qtum.md](chain-qtum.md) |
| Old coins (PPC, NMC, FTC, NVC, CLAM, BLK, RDD, ...) | ✅ | ✗ | ✗ | [chain-old-coins.md](chain-old-coins.md) |
| Tron | ✅ | ✗ | ✗ | [chain-tron.md](chain-tron.md) |
| Solana | ✅ | ✗ | ✗ | [chain-solana.md](chain-solana.md) |
| Cosmos Hub | ✅ | ✅ utxo-fetch (host-side, manual) | ✅ MsgSend (acct-tx, TTY confirm) | [chain-cosmos.md](chain-cosmos.md) |
| Algorand | ✅ (own mnemonic) | ✅ utxo-fetch (host-side, manual) | ✅ pay / close-to (acct-tx, TTY confirm) | [chain-algorand.md](chain-algorand.md) |
| Cardano | ✅ (Shelley base, Icarus) | ✅ utxo-fetch (Koios, host-side) | ✅ ADA-only payment/sweep (acct-tx, TTY confirm) | [chain-cardano.md](chain-cardano.md) |
| Zcash shielded (Sapling) | ✅ (address + viewing key) | ✗ | ✗ | [zcash-shielded.md](zcash-shielded.md) |
| TON | ✅ (wallet v4r2) | ✅ utxo-fetch (host-side, manual) | ✅ v4r2 transfer/sweep (acct-tx, TTY confirm) | [chain-ton.md](chain-ton.md) |
| Polkadot | ✅ (root sr25519) | ✅ utxo-fetch (Asset Hub RPC, host-side) | ⚠️ UNVERIFIED Asset Hub transfer/sweep (acct-tx, TTY confirm) | [chain-polkadot.md](chain-polkadot.md) |
| Stellar | ✅ | ✅ utxo-fetch (host-side, manual) | ✅ Payment / AccountMerge (acct-tx, TTY confirm) | [chain-stellar.md](chain-stellar.md) |
| Monero | ✅ | ✅ xmr-wallet scan (stagenet) | ✅ xmr-wallet sweep (stagenet, TTY confirm) | [monero.md](monero.md) |

## By goal
| Goal | Recipe |
|---|---|
| Find which derivation path a wallet used | [derive.md](derive.md) |
| Check whether anything is left | [goal-check-balance.md](goal-check-balance.md) |
| Move everything to a new address | [goal-sweep.md](goal-sweep.md) |
| Read a transaction before signing/sending | [decode-a-transaction.md](decode-a-transaction.md) |

Fee warnings (`high_fee`, `high_fee_rate`) use per-coin limits from measured mainnet fee rates (docs/CHAINS.md "Fee-warning limits").
| Verify, and sign on an offline machine | [goal-verify-and-offline.md](goal-verify-and-offline.md) |

Zcash transparent (t1/t3) is a supported chain for validate/convert/sweep; shielded: [zcash-shielded.md](zcash-shielded.md).

Worldcoin (wdc) txs decode as Bitcoin-legacy (mainnet-checked) but wdc remains unverified: no SLIP-44 path. Quark (qrk) txs are Bitcoin-legacy (10 mainnet txids, 10 signatures checked) with 5 decimals; sweep build is supported (untested on mainnet).
