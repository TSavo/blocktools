# Chain table

Source of truth: `crates/core/src/chains.rs`. Known-answer vectors come from `scripts/kat-chains.py`, an independent base58check that uses only hashlib, and are checked in the `kat_long_tail` test. tx-build only signs chains whose Sign is `Standard`; it refuses ForkId (bch/bsv/btg), PosTime only for pot (ppc/nvc/clam/rdd have a dedicated pos-ntime builder/signer, `crates/tx/src/pos.rs`; blk is Standard) and Unknown (qrk, plus the non-UTXO chains, which have their own signers). No coin other than BTC has been signed and accepted on a real network.

### Supported (verified)

| name | ticker | SLIP-44 | p2pkh | p2sh | hrp | wif | checksum | decimals | forkid | tx format | sweep build | sources |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| btc | BTC | 0 | 00 | 05 | bc | 128 | sha256d | 8 | — | legacy | yes | esplora blockstream.info |
| ltc | LTC | 2 | 30 | 32 | ltc | 176 | sha256d | 8 | — | legacy | yes | esplora litecoinspace.org |
| doge | DOGE | 3 | 1e | 16 | — | 158 | sha256d | 8 | — | legacy | yes | none |
| eth | ETH | 60 | — | — | — | — | — | 18 | — | evm | no | none |
| tron | TRX | 195 | — | — | — | — | — | 6 | — | account | no | none |
| xrp | XRP | 144 | — | — | — | — | — | 6 | — | account | no | none |
| sol | SOL | 501 | — | — | — | — | — | 9 | — | account | no | none |
| atom | ATOM | 118 | — | — | cosmos | — | — | 6 | — | account | no | none |
| algo | ALGO | 283 | — | — | — | — | — | 6 | — | account | no | none |
| ada | ADA | 1815 | — | — | — | — | — | 6 | — | account | no | none |
| ton | TON | 607 | — | — | — | — | — | 9 | — | account | no | none |
| dot | DOT | 354 | — | — | — | — | — | 10 | — | account | no | none |
| xlm | XLM | 148 | — | — | — | — | — | 7 | — | account | no | none |
| qtum | QTUM | 2301 | 3a | 32 | qc | 128 | sha256d | 8 | — | legacy | yes | qtuminfo qtum.info |
| ftc | FTC | 8 | 0e | 05 | fc | 142 | sha256d | 8 | — | legacy | yes | none |
| nmc | NMC | 7 | 34 | 0d | nc | 180 | sha256d | 8 | — | legacy | yes | none |
| dash | DASH | 5 | 4c | 10 | — | 204 | sha256d | 8 | — | legacy | yes | blockbook blockbook.dash.zelcore.io; insight insight.dash.org |
| vtc | VTC | 28 | 47 | 05 | vtc | 128 | sha256d | 8 | — | legacy | yes | blockbook blockbook.vtc.zelcore.io |
| dgb | DGB | 20 | 1e | 3f | dgb | 128 | sha256d | 8 | — | legacy | yes | blockbook blockbook.dgb.zelcore.io |
| via | VIA | 14 | 47 | 21 | via | 199 | sha256d | 8 | — | legacy | yes | blockbook blockbook.viacoin.org |
| mona | MONA | 22 | 32 | 37 | mona | 176 | sha256d | 8 | — | legacy | yes | insight mona.insight.monaco-ex.org |
| rvn | RVN | 175 | 3c | 7a | — | 128 | sha256d | 8 | — | legacy | yes | blockbook blockbook.rvn.zelcore.io; blockbook blockbook.ravencoin.org |
| xpm | XPM | 24 | 17 | 53 | — | 151 | sha256d | 8 | — | legacy | yes | cryptoid chainz.cryptoid.info |
| trc | TRC | 83 | 00 | 05 | — | 128 | sha256d | 8 | — | legacy | yes | none |
| mec | MEC | 217 | 32 | 05 | mec | 178 | sha256d | 8 | — | legacy | yes | none |
| aur | AUR | 85 | 17 | 05 | — | 176 | sha256d | 8 | — | legacy | yes | cryptoid chainz.cryptoid.info |
| bch | BCH | 145 | 00 | 05 | — | 128 | sha256d | 8 | 0 | forkid | yes | none |
| bsv | BSV | 236 | 00 | 05 | — | 128 | sha256d | 8 | 0 | forkid | yes | woc whatsonchain.com |
| btg | BTG | 156 | 26 | 17 | btg | 128 | sha256d | 8 | 79 | forkid | yes | none |
| ppc | PPC | 6 | 37 | 75 | pc | 183 | sha256d | 6 | — | pos-ntime | yes | blockbook blockbook.peercoin.net |
| nvc | NVC | 50 | 08 | 14 | — | 136 | sha256d | 6 | — | pos-ntime | yes | cryptoid chainz.cryptoid.info |
| clam | CLAM | 23 | 89 | 0d | — | 133 | sha256d | 8 | — | pos-ntime | yes | cryptoid chainz.cryptoid.info |
| blk | BLK | 10 | 19 | 55 | — | 153 | sha256d | 8 | — | legacy | yes | cryptoid chainz.cryptoid.info |
| rdd | RDD | 4 | 3d | 05 | rdd | 189 | sha256d | 8 | — | pos-ntime | yes | blockbook blockbook.reddcoin.com |
| pot | POT | 81 | 37 | 6e | — | 183 | sha256d | 8 | — | pos-ntime | no | cryptoid chainz.cryptoid.info |
| qrk | QRK | 82 | 3a | 09 | — | 186 | sha256d | 5 | — | legacy | yes | cryptoid chainz.cryptoid.info |
| zec | ZEC | 133 | 1cb8 | 1cbd | — | 128 | sha256d | 8 | — | zcash-v5 | yes (transparent P2PKH) | none |
| grs | GRS | 17 | 24 | 05 | grs | 128 | groestl512d | 8 | — | legacy-sha256 | yes | none listed |

### Fee-warning limits (verify-tx / wasm `verifyTx`, `chainParams().fee_warn`)

`high_fee` fires above `fee` base units, `high_fee_rate` above `rate` base units per vbyte. Default 1,000,000 / 500 (Bitcoin-tuned). A per-coin row is 20 x the measured median fee rate x a 1,000 vB sweep (rate limit 20 x median), never below the default. Measured 2026-10-24 from recent mainnet blocks (non-coinbase txs, fee = inputs - outputs); scripts in the commit message basis strings.

Since 2026-10-25: (1) the `fee` limit is per started 1,000 vB of the tx (`FeeWarn::fee_for(vsize)` = fee x ceil(vsize/1000)), so a 147-input VTC sweep (~21,800 vB) is checked against 22 x 2,000,000, not 2,000,000; (2) the hard fee-rate cap in every sweep builder (`buildUnsignedSweep*`, legacy, pos-ntime and zec) is per coin, `FeeWarn::rate_cap()` = max(2,000, 4 x rate limit): btc/default 2,000, xpm 8,000,000 (measured median 100,312 sat/B is now buildable). **Break:** the pos-ntime and zec builders previously allowed up to 100,000 sat/B; they now get their row's cap (2,000 unless the row has a measured limit). (unmeasured)

**Default fee cap (signing, no --max-fee; 3ec1d1a).** Every signing route (tx-sign, tx-verify, envelope, wasm `verifyTx`) refuses `fee_above_cap` above max(100,000 sat, the chain's rate limit from this table x the tx's vsize), even with warnings waived; an explicit max_fee replaces it. The verdict reports `fee_cap` {chain, cap, source}. Measured by `crates/tx/tests/fee_cap_chains.rs`: SwapChan's corpus of 35 legitimate sweeps all pass (the old flat 100,000-sat cap refused 9 of 35); on each of the 27 buildable chains a fee 1 unit over the cap is refused and 10x the cap passes only with an explicit max_fee. BTC: a 1-input tx paying 240,000 sat is refused.

| chain | fee limit | rate limit | measured median | sample |
|---|---|---|---|---|
| dgb | 10,000,000 | 10,000 | 512 sat/vB | 60 txs, blocks 24444779-24445073, blockbook.dgb.zelcore.io (unmeasured) |
| rvn | 20,000,000 | 20,000 | 1004 sat/vB | 60 txs, blocks 4596227-4596275, blockbook.rvn.zelcore.io (unmeasured) |
| qtum | 14,000,000 | 14,000 | 700 sat/vB | 100 txs, blocks 6253698-6255768, qtum.info (unmeasured) |
| xpm | 2,000,000,000 | 2,000,000 | 100,312 sat/B | 30 txs, blocks 7064002-7064118, chainz.cryptoid.info (raw rebuilt from explorer JSON, sha256d = txid, exact size) (unmeasured) |
| vtc | 2,000,000 | 2,000 | 101 sat/vB | 60 txs, blocks 2703728-2703858, blockbook.vtc.zelcore.io (unmeasured) |
| doge | 1,200,000,000 | 1,200,000 | 60,463 sat/B (p10 2,418, p90 523,560) | 100 txs, blocks 6429664-6429671, blockbook.doge.zelcore.io, sha256d-checked. Policy minimum 1,000 sat/B (RECOMMENDED_MIN_TX_FEE 0.01 DOGE/kB) is far below what wallets pay (unmeasured) |
| ftc | 40,000,000 | 40,000 | 2,000 sat/vB (p10 600) | 100 txs (21 segwit), blocks 6407004-6408299, blockbook.feathercoin.com (unmeasured) |
| mona | 2,000,000 | 2,000 | 2.54 sat/vB; p75 and p90 = 100 | 100 txs, blocks 4142748-4143093, mona.insight.monaco-ex.org, exact vsize (witness stripped), 100/100 txids checked. Bimodal: ~2.5 (relay-minimum wallets) and 100 (Monacoin Core DEFAULT_TRANSACTION_MINFEE 100,000/kB); the limit is 20 x the 100 mode (unmeasured) |
| aur | 2,000,000 | 2,000 | 102.8 sat/B | 30 txs, blocks 5913204-5913347, chainz.cryptoid.info (raw rebuilt, sha256d = txid, exact size) (unmeasured) |

**MONA rate (SwapChan uses 220):** the chain data says 2.5 sat/vB is the median and 100 sat/vB the common wallet default; no sampled tx paid 220 (max 349, one outlier). 2.5 is right as "what the chain accepts" (node relayfee 0.001 MONA/kB = 1 sat/B); 100 matches Monacoin Core's default minimum tx fee. 220 is not supported by the data: it overpays ~2x the wallet default and ~90x the median. Suggest 100 (wallet-compatible) or a floor of 3. (unmeasured)

Measured and left at the default: dash (3.9 sat/B, 60 txs, blockbook.dash.zelcore.io), trc (re-measured 2026-10-25: median 20.0 sat/B, p10 1.32, p90 20.1, 100 txs in 2,743 blocks 3325168-3327910, insight.terracoin.io, txid-checked 100/100; replaces the earlier 14-tx 14.8 figure), ppc (blockbook reports fee 0 for most txs; fees are burned), via (4 txs in 400 blocks, all fee 0). Also measured: wdc 5.4 sat/B (4 txs, block 11881187; default kept). Not measured (default applies): every other row, including nmc, mec, nvc, clam, blk, pot, qrk, grs, bch, bsv, btg, ltc. (unmeasured)

**RDD (not measured):** source found, rddblockexplorer.com (blockbook). Nearly every tx is a PoSV stake (outputs > inputs); a scan of ~9,000 blocks (6002715-6011409) found only 32 fee-paying txs, and the run was stopped before fees were computed. RDD keeps the default limits (now size-scaled); its own row still needs measuring.

**ZEC vs ZIP-317 (2026-10-25):** 200 txs, blocks 3529835-3529915, blockbook.zec.zelcore.io. Ratio fee / ZIP-317 conventional fee (5,000 x max(2, transparent inputs, transparent outputs)): median 1.48, p10 1.00, 73/199 exactly 1.00, 1 below 1. The upper tail (p90 ~125,000x) is not real overpayment: blockbook cannot see shielded value, so for shielding/unshielding txs inputs - outputs is not the fee; only transparent-only txs are meaningful there, and the ZIP-317 figure is a lower bound when shielded actions exist. Rate median 49.7 sat/B (ZIP-317 minimum on a 1-in-1-out tx). Default limits kept. **Immature coinbase:** the ZEC explorer SwapChan uses (blockbook.zec.zelcore.io) lists immature coinbase outputs as spendable UTXOs (reported by SwapChan; not re-measured here); consensus requires 100 confirmations (COINBASE_MATURITY). Consumers must drop UTXOs with `coinbase: true` and confirmations < 100 before `buildUnsignedSweep`; blocktools cannot tell from `{txid,vout,amount,address}` alone. (unmeasured)

### Unverified (never returned as supported)

| name | ticker | SLIP-44 | p2pkh | p2sh | hrp | wif | checksum | decimals | forkid | tx format | sweep build | sources |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| wdc | WDC | 0 | 49 | 05 | — | 201 | sha256d | 8 | — | legacy | no | cryptoid chainz.cryptoid.info |
| anc | ANC | 0 | 17 | 0f | — | 151 | sha256d | 8 | — | legacy | no | none |
| bcc | BCC | 0 | 12 | 55 | — | 146 | sha256d | 8 | — | pos-ntime | no | none |

Zcash Sapling: `zec-sapling` CLI (ZIP-32, m/32'/133'/i', zs1 default address, optional 0600 viewing-key file; `--unified` adds the ZIP-316 u1 orchard+sapling+p2pkh address and t1). No spend/scan.

Zcash transparent is listed by wasm `listChains`/`supportedChains` (scope transparent) since 2026-10-25. Evidence: ZIP-243/244 official vectors, 7 mainnet txs (txid + signature), 21 mainnet script->address pairs from api.blockchair.com (crates/tx/tests/data/zec_addresses.txt). Untested: BIP44 m/44'/133' derivation, xpubs, broadcast, v6.

WDC: tx format confirmed Bitcoin-legacy on 4 mainnet txs (block 11881187): txid = sha256d, 357 P2PKH signatures verify under the legacy sighash, and every input address re-derives under p2pkh 73 (crates/tx/tests/wdc.rs). Still `verified: false`: no SLIP-44 coin type, so no derivation path can be checked. QRK (2026-10-25): tx format Bitcoin-legacy, found via chainz `api.dws?q=lasttxs` (block-by-block scanning saw only coinbase): 10/10 recent non-coinbase txs rebuild to their txid under sha256d, but only with values x 1e5, i.e. **QRK has 5 decimals** (COIN = 100000; the table said 8, now fixed: `decimals` 5). crates/tx/tests/qrk.rs: 2 txs (blocks 13906691, 13907052; 8 and 170 inputs), 10 P2PKH signatures verify under the legacy sighash and re-derive to the chainz input addresses under p2pkh 58; 168 P2PK inputs are not checked (pubkey lives in the prevout). Row now `Standard`, so `buildUnsignedSweep` supports qrk. Untested: a built QRK sweep broadcast on mainnet; QRK fee rates (default limits apply).

## Account payments (2026-10-25)

xlm, algo, atom, ton, ada and dot have payment/sweep builders in `acct-tx` (see recipes/chain-polkadot.md, chain-cardano.md, chain-ton.md, chain-stellar.md, chain-algorand.md, chain-cosmos.md). The table's
`sweep build` column is the wasm/UTXO builder only and stays `no` for them.

## Groestlcoin extended keys and taproot (2026-10-25)

GRS xpub/tpub strings use the Groestl-512 checksum and are accepted only with `--chain grs` (vectors: Groestlcoin/eclair commit f52fbf9, 4 tpub pairs); classify reports them as `xpub`. GRS rows include `p2tr` (grs1p…, BIP341 vector); spending GRS taproot inputs is refused. Untested: real Electrum-GRS mainnet xpub, any mainnet grs1p.

## Monero (2026-10-25)

Scan and sweep: host tool `xmr-wallet` over a loopback monero-wallet-rpc. 2026-10-25 stagenet run (Mac, official monero v0.18.5.4 binaries, SHA-256 checked against the published hashes.txt): faucet 0.5 XMR seen by `xmr-wallet scan` (unlocked 500000000000 at height 2236134); `xmr-wallet sweep --relay` planned amount 499969620000 + fee 30380000 = unlocked, relayed tx bb300227e8e6c418fe7d825ac432d79abc2d4b943d99e053eabfba3c8197a96d (mined in stagenet block 2236135, checked on a public stagenet node); a view-only `scan` of the destination wallet shows that amount incoming (pool). The TTY confirm was answered by an `expect` script standing in for a human. Untested: mainnet, Polyseed/13-word/non-English seeds, subaddresses.

## Solana public data (2026-10-25)
wasm/lib `sol`: PDA/ATA, on-curve, Anchor discriminator, legacy+v0 tx decode, ed25519 signature check, `solVerifyTx` policy. No Solana builder yet (planned: acct-tx style, solders vectors).
- 2026-10-25: BCH CashAddr accepted by `addressToScript('bch', …)` and converted by `cashAddrToLegacy` / `legacyToCashAddr`.
- 2026-10-25: EVM transfer builder for any chain id (`buildEvmTransfer`); UTXO selection (`selectUtxos`).
- 2026-10-25: EVM recovery/sweep verifier (SwapChan parity, raw tx entry points).
- 2026-10-25: Solana v1 transactions (SIMD-0385) decode + verify; XRP X-address kind `xaddress` in detectAddressInfo.
- 2026-10-25: `buildPsbtWithMemo` output order `[to, change, OP_RETURN]` (THORChain), optional memo, selected-input fee fix.
- 2026-10-25: Tron txID + raw_data decode (`tronDecodeTx`); BTC-family PSBT with OP_RETURN memo (`buildPsbtWithMemo`).

Every non-segwit input needs `prev_tx`: P2PKH on every chain including the fork-id chains BCH/BSV/BTG (their sighash commits the amount, but blocktools checks by script type and does not sign fork-id), GRS and PoS-nTime. Only zec is exempt (ZIP-243/244 amounts via `zec_prevouts`).
- 2026-10-25: `buildPsbtWithMemo` defaults to non-RBF (0xffffffff); optional trailing `rbf` arg.

## Chain quirks and their known-answer vectors (2026-10-25)

Every way a chain departs from plain Bitcoin is listed here with at least one independent
known-answer test (KAT): a vector from another implementation, a spec, or real chain data, never
only our own output. `crates/tx/tests/quirks.rs` parses this table and fails if a row has no KAT,
names a test that does not exist, or lacks a source, and if a chain with a quirk in code
(`pos::layout`, the zec path, single-SHA-256 GRS digests) has no row. Add the vector with the quirk.

<!-- quirks:begin -->
| quirk | chains | KAT (tests file::fn) | vector source |
|---|---|---|---|
| groestl-single-sha256-bip143 | grs | grs.rs::bip143_single_sha256_vectors | groestlcoinjs-lib test/fixtures/transaction.json hashForWitnessV0 (data/grs_witness_v0.txt) |
| groestl-single-sha256-legacy | grs | grs.rs::mainnet_signatures_verify_under_single_sha256 | Groestlcoin mainnet txs, api.blockchair.com raw/transaction (data/grs_mainnet.txt) |
| pos-ntime-after-version | ppc nvc clam | pos.rs::mainnet_txids_and_signatures | PPC raw hex from Blockbook; NVC/CLAM from chainz.cryptoid.info JSON, txid-checked (data/pos_mainnet.txt) |
| pos-ntime-after-locktime | rdd | pos.rs::mainnet_txids_and_signatures | RDD mainnet raw hex from Blockbook (data/pos_mainnet.txt) |
| pos-nvc-json-serialize | nvc | nvc_json.rs::mainnet_json_reserializes_to_txid | api.novaco.in gettransaction JSON, coinstake + regular + PoS coinbase, txid-checked (data/nvc_*.json) |
| blk-bitcoin-layout | blk | pos.rs::blackcoin_is_bitcoin_layout | Blackcoin mainnet txs (data/pos_mainnet.txt `blk` rows) |
| zcash-v5-zip244 | zec | zcash.rs::zip244_vectors | zcash-test-vectors zip_0244.json (data/zec_zip244.txt) |
| zcash-v4-zip243 | zec | zcash.rs::zip243_vectors | zcash-test-vectors zip_0243.json (data/zec_zip243.txt) |
| zcash-envelope-mainnet | zec | zcash.rs::mainnet_txs | zec mainnet txs, api.blockchair.com raw/transaction (data/zec_mainnet.txt) |
| zcash-blake2b-personal | zec | zcash.rs::blake2b_matches_hashlib | Python hashlib.blake2b with person= |
| p2sh-wrapped-segwit | btc ltc | sign.rs::bip143_p2sh_p2wpkh_byte_exact | BIP143 P2SH-P2WPKH example |
| p2sh-bare-amount-uncommitted | btc ltc | sign.rs::bare_p2sh_is_not_amount_committed | BIP143 vs legacy sighash definitions (amount in BIP143 preimage only) |
| evm-eip155-chain-id | eth bsc polygon avax | kat.rs::eip155_example | EIP-155 spec example |
| qrk-5-decimals-legacy | qrk | qrk.rs::qrk_mainnet_txs_are_bitcoin_legacy | chainz.cryptoid.info tx.raw.dws, txid-checked (data/qrk_mainnet.txt) |
| qtum-legacy | qtum | qtum.rs::qtum_mainnet_txs_are_bitcoin_legacy | qtum.info api raw-tx (data/qtum_mainnet.txt) |
| wdc-legacy | wdc | wdc.rs::wdc_mainnet_txs_are_bitcoin_legacy | chainz.cryptoid.info tx.raw.dws (data/wdc_mainnet.txt) |
<!-- quirks:end -->

## The registry as data
`chain-table` prints the CHAINS table above as JSON (one object per chain; `--array` for a single
array; `chain-table btc` for one row): name, ticker, SLIP-44 `coin_type`, `curve`, `encoding` with
its version bytes / hrp / SS58 prefix, `native_seed`, `sign` (UTXO sighash scheme; `account_family`
means the chain is signed by its own tool, e.g. acct-tx / xrp-tx), `buildable` (tx-build signs it),
`verified` and the parameter `source`. The wasm build exports the same array as `chainTable()`.
