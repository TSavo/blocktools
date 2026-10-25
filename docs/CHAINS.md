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
| qrk | QRK | 82 | 3a | 09 | — | 186 | sha256d | 8 | — | unknown | no | cryptoid chainz.cryptoid.info |
| zec | ZEC | 133 | 1cb8 | 1cbd | — | 128 | sha256d | 8 | — | zcash-v5 | yes (transparent P2PKH) | none |
| grs | GRS | 17 | 24 | 05 | grs | 128 | groestl512d | 8 | — | legacy-sha256 | yes | none listed |

### Fee-warning limits (verify-tx / wasm `verifyTx`, `chainParams().fee_warn`)

`high_fee` fires above `fee` base units, `high_fee_rate` above `rate` base units per vbyte. Default 1,000,000 / 500 (Bitcoin-tuned). A per-coin row is 20 x the measured median fee rate x a 1,000 vB sweep (rate limit 20 x median), never below the default. Measured 2026-10-24 from recent mainnet blocks (non-coinbase txs, fee = inputs - outputs); scripts in the commit message basis strings.

| chain | fee limit | rate limit | measured median | sample |
|---|---|---|---|---|
| dgb | 10,000,000 | 10,000 | 512 sat/vB | 60 txs, blocks 24444779-24445073, blockbook.dgb.zelcore.io |
| rvn | 20,000,000 | 20,000 | 1004 sat/vB | 60 txs, blocks 4596227-4596275, blockbook.rvn.zelcore.io |
| qtum | 14,000,000 | 14,000 | 700 sat/vB | 100 txs, blocks 6253698-6255768, qtum.info |
| xpm | 2,000,000,000 | 2,000,000 | 100,000 sat/B (est. size) | 40 txs, blocks 7063926-7064103, chainz.cryptoid.info |
| vtc | 2,000,000 | 2,000 | 101 sat/vB | 60 txs, blocks 2703728-2703858, blockbook.vtc.zelcore.io |
| aur | 2,000,000 | 2,000 | 102 sat/B (est. size) | 41 txs, blocks 5913113-5913344, chainz.cryptoid.info |

Measured and left at the default: mona (median 2.5 sat/vB, 60 txs, blocks 4142846-4143045, mona.insight.monaco-ex.org; node relayfee 0.001 MONA/kB), dash (3.9 sat/B, 60 txs, blockbook.dash.zelcore.io), trc (14.8 sat/B, only 14 txs in 300 blocks 3327566-3327865, insight.terracoin.io), ppc (blockbook reports fee 0 for most txs; fees are burned), via (4 txs in 400 blocks, all fee 0). "est. size" = 10 + 148/input + 34/output (P2PKH), because chainz does not return tx size. Not measured (default applies): every other row, including zec, nmc, ftc, mec, nvc, clam, blk, rdd, pot, qrk, grs, bch, bsv, btg, ltc, doge.

### Unverified (never returned as supported)

| name | ticker | SLIP-44 | p2pkh | p2sh | hrp | wif | checksum | decimals | forkid | tx format | sweep build | sources |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| wdc | WDC | 0 | 49 | 05 | — | 201 | sha256d | 8 | — | legacy | no | cryptoid chainz.cryptoid.info |
| anc | ANC | 0 | 17 | 0f | — | 151 | sha256d | 8 | — | legacy | no | none |

Zcash Sapling: `zec-sapling` CLI (ZIP-32, m/32'/133'/i', zs1 default address, optional 0600 viewing-key file). No spend/scan.

Zcash transparent is listed by wasm `listChains`/`supportedChains` (scope transparent) since 2026-10-25. Evidence: ZIP-243/244 official vectors, 7 mainnet txs (txid + signature), 21 mainnet script->address pairs from api.blockchair.com (crates/tx/tests/data/zec_addresses.txt). Untested: BIP44 m/44'/133' derivation, xpubs, broadcast, v6.
