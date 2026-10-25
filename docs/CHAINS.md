# Chain table

Source of truth: `crates/core/src/chains.rs`. Known-answer vectors come from `scripts/kat-chains.py`, an independent base58check that uses only hashlib, and are checked in the `kat_long_tail` test. tx-build only signs chains whose Sign is `Standard`; it refuses ForkId (bch/bsv/btg), PosTime (ppc/nvc/clam/blk/rdd/pot) and Unknown (qrk, plus the non-UTXO chains, which have their own signers). No coin other than BTC has been signed and accepted on a real network.

| name | ticker | SLIP-44 | explorer/API sources (checked 2026-10-24) |
|---|---|---|---|
| btc | BTC | 0 | blockstream.info |
| ltc | LTC | 2 | litecoinspace.org |
| doge | DOGE | 3 | none listed |
| eth | ETH | 60 | none listed |
| tron | TRX | 195 | none listed |
| xrp | XRP | 144 | none listed |
| sol | SOL | 501 | none listed |
| qtum | QTUM | 2301 | none listed |
| ftc | FTC | 8 | none listed |
| nmc | NMC | 7 | none listed |
| dash | DASH | 5 | chainz.cryptoid.info |
| vtc | VTC | 28 | chainz.cryptoid.info |
| dgb | DGB | 20 | chainz.cryptoid.info |
| via | VIA | 14 | none listed |
| mona | MONA | 22 | none listed |
| rvn | RVN | 175 | blockbook.ravencoin.org |
| xpm | XPM | 24 | chainz.cryptoid.info |
| trc | TRC | 83 | none listed |
| mec | MEC | 217 | none listed |
| aur | AUR | 85 | chainz.cryptoid.info |
| bch | BCH | 145 | none listed |
| bsv | BSV | 236 | none listed |
| btg | BTG | 156 | none listed |
| ppc | PPC | 6 | chainz.cryptoid.info |
| nvc | NVC | 50 | chainz.cryptoid.info |
| clam | CLAM | 23 | chainz.cryptoid.info |
| blk | BLK | 10 | chainz.cryptoid.info |
| rdd | RDD | 4 | none listed |
| pot | POT | 81 | chainz.cryptoid.info |
| qrk | QRK | 82 | chainz.cryptoid.info |

### Unverified chains (, refused by every other call)

| name | ticker | SLIP-44 | sources |
|---|---|---|---|
| wdc | WDC | 0 | chainz.cryptoid.info |
| anc | ANC | 0 | none listed |
