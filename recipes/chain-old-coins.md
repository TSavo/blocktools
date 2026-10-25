# Chain: old coins (Peercoin, Namecoin, Feathercoin, Novacoin, Clams, BlackCoin, ReddCoin, ...)

`blocktools` encodes addresses and WIF for every row in `derive --list-chains` (each row is checked
against an outside key-1 vector from scripts/kat-chains.py). Offline sweep builds (tx-build) exist for every row whose
`Sign` column in docs/CHAINS.md is not `none`. `recipes/recover.sh` automates sweep only for btc/ltc/doge/eth; for the
other chains, build from a UTXO list as shown below.

<!-- e2e: expect=PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9 ; expect=N7FdkoPbHSxKfrSVVbRu3NZtrLqc1oKpAR ; expect=6pQiLg4eJbM2bP9CZemnccDzwB3kz2Ae1x ; expect=RjJ4cn5Bg58D2khGiNRmQW1yWtA6Py9kWa -->
    ./blocktools run 'key-to-addresses --chain ppc,nmc,ftc,rdd < /in/key.hex'

<!-- e2e: rc=3 ; expect=PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9 ; expect=addresses only -->
    recipes/recover.sh /in/key.hex - --chain ppc

Every other old-coin row, key 1 (uncompressed p2pkh, as old clients made them; vectors from scripts/kat-chains.py):

<!-- e2e: expect=4QP6S2Gv3WZmgnJgR8mshrbHA9W6hQiTxR ; expect=xJyuT2j5dnLoBhHraFjzG2hmMDjnS3fefx ; expect=BF8MAsLp7aSfb9g9qGSHwzDerit8nAZAJX ; expect=QXHFfTBKYXjaaTH1e7Rox8CcdNPGHVhM59 ; expect=AST9CekEhDWuxHPynRmeyjg5biNFSijvb3 ; expect=XmN7PQYWKn5MJFna5fRYgP6mxT2F7xpekE ; expect=Vkg6Ts44mskyD668xZkxFkjqovjXX9yUzZ ; expect=RKxTdfmtxtfLDKZBgx6SvNkBtNu9jRYnLh ; expect=MJaRnao1s62a2zAKSkmG582KbLKianqb7v ; expect=GUXByHDZLvU4DnVH9imSFckt3HEQ5cFgE5 -->
    ./blocktools run 'key-to-addresses --chain nvc,clam,blk,qrk,xpm,dash,vtc,dgb,via,mona,rvn,trc,mec,aur,bch,bsv,btg,pot < /in/key.hex'

(trc/bch/bsv share Bitcoin's 1... form; dgb shares Dogecoin's D... form; pot shares Peercoin's P... form. Check
`"chain"` on each line.)

## Sweep a PoS coin (Peercoin-style nTime: ppc, nvc, clam, rdd)

The unsigned tx carries a timestamp: pass `--time UNIX` (now, give or take, for the network to accept it). Key 1 -> key 2,
one 0.01 PPC output in a UTXO list (on a real recovery `utxo-fetch` or an explorer gives you this list):

<!-- e2e: expect=P9CXqzQyLNguvGoLDeuGx28QZjotMoQcCZ ; expect="amount":999020 -->
    ./blocktools run 'tx-build --chain ppc --utxos /in/u-ppc.json --to P9CXqzQyLNguvGoLDeuGx28QZjotMoQcCZ --sweep --fee-rate 5 --time 1792800000 | tx-decode --chain ppc'

<!-- e2e: expect=4EKBZtQRxtujUuFG4wFJA8LRz2hYwxn6V4 -->
    ./blocktools run 'tx-build --chain nvc --utxos /in/u-nvc.json --to 4EKBZtQRxtujUuFG4wFJA8LRz2hYwxn6V4 --sweep --fee-rate 5 --time 1792800000 | tx-decode --chain nvc'

<!-- e2e: expect=x8uzatrbZAgkypESE4DQiJSvB6wEgP1hTz -->
    ./blocktools run 'tx-build --chain clam --utxos /in/u-clam.json --to x8uzatrbZAgkypESE4DQiJSvB6wEgP1hTz --sweep --fee-rate 5 --time 1792800000 | tx-decode --chain clam'

<!-- e2e: expect=RZE9keChbTUApsdrNAuBrmm8LmMYdn63TB -->
    ./blocktools run 'tx-build --chain rdd --utxos /in/u-rdd.json --to RZE9keChbTUApsdrNAuBrmm8LmMYdn63TB --sweep --fee-rate 5 --time 1792800000 | tx-decode --chain rdd'

Check the destination before signing:

<!-- e2e: expect="tool":"tx-verify" ; expect="failures":[] -->
    ./blocktools run 'tx-build --chain ppc --utxos /in/u-ppc.json --to P9CXqzQyLNguvGoLDeuGx28QZjotMoQcCZ --sweep --fee-rate 5 --time 1792800000 | tx-verify --chain ppc --expect-to P9CXqzQyLNguvGoLDeuGx28QZjotMoQcCZ'

## Sweep BlackCoin, Primecoin, Quarkcoin (plain Bitcoin layout)

BLK dropped nTime (its tx layout is Bitcoin's; 3 mainnet vectors). XPM's fees are large per byte; see CHAINS.md.

<!-- e2e: expect=B54SJjUL2xndPGcjV4uiQFxogc5b3eMhts -->
    ./blocktools run 'tx-build --chain blk --utxos /in/u-blk.json --to B54SJjUL2xndPGcjV4uiQFxogc5b3eMhts --sweep --fee-rate 5 | tx-decode --chain blk'

<!-- e2e: expect=AGPELWskcbrskQLZSEF5S1RERbZhgaS6Ep -->
    ./blocktools run 'tx-build --chain xpm --utxos /in/u-xpm.json --to AGPELWskcbrskQLZSEF5S1RERbZhgaS6Ep --sweep --fee-rate 5 | tx-decode --chain xpm'

<!-- e2e: expect=QMDLoKJqTv5YNaDbHuuEQPwmTFaiaKHJVp -->
    ./blocktools run 'tx-build --chain qrk --utxos /in/u-qrk.json --to QMDLoKJqTv5YNaDbHuuEQPwmTFaiaKHJVp --sweep --fee-rate 5 | tx-decode --chain qrk'

UNVERIFIED: the QRK tx format. No non-coinbase QRK tx turned up in 800 recent blocks, so the build assumes the Bitcoin
legacy layout. Test a small amount first.

Signing (`tx-sign`, human-typed code on /dev/tty) can't run inside recipe-check. scripts/e2e.d/sweep-alt.sh covers
build -> verify -> sign -> decode against a 127.0.0.1 mock chain (key 1). Every builder is checked against real mainnet txs
in crates/tx/tests. UNTESTED: whether each network accepts the result (min relay fee, nTime window).

From an old client's wallet.dat: see input-wallet-dat.md ("Old-coin clients").

Other routes: a human can import the key into that coin's own client (`./blocktools reveal` shows the coin's WIF).
NOT BUILT: broadcast for these chains (tx-broadcast covers btc/ltc/doge/eth backends), Zcash shielded spends. See
docs/ROADMAP.md.
