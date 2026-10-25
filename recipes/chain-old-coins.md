# Chain: old coins (Peercoin, Namecoin, Feathercoin, Novacoin, Clams, BlackCoin, ReddCoin, ...)

`blocktools` encodes addresses and WIF for every row in `derive --list-chains` (each row is checked
against an outside key-1 vector in crates/core). Sweep is not built for these chains.

<!-- e2e: expect=PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9 ; expect=N7FdkoPbHSxKfrSVVbRu3NZtrLqc1oKpAR ; expect=6pQiLg4eJbM2bP9CZemnccDzwB3kz2Ae1x ; expect=RjJ4cn5Bg58D2khGiNRmQW1yWtA6Py9kWa -->
    ./blocktools run 'key-to-addresses --chain ppc,nmc,ftc,rdd < /in/key.hex'

<!-- e2e: rc=3 ; expect=PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9 ; expect=addresses only -->
    recipes/recover.sh /in/key.hex - --chain ppc

From an old client's wallet.dat: see input-wallet-dat.md ("Old-coin clients").

How to move the funds today: a human imports the key into that coin's own client (`./blocktools reveal`
shows the coin's WIF). NOT BUILT: transaction builders for PoS coins (Peercoin-style `nTime` field),
Zcash v4/v5, and Groestl hashing (GRS). The plan is in docs/ROADMAP.md.
