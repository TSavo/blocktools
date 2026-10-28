# blocktools

> **⚠️ DANGEROUS: use at your own risk.** Code that handles keys and signs transactions
> should always be read and audited by you before you trust it with real funds.
> **Used incorrectly, it can destroy your money**: signing to a wrong address, paying a
> huge fee, losing keys, or sending on the wrong chain. You are responsible for verifying
> every transaction. It opens hostile wallet files and extracts secrets, so run it only
> sealed and offline (`./blocktools run`, `--network none`). The unit tests are evidence,
> not a substitute for your own review. See [docs/SECURITY.md](docs/SECURITY.md).


## What it is

blocktools recovers keys and addresses from old wallet files and seed phrases, and builds,
checks and signs transactions, offline. It is a set of small Unix filters (Rust; one JSON object
per line on stdin/stdout) that you chain into pipelines. Every tool that touches a secret is meant
to run inside a sealed container started by the `./blocktools` wrapper; what comes out of that
container to you (or to an AI agent driving it) is addresses, derivation paths and statuses only.
See [DESIGN.md](DESIGN.md) for the pipe rules and [docs/SECURITY.md](docs/SECURITY.md) for the
threat model.

## What the recovery side is tested against

blocktools has **not been tested against any real lost wallet (untested)**. Nobody has handed us a real
corrupted wallet or a real forgotten password, so the headline promise rests on synthetic tests only.
What is measured (Linux x86_64, `scripts/e2e.d/recovery-real.sh`, run in CI's e2e stage):

* Wallet files written by the real third-party software, with throwaway keys and passwords
  (generated fresh at test time by `scripts/recovery-gen.sh`, never committed; see docs/FIXTURES.md): Bitcoin Core 25.2 legacy BDB and descriptor (SQLite) wallet.dat,
  Electrum 4.5.8 segwit wallets (whole-file encrypted and keystore-only), and an eth-account 0.13.4
  scrypt keystore (the geth/MetaMask-export format). A BIP39 phrase from python-mnemonic (the Trezor
  reference) with addresses computed by Bitcoin Core's `deriveaddresses`.
* Damage a user would plausibly have: a typo'd seed word, two swapped words, a missing word, an
  unknown word (`?`), on the BIP39 and Electrum seeds; a password remembered only as "horse battery"
  plus a digit, or with two letters swapped. `seed-repair` / `pw-candidates` and the wallet readers
  must reach the address the generator itself printed. Candidate counts and attempt numbers are
  printed by the script on each run.
* Our own writers, not third-party ones: `scripts/make-fixtures.py` (dat-read e2e) and
  `scripts/electrum-bie1-gen.py`. btcrecover's test wallets (fetched by `scripts/fetch-fixtures.sh`)
  are third-party files but not ours to regenerate.

Not covered: a swap (or typo) that still passes the BIP39 checksum (about 1 in 16 for a swap): seed-repair then reports `checksum_ok` and searches nothing, so the test picks a swap whose checksum fails; wallets damaged on disk (truncated or bit-flipped files), MetaMask's browser vault, Exodus,
hardware-wallet passphrases, multisig, passwords not reachable from the tokens you give, seeds with more
than two unknown words, and every wallet version other than those named above.

## Install

### From the v0.1.0 release (Linux x86_64 only)

Releases are built for Linux x86_64 only. There is no macOS, Windows or ARM asset; on those, build from source.

```sh
gh release download v0.1.0 -R TSavo/blocktools     # or download both files from the Releases page
sha256sum -c SHA256SUMS                            # must print: blocktools-v0.1.0-linux-x86_64.tar.gz: OK
tar xzf blocktools-v0.1.0-linux-x86_64.tar.gz
cd blocktools-v0.1.0-linux-x86_64
export PATH=$PWD/bin:$PATH MANPATH=$PWD/share/man:
man blocktools
```

The tarball holds `bin/` (the tools), `share/man/` and `man/` (manual pages), `recipes/`,
`DESIGN.md`, `EXPORTS.md`, `LICENSE` and the `blocktools` wrapper. The binaries are **not**
static: they are dynamically linked against glibc (`ldd bin/derive` lists `libc.so.6` and
`libgcc_s.so.1`). The tarball is Linux x86_64 and glibc-linked: 40 of its 41 tools need glibc 2.34
or newer, and `sealed-run` needs glibc 2.39 or newer. Measured per binary as the newest GLIBC_ symbol
version: `for b in bin/*; do echo "$(objdump -T $b | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1) $b"; done`
(40 lines GLIBC_2.34, one GLIBC_2.39 for `bin/sealed-run`). Only the sealed Docker image is built from static musl binaries.
Do not skip the checksum step: an archive that fails `sha256sum -c` must not be run.

**Sealed mode from a tarball.** The tarball has no Dockerfile or sources, so its `./blocktools
build` cannot work. To get the sealed image, check out the same release and build it there; the
image does not depend on the tarball:

```sh
git clone --branch v0.1.0 https://github.com/TSavo/blocktools && cd blocktools
./blocktools build                                 # image blocktools:local; then ./blocktools run '...'
```

Until then, the tarball's `bin/sealed-run agent '<pipeline>'` gives the same output redaction but
no container isolation (no `--network none`): use it only on an offline machine.

**v0.1.0 and `derive --address-list`.** In v0.1.0, `redact` (and so `sealed-run agent` and
`./blocktools run`) drops the plain `label<TAB>path<TAB>address` lines, so the list comes back
empty (`"count":0`). Fixed on main after v0.1.0: redact now passes those lines through its leak check, so with a source build `./blocktools run '... | derive --address-list' > addresses.txt` works (recipes/derive.md). With v0.1.0, build the same list from JSON instead:

```sh
... | derive --chain btc --count 1 --public-only | redact | jq -r 'select(.address)|[.chain+" "+.kind,.path,.address]|@tsv' > addresses.txt
```

Measured 2026-10-26 on Linux with the v0.1.0 `bin/`: download, `sha256sum -c` OK, the `ldd`
and `objdump` results above, the `--address-list` count 0 and the `jq` workaround (4 btc lines),
and every wallet example below through `sealed-run agent`. Not measured: actually running on glibc 2.34-2.38 (only
the symbol versions were read; `sealed-run` is expected to fail to load there) or older, macOS.

### Debian / Ubuntu (apt, amd64)

```sh
sudo install -d -m 0755 /etc/apt/keyrings
sudo wget -O /etc/apt/keyrings/blocktools-archive-keyring.asc \
  https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/apt/blocktools-archive-keyring.asc
echo "deb [signed-by=/etc/apt/keyrings/blocktools-archive-keyring.asc] https://tsavo.github.io/blocktools/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/blocktools.list
sudo apt update && sudo apt install blocktools
```

Needs glibc 2.34+ (Debian 12, Ubuntu 22.04+); `sealed-run` needs glibc 2.39+ (Ubuntu 24.04). Key
fingerprint and measurements (debian:12, ubuntu:22.04 and 24.04 containers, 2026-10-26): [docs/APT-SIGNING.md](docs/APT-SIGNING.md).

### Alpine (apk, x86_64)

```sh
wget -O /etc/apk/keys/blocktools@tsavo-2026.rsa.pub \
  https://raw.githubusercontent.com/TSavo/blocktools/main/packaging/alpine/keys/blocktools@tsavo-2026.rsa.pub
echo https://tsavo.github.io/blocktools/alpine >> /etc/apk/repositories
apk update && apk add blocktools
```

Static musl binaries; current package is the untagged pre-release `0.1.1_pre20261026`. Measured in an
`alpine:latest` (3.24.3) container on 2026-10-26: install from the live URL, 43 of 43 executables run,
refused without the key: [docs/APK-SIGNING.md](docs/APK-SIGNING.md).

### From source

```sh
git clone https://github.com/TSavo/blocktools && cd blocktools
cargo build --locked --release --workspace         # tools land in target/release/
./blocktools build                                 # the sealed image (needs a Docker host)
```

## Sealed runs

`./blocktools run '<pipeline>'` runs the pipeline in a container with `--network none`, a
read-only root filesystem, all capabilities dropped, a non-root user and memory/pid limits.
`./in` is mounted read-only at `/in` and `./secrets` (passwords, one per file) read-only at
`/secrets` (`BLOCKTOOLS_IN` / `BLOCKTOOLS_SECRETS` move them). Its stdout passes through
`sealed-run agent`, which replaces every key field with `[REDACTED]` and drops lines that fail its
leak check, so the output is safe to paste or to hand to an agent. `./blocktools reveal` is the
human-only variant: it needs a real terminal and a typed code, then prints keys.
`scripts/sealed-check.sh` checks these flags on a real container (Linux Docker only).
**macOS sealed path is unverified (untested).** The macos CI job runs the tools natively, not sealed. One hand check on a Mac
(macOS 26.3.1 x86_64; Docker Desktop not running, so `docker` pointed at an `ssh://` context on a Linux host): the container
ran on the remote host and saw an empty `/in`, because bind mounts resolve on the Docker host (hand-measured once, not re-run in CI) (untested).
`./blocktools run`/`reveal` now refuse an `ssh://` or `tcp://` engine (`DOCKER_HOST` or the current context) before starting
a container (`scripts/e2e.d/wrapper-remote.sh`, Linux, fake docker binary); set `BLOCKTOOLS_ALLOW_REMOTE=1` only if the files are on that host.
Without Docker, `sealed-run agent '<pipeline>'` gives the same redaction but none of the
container isolation.

## Worked examples (public test fixtures only)

Each command below is run as written by `scripts/recipe-check.py` in CI, through the same
`sealed-run agent` boundary. Put the file in `./in/` and its password in `./secrets/`. The
fixtures are public: the BIP39 vector "abandon … about", the Web3 Secret Storage keystore vector,
and btcrecover's test wallets (`scripts/fetch-fixtures.sh`; password `btcr-test-password`).
Never put a real wallet on a networked machine.

**Seed phrase** (`in/seed.txt` = the 12-word "abandon … about" vector; CI's copy has two typos, which `seed-repair` fixes before `seed-to-master` sees it):

<!-- e2e: expect=bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu ; expect="wif":"[REDACTED]" -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain btc --count 1'

<!-- e2e: expect=0x9858EfFD232B4033E47d90003D41EC34EcaEda94 -->
    ./blocktools run 'seed-repair < /in/seed.txt | seed-to-master | derive --chain eth --count 1'

**Bitcoin Core wallet.dat** (btcrecover's `bitcoincore-wallet.dat`, BDB):

<!-- e2e: expect=1Ak4Z3NsRigsn9wpwZNoRobNzy9jokxQxx ; needs=old-client-wallet.dat -->
    ./blocktools run 'read-file /secrets/multibit.pw /in/old-client-wallet.dat | dat-read | key-to-addresses --chain btc'

**Ethereum keystore** (Web3 Secret Storage test vector, password `testpassword`):

<!-- e2e: expect=0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b -->
    ./blocktools run 'read-file /secrets/keystore.pw /in/keystore.json | keystore-open'

**Old Electrum 1.x seed** (Electrum's own test vector; 12 words from the 1626-word list, or the 32-hex seed) and **brainwallets** (`phrase-to-key`: sha256 of the phrase as brainwallet.org/bitaddress.org did, or WarpWallet):

<!-- e2e: expect=1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo -->
    ./blocktools run 'seed-to-master < /in/electrum-old-seed.txt | derive --chain btc --count 1'

<!-- e2e: expect=1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T -->
    ./blocktools run 'phrase-to-key < /in/brainwallet.txt | key-to-addresses --chain btc'

**Which of your phrases is funded, offline** (`utxo-set`, `wallet-finder`): load a Bitcoin Core `dumptxoutset` file into RAM and test addresses, or every sentence and word run of your own text, against it without asking any server. Hits print phrase, scheme, address and balance, never a key. Recipe: [recipes/goal-find-funded-phrase.md](recipes/goal-find-funded-phrase.md).

<!-- e2e: expect="hits":5 ; expect="status":"ok" -->
    wallet-finder --dump /in/utxo.dat < /in/notes.txt > /secrets/hits.jsonl

**Electrum** (btcrecover's Electrum 4.4.3 wallet):

<!-- e2e: expect=bc1qsz0dhew357cj6eznmcawgyf44jzpgcax2lvfvm ; needs=electrum-wallet -->
    ./blocktools run 'read-file /secrets/electrum.pw /in/electrum-wallet | electrum-read | seed-to-master | derive --chain btc --count 1'

**MultiBit Classic** (`.key` export):

<!-- e2e: expect=166UVSG9WX81Pkp9f8o4htYV9M3KBqXHdV ; needs=multibit.key -->
    ./blocktools run 'read-file /secrets/multibit.pw /in/multibit.key | multibit-read | key-to-addresses --chain btc'

**Armory** (`.wallet`):

<!-- e2e: expect=1H29eJEsQCtwCRc737gZyD7HtpxxdQNQzv ; needs=armory.wallet -->
    ./blocktools run 'read-file /secrets/armory.pw /in/armory.wallet | armory-read | key-to-addresses --chain btc'

Not sure what a file is? `classify` names it, and `recipes/recover.sh FILE - --goal addresses`
picks the pipeline for you:

<!-- e2e: expect="class":"wallet_dat" ; needs=old-client-wallet.dat -->
    ./blocktools run 'classify /in/old-client-wallet.dat'

## Where to go next

* Manual pages for every tool, `recover.sh` and the wrapper: `man/` in the repo
  (`man -l man/man7/blocktools.7`), `share/man/` in the release. They are generated from `--help`
  by `scripts/gen-man.py`, and CI fails if they are stale.
* Recipes, by input, chain and goal (sweep, balance, verify offline): [recipes/README.md](recipes/README.md).
  Every recipe has at least one example that CI runs.
* [Getting started](docs/getting-started.md) · [cookbook](docs/cookbook.md) ·
  [troubleshooting](docs/troubleshooting.md) · [refusal codes](docs/REFUSALS.md) ·
  [paths](docs/PATHS.md) · [policy files](docs/POLICY.md) · [chains](docs/CHAINS.md) ·
  [library API](docs/library-api.md) · [wasm/TS](bindings/wasm/README.md) ·
  [parity generators](docs/PARITY-GENERATORS.md) · [docs index](docs/README.md).

## Status

Status: the sealed image builds on Linux docker (47.9 MB of uncompressed layers via `docker save` on a containerd image store at 189e40f, 40 binaries: the 39 entries of `crates/io/sealed-tools.txt` plus sealed-run; host tools such as contract-call are not in the image; `scripts/image-size.sh` prints the instrument and the docker version/storage driver, because `docker image inspect` differs between image stores) (unmeasured). `scripts/sealed-check.sh` checks the sealed run on a real container (untested since chainstate-dump joined the image): network none, read-only rootfs, all capabilities dropped, read-only /in, and no secret material in agent output (Linux docker only) (untested). Phase-2 tools (tx-build, tx-verify, tx-sign, tx-broadcast, account and XRP signers) are covered by unit/KAT tests and `scripts/e2e-local.sh`; `sealed-run human` (what `reveal` runs inside the container) is driven through a pty in e2e. Not yet tested: `./blocktools reveal` itself under Docker on a real terminal. See DESIGN.md "Verified status".

Host-side network tools (`utxo-fetch`, `tx-broadcast`, `rpc`) never enter the sealed image, and `sealed-run` refuses them (status `unsupported`, exit 2, measured 2026-10-26): run them on the host, after the sealed steps. `rpc` is a pipe filter for node and wallet RPC endpoints (EVM, bitcoind and forks, Solana, Tron, Cosmos LCD, Esplora, Blockbook) that refuses key-export, unlock and wallet-signing methods by default; see `docs/RPC.md` (mock-tested; one measured public read).

Tests: `cargo test --release && sh scripts/e2e-local.sh`; the full gate is `sh scripts/gate.sh`.
Test vectors are public. Never commit real wallet data; `in/` and `secrets/` are git-ignored.
