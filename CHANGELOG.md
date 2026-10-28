# Changelog

All notable changes to blocktools. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org/). Every entry names the commit(s) it comes from.
Numbers and security statements here are only those registered as measured in docs/claims.toml
(claim id in brackets); anything not measured is under "Known limitations" in plain words.

## [0.2.0] - Unreleased (release candidate; not tagged)

Version 0.2.0 in every Cargo.toml, internal pin, the wasm package, lockfiles and man pages (version-check) (4212b19).
Minor version: new tools, new wasm exports and new flags; no CLI flag, wasm export or tool was removed
(checked against v0.1.1: the pinned wasm export list in scripts/wasm-check.sh only gained names; no
`tools/` crate was removed; no option was removed from any man page). Behaviour changes that can affect
existing scripts are listed under "Changed".

### Added
- THORChain UTXO inbound (swap from a UTXO coin): `tx-build --memo STRING` / `--op-return HEX` adds a
  zero-value trailing `OP_RETURN` to the UTXO build path (THORChain inbound shape `[vault, change,
  OP_RETURN memo]`; refused above the chain's relay limit — BCH 220, else 80 bytes;
  `blocktools_tx::build::op_return_script`), and `tx-sign`/`tx-verify`/`tx-envelope` accept exactly one
  zero-value `OP_RETURN` as a non-destination memo instead of `unexpected_output`/`has_warnings`
  (`crates/tx/src/policy.rs`); `tx-sign` shows the memo (UTF-8 if printable, else hex) on the `/dev/tty`
  summary and keeps the typed-code confirmation. A second `OP_RETURN`, or a non-zero-value `OP_RETURN`,
  is still refused. Recipe `recipes/thorchain-swap-utxo.md`; `scripts/e2e.d/thorchain-utxo.sh` drives the
  shipped path node-free (build → `verify_thor_send` → pty sign → decode) with the two negative probes,
  and `scripts/e2e.d/memo-regtest.sh` runs it against the real LTC/DOGE/BCH regtest nodes.
- THORChain (`rune`) account support: `acct-tx keys|build|decode|sign --chain rune` signs a
  THORChain `MsgDeposit` (chain_id `thorchain-1`, SIGN_MODE_DIRECT, `/cosmos.crypto.secp256k1.PubKey`) —
  the transaction behind every THORChain swap-from-RUNE and THORName action; the action rides in the
  deposit memo, and the native fee (RfRune) is deducted by the chain (gas limit only, no fee coin).
  `crates/acct/src/thor.rs`. Unsigned = SignDoc, signed = TxRaw; `decode` verifies the signature and
  refuses a TxBody memo, a fee coin, extra coins or a signer that does not match the pubkey. KAT: body,
  auth_info and signed TxRaw byte-equal to the real mainnet `swapchan` THORName register/alias txs
  (`crates/acct/tests/thorchain.rs`); `scripts/e2e.d/thorchain.sh` drives keys/build/decode, the pty sign
  (wrong code aborts), and the `--expect-memo` guard. Recipes `recipes/chain-thorchain.md`,
  `recipes/thorchain-thorname.md`, `recipes/thorchain-swap-evm.md`; `rune` sign in `docs/CHAINS.md`.
- Contract tools. `log-decode` (offline event-log decoding) and `contract-call` (host tool: `eth_call`
  with return/revert decoding, `--read` state reads, chain id from the endpoint) (9bce34a).
  `contract-trace` (host tool: `eth_call` with checked state overrides, `debug_traceCall` passthrough as
  JSON lines behind `--allow-unlisted`) (12240d6). `bytecode-inspect --metadata/--sources`: offline
  Solidity metadata/source check against the CBOR trailer (035b24b; wasm lockfile follow-up f3c23ea).
- EVM contract call and creation end to end: `tx-build --data/--create`, `tx-verify`/`tx-sign
  --call/--abi/--create-hash` (strict decode shown in the summary, unknown selectors flagged), recipe
  `recipes/evm-contract-tx.md` (f2e066a); EVM API `approve_json`, `lift_approved`, encode from a JSON
  ABI by name (45b6741); `build_evm_transfer` data/create fields (b57df0c).
- wasm exports `evmApproveCall` and `verifyTx` call checking, `buildEvmTransfer` data/create (f90a6dd);
  `verifyThorSend`, and `tx-envelope` op `verify_thor_send` (80781bd). EXPORTS.md lists every export.
- `verifyThorSend` / `verify_thor_send`: fail-closed check of a THORChain inbound send on btc, ltc, doge
  and bch: exactly [vault == amount, optional change to the change address, OP_RETURN == memo bytes],
  non-RBF, fee within a cap, every input proven and owned by the taker address(es); named failure reasons
  (80781bd, 0e4a6ba).
- LTC/DOGE/BCH THORChain memo sends: per-chain dust and OP_RETURN limits in the memo PSBT builder (ca85a68);
  BCH vault CashAddr forms (446bd29); e2e `scripts/e2e.d/memo-regtest.sh` builds, signs and sends memo
  transactions to the pinned LTC, DOGE and BCH regtest nodes and checks the outputs on chain (39d6a01, 0e4a6ba).
- `utxo-set` and `wallet-finder`: Bitcoin Core `dumptxoutset` files (Core 25-27 and 28+ layouts) into an
  in-RAM exact set of funded scripts with a bloom filter in front; wallet-finder expands free text into
  candidate keys (7f1310b, f4bc4c2). Core 0.21-24 / Litecoin 0.21.x dumps, layout detected by
  trial-decoding and refused if ambiguous (fda3853, cd93cd8).
- Chainstate reading without `dumptxoutset`: pure-Rust read-only LevelDB reader for the `C` and old
  Dogecoin-era `c` layouts with obfuscation (71e61b5), Snappy, MANIFEST live set (046f360);
  `utxo-set --chainstate DIR` and `--write-dump OUT` (2bcc4d1); refuses a locked live directory and
  wrong era/key loudly (bf64dfd); standalone `chainstate-dump` tool (5b195d9), bounded open files
  (48affb6), `--hash-serialized` (48582cc).
- `rpc`: `rawtx`/`block`/`blockinfo`/`prevtxs` shortcuts (29cc5b1); `--timeout SECS` with a longer
  default for slow methods and a distinct `timeout` status (3c8c354); default timeout 30 s
  [rpc-timeout-30s].
- `tx-decode --prevtxs FILE` (offline prevout source) reports input values and fee (ea75965, 8a4fa78);
  recipe `recipes/rpc-decode.md` with a mock bitcoind (d502921, 21fb129).
- Real-node fork tests: `scripts/e2e.d/fork-regtest.sh` builds, verifies, signs and broadcasts sweeps on
  sha256-pinned regtest nodes for ltc, doge, bch (8ffa45b), dash, dgb, grs, btg (1805950), rvn (9516a6a),
  nmc and bsv (d1f4f93) [fork-regtest-ltc ... fork-regtest-bsv].
- Packaging: `gate.sh package` builds a release-layout tarball with SHA256SUMS and checks the binary
  architecture and a BIP84 vector through the unpacked tarball; CI packages on macOS arm64 and Linux
  aarch64 (006d03b) [package-macos-arm64, package-linux-aarch64]. These arm64 tarballs are CI artifacts
  only; the release workflow publishes Linux x86_64 (see Known limitations).
- Release repositories: `scripts/release-repos.sh` builds and signs the apk/apt/rpm repositories host-side
  and publishes them to gh-pages; the release workflow's `repos` job runs it on a v* tag, and
  `workflow_dispatch` runs an unsigned `repos-dry-run` (e986852, 2b7621f, 1f35e54).
- macOS: `docs/MACOS.md` defines sealed-on-macOS; `scripts/macos-sealed-check.sh` refuses remote or stopped
  engines (c71bbbb, 8ba288c); the macos CI job is blocking (ab5e316) [e2e-macos].
- `tx-decode --chain eth`: decodes legacy (pre-155 and 155), EIP-2930, 1559, 4844 (including the blob network
  wrapper) and 7702 raw transactions through a decode-only view; the signing parser is unchanged; EVM bytes are
  also auto-detected without `--chain` (62e8201) [tx-decode-evm-mainnet]. `tx-decode --chain
  xlm|algo|atom|ton|ada|dot|sol|tron|xrp` runs that chain's existing decoder, byte-identical in stdout and exit
  code (0a83f1c) (issue #11).
- `docs/COVERAGE.md`: verb x chain matrix measured from the CLIs; docs-check rule D-coverage fails on an
  unlisted multi-tool cell, a stale listing or a stale matrix, with 4 gate-negatives (bee1d50) (issue #11).
- e2e `scripts/e2e.d/evm-devnet.sh`: contract creation, a contract call and a value transfer on a pinned
  geth `--dev` node under the default schedule and Amsterdam, gas from `eth_estimateGas`; gas below the
  estimate fails on chain (b84d79e) [evm-devnet-create-call] (issue #9).
- Measured chain capability table (`scripts/chain-caps.py`, `tests/chain_caps.rs`, docs-check) (c362169, 126d4e8).
- `tty::confirm_ack`: a typed acknowledgement distinct from the confirmation code (3a21083).
- e2e recovery against wallets written at test time by Bitcoin Core 25.2, Electrum 4.5.8, eth-account and
  python-mnemonic (d9a6056; scope documented in 0f8a581) [recovery-synthetic-thirdparty].

### Changed
- `rpc sendraw` and `tx-broadcast` show input values and fee before the confirmation code; when the fee
  cannot be proven (bare signed UTXO hex, no prevouts) they print a FEE UNKNOWN banner and require typing
  `ACK FEE-UNKNOWN` first (5a7d5aa, a75edb3) [sendraw-fee-shown]. Interactive flows that typed only the
  code now need the acknowledgement.
- `rpc`: params must be one JSON array (or object) argument; `rpc URL getblockhash 2` is now `bad_input`
  (exit 2, nothing sent) instead of sending a non-array params value nodes reject; write `'[2]'` (29cc5b1).
- `rpc --timeout` accepts a wider range (3c8c354); existing values stay valid.
- Packages: `phrase-to-key` is now shipped in deb/rpm/apk; it was in the v0.1.1 tarball only (907c318).
- `./blocktools run`/`reveal` refuse a remote docker engine (ssh/tcp context or `DOCKER_HOST`) unless
  `BLOCKTOOLS_ALLOW_REMOTE=1` (7c98c98) [wrapper-remote-refusal].
- Claims registry gates: stamped commits must have a green main CI run (K-ci), expect vs statement agreement
  (K-agree) (24688cd, 5a2ceb4, 57492bd, 751299a).

### Fixed
- `scripts/release-repos.sh` and `scripts/package-native.sh` no longer bind-mount host paths into docker: sources and
  staging go in as a tar on stdin and binaries, .rpm and .apk come back as a tar on stdout. On a Docker Desktop daemon
  (the signer runner) a WSL2 distro path mounts empty, so repos-dry-run failed with "could not find Cargo.toml in
  /src" (8a7b876).
- `scripts/e2e.d/evm-devnet.sh` waits for each killed geth before removing its datadir; the cleanup raced the node
  and turned a passing run into exit 1.
- `tx-verify`/`tx-sign` could not authorize an ERC-20 `approve` (or any non-transfer contract call) even
  with a `--policy` `allow_calls` entry for its exact `(contract, selector)`: the tools added the general
  findings an allow_calls match authorizes (`token_call_not_transfer` or `unknown_contract_call`,
  `has_warnings`, and for signing `destination_not_expected`) into their own verdict, then merged the
  policy file's findings only by ADDITION, never lifting the general ones the allowance waives -- so
  neither a token `approve` nor an opaque contract call (e.g. THORChain `depositWithExpiry`) listed in
  `allow_calls` could verify or sign. A new `policy_file::apply` merges and lifts in one place; both
  tools call it (issue #12). Regression: `scripts/e2e.d/approve-policy.sh`.
- `keystore-open` accepts eth-keyfile keystores whose IV lost leading zero bytes (previously reported
  unsupported; cause of a flaky recovery test) (3c7c460) [scrypt-bounds, recovery-synthetic-thirdparty].
- rpc tests ignore stray loopback connections (8acb94a); mock-bitcoind start wait for slower runners
  (c6c33f3); EPIPE tolerated when a tool refuses before reading stdin (8ba288c).
- Sealed image build: the Dockerfile copies `fixtures/utxo`, which the utxo dump tests read; the image
  build failed at cd93cd8 (678a8dd).
- Recipe `recipes/evm-contract-tx.md` used `--gas 100000` for a contract creation, which ran out of gas on
  Sepolia (status 0x0, gasUsed = limit; the init code was correct). It now takes `--gas` from `eth_estimateGas`
  on the user's chain: the same init code is estimated at 56132 on the default schedule and 226175 on
  Amsterdam, and on Amsterdam `--gas 100000` reproduces the Sepolia failure (b84d79e)
  [evm-devnet-create-call] (issue #9). The recipe also records the publicnode estimates for Ethereum
  mainnet and Sepolia taken by hand on 2026-10-27 (not a registered claim).
- `tx-decode --chain xmr` (and any other chain-table name that is not a UTXO chain, zec, eth or a delegated
  chain) parsed the input as a Bitcoin-family transaction; it now refuses with `unsupported_chain`, exit 2,
  before reading input (edf98c3; e2e tx-decode.sh).
- Sealed image build: the Dockerfile also copies `fixtures/leveldb` and `recipes/fixtures/evm-sol` (189e40f).
- recovery-real swap case picks a swap that fails the BIP39 checksum (62027dc).
- `fork-regtest` prints a labelled SKIP on non-Linux-x86_64 hosts instead of failing (49e6527).
- CHAINS.md no longer lists qrk as refused (2fcb79b); wasm lockfile gained sha2, fixing `wasm-check --locked` (f3c23ea).

### Security
- Fee is shown or explicitly acknowledged before any broadcast of a signed UTXO transaction
  (5a7d5aa, a75edb3) [sendraw-fee-shown].
- `rpc` deny-list: secret export/import/unlock and wallet-signing methods are refused before any request
  is sent (29cc5b1, 3c8c354) [rpc-deny-list]; response size capped and redirects refused [rpc-response-size-cap].
- Remote docker engines refused for sealed runs (7c98c98) [wrapper-remote-refusal].
- Release signing stays host-side: the signer runner's job-started hook admits only `release.yml` on a v*
  tag or a main `workflow_dispatch` (e986852).
- Boundary tests for input caps (977b94a) [redact-512, read-file-64mib, tx-input-4mib].
- secret-scan: tests derive block-hash literals instead of embedding them (cd93cd8).

### Known limitations
- The signed `repos` job has never run on a real tag; v0.1.1's repositories were signed by running the
  same scripts by hand on the host. Whether GitHub Pages redeploys after the job's push is not observed.
- The release publishes Linux x86_64 only. macOS arm64 and Linux aarch64 tarballs are built and checked
  in CI but not attached to the release, and the apk/apt/rpm repositories are x86_64 only.
- Not measured for this release candidate: the sealed run on Linux (sealed-run-linux; the Docker host used
  for measuring cannot bind-mount the input directory) and the mainnet fee figures in docs/ROADMAP.md
  (chains-fee-figures; no measuring command). docs/CLAIMS.md lists every claim with its status.
- The THORChain memo sends and `verifyThorSend` are tested against regtest nodes and fixtures only, never
  on mainnet.
- Sealed operation on macOS has never been run on a Mac; no recovery tool has been tested against a real
  lost or corrupted wallet.
- The CI runners hold the host Docker socket; the signer hook limits what the signer runner runs, not
  what a container job can reach.
