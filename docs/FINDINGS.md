# Review findings ledger

Every finding from T's reviews has a permanent id. A finding marked `fixed` must name the commit that
fixed it and a guard: a test file containing the token `finding:<id>`, which runs in scripts/gate.sh.
`scripts/findings-check.sh` (run by docs-check) parses the table below. It fails if a fixed finding has no
guard, if the guard file is missing or does not carry the token, if the commit is not an ancestor of HEAD,
or if a row has an unknown status. `open` rows are still unfixed and have no guard yet. They are listed so
they can't be forgotten, and the check prints them on every run.

| id | finding | status | fixed in | guard |
|----|---------|--------|----------|-------|
| R1-1 | Envelope/C ABI/wasm paths had no default fee cap (could sign a 9.99 ETH fee) | fixed | 4949027 | crates/blocktools/tests/fee_cap_paths.rs |
| R1-2 | seed-repair accepts an unknown --scheme silently | open | - | - |
| R1-3 | classify CLASSES list misses bip38 and blockchain_wallet; no test ties it to emitted kinds | open | - | - |
| R1-4 | sha-1 crate (deprecated name) instead of sha1 | open | - | - |
| R1-5 | println! in tool bins (10 tools); no hygiene rule against it | open | - | - |
| R1-6 | recipes.sh errors instead of skipping when python `cryptography` is missing | open | - | - |
| R1-7 | Image size in docs not tied to a revision label | open | - | - |
| R1-8 | Mac e2e tx-sign pin-tty step fails (rc=2 near tx-sign.sh:35) | open | - | - |
| R2-1 | Sealed image build broken (check-deps needs python3 in builder); README size unmeasured | fixed | 26b3373 | scripts/check-deps-regress.sh |
| R2-2 | CI red: non-ASCII emoji in man pages under groff LC_ALL=C | fixed | a22023f | scripts/gate-negatives.sh |
| R2-3 | hygiene BSD-skew rules used \s, inert on macOS git grep | fixed | 8160aeb | scripts/hygiene-check.sh |
| R2-5 | check-deps: pipe masked cargo exit 101 (stale lock) | fixed | bb1ceff | scripts/check-deps-regress.sh |
| R2-6 | release.yml can publish without required reviewers on the release environment | open | - | - |
| R2-7 | Readers (bip38-open, blockchain-read, pw-candidates, tx-envelope, chain-table) "unsupported" under sealed-run | open | - | - |
| R2-8 | Doc numbers not tied to a measuring command (claims registry) | fixed | 997c606 | scripts/gate-negatives.sh |
| R2-9 | Gates grep for words instead of testing the property | fixed | 76c9850 | scripts/gate-negatives.sh |
| R2-10 | CI and local verify-and-push ran different step lists | fixed | 94449bd | scripts/ci-gate-check.sh |
| R2-11 | No macOS CI coverage, so Mac failures surface only in manual reruns | open | - | - |
| R2-12 | CI checkout was shallow (fetch-depth 1), so findings-check misreported real commits as missing | fixed | 14700aa | scripts/gate-negatives.sh |
| D1-1 | BCH CashAddr not detected (reproduced on db291f5 by SwapChan run 2 and again here, 2026-10-25): wasm detectAddressInfo("bitcoincash:qpm2…gdx6a") and the bare "qpm2…" form both return candidates:[] (legacy 1BpEi… is detected). Repro: node -e 'console.log(require("./bindings/wasm/pkg/node/blocktools_wasm.js").detectAddressInfo("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a"))' | open | - | - |
| D1-3 | (reproduced on db291f5 by SwapChan run 2 and again here, 2026-10-25) EVM check_these prints "gas N x 0 gwei" when maxFeePerGas < 1 gwei (integer division, crates/tx/src/lib.rs:364); MAX FEE line is correct. Repro: buildEvmTransfer gasPrice 257309485, then verifyTx -> "(gas 124540 x 0 gwei)" | open | - | - |
| D1-5 | recipes/chain-solana.md and chain-tron.md said transfers are NOT BUILT, but wasm solBuildTransfer (incl. sweep_balance) and tronBuildTransfer build unsigned txs; only the CLI lacks a builder. Sweep amount logic not reviewed | open | - | - |
| D1-7 | EVM decode/verify names a contract call only by selector (Universal Router 0x3593564c) until abi-decode lands | open | - | - |
| D1-8 | Algorand, TON, Cardano chain recipes: address-validate steps untested with real addresses (SwapChan used placeholders) | open | - | - |
| D1-9 | (reproduces on db291f5) No signer for Solana or Tron, and no broadcast for any account chain (tx-broadcast is UTXO-only) | open | - | - |
| D1-10 | (reproduces on db291f5) Tron has no offline verify-with-expectations (Solana has solVerifyTx; Tron only tronDecodeTx/tronTxId) | open | - | - |
| D1-11 | tx-build --chain eth does not compare --chain-id with the chain_id in the --account file: an account fetched from a chain-1 node built a chain-8453 tx with chain 1 nonce/balance (rc=0). Repro: recipes/paths/evm-sweep.sh 8453 ... against scripts/mock-chain.py | fixed | e9e81fd | scripts/e2e.d/net.sh |
| D1-12 | tx-verify emits three failure codes that are not in the schema TX_FAILURES vocabulary: eth_value_with_token_call, chain_id_not_pinned, legacy_input_amount_unproven. Inside a sealed run, redact drops the whole refusal line, so the agent sees no failure at all (redact reports count 0). Repro: python3 scripts/e2e-only/evm-fixture.py value-and-token, pipe it into target/release/tx-verify --chain-id 1 --expect-to 0x2B5AD5c4795c026514f8317c7a215E218DcCD6cF, then pipe that output into target/release/redact | fixed | a63322d | crates/schema/src/lib.rs |
| D1-13 | wasm solBuildTransfer rejects a numeric lamports value with bad_number; a decimal string is accepted. The docs say lamports must be a string. (SwapChan also reported a memory-out-of-bounds trap; not reproduced here.) | open | - | - |
| D1-14 | Bad input does not always exit with the same code. tx-verify, tx-decode, tx-build and bip38-open exit 2 with status bad_input. keystore-open, blockchain-read and tx-broadcast (bad_psbt) exit 1 with status bad_input. acct-tx, xrp-tx and xmr-keys exit 1 with status error, or with no status field at all. tx-envelope exits 0 with status error. The old man pages claimed "3 = refused", but the tools exit 1 for a refusal; only recover.sh uses 3. Repro: the EXAMPLES in man/man1/*.1, run by scripts/gen-man.py --check | fixed | 264c577 | scripts/gen-man.py |

## Notes outside this ledger (SwapChan side or expected; not blocktools defects)

From SwapChan's chain-recipe drafts (2026-10-25, ~8:25-8:30 PM PDT); not reproduced here unless stated.

- D1-2 (SwapChan): MCP verify_tx lists Bitcoin in its schema but refuses it ("verify_tx does not decode Bitcoin yet"). Not reproduced here (we do not call the SwapChan MCP).
- D1-4 (shared doc): the stale "NOT BUILT" text was in this repo's recipes/chain-tron.md; tracked as D1-5.
- D1-6 (expected): replaying already-mined fixtures through SwapChan verify_tx gives "danger" because the chain state moved on. verify_tx is for unsigned, not-yet-sent txs.
- SwapChan #9: SwapChan's MCP verify_tx returned HTTP 502 for a Tron tx hex (evidence/r2). That is the SwapChan service, not blocktools; not reproduced here.
