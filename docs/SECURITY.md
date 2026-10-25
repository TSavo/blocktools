# Security

> **⚠️ DANGEROUS: use at your own risk.** Code that handles keys and signs transactions
> should always be read and audited by you before you trust it with real funds.
> **Used incorrectly, it can destroy your money**: signing to a wrong address, paying a
> huge fee, losing keys, or sending on the wrong chain. You are responsible for verifying
> every transaction. It opens hostile wallet files and extracts secrets, so run it only
> sealed and offline (`./blocktools run`, `--network none`). The unit tests are evidence,
> not a substitute for your own review. See [docs/SECURITY.md](SECURITY.md).

## What is tested (measured 2026-10-24, box, `cargo test --release` + `make e2e`)
* 36 Rust unit tests pass, 0 fail. 17 end-to-end checks pass (`scripts/e2e-local.sh`).
* Known-answer vectors: BIP39/BIP32 "abandon…about" root; BIP44/49/84/86 BTC;
  ETH (EIP-55); LTC, DOGE, Tron (indices 0/1 and xpub parity TDTk…), XRP (incl.
  ACCOUNT_ZERO), Solana (SLIP-10 and ed25519 key 1); private key 1 in every
  encoding; Electrum standard/segwit seeds from Electrum's own test suite; base58
  edge cases; EIP-55 token addresses; Tron hex conversion and rejects.
  Non-standard goldens were cross-checked with an independent Python implementation
  (`scripts/kat.py`), not only against our own code.
* Boundary: every e2e pipeline runs through `sealed-run agent` and is grepped for
  secret-shaped strings (`LEAK` regex); secret fields must appear as `[REDACTED]`.
* Fixtures are self-made, throwaway, generated at test time; no real wallet or key
  has been used. A secret scanner runs before every push.

## What is NOT tested / known limits
* Not externally reviewed; no fuzzing yet, no formal review of the parsers against hostile files
  beyond size bounds and unit tests.
* Docker image verification on real hardware is done per release step only.
* Terminal confirmation reads /dev/tty; an attacker who controls the terminal
  (or a TTY emulator / agent with terminal access) can type the code. That residual
  risk is inherent: a human must read the summary themselves.
* Signing / broadcasting tools are tested only against fixtures and a mock server.
* Old git history (commit 360a78e) contains throwaway test wallet files (public
  phrases, no value); history is deliberately not rewritten.

## Reporting issues
Report vulnerabilities privately to the maintainer via a GitHub security advisory
on the repository (Security → Report a vulnerability), not in a public issue. Do not
include real keys, seeds or wallet files in any report.

## Legacy-input amount proof

**Legacy-input amount proof (security review 2026-10-25).** A legacy (pre-segwit) sighash does not commit to the
amount being spent, so a host that lies about an input's value can make a signer pay a hidden fee (the classic
P2PKH fee attack). Rule, applied to every legacy-sighash family (BTC/LTC/DOGE/BLK/... P2PKH, GRS, PoS-nTime):
an input whose script is neither a witness program nor P2SH(-P2WPKH) must carry its full previous transaction.
`utxo-fetch` adds `prev_tx` (raw hex) for such inputs; `tx-build` refuses without it (`legacy_input_needs_prev_tx`)
or when its txid (chain digest: GRS single SHA-256) or output disagrees with the claimed amount/script; the PSBT gets
`non_witness_utxo`, PoS envelopes get `pos_prevouts[i].prev_tx`. `tx-decode` reports `unproven_inputs`; `tx-verify`
fails with `legacy_input_amount_unproven` (not waivable by `--allow-warnings`); `tx-sign` refuses to sign such an
input. Zcash (ZIP-243/244) and forkid chains (BCH/BSV/BTG) commit to amounts in the sighash, so a lying amount only
produces an invalid signature; the PSBT check still applies to them.
