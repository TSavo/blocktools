# Security

> **⚠️ DANGEROUS: use at your own risk.** This code needs an independent security
> audit before use with real funds or real keys. It opens hostile wallet files and
> extracts secrets. Run it only sealed and offline (`./keyrescue run`, `--network none`).
> **Used incorrectly, these tools can destroy funds**: signing to a wrong address,
> paying a huge fee, losing keys, or sending to an address on the wrong chain. You are
> responsible for verifying every transaction before it is signed or broadcast.
> The unit tests are the main evidence of correctness; they are not a substitute for
> an audit.

## What is tested (measured 2026-10-24, box, `cargo test --release` + `make e2e`)
* 36 Rust unit tests pass, 0 fail. 17 end-to-end checks pass (`scripts/e2e-local.sh`).
* Known-answer vectors: BIP39/BIP32 "abandon…about" root; BIP44/49/84/86 BTC;
  ETH (EIP-55); LTC, DOGE, Tron (indices 0/1 and xpub parity TDTk…), XRP (incl.
  ACCOUNT_ZERO), Solana (SLIP-10 and ed25519 key 1); private key 1 in every
  encoding; Electrum standard/segwit seeds from Electrum's own test suite; base58
  edge cases; EIP-55 token addresses; Tron hex conversion and rejects.
  Non-standard goldens were cross-checked with an independent Python implementation
  (`scripts/kat.py`), not only against our own code.
* Boundary: every e2e pipeline runs through `kr-run agent` and is grepped for
  secret-shaped strings (`LEAK` regex); secret fields must appear as `[REDACTED]`.
* Fixtures are self-made, throwaway, generated at test time; no real wallet or key
  has been used. A secret scanner runs before every push.

## What is NOT tested / known limits
* No audit, no fuzzing yet, no formal review of the parsers against hostile files
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
