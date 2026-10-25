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
* Terminal confirmation is NOT proof of a human: any process that can spawn a pty can type the
  code (see "Terminal confirmation: residual risk" below). Terminal pinning narrows it; it doesn't close it.
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
input. **BCH/BSV/BTG are not exempt:** their fork-id sighash commits to the amount (a lying amount would only
give an invalid signature), but blocktools does not sign fork-id inputs itself and every check keys on the script
type, so a P2PKH input on these chains needs `prev_tx` exactly like BTC P2PKH (test `forkid_needs_prev_tx`;
same rule for tx-build, `buildUnsignedSweep` in wasm, tx-decode/tx-verify and tx-sign). Only Zcash, whose
transactions are not PSBTs and carry amounts in the `zec_prevouts` envelope committed by ZIP-243/244, is exempt.

## Terminal confirmation: residual risk (security review 2026-10-25)

Earlier docs said "agent shells have no TTY". That is false: any process that can fork a pseudo-terminal
(Python `pty.fork`, `script`, `expect`, tmux) gets a controlling terminal, reads the code from it and
types it back. scripts/e2e-only/tty-drive.py does exactly that, and e2e uses it to drive `reveal`,
`sealed-run human` and `tx-sign`. The typed code proves that *something* answered on a terminal, not
that a human read the summary.

Partial mitigation: **terminal pinning.** The human runs `sealed-run pin-tty` once in their own terminal.
It records that terminal's session id and controlling-tty device in `~/.config/blocktools/tty-pin`
(from the password database, not `$HOME`; mode 0600). `$BLOCKTOOLS_TTY_PIN` can add a second pin but
can't remove one. While a pin exists, every confirmation (`tx-sign`, `tx-broadcast`, `acct-tx`, `xrp-tx`,
`xmr-wallet`, `sealed-run human`) refuses from any other session with `tty_session_not_pinned`. An unreadable pin
fails closed. e2e checks that a pin made in one pty refuses a code from a freshly spawned pty.

What it does NOT stop:
* an agent running as the same Unix user can delete or rewrite the pin (or pin its own pty first);
* injection into the pinned terminal itself (TIOCSTI where the kernel allows it, ptrace,
  `tmux send-keys`, terminal-emulator automation);
* platforms without /proc (macOS): there the session can't be read, so any pin fails closed and
  confirmation is refused while a pin exists.

It only helps when the agent runs as a different user (or in a container) that can't write the pin.
The real control is still the human reading the summary on a terminal the agent does not drive.

## Keystore KDF bounds (security review 2026-10-25)

`keystore-open` used per-knob caps (p ≤ 4) that rejected the Web3 spec's own scrypt vector (p=8). It now
bounds what matters: memory 128·N·r ≤ 256 MiB and work N·r·p ≤ 2^24 (8x geth standard), checked with
overflow-safe arithmetic before any allocation. The RustCrypto `scrypt` crate also refuses N ≥ 2^(16r)
(RFC 7914), which the spec vector (N=2^18, r=1) violates; those parameters use an in-tree RFC 7914
implementation that is tested against the crate and RFC 7914 vector 2. Tests: spec vector (p=8),
geth --lightkdf (N=4096, r=8, p=6), bounds, hostile 8 GiB request refused.
