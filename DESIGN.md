# keyrescue: design

keyrescue is a set of small Unix command-line tools that recover keys from old
wallet files and sign transactions. The tools run inside a sealed, offline
container. It ships tools only: it is not an agent and not an MCP server.
It is a companion to [SwapChan](https://swapchan.com), which never holds keys.

## 1. Model: the tools print keys, the boundary filters them

Every tool is an ordinary Unix filter. It reads files or stdin, does one job,
and writes **JSON lines** to stdout. Tools print secrets (mnemonics, WIF,
private keys), because printing them is the job, for a human or the next tool in
the pipe. Tools do not police their own output.

The rule that **the agent never sees secrets** is enforced at one boundary:

```
host (agent)                         sealed container (--network none)
-----------                          ---------------------------------
./keyrescue run '<pipeline>'  --->   kr-run agent '<pipeline>'
                                       sh -c pipeline 2>/dev/null
                                         | kr-redact               ---> stdout to the agent
./keyrescue reveal '<pipeline>' -->  kr-run human: needs a TTY + typed one-time code,
   (T at a terminal)                   writes raw output to /dev/tty only
```

* `kr-redact` is the only process whose stdout reaches the agent. It keeps only
  allowlisted fields, each with a strict validator (§3). A line that fails any
  check is dropped completely. It ends with a summary line (kept/dropped counts).
* Tool stderr is discarded. Raw output is never written to disk, not even tmpfs.
* Leak tests target `kr-redact` and the end-to-end agent view
  (`crates/kr-schema` tests, `scripts/e2e-local.sh`), not the individual tools.

## 2. Threat model

| Threat | Mitigation |
|---|---|
| Agent (LLM) context leaks keys (logs, prompt injection, transcripts) | Agent only gets `kr-redact` output; allowlist + validators + leak scan |
| Hostile wallet files / filenames carrying instructions | Treated as data only; bounded reads; no eval/pickle/shell-outs in tools; filenames never interpreted |
| Hostile KDF params (CPU/memory DoS) | Bounded scrypt/PBKDF2 parameters; container memory/pids/CPU limits |
| Exfiltration over the network | `--network none`; no network tools in the image; no network code in tools |
| Container escape / privilege | non-root uid 10001, `--cap-drop ALL`, `no-new-privileges`, read-only rootfs, noexec tmpfs |
| Persistence of secrets on disk | Only tmpfs is writable; inputs mounted read-only; `--log-driver none` |
| Blind signing / tampered unsigned tx | `tx-verify` decodes inside the container; human confirms on the TTY (§6) |
| Password in agent context, argv or env | Passwords come only from a read-only file in `/secrets` or a `/dev/tty` prompt |
| Agent runs `reveal` | `reveal` needs a real TTY and a random code typed by the human; agent shells have no TTY |

Out of reach: a compromised Docker host (Battleaxe) or kernel, or a human who
pastes keys into chat.

## 3. Agent-facing schema (enforced by `kr-redact`)

One JSON object per line, at most 512 bytes. Allowlisted fields:

| field | validator |
|---|---|
| `tool` | enum of keyrescue tool names |
| `status` | enum: ok, checksum_ok, checksum_fail, no_candidates, too_many_candidates, bad_input, wrong_password, unsupported, error, done (**required**) |
| `kind` | enum: p2pkh, p2sh-p2wpkh, p2wpkh, p2tr, eth |
| `address` | base58 `1…`/`3…`, bech32/bech32m `bc1…`, or `0x` + 40 hex |
| `path` | `m(/N'?){0,8}` |
| `candidate`, `count`, `index`, `changed_words`, `line` | integer ≤ 1e9 |

Unknown fields are dropped. A listed field that fails its validator drops the
whole line. Then the serialized line is scanned and dropped if it contains a
64-hex run, `xprv/yprv/zprv/tprv…`, a WIF-shaped string, or 3+ consecutive
BIP39 words. Txids (64 hex) are blocked on purpose until phase 2 adds a typed
`txid` field.

## 4. Tools (one job each)

| tool | in | out (raw, may contain secrets) | phase |
|---|---|---|---|
| `seed-repair` | phrase on stdin | `{status:checksum_ok, candidate, changed_words, mnemonic}` | 1 ✅ |
| `derive` | stdin JSON lines: optional `{passphrase}`, then `{mnemonic, candidate}` | `{kind, path, address, wif / private_key}` | 1 ✅ |
| `keystore-open` | stdin: line 1 = password, rest = keystore JSON (or `--password-tty`) | `{kind:eth, address, private_key}` | 1 ✅ |
| `kr-redact` | raw lines | public lines only | 1 ✅ |
| `walletdat-read` | Bitcoin Core `wallet.dat` (BDB/SQLite, bounded own parser, no libdb) | keys, addresses | 2 |
| `electrum-open`, `multibit-open`, `armory-open` | respective formats | keys, addresses | 2 |
| `utxo-match` | addresses + UTXO JSON file (from host) | matched address/amount | 2 |
| `tx-verify` | unsigned PSBT/tx file | plain summary: inputs, outputs, fee, change | 2 |
| `tx-sign` | PSBT + key stream + confirmation | signed raw tx hex | 2 |

Composition example (in the container): `seed-repair < /in/seed.txt | derive --count 5`.

**seed-repair algorithm (phase 1):** lengths 12/15/18/21/24. Unknown words → words
within edit distance 2 or sharing the 4-letter prefix (BIP39 words are unique by
4 letters). Searches combinations, capped at 200k, and keeps the ones whose
BIP39 checksum is valid. If every word is known but the checksum fails, it tries
adjacent swaps, then each single-word substitution. Phase 2: missing word
positions and wordlists in other languages.

**derive paths:** m/44'/0'/0'/0/i, m/49'…, m/84'…, m/86'… (BIP86 taproot), and
m/44'/60'/0'/0/i (ETH, EIP-55). Phase 2: change chain, more accounts,
Electrum-seed derivation, custom paths.

## 5. Passwords and passphrases

Passwords and passphrases arrive on **stdin**, as data in the stream. The human
puts them in `$KR_SECRETS` (mounted read-only at `/secrets`, host dir chmod 700,
git-ignored), and the pipeline's shell feeds them in, e.g.
`cat /secrets/ks-password /in/ks.json | keystore-open`. The tool itself never
opens a named file. The only other source is `keystore-open --password-tty`, a
prompt to the human on `/dev/tty`. Nothing is ever read from argv or env.
Values are zeroized after use (`zeroize`).

## 5a. Pipe principles

1. **Utilities, not a server.** keyrescue is separate Unix programs, not an MCP
   server. Each does exactly one thing, keeps no hidden state, and is named for
   what it does: one reads DAT files (`dat-read`, phase 2), one opens JSON
   keystores (`keystore-open`), one repairs recovery phrases (`seed-repair`).
   Each takes its format in and gives its format out (JSON lines).
2. **stdin and stdout only.** Secrets and outputs travel only through stdin and
   stdout: never environment variables, never file names, never argv. Output is
   always on stdout. Files reach a tool only via shell redirection
   (`< /in/x`, `cat a b |`) in the pipeline script. The tool sees a stream,
   not a path. argv carries only non-secret options (`--count 5`).
3. **A half-complete pipe leaks secrets. A complete pipe emits only the intended output.**
   Complete pipe: `wallet file → master key → derived key → signed transaction`.
   The secret never leaves the pipe and only the signed tx comes out. So a
   recovery utility may output only a master key, with derivation as a second
   utility piped after it. Cutting the pipe early (stopping after `derive`) prints
   keys, which is fine for a human at a terminal and never shown to the agent.
4. **Agent workflow.** The agent writes a short script that chains the utilities,
   runs it with `./keyrescue run '<script>'`, and gets back only the final
   output. `kr-redact` still filters everything the agent sees (§3), so even a
   half-complete pipe written by mistake shows the agent only addresses, paths
   and statuses.

### Conformance audit (phase 1 code)

| Place | Status |
|---|---|
| `seed-repair` | ✅ stdin only (`--in FILE` removed) |
| `derive` | ✅ stdin only (`--phrase-file`, `--passphrase-file` removed; passphrase is a `{"passphrase":…}` line) |
| `keystore-open` | ✅ stdin only: line 1 = password, rest = keystore (`--in`, `--password-file` removed) |
| `kr-run` agent mode | ✅ no longer tees raw output to a tmpfs file; tool stderr is discarded |
| **Deviation:** `keystore-open --password-tty` | Reads the password from `/dev/tty`, a human side channel, not stdin. Kept for typing passwords that are never stored. To decide: keep, or require stdin only (human pipes `cat /dev/tty` themselves). |
| **Deviation:** `derive` emits a `wif`/`private_key` per address | That is a half-complete pipe by design today. Planned split: `seed-to-master` (mnemonic → master xprv), `derive` (xprv → child keys + addresses), `tx-sign` (keys + PSBT → signed tx). |
| **Deviation:** `kr-run`/`keyrescue` take the pipeline script via argv | The script is agent-written public text, never a secret. Alternative: feed the script on stdin. |
| **Deviation:** passwords staged as files in `/secrets` | The human stores them, and the tool still receives them via stdin. Alternative: a dedicated fd (e.g. `3< /secrets/pw`) if mixing with data on stdin proves awkward. |
| Naming | `derive` is generic. Planned names: `dat-read`, `keystore-open`, `seed-repair`, `seed-to-master`, `derive`, `tx-verify`, `tx-sign`. |

## 5b. Minimal dependencies

Each utility depends on as few crates as possible: ideally one cryptography
library and little else. Non-crypto helpers (hex encoding, output JSON lines,
address/path validators, leak scanner) are plain std code. Crypto primitives are
never hand-rolled. `scripts/check-deps.sh` (also run in the Docker build) fails
if any crate's dependency tree gains a crate not listed in `deps/<crate>.allow`.

Measured with `cargo tree -e normal` (unique crates excluding the crate itself):

| crate | before: direct / total | after: direct / total | direct deps now |
|---|---|---|---|
| seed-repair | 12 / 52 | 1 / 8 | bip39 |
| derive | 12 / 52 | 5 / 28 | bip39, bitcoin, sha3, zeroize, serde_json |
| keystore-open | 12 / 52 | 9 / 27 | secp256k1, sha3, scrypt, pbkdf2, sha2, aes, ctr, zeroize, serde_json |
| kr-schema | 4 / 21 | 2 / 12 | bip39 (wordlist), serde_json |
| kr-redact | 2 / 22 | 2 / 13 | kr-schema, serde_json |

Removed: `regex`, `hex`, `serde` (derive), and every unused crate the tools had
inherited. Justification for what stays:

* **bip39**: BIP39 wordlist, checksum, PBKDF2-HMAC-SHA512 seed (rust-bitcoin project).
* **bitcoin** (derive only): BIP32, address encodings incl. bech32m/taproot tweak, WIF; brings secp256k1 (libsecp256k1).
* **secp256k1** (keystore-open): public key from private key for the ETH address, without all of `bitcoin`.
* **sha3**: Keccak-256 for ETH addresses and keystore MAC (not in the rust-bitcoin stack).
* **scrypt, pbkdf2, sha2, aes, ctr** (keystore-open): the Web3 v3 keystore KDFs and cipher, all RustCrypto.
* **serde_json**: parsing *hostile* JSON input (keystore files, pipe input in derive/kr-redact) must be robust. A hand-rolled parser on untrusted input is a bigger risk than one well-fuzzed crate. Output JSON is hand-written.
* **zeroize**: wiping secrets from memory.

Deferred (to decide):
* **One crypto family.** Today there are two: rust-bitcoin (bip39/bitcoin/secp256k1)
  and RustCrypto (sha3, scrypt, pbkdf2, sha2, aes, ctr). One option is RustCrypto
  only (`k256` + `bip32` crates + own address encoding), which drops libsecp256k1's
  C code but replaces a very widely audited library. The other is rust-bitcoin
  only, but it has no Keccak, scrypt or AES, so keystore-open still needs RustCrypto.
* **Dropping serde_json** with a minimal bounded JSON-lines reader shared by the
  tools: possible, but deferred because it means a hand-written parser of hostile input.
* `cargo-deny` (license/advisory checks) is not installed. The allowlist script
  covers growth only.

## 6. Signing flow (phase 2, designed only)

1. Host: the agent uses SwapChan `find_money` to locate funds for the public
   addresses and `signing_guide` to build an **unsigned** PSBT. The agent writes
   the PSBT and UTXO JSON into `in/`.
2. Container: `tx-verify` decodes the PSBT itself, checks that the inputs match the
   UTXO file, and sums inputs, outputs, fee and change. Change must go back to an
   address we derived. It returns the public summary to the agent.
3. `keyrescue sign` (human mode, TTY required) prints a plain-language summary on
   the TTY ("Send 0.0123 BTC to bc1q…, fee 0.00002 BTC (5 sat/vB), change 0 → …"),
   plus a random code. The human types the code. The agent never sees or relays it.
4. `tx-sign` signs only the exact PSBT hash that was confirmed and writes the
   signed raw hex to stdout. The redactor passes it through as a typed
   `signed_tx` field (raw tx only, shape-checked).
5. Host: the agent runs SwapChan `verify_tx` on the hex, then `broadcast_tx`.

## 7. SwapChan integration (host side only)

The container never talks to SwapChan. Public data (addresses, unsigned
txs, signed hex) moves between the agent's SwapChan MCP tools and the container
as files in `in/` and lines from `kr-redact`.

## 8. Build and run

* `Dockerfile`: two stages pinned by digest (rust:1.85-alpine → alpine:3.20),
  static musl binaries, tests run during build, non-root user, network tools removed.
* `./keyrescue build | run '<pipeline>' | reveal '<pipeline>'`, plus `make recover`
  and `make reveal` for one-command use.

### Verified status (2026-10-24, Battleaxe, Docker 29.8.2, linux/amd64)

Measured: the image builds (dependency allowlist check + `cargo test` in the build stage), and the
runtime image is 18.2 MB. Under the full sealing flags:
* `seed-repair | derive` on the public "abandon … about" vector with typos, through `kr-run agent`:
  7 lines, only addresses, paths and statuses, with the expected BIP44/49/84/86/ETH addresses.
* `keystore-open` on the Web3 spec vector: only `0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b`.
* Leak grep (wif, private_key, mnemonic, abandon, 64-hex) on agent output: 0 matches. The raw tool output
  without the boundary does contain keys, as intended.
* Inside: uid 10001, only `lo` interface, an HTTP connect to 1.1.1.1 fails, DNS fails, `touch /usr/x`
  gives "Read-only file system", executing a binary copied to the tmpfs fails, CapEff=0, NoNewPrivs=1.
* `kr-run human` without a TTY refuses (exit 3).

Not yet exercised: `./keyrescue` itself (its `-v`-style bind mounts resolve on the Docker *host*, so
with a remote context like Battleaxe, `in/` and `secrets/` must exist there; the test above fed data on stdin),
and `reveal` with a real TTY. Note: busybox still contains a `wget` applet (symlinks removed only);
harmless with `--network none`, but a distroless/scratch runtime would drop it.

## 9. Out of scope

Brute-forcing unknown passwords at scale (GPU cracking), any network access in
the container, holding funds, custody, broadcasting from the container, hardware
wallets, and any key escrow or backup service.

## 10. Roadmap

* **Phase 1 (this commit):** seed-repair, derive (BIP44/49/84/86, ETH), keystore-open, kr-redact, sealed wrapper.
* **Phase 2:** wallet.dat reader, Electrum, MultiBit, Armory; utxo-match; tx-verify, tx-sign + TTY confirmation; typed `txid`/`signed_tx` fields.
* **Phase 3:** password-candidate lists from a human-provided file (bounded), missing-word repair, more chains.
