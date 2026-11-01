# Strict ABI decoding: what blocktools rejects

`abi-decode`, `contract-call`, `tx-verify` and the wasm `evmAbiDecode*` exports all share one decoder
(`crates/evm/src/abi.rs`). It accepts only the **canonical** encoding, the one solc and the Solidity ABI spec
encoder produce. Anything else is refused with a typed error code (exit 2 / `bad_input` from the CLIs).

"Strict" means all of the following:

| Rule | Error code |
|---|---|
| Every offset and length fits in the data; arithmetic is checked (no wrap near 2^64 or 2^256) | `offset_or_length_out_of_bounds`, `offset_or_length_too_large`, `data_too_short`, `bytes_out_of_bounds`, `array_length_out_of_bounds` |
| Each dynamic tail starts exactly where the previous one ended, in head order: no pointer into the head, no gap, no overlap, no aliasing, no reordering, no unaligned offset (also inside nested tuples and arrays) | `non_canonical_offset` |
| The data ends exactly after the last tail (also checked per nested level) | `trailing_data` |
| `address` padding (the high bytes above the address) is zero | `dirty_address` |
| `uintN` (N<256) has no bits above N; `intN` is properly sign-extended | `dirty_uintN`, `dirty_intN` |
| `bytesN` padding is zero; `bytes`/`string` tails are zero-padded to a whole word | `dirty_bytesN`, `dirty_bytes_padding`, `bytes_padding_missing` |
| `bool` is exactly 0 or 1 | `dirty_bool` |
| `string` is valid UTF-8 | `string_not_utf8` |
| Type nesting depth is bounded, checked before decoding | `too_deep` |
| Total decoded values are bounded, checked before allocating (a huge length of zero-size elements cannot allocate) | `too_many_values` |

Every row has named cases in [`crates/evm/tests/abi_strict.rs`](../crates/evm/tests/abi_strict.rs)
(each case must be rejected with its exact code and must not panic), alongside canonical spec vectors that must
still decode. The aliasing DoS case is in [`crates/evm/tests/kat.rs`](../crates/evm/tests/kat.rs).

## Opt-in: accept trailing bytes (`--allow-trailing`)

Real inputs sometimes carry bytes after the encoded values: an ERC-2771 sender or a referral tag appended to
calldata, an extra word, or an `eth_call` result longer than the outputs you declared (for example
`(uint112,uint112)` over `getReserves()`'s 3 words). The default stays strict and refuses them with `trailing_data`.

`abi-decode --allow-trailing` (wasm: `evmAbiDecode` request field `"allow_trailing": true`) lifts only the
top-level end check. The decoder reads the values as usual, and the result gains `trailing_hex`: exactly the bytes
after the last consumed byte, as `0x` hex. Every other rule in the table still applies, including the
nested-level canonical-tail checks. Presence rule: when the option is on, `trailing_hex` is always present (`"0x"`
when nothing trails); when it is off, the key is absent. It applies to calldata, `--types`, `--output` and log data.
In wasm the field must be a JSON boolean; any other value throws `allow_trailing_must_be_bool`.

It is never the default, and no environment variable or config file can turn it on (deny by default,
[POLICY.md](POLICY.md)). `tx-verify` does not accept trailing calldata: see `unknown_contract_call` in
[REFUSALS.md](REFUSALS.md). The suffix cases are tested in `crates/evm/tests/abi_strict.rs`
(`allow_trailing_*`), `bindings/wasm/test.mjs` and [recipes/evm-decode-calldata.md](../recipes/evm-decode-calldata.md).

## How this compares with other decoders

[`scripts/abi-fuzz/`](../scripts/abi-fuzz/) is a differential fuzz with a fixed seed, run by
[`.github/workflows/abi-fuzz.yml`](../.github/workflows/abi-fuzz.yml). It encodes random values with
`abi-encode`, checks the bytes against ethers, and decodes with `abi-decode`, ethers, viem and Foundry `cast`
(pinned versions in the workflow), which must all return the same values. It then mutates valid encodings, and all
four must accept or reject together. The only exceptions are listed, with reasons, in
[`scripts/abi-fuzz/allow.json`](../scripts/abi-fuzz/allow.json). In every listed case another decoder is
**more lenient** than blocktools; for example, they accept trailing bytes, non-canonical offsets or dirty padding.
A case where blocktools accepts something another decoder rejects is not allow-listed and fails the job.

Being lenient is not a bug in those libraries. A strict decoder matters here because blocktools shows people what
they are about to sign: two different byte strings must not decode to the same displayed call.
