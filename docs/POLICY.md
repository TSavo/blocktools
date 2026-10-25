# Offline policy file

`tx-verify --policy FILE`, `tx-sign --policy FILE` and wasm `checkTxPolicy(tx, chain, json)` check a
transaction against declarative rules **before** signing. tx-sign checks again on the signed bytes.
It works offline and refuses anything the file does not allow. The rule used is the one named by
`--chain` (or the detected chain). `tx-verify` reports the file's sha256, so you can tell which
policy made each decision.

```json
{"version": 1, "chains": {
  "btc": {"allow_to": ["bc1q..."], "change": ["bc1q..."], "max_value": 5000000, "max_fee": 20000, "max_outputs": 2},
  "bsc": {"chain_id": 56, "allow_to": ["0x..."], "max_value": "1000000000000000000",
          "allow_tokens": ["0x...token"], "allow_calls": [{"to": "0x...", "selector": "0x095ea7b3"}]}
}}
```

| key | meaning | refusal |
|---|---|---|
| (chain has no entry) | deny | `policy:no_rule_for_chain` |
| `chain_id` | EVM: required, must equal the tx chain id | `policy:chain_id` |
| `allow_to` | every recipient: UTXO outputs that are not `change`; EVM `to`, or the ERC-20 recipient | `policy:allow_to` |
| `change` | UTXO outputs that are allowed and not counted in `max_value` | — |
| `max_value` | UTXO: sum of non-change outputs (sats). EVM: native wei, or token base units | `policy:max_value` |
| `max_fee` | sats, or wei (gas × max fee per gas). Defaults to tx-sign's default cap | `policy:max_fee` |
| `max_outputs` | UTXO output count | `policy:max_outputs` |
| `allow_tokens` | ERC-20 contracts allowed for `transfer()` | `policy:allow_tokens` |
| `allow_calls` | any other contract call needs a matching (`to`, 4-byte `selector`) pair. A listed `approve` also accepts its `token_approve` warning | `policy:allow_calls` |

Numbers can be JSON integers or decimal strings (needed above 2^53). Unknown keys are errors
(`policy_unknown_key`), so a typo cannot silently drop a rule. The base checks always apply and
cannot be turned off by the file: `legacy_input_amount_unproven`, `has_warnings`,
`no_replay_protection`, `eth_value_with_token_call` and `fee_unknown`. Flags given with the file
(`--expect-to`, `--chain-id`, ...) are checked as well. The file can only add refusals.

The design follows the public descriptions of hosted policy engines (allowlists, value caps,
chain pins, deny by default), but it runs locally with no server. See docs/ROADMAP-PARITY.md.
