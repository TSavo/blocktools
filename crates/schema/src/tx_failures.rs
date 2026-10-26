// Included by blocktools-schema (redact allowlist) and blocktools-tx (code! macro). No deps.
/// tx-verify / tx-sign policy failures (blocktools_tx::policy).
pub const TX_FAILURES: &[&str] = &["has_warnings", "fee_above_cap", "fee_unknown", "chain_id_mismatch", "no_chain_id", "no_replay_protection",
    "token_call_not_transfer", "unknown_contract_call", "destination_not_expected", "unexpected_output", "expected_destination_missing", "input_without_key",
    // D1-12: these were emitted by tx-verify but missing here, so redact dropped the refusal line.
    "legacy_input_amount_unproven", "chain_id_not_pinned", "eth_value_with_token_call",
    "fee_over_10pct_of_inputs",
    // policy-file findings (blocktools_tx::policy_file)
    "policy:no_rule_for_chain", "policy:chain_id", "policy:allow_tokens", "policy:allow_calls", "policy:allow_to", "policy:max_value", "policy:max_outputs", "policy:max_fee"];
/// Compile-time membership test used by blocktools_tx's `code!` macro: every failure code the
/// verifier can emit is checked against TX_FAILURES when the crate is built.
pub const fn is_tx_failure(s: &str) -> bool {
    let (s, mut i) = (s.as_bytes(), 0);
    while i < TX_FAILURES.len() {
        let t = TX_FAILURES[i].as_bytes();
        if t.len() == s.len() { let mut j = 0; while j < s.len() && s[j] == t[j] { j += 1 } if j == s.len() { return true } }
        i += 1;
    }
    false
}
