//! Policy checks shared by tx-verify and tx-sign. Every failure is a short fixed string.
use crate::Decoded;

/// Default fee caps applied by tx-sign unless the human passes a larger --max-fee.
pub const DEFAULT_MAX_FEE_SATS: u128 = 100_000; // 0.001 BTC/LTC; 1000 DOGE-sats is tiny, pass --max-fee for DOGE
pub const DEFAULT_MAX_FEE_WEI: u128 = 10_000_000_000_000_000; // 0.01 ETH-equivalent

#[derive(Default, Debug, Clone)]
pub struct Policy {
    /// Addresses that must receive funds (BTC outputs; EVM `to`, or token recipient for ERC-20).
    pub expect_to: Vec<String>,
    /// Extra BTC addresses allowed to receive change.
    pub change: Vec<String>,
    pub chain_id: Option<u64>,
    /// sats (UTXO) or wei (EVM: gas * max fee per gas)
    pub max_fee: Option<u128>,
    pub allow_warnings: bool,
    /// EVM: accept a nonzero native `value` alongside token-transfer calldata (normally a mistake: the
    /// ETH goes to the token contract, usually unrecoverable).
    pub allow_value_with_token: bool,
}

fn same(a: &str, b: &str) -> bool { if a.starts_with("0x") { a.eq_ignore_ascii_case(b) } else { a == b } }

/// Fee cap tx-sign uses when `--max-fee` is not given; tx-verify and wasm verifyTx apply it to EVM too.
pub fn default_max_fee(d: &Decoded) -> u128 { if d.evm.is_some() { DEFAULT_MAX_FEE_WEI } else { DEFAULT_MAX_FEE_SATS } }

/// The one verifier every route to a signature goes through (tx-verify, tx-sign, tx-envelope /
/// blocktools.sign/v1, C ABI, wasm verifyTx/checkTx/checkTxPolicy). `findings` empty means ok;
/// `check_these` is the plain summary with the boxed CHECK THESE block the human must read.
pub struct Verdict { pub findings: Vec<&'static str>, pub check_these: String }
pub fn verify(d: &Decoded, p: &Policy) -> Verdict { Verdict { findings: check(d, p), check_these: d.text() } }

/// Effective fee cap: the caller's explicit cap, else the default for this tx's family. Never "no cap".
pub fn effective_max_fee(d: &Decoded, p: &Policy) -> u128 { p.max_fee.unwrap_or_else(|| default_max_fee(d)) }

pub fn check(d: &Decoded, p: &Policy) -> Vec<&'static str> {
    let mut f = Vec::new();
    let cap = effective_max_fee(d, p);
    // Never overridable: the signed bytes do not commit to these amounts, so the fee shown is unproven.
    if d.unproven_inputs > 0 { f.push("legacy_input_amount_unproven") }
    if !p.allow_warnings && d.warnings.iter().any(|w| *w != "unsigned") { f.push("has_warnings") }
    if let Some(t) = &d.evm {
        let fee = t.max_fee_per_gas.saturating_mul(t.gas as u128);
        if fee > cap { f.push("fee_above_cap") }
        match (p.chain_id, t.chain_id) { (Some(a), Some(b)) if a != b => f.push("chain_id_mismatch"), (Some(_), None) => f.push("no_chain_id"), _ => {} }
        if t.chain_id.is_none() { f.push("no_replay_protection") }
        // Machine check, not the human: the caller must say which network it means (e.g. BSC = 56).
        if p.chain_id.is_none() { f.push("chain_id_not_pinned") }
        let dest = match crate::evm::token_call(&t.data) {
            Some(tc) if tc.method == "transfer" => {
                if t.value > 0 && !p.allow_value_with_token { f.push("eth_value_with_token_call") }
                Some(crate::addr(&tc.to))
            }
            Some(_) => { f.push("token_call_not_transfer"); None }
            None if !t.data.is_empty() => { f.push("unknown_contract_call"); None }
            None => t.to.map(|a| crate::addr(&a)),
        };
        if !p.expect_to.is_empty() {
            match dest { Some(d) if p.expect_to.iter().any(|e| same(e, &d)) => {}, _ => f.push("destination_not_expected") }
        }
    } else {
        match d.fee { None => f.push("fee_unknown"), Some(x) if x as u128 > cap => f.push("fee_above_cap"), _ => {} }
        if !p.expect_to.is_empty() {
            for o in &d.outputs {
                match &o.address {
                    Some(a) if p.expect_to.iter().chain(&p.change).any(|e| same(e, a)) => {}
                    _ => { f.push("unexpected_output"); break }
                }
            }
            for e in &p.expect_to { if !d.outputs.iter().any(|o| o.address.as_deref().is_some_and(|a| same(e, a))) { f.push("expected_destination_missing"); break } }
        }
    }
    f
}
