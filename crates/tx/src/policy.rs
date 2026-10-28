//! Policy checks shared by tx-verify and tx-sign. Every failure is a short fixed string.
use crate::Decoded;

/// Default fee caps applied by tx-sign unless the human passes a larger --max-fee.
/// UTXO floor: the default cap is never below this (0.001 BTC). Per-chain cap: see `default_fee_cap`.
pub const DEFAULT_MAX_FEE_SATS: u128 = 100_000;
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
/// UTXO outputs: exact match, or on bch the same output script (CashAddr and legacy name one script).
fn same_out(chain: &str, e: &str, a: &str) -> bool {
    if e == a { return true }
    if chain != "bch" { return false }
    let Some(c) = blocktools_core::chains::chain(chain) else { return false };
    matches!((blocktools_core::chains::address_to_script(c, e), blocktools_core::chains::address_to_script(c, a)), (Some(x), Some(y)) if x == y)
}

/// The fee cap a verdict used, and where it came from ("explicit" = the human's max_fee).
#[derive(Debug, Clone, PartialEq)]
pub struct FeeCap { pub chain: String, pub cap: u128, pub source: &'static str }

/// Default cap when no max_fee is given. EVM: 0.01 ETH-equivalent. UTXO: per chain, from the one
/// fee table (`chains::fee_warn(chain)`, CHAINS.md "Fee-warning limits"): the chain's rate limit
/// (20 x measured median, base units per vbyte) x the tx's vsize, never below DEFAULT_MAX_FEE_SATS.
/// BTC (rate 500): a ~200 vB tx is capped at 100,000 sats; DOGE (1,200,000/B) at ~0.002 DOGE x vB.
pub fn default_fee_cap(d: &Decoded) -> FeeCap {
    if d.evm.is_some() { return FeeCap { chain: d.chain.clone(), cap: DEFAULT_MAX_FEE_WEI, source: "default_evm" } }
    let fw = blocktools_core::chains::fee_warn(&d.chain);
    let by_rate = (fw.rate as u128).saturating_mul(d.vsize.unwrap_or(0) as u128);
    if by_rate > DEFAULT_MAX_FEE_SATS { FeeCap { chain: d.chain.clone(), cap: by_rate, source: "chain_rate_x_vsize" } }
    else { FeeCap { chain: d.chain.clone(), cap: DEFAULT_MAX_FEE_SATS, source: "floor" } }
}
/// Fee cap tx-sign uses when `--max-fee` is not given; tx-verify and wasm verifyTx apply it to EVM too.
pub fn default_max_fee(d: &Decoded) -> u128 { default_fee_cap(d).cap }
/// The cap `check` applies: the caller's explicit cap, else the per-chain default. Never "no cap".
pub fn fee_cap(d: &Decoded, p: &Policy) -> FeeCap {
    match p.max_fee { Some(c) => FeeCap { chain: d.chain.clone(), cap: c, source: "explicit" }, None => default_fee_cap(d) }
}

/// The one verifier every route to a signature goes through (tx-verify, tx-sign, tx-envelope /
/// blocktools.sign/v1, C ABI, wasm verifyTx/checkTx/checkTxPolicy). `findings` empty means ok;
/// `check_these` is the plain summary with the boxed CHECK THESE block the human must read.
pub struct Verdict { pub findings: Vec<&'static str>, pub check_these: String, pub fee_cap: FeeCap }
pub fn verify(d: &Decoded, p: &Policy) -> Verdict { Verdict { findings: check(d, p), check_these: d.text(), fee_cap: fee_cap(d, p) } }

/// Effective fee cap: the caller's explicit cap, else the default for this tx's family. Never "no cap".
pub fn effective_max_fee(d: &Decoded, p: &Policy) -> u128 { fee_cap(d, p).cap }

impl FeeCap { pub fn json(&self) -> serde_json::Value { serde_json::json!({"chain": self.chain, "cap": self.cap.to_string(), "source": self.source}) } }

/// Share of the inputs a fee may take before `check` refuses it (no explicit max_fee): 1/10.
pub const MAX_FEE_SHARE_OF_INPUTS_DIV: u128 = 10;
/// Inputs total = the inputs' amounts when all are known, else fee + outputs (same thing for a
/// well-formed tx). True when fee x 10 > that total.
fn fee_over_input_share(d: &Decoded, fee: u64) -> bool {
    let ins: Option<u128> = d.inputs.iter().map(|i| i.amount.map(u128::from)).sum();
    let total = ins.filter(|_| !d.inputs.is_empty()).unwrap_or_else(|| fee as u128 + d.outputs.iter().filter_map(|o| o.amount).map(u128::from).sum::<u128>());
    (fee as u128).saturating_mul(MAX_FEE_SHARE_OF_INPUTS_DIV) > total
}

pub fn check(d: &Decoded, p: &Policy) -> Vec<&'static str> {
    let mut f = Vec::new();
    let cap = effective_max_fee(d, p);
    // A THORChain-style inbound carries exactly one zero-value OP_RETURN memo alongside the real
    // destination(s). Accept that single memo as a non-destination output: it is not an
    // `unexpected_output`, and its `op_return_output` warning does not trip `has_warnings`. Two
    // OP_RETURNs, or a non-zero-value OP_RETURN, are NOT a memo and stay refused (unexpected_output).
    let op_returns = d.outputs.iter().filter(|o| o.kind == "op_return").count();
    let memo_ok = op_returns == 1 && d.outputs.iter().filter(|o| o.kind == "op_return").all(|o| o.amount.unwrap_or(0) == 0);
    // Never overridable: the signed bytes do not commit to these amounts, so the fee shown is unproven.
    if d.unproven_inputs > 0 { f.push(crate::code!("legacy_input_amount_unproven")) }
    if !p.allow_warnings && d.warnings.iter().any(|w| *w != "unsigned" && !(memo_ok && *w == "op_return_output")) { f.push(crate::code!("has_warnings")) }
    if let Some(t) = &d.evm {
        let fee = t.max_fee_per_gas.saturating_mul(t.gas as u128);
        if fee > cap { f.push(crate::code!("fee_above_cap")) }
        match (p.chain_id, t.chain_id) { (Some(a), Some(b)) if a != b => f.push(crate::code!("chain_id_mismatch")), (Some(_), None) => f.push(crate::code!("no_chain_id")), _ => {} }
        if t.chain_id.is_none() { f.push(crate::code!("no_replay_protection")) }
        // Machine check, not the human: the caller must say which network it means (e.g. BSC = 56).
        if p.chain_id.is_none() { f.push(crate::code!("chain_id_not_pinned")) }
        let dest = match crate::evm::token_call(&t.data) {
            Some(tc) if tc.method == "transfer" => {
                if t.value > 0 && !p.allow_value_with_token { f.push(crate::code!("eth_value_with_token_call")) }
                Some(crate::addr(&tc.to))
            }
            Some(_) => { f.push(crate::code!("token_call_not_transfer")); None }
            None if !t.data.is_empty() => { f.push(crate::code!("unknown_contract_call")); None }
            None => t.to.map(|a| crate::addr(&a)),
        };
        if !p.expect_to.is_empty() {
            match dest { Some(d) if p.expect_to.iter().any(|e| same(e, &d)) => {}, _ => f.push(crate::code!("destination_not_expected")) }
        }
    } else {
        match d.fee { None => f.push(crate::code!("fee_unknown")), Some(x) if x as u128 > cap => f.push(crate::code!("fee_above_cap")), _ => {} }
        // A fee over 10% of what the inputs hold is almost always a mistake (wrong change, unit slip),
        // even under the absolute cap. Refused unless the human gave an explicit max_fee.
        if p.max_fee.is_none() { if let Some(x) = d.fee { if fee_over_input_share(d, x) { f.push(crate::code!("fee_over_10pct_of_inputs")) } } }
        if !p.expect_to.is_empty() {
            for o in &d.outputs {
                // The single accepted zero-value OP_RETURN memo is not a destination; skip it.
                if memo_ok && o.kind == "op_return" { continue }
                match &o.address {
                    Some(a) if p.expect_to.iter().chain(&p.change).any(|e| same_out(&d.chain, e, a)) => {}
                    _ => { f.push(crate::code!("unexpected_output")); break }
                }
            }
            for e in &p.expect_to { if !d.outputs.iter().any(|o| o.address.as_deref().is_some_and(|a| same_out(&d.chain, e, a))) { f.push(crate::code!("expected_destination_missing")); break } }
        }
    }
    f
}
