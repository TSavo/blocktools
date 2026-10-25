//! Offline policy file: declarative, deny-by-default rules checked before signing (tx-verify
//! `--policy FILE`, tx-sign `--policy FILE`, wasm `checkTxPolicy`). Public data only.
//!
//! {"version":1,"chains":{"<chain>":{
//!    "chain_id":56,                      EVM: required; the tx must carry it
//!    "allow_to":["ADDR",...],            every recipient (UTXO outputs; EVM to / token recipient)
//!    "change":["ADDR",...],              UTXO: extra outputs allowed, not counted in max_value
//!    "max_value":"N",                    UTXO: sum of non-change outputs (sats); EVM: native wei or token units
//!    "max_fee":"N",                      sats, or wei (gas x max fee per gas)
//!    "max_outputs":N,                    UTXO
//!    "allow_tokens":["0x.."],            EVM: ERC-20 contracts allowed for transfer()
//!    "allow_calls":[{"to":"0x..","selector":"0x12345678"}]  EVM: other contract calls allowed
//! }}}
//! A chain with no entry is refused. Every refusal is `policy:<rule>`; the base checks of
//! `policy::check` (unproven amounts, warnings, replay protection, value-with-token) still apply.
use crate::{policy, Decoded};
use bitcoin::hashes::{sha256, Hash};
use serde_json::Value;

const KEYS: [&str; 8] = ["chain_id", "allow_to", "change", "max_value", "max_fee", "max_outputs", "allow_tokens", "allow_calls"];

#[derive(Debug, Clone, Default)]
pub struct Rule {
    pub chain_id: Option<u64>, pub allow_to: Vec<String>, pub change: Vec<String>, pub max_value: Option<u128>,
    pub max_fee: Option<u128>, pub max_outputs: Option<usize>, pub allow_tokens: Vec<String>, pub allow_calls: Vec<(String, [u8; 4])>,
}
#[derive(Debug, Clone)]
pub struct PolicyFile { pub rules: Vec<(String, Rule)>, pub sha256: String }

fn big(v: &Value) -> Result<u128, &'static str> {
    match v {
        Value::Number(n) => n.as_u64().map(u128::from).ok_or("policy_bad_number"),
        Value::String(s) if !s.is_empty() && s.len() <= 39 && s.bytes().all(|b| b.is_ascii_digit()) => s.parse().map_err(|_| "policy_bad_number"),
        _ => Err("policy_bad_number"),
    }
}
fn strs(v: Option<&Value>) -> Result<Vec<String>, &'static str> {
    match v { None => Ok(vec![]), Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(str::to_string).ok_or("policy_bad_list")).collect(), _ => Err("policy_bad_list") }
}

pub fn parse(text: &str) -> Result<PolicyFile, &'static str> {
    let v: Value = serde_json::from_str(text).map_err(|_| "policy_bad_json")?;
    if v.get("version").and_then(Value::as_u64) != Some(1) { return Err("policy_bad_version") }
    if v.as_object().is_some_and(|o| o.keys().any(|k| k != "version" && k != "chains")) { return Err("policy_unknown_key") }
    let mut rules = vec![];
    for (chain, r) in v.get("chains").and_then(Value::as_object).ok_or("policy_missing_chains")? {
        let o = r.as_object().ok_or("policy_bad_rule")?;
        if o.keys().any(|k| !KEYS.contains(&k.as_str())) { return Err("policy_unknown_key") }
        let mut calls = vec![];
        if let Some(c) = o.get("allow_calls") {
            for e in c.as_array().ok_or("policy_bad_list")? {
                let to = e.get("to").and_then(Value::as_str).ok_or("policy_bad_call")?.to_string();
                let sel = e.get("selector").and_then(Value::as_str).ok_or("policy_bad_call")?;
                let b = blocktools_core::hex_dec(sel.trim_start_matches("0x")).ok_or("policy_bad_call")?;
                calls.push((to, <[u8; 4]>::try_from(b.as_slice()).map_err(|_| "policy_bad_call")?));
            }
        }
        rules.push((chain.clone(), Rule {
            chain_id: o.get("chain_id").map(big).transpose()?.map(|x| x as u64),
            allow_to: strs(o.get("allow_to"))?, change: strs(o.get("change"))?,
            max_value: o.get("max_value").map(big).transpose()?, max_fee: o.get("max_fee").map(big).transpose()?,
            max_outputs: o.get("max_outputs").map(big).transpose()?.map(|x| x as usize),
            allow_tokens: strs(o.get("allow_tokens"))?, allow_calls: calls,
        }));
    }
    Ok(PolicyFile { rules, sha256: blocktools_core::hex_enc(sha256::Hash::hash(text.as_bytes()).to_byte_array()) })
}

fn same(a: &str, b: &str) -> bool { if a.starts_with("0x") { a.eq_ignore_ascii_case(b) } else { a == b } }
fn u256_small(b: &[u8; 32]) -> Option<u128> { if b[..16].iter().any(|&x| x != 0) { None } else { Some(u128::from_be_bytes(b[16..].try_into().unwrap())) } }

/// Findings for `d` under the file's rule for `chain` (empty = allowed).
pub fn check(d: &Decoded, chain: &str, pf: &PolicyFile) -> Vec<String> {
    let Some((_, r)) = pf.rules.iter().find(|(c, _)| c == chain) else { return vec!["policy:no_rule_for_chain".into()] };
    let base = policy::Policy { chain_id: r.chain_id, max_fee: r.max_fee.or(Some(policy::default_max_fee(d))), ..Default::default() };
    let mut f: Vec<String> = Vec::new();
    let mut allowed_call = false;
    if let Some(t) = &d.evm {
        if r.chain_id.is_none() { f.push("policy:chain_id".into()) }
        let tc = crate::evm::token_call(&t.data);
        let to = t.to.map(|a| crate::addr(&a));
        let (dest, amount) = match &tc {
            Some(c) if c.method == "transfer" => {
                if !to.as_deref().is_some_and(|a| r.allow_tokens.iter().any(|x| same(x, a))) { f.push("policy:allow_tokens".into()) }
                (Some(crate::addr(&c.to)), u256_small(&c.amount))
            }
            _ if !t.data.is_empty() => {
                let sel: Option<[u8; 4]> = t.data.get(..4).and_then(|s| s.try_into().ok());
                allowed_call = to.as_deref().zip(sel).is_some_and(|(a, s)| r.allow_calls.iter().any(|(x, xs)| same(x, a) && *xs == s));
                if !allowed_call { f.push("policy:allow_calls".into()) }
                (to.clone(), Some(t.value))
            }
            _ => (to.clone(), Some(t.value)),
        };
        if !allowed_call && !dest.as_deref().is_some_and(|a| r.allow_to.iter().any(|x| same(x, a))) { f.push("policy:allow_to".into()) }
        if let Some(m) = r.max_value { if amount.is_none_or(|v| v > m) || (tc.is_some() && t.value > m) { f.push("policy:max_value".into()) } }
    } else {
        let mut total: u128 = 0;
        for o in &d.outputs {
            let a = o.address.as_deref();
            if a.is_some_and(|a| r.change.iter().any(|x| same(x, a))) { continue }
            if !a.is_some_and(|a| r.allow_to.iter().any(|x| same(x, a))) { f.push("policy:allow_to".into()); }
            total = total.saturating_add(o.amount.unwrap_or(u64::MAX) as u128);
        }
        f.dedup();
        if let Some(m) = r.max_value { if total > m { f.push("policy:max_value".into()) } }
        if let Some(m) = r.max_outputs { if d.outputs.len() > m { f.push("policy:max_outputs".into()) } }
    }
    for b in policy::check(d, &base) {
        // A listed (contract, selector) is the explicit allowance for the approve warning it raises.
        if allowed_call && b == "has_warnings" && d.warnings.iter().all(|w| matches!(*w, "unsigned" | "token_approve")) { continue }
        if allowed_call && (b == "unknown_contract_call" || b == "token_call_not_transfer") { continue }
        let s = match b { "fee_above_cap" => "policy:max_fee", "chain_id_mismatch" | "no_chain_id" => "policy:chain_id", "chain_id_not_pinned" => continue, x => x };
        if !f.iter().any(|y| y == s) { f.push(s.into()) }
    }
    f
}
