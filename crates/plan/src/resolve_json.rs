//! `resolve(plan JSON, context JSON) -> unsigned JSON`: the one resolve path `tx-plan resolve` and the
//! wasm `txPlanResolve` export share, so the two can never disagree. Keyless: a Plan and a Context hold
//! only public facts (addresses, amounts, nonce, gas, fee-rate, UTXOs, a signer PUBKEY for Account).
//! Output (one JSON object, keys per family):
//!   evm:     {"chain","family":"evm","type":"evm-1559","unsigned_tx": hex}
//!   utxo:    {"chain","family":"utxo","type":"psbt", ...the utxo resolver's fields (psbt, fee, ...)}
//!   account: {"chain","family":"account","type":"cosmos-signdoc","sign_doc": hex}  (feature `account`)
use crate::{context, Family, Plan, Step};
use serde_json::{json, Value};

fn num_of(v: &Value) -> Option<u64> {
    match v { Value::Number(n) => n.as_u64(), Value::String(s) => s.parse().ok(), _ => None }
}
fn cx_u64(cx: &Value, k: &str) -> u64 { cx.get(k).and_then(num_of).unwrap_or(0) }
fn cx_u128(cx: &Value, k: &str) -> Result<u128, String> {
    match cx.get(k) {
        Some(Value::Number(n)) => Ok(n.as_u64().map(u128::from).unwrap_or(0)),
        Some(Value::String(s)) => s.parse().map_err(|_| format!("bad context number: {k}")),
        _ => Ok(0),
    }
}

/// The plan's family; for an empty chain, the family a represented `Raw` step names in its kind prefix.
pub fn family(plan: &Plan) -> Result<Family, String> {
    if let Some(f) = plan.family() { return Ok(f); }
    if plan.chain.is_empty() {
        if let Some(f) = plan.steps.iter().find_map(|s| match s {
            Step::Raw { kind, .. } => match kind.split('.').next() {
                Some("account") => Some(Family::Account),
                Some("utxo") => Some(Family::Utxo),
                Some("evm") => Some(Family::Evm),
                _ => None,
            },
            _ => None,
        }) { return Ok(f); }
    }
    Err(format!("unknown chain / family: {}", plan.chain))
}

/// Resolve a parsed plan against a parsed context. Errors are the family resolvers' own messages.
pub fn resolve(plan: &Plan, cx: &Value) -> Result<Value, String> {
    if !cx.is_object() { return Err("bad context JSON: expected an object".into()); }
    let fam = family(plan)?;
    let mut o = json!({"chain": plan.chain, "family": fam});
    match fam {
        Family::Evm => {
            let c = context::Evm { nonce: cx_u64(cx, "nonce"), gas: cx_u64(cx, "gas"),
                max_fee_per_gas: cx_u128(cx, "max_fee_per_gas")?, priority_fee: cx_u128(cx, "priority_fee")? };
            let tx = crate::evm::resolve(plan, &c)?;
            o["type"] = json!("evm-1559");
            o["unsigned_tx"] = json!(blocktools_core::hex_enc(tx.encode_unsigned()));
        }
        Family::Utxo => {
            let c = context::Utxo { fee_rate: cx_u64(cx, "fee_rate") };
            let v = crate::utxo::resolve(plan, &c)?;
            o["type"] = json!("psbt");
            if let Some(obj) = v.as_object() { for (k, val) in obj { o[k.clone()] = val.clone(); } }
        }
        #[cfg(feature = "account")]
        Family::Account => {
            let c = context::Account { sequence: cx_u64(cx, "sequence"), account_number: cx_u64(cx, "account_number"),
                gas: cx_u64(cx, "gas"), pubkey: cx.get("pubkey").and_then(|v| v.as_str()).unwrap_or("").to_string() };
            let doc = crate::account::resolve(plan, &c)?;
            o["type"] = json!("cosmos-signdoc");
            o["sign_doc"] = json!(blocktools_core::hex_enc(&doc));
        }
        #[cfg(not(feature = "account"))]
        Family::Account => return Err("family_not_built: account (this build has no Account family)".into()),
    }
    Ok(o)
}

/// Text in, text out (the wasm boundary): `plan` is a Plan JSON (deny_unknown_fields), `context` a JSON object.
pub fn resolve_str(plan: &str, context: &str) -> Result<Value, String> {
    let p: Plan = serde_json::from_str(plan).map_err(|e| format!("bad Plan JSON: {e}"))?;
    let cx: Value = serde_json::from_str(context).map_err(|e| format!("bad context JSON: {e}"))?;
    resolve(&p, &cx)
}
