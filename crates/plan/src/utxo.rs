//! UTXO family: resolve a `Plan` to an unsigned PSBT (THORChain-inbound style) by orchestrating
//! `blocktools::psbtmemo::build_with` -- no encoding and no coin selection of its own, per the RFC #15
//! "orchestrate, never duplicate" rule. `check` reuses `blocktools::thor::verify_send` verbatim so the
//! IR verdict and the raw `verify_thor_send` tool can never disagree. Live facts come via `context::Utxo`.
use crate::{context, Family, Finding, Plan, Step};
use serde_json::{json, Value};

/// Compile the UTXO plan's structural steps into one unsigned PSBT with an optional OP_RETURN memo.
/// Mapping onto [`blocktools::psbtmemo::build_with`]:
///   `AddInput`  -> a utxos JSONL line `{"txid","vout","amount","address"[,"prev_tx"]}`
///   `AddOutput` -> `to` + `send` (an empty amount means sweep: `send = None`, pay everything to `to`)
///   `Change`    -> the change address        `OpReturn` -> the memo bytes (hex-decoded)
///   `FeeRate`   -> fee-rate (else `cx.fee_rate`)   `Rbf` -> replaceability (default non-RBF, per THORChain)
/// Assertion steps and `Raw` are ignored here (they belong to `check`). A step from another family errors.
pub fn resolve(plan: &Plan, cx: &context::Utxo) -> Result<Value, String> {
    if plan.family() != Some(Family::Utxo) {
        return Err(format!("not a utxo-family chain: {}", plan.chain));
    }
    let mut utxos = String::new();
    let mut to: Option<String> = None;
    let mut send: Option<u64> = None;
    let mut change: Option<String> = None;
    let mut memo: Vec<u8> = Vec::new();
    let mut fee_rate = cx.fee_rate;
    let mut rbf = false;
    for s in &plan.steps {
        match s {
            Step::AddInput { txid, vout, amount, address, prev_tx } => {
                let line = match prev_tx {
                    Some(h) => json!({"txid": txid, "vout": vout, "amount": amount, "address": address, "prev_tx": h.trim_start_matches("0x")}),
                    None => json!({"txid": txid, "vout": vout, "amount": amount, "address": address}),
                };
                utxos.push_str(&line.to_string());
                utxos.push('\n');
            }
            Step::AddOutput { to: t, amount } => {
                if to.is_some() { return Err("utxo plan supports a single AddOutput destination (plus Change)".into()); }
                to = Some(t.clone());
                let a = amount.trim();
                if !a.is_empty() { send = Some(a.parse().map_err(|_| "bad AddOutput amount")?); }
            }
            Step::Change { address } => change = Some(address.clone()),
            Step::OpReturn { memo: m } => {
                memo = blocktools_core::hex_dec(m.trim_start_matches("0x")).ok_or("bad OpReturn memo hex")?;
            }
            Step::FeeRate { sat_per_vb } => fee_rate = *sat_per_vb,
            Step::Rbf { enabled } => rbf = *enabled,
            Step::Locktime { value } if *value != 0 => return Err("utxo resolve: nonzero locktime unsupported by the memo builder".into()),
            Step::Locktime { .. } => {}
            Step::ExpectTo { .. } | Step::ExpectOut { .. } | Step::ExpectMemo { .. } | Step::CapFee { .. } | Step::Raw { .. } => {}
            other => return Err(format!("step not valid for the utxo family: {other:?}")),
        }
    }
    if utxos.is_empty() { return Err("utxo plan has no AddInput".into()); }
    let to = to.ok_or("utxo plan has no AddOutput (destination)")?;
    blocktools::psbtmemo::build_with(&plan.chain, &utxos, &to, send, change.as_deref(), fee_rate, &memo, rbf)
}

/// Assert the resolved PSBT satisfies the plan's inbound assertions, reusing `thor::verify_send` (the
/// exact logic behind the `verify_thor_send` tool) so the two always agree. `ExpectTo` is the vault,
/// `ExpectMemo` the OP_RETURN payload, `Change` the (optional) change address; the asserted vault amount
/// is the amount the resolve actually produced at output[0]. Every `verify_send` failure reason becomes a
/// `Finding{code}`; an empty vector means the bytes match the plan.
pub fn check(plan: &Plan, resolved: &Value) -> Vec<Finding> {
    let f = |c: &str| vec![Finding { code: c.into() }];
    let Some(psbt) = resolved.get("psbt").and_then(|x| x.as_str()) else { return f("tx"); };
    let mut vault: Option<String> = None;
    let mut memo: Option<String> = None;
    let mut change: Option<String> = None;
    for s in &plan.steps {
        match s {
            Step::ExpectTo { address } => vault = Some(address.clone()),
            Step::ExpectMemo { memo: m } => memo = Some(m.clone()),
            Step::Change { address } => change = Some(address.clone()),
            _ => {}
        }
    }
    let Some(vault) = vault else { return f("vault"); };
    let memo = memo.unwrap_or_default();
    let amount = resolved.get("outputs").and_then(|o| o.as_array()).and_then(|a| a.first())
        .and_then(|o| o.get("value")).and_then(|v| v.as_str()).and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let r = blocktools::thor::verify_send(&plan.chain, psbt, &vault, memo.as_bytes(), amount, change.as_deref(), &[], None);
    r.get("failures").and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(|c| Finding { code: c.into() })).collect())
        .unwrap_or_default()
}
