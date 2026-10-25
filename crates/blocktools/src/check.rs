//! `check::tx_json`: fail-closed transaction check with public inputs only.
//!
//! In:  `{"chain", "raw_tx_hex", "expected_outputs":[{"address","amount"?}], "max_fee", "owner_addr",
//!        "input_values"?:[sats...]}`  (`amount`/`max_fee` as integer or decimal string; sats or wei)
//! Out: `{"ok", "reasons":[...], "outputs":[{"address","amount"}], "fee", "inputs":[{"txid","vout","amount"}]}`
//!
//! `ok` is true only when every check passed: chain known and verified, tx decodes, every
//! expected output is present (with the exact amount when given), every other output pays
//! `owner_addr` (change), the fee is known (from the tx/PSBT or `input_values`) and at most
//! `max_fee`, and the decoder raised no warnings (other than "unsigned", and "input_amounts_unknown",
//! which is covered by `fee_unknown` / `input_values`). Anything missing or unparseable is a reason.
use blocktools_core::chains;
use blocktools_tx::policy::{check, Policy};
use serde_json::{json, Value};

fn num(v: Option<&Value>) -> Option<u128> {
    match v? { Value::Number(n) => n.as_u64().map(u128::from), Value::String(s) => s.trim().parse().ok(), _ => None }
}
fn same(a: &str, b: &str) -> bool { if a.starts_with("0x") { a.eq_ignore_ascii_case(b) } else { a == b } }

pub fn tx_json(input: &str) -> String {
    let mut reasons: Vec<String> = Vec::new();
    let fail = |r: &str| json!({"ok": false, "reasons": [r], "outputs": [], "fee": null, "inputs": []}).to_string();
    let Ok(v) = serde_json::from_str::<Value>(input) else { return fail("bad_json") };
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|x| !x.is_empty());
    let Some(chain) = s("chain") else { return fail("chain_missing") };
    let Some(c) = chains::chain(chain) else { return fail("unknown_chain") };
    if !c.verified { return fail("unverified_chain") }
    let Some(raw) = s("raw_tx_hex") else { return fail("raw_tx_hex_missing") };
    let d = match blocktools_tx::decode(raw, chain) { Ok(d) => d, Err(e) => return fail(e) };
    let owner = s("owner_addr");
    match owner { None => reasons.push("owner_addr_missing".into()), Some(o) if crate::address::validate(chain, o).is_err() => reasons.push("owner_addr_invalid".into()), _ => {} }
    let max_fee = num(v.get("max_fee"));
    if max_fee.is_none() { reasons.push("max_fee_missing".into()) }
    let mut expected: Vec<(String, Option<u128>)> = Vec::new();
    match v.get("expected_outputs").and_then(|x| x.as_array()) {
        Some(a) if !a.is_empty() => for e in a {
            let Some(addr) = e.get("address").and_then(|x| x.as_str()) else { reasons.push("expected_output_bad".into()); continue };
            if crate::address::validate(chain, addr).is_err() { reasons.push("expected_address_invalid".into()) }
            if e.get("amount").is_some() && num(e.get("amount")).is_none() { reasons.push("expected_amount_bad".into()) }
            expected.push((addr.to_string(), num(e.get("amount"))));
        },
        _ => reasons.push("expected_outputs_missing".into()),
    }
    let (outputs, inputs, fee): (Vec<(Option<String>, Option<u128>)>, Value, Option<u128>) = if let Some(t) = &d.evm {
        // EVM: one effective output (to + value, or token recipient + amount); fee = gas * max fee/gas.
        let p = Policy { expect_to: expected.iter().map(|e| e.0.clone()).collect(), change: vec![], chain_id: None, max_fee, allow_warnings: false };
        reasons.extend(check(&d, &p).into_iter().filter(|r| *r != "fee_above_cap").map(String::from));
        let (to, amt) = match blocktools_tx::evm::token_call(&t.data) {
            Some(tc) => (Some(blocktools_tx::addr(&tc.to)), blocktools_tx::evm::dec(&tc.amount).parse().ok()),
            None => (t.to.map(|a| blocktools_tx::addr(&a)), Some(t.value)),
        };
        (vec![(to, amt)], json!([{"from": t.from().map(|a| blocktools_tx::addr(&a))}]), Some(t.max_fee_per_gas.saturating_mul(t.gas as u128)))
    } else {
        if matches!(c.sign, chains::Sign::PosTime | chains::Sign::Unknown) { reasons.push("unsupported_sighash_for_chain".into()) }
        let outs: Vec<_> = d.outputs.iter().map(|o| (o.address.clone(), o.amount.map(u128::from))).collect();
        let ins = json!(d.inputs.iter().map(|i| json!({"txid": i.txid, "vout": i.vout, "amount": i.amount})).collect::<Vec<_>>());
        let fee = d.fee.map(u128::from).or_else(|| {
            let iv: Vec<u128> = v.get("input_values")?.as_array()?.iter().map(|x| num(Some(x))).collect::<Option<_>>()?;
            if iv.len() != d.inputs.len() { return None }
            iv.iter().sum::<u128>().checked_sub(outs.iter().map(|o| o.1.unwrap_or(0)).sum())
        });
        for w in &d.warnings { if *w != "unsigned" && *w != "input_amounts_unknown" { reasons.push(format!("warning:{w}")) } }
        // every output must be expected or change to owner
        for (a, _) in &outs {
            match a { Some(a) if expected.iter().any(|e| same(&e.0, a)) || owner.is_some_and(|o| same(o, a)) => {}, _ => { reasons.push("unexpected_output".into()); break } }
        }
        (outs, ins, fee)
    };
    for (addr, amt) in &expected {
        let hit = outputs.iter().any(|(a, v)| a.as_deref().is_some_and(|a| same(a, addr)) && amt.map_or(true, |x| *v == Some(x)));
        if !hit { reasons.push(if outputs.iter().any(|(a, _)| a.as_deref().is_some_and(|a| same(a, addr))) { "expected_amount_mismatch" } else { "expected_output_missing" }.into()) }
    }
    match (fee, max_fee) { (None, _) => reasons.push("fee_unknown".into()), (Some(f), Some(m)) if f > m => reasons.push("fee_above_max".into()), _ => {} }
    reasons.sort(); reasons.dedup();
    json!({"ok": reasons.is_empty(), "reasons": reasons,
           "outputs": outputs.iter().map(|(a, v)| json!({"address": a, "amount": v.map(|x| x.to_string())})).collect::<Vec<_>>(),
           "fee": fee.map(|x| x.to_string()), "inputs": inputs}).to_string()
}
