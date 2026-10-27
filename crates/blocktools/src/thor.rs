//! `verify_send`: fail-closed check of a THORChain inbound send on btc/ltc/doge/bch, public data only.
//!
//! Required shape (SwapChan): `[vault == expected_amount, optional change -> change_addr, OP_RETURN == memo]`,
//! nothing else; every input non-RBF (nSequence 0xffffffff); every input value known (PSBT witness_utxo
//! on amount-committing inputs, or a non_witness_utxo whose txid matches the prevout); every input owned
//! by one of `takers` when any are given; fee at most `max_fee` (default: the chain's high-fee warning).
//! Out: `{ok, failures:[...], outputs:[{address, amount, kind}], memo, fee, rbf}`. Reasons:
//! `chain` `tx` `vault` `amount` `memo` `change` `output_count` `rbf` `fee` `input_unknown` `input_foreign`
//! `vault_invalid` `change_invalid` `taker_invalid`. Addresses compare by output script (BCH CashAddr,
//! prefixed or not, and legacy are equal).
use bitcoin::psbt::Psbt;
use bitcoin::script::Instruction;
use bitcoin::Transaction;
use blocktools_core::chains;
use blocktools_tx::digest;
use serde_json::{json, Value};

pub const CHAINS: [&str; 4] = ["btc", "ltc", "doge", "bch"];

fn fail(r: &str) -> Value { json!({"ok": false, "failures": [r], "outputs": [], "memo": null, "fee": null, "rbf": null}) }

/// OP_RETURN payload: all pushes concatenated; None when the script is not OP_RETURN or has a non-push.
fn op_return_data(s: &bitcoin::Script) -> Option<Vec<u8>> {
    if !s.is_op_return() { return None }
    let mut d = Vec::new();
    for i in bitcoin::Script::from_bytes(&s.as_bytes()[1..]).instructions() {
        match i.ok()? { Instruction::PushBytes(b) => d.extend_from_slice(b.as_bytes()), Instruction::Op(_) => return None }
    }
    Some(d)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_send(chain: &str, tx: &str, vault: &str, memo: &[u8], amount: u64, change: Option<&str>, takers: &[String], max_fee: Option<u64>) -> Value {
    let chain = chain.trim();
    if !CHAINS.contains(&chain) { return fail("chain") }
    let Some(c) = chains::chain(chain) else { return fail("chain") };
    let dg = digest::Digest::for_chain(c);
    let spk = |a: &str| crate::cashaddr::address_to_script(chain, a.trim()).ok();
    let mut f: Vec<&str> = Vec::new();
    let vs = spk(vault); if vs.is_none() { f.push("vault_invalid") }
    let cs = change.filter(|x| !x.trim().is_empty()).map(spk);
    if matches!(cs, Some(None)) { f.push("change_invalid") }
    let ts: Vec<Option<Vec<u8>>> = takers.iter().filter(|x| !x.trim().is_empty()).map(|t| spk(t)).collect();
    if ts.iter().any(Option::is_none) { f.push("taker_invalid") }
    let Ok(b) = blocktools_tx::input_bytes(tx) else { return fail("tx") };
    // (unsigned tx, per-input prevout or None)
    let (t, prev): (Transaction, Vec<Option<bitcoin::TxOut>>) = if b.starts_with(b"psbt\xff") {
        let Ok(p) = Psbt::deserialize(&b) else { return fail("tx") };
        if p.inputs.len() != p.unsigned_tx.input.len() { return fail("tx") }
        let prev = p.inputs.iter().zip(&p.unsigned_tx.input).map(|(i, ti)| {
            if let Some(o) = digest::proven_prevout(i, &ti.previous_output, dg) { return Some(o) }
            let o = i.witness_utxo.clone()?;
            (!digest::input_amount_uncommitted(&o.script_pubkey, i.redeem_script.as_deref())).then_some(o)
        }).collect();
        (p.unsigned_tx, prev)
    } else {
        let Ok(t) = bitcoin::consensus::deserialize::<Transaction>(&b) else { return fail("tx") };
        let n = t.input.len(); (t, vec![None; n])
    };
    if t.input.is_empty() || t.output.is_empty() { return fail("tx") }
    if prev.iter().any(Option::is_none) { f.push("input_unknown") }
    if !ts.is_empty() && prev.iter().flatten().any(|o| !ts.iter().flatten().any(|s| s == o.script_pubkey.as_bytes())) { f.push("input_foreign") }
    let rbf = t.input.iter().any(|i| i.sequence.0 != 0xffff_ffff);
    if rbf { f.push("rbf") }
    let o = &t.output;
    let n = o.len();
    let mut memo_got: Option<Vec<u8>> = None;
    if !(2..=3).contains(&n) { f.push("output_count") }
    if o.iter().take(n.saturating_sub(1)).any(|x| x.script_pubkey.is_op_return()) { f.push("output_count") }
    if vs.as_deref().is_some_and(|v| o[0].script_pubkey.as_bytes() != v) { f.push("vault") }
    if o[0].value.to_sat() != amount { f.push("amount") }
    match op_return_data(&o[n - 1].script_pubkey) {
        Some(d) => { if d != memo { f.push("memo") } memo_got = Some(d) }
        None => f.push("memo"),
    }
    if n == 3 {
        match &cs { Some(Some(s)) if o[1].script_pubkey.as_bytes() == s.as_slice() => {}, _ => f.push("change") }
    }
    let out_sum: u64 = o.iter().map(|x| x.value.to_sat()).sum();
    let fee = prev.iter().map(|p| p.as_ref().map(|x| x.value.to_sat())).sum::<Option<u64>>().and_then(|i| i.checked_sub(out_sum));
    if prev.iter().all(Option::is_some) {
        let vsize = t.vsize() as u64 + t.input.iter().filter(|i| i.script_sig.is_empty() && i.witness.is_empty()).count() as u64 * 107;
        let cap = max_fee.unwrap_or_else(|| chains::fee_warn(chain).fee_for(vsize));
        match fee { Some(x) if x <= cap => {}, _ => f.push("fee") }
    }
    f.sort(); f.dedup();
    let outs: Vec<Value> = o.iter().map(|x| {
        let a = chains::script_to_address(c, x.script_pubkey.as_bytes());
        json!({"address": a.as_ref().map(|y| y.1.clone()), "amount": x.value.to_sat().to_string(), "kind": a.map(|y| y.0).unwrap_or(if x.script_pubkey.is_op_return() { "op_return" } else { "nonstandard" })})
    }).collect();
    json!({"ok": f.is_empty(), "failures": f, "outputs": outs,
           "memo": memo_got.as_ref().map(|m| String::from_utf8_lossy(m).into_owned()),
           "fee": fee.map(|x| x.to_string()), "rbf": rbf})
}

/// JSON form: `{"chain","tx","vault","memo","amount","change"?,"taker"?: str|[str],"max_fee"?}`.
pub fn verify_send_json(input: &str) -> String {
    let Ok(v) = serde_json::from_str::<Value>(input) else { return fail("bad_json").to_string() };
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("");
    let n = |k: &str| v.get(k).and_then(|x| x.as_u64().or_else(|| x.as_str()?.trim().parse().ok()));
    let Some(amount) = n("amount") else { return fail("amount").to_string() };
    let takers: Vec<String> = match v.get("taker") { Some(Value::String(t)) => vec![t.clone()], Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(), _ => vec![] };
    let ch = s("change");
    verify_send(s("chain"), s("tx"), s("vault"), s("memo").as_bytes(), amount, (!ch.is_empty()).then_some(ch), &takers, n("max_fee")).to_string()
}
