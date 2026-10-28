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
/// Assertion steps are ignored here (they belong to `check`). A step from another family errors.
///
/// Totality: a `Raw{kind:"utxo.psbt"}` step carries a fully-built result verbatim (the inverse of
/// `represent`'s fallback) so `resolve(represent(tx)) == tx` holds for every UTXO tx, even one whose
/// coin-selection / fee shape cannot be re-derived structurally (fee-rate is not in the wire bytes).
pub fn resolve(plan: &Plan, cx: &context::Utxo) -> Result<Value, String> {
    if plan.family() != Some(Family::Utxo) {
        return Err(format!("not a utxo-family chain: {}", plan.chain));
    }
    // Totality escape hatch: an opaque, fully-built PSBT result rebuilt verbatim.
    for s in &plan.steps {
        if let Step::Raw { kind, fields } = s {
            if kind == "utxo.psbt" { return Ok(fields.clone()); }
        }
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

/// The inverse of `resolve`: lift a fully-built UTXO result (the `{psbt, fee, vsize, rbf, outputs}` JSON
/// that `build_with` / `tx-decode` emit) back into the IR. The THORChain-inbound sweep shape -- one or
/// more inputs swept to a single destination (VOUT0), with an optional OP_RETURN memo and no change --
/// recovers structurally: every input to `AddInput` (with its `prev_tx`, amount and address read from the
/// PSBT's `non_witness_utxo`), the destination to a sweep `AddOutput` (empty amount), the OP_RETURN to
/// `OpReturn`, plus the matching `ExpectTo`/`ExpectMemo` assertions. The live fee-rate is NOT part of the
/// IR and is dropped; it comes back in via `context::Utxo` at resolve time.
///
/// Anything outside that shape -- a change output, more than one payment output, a non-zero locktime, a
/// script with no address, an RBF mix, a non-standard OP_RETURN push -- cannot be re-derived so that
/// `build_with` reproduces the exact bytes (its fee and coin selection are a function of the fee-rate,
/// which the wire bytes do not carry). Those round-trip through `Raw{kind:"utxo.psbt"}`, which holds the
/// built result verbatim for `resolve` to hand back unchanged. `represent` therefore never fails.
pub fn represent(resolved: &Value, chain: &str) -> Plan {
    represent_structural(resolved, chain).unwrap_or_else(|| Plan {
        chain: chain.into(),
        chain_id: None,
        steps: vec![Step::Raw { kind: "utxo.psbt".into(), fields: resolved.clone() }],
    })
}

/// The OP_RETURN data push after the `0x6a` opcode: a direct push (len <= 75) or `OP_PUSHDATA1` (0x4c len).
fn op_return_payload(script: &[u8]) -> Option<Vec<u8>> {
    if script.first() != Some(&0x6a) { return None; }
    let rest = script.get(1..)?;
    let (len, off) = match *rest.first()? {
        n if n <= 75 => (n as usize, 1usize),
        0x4c => (*rest.get(1)? as usize, 2usize),
        _ => return None,
    };
    Some(rest.get(off..off.checked_add(len)?)?.to_vec())
}

/// Try the structural recovery; `None` means the shape is not a clean inbound sweep and the caller
/// falls back to `Raw{kind:"utxo.psbt"}` so the exact bytes still round-trip.
fn represent_structural(resolved: &Value, chain: &str) -> Option<Plan> {
    use bitcoin::psbt::Psbt;
    let c = blocktools_core::chains::supported(chain)?;
    let psbt = Psbt::deserialize(&blocktools_core::b64::decode(resolved.get("psbt")?.as_str()?)?).ok()?;
    let tx = &psbt.unsigned_tx;
    if tx.lock_time.to_consensus_u32() != 0 { return None; } // resolve can't rebuild a nonzero locktime
    let mut steps: Vec<Step> = Vec::new();
    let mut total_in: u64 = 0;
    let mut rbf: Option<bool> = None;
    for (i, txin) in tx.input.iter().enumerate() {
        let inp = psbt.inputs.get(i)?;
        let prevout = inp.non_witness_utxo.as_ref()
            .and_then(|t| t.output.get(txin.previous_output.vout as usize).cloned())
            .or_else(|| inp.witness_utxo.clone())?;
        let amount = prevout.value.to_sat();
        total_in = total_in.checked_add(amount)?;
        let address = blocktools_core::chains::script_to_address(c, prevout.script_pubkey.as_bytes())?.1;
        let prev_tx = inp.non_witness_utxo.as_ref()
            .map(|t| format!("0x{}", blocktools_core::hex_enc(bitcoin::consensus::serialize(t))));
        let this = match txin.sequence.0 { 0xffff_fffd => true, 0xffff_ffff => false, _ => return None };
        match rbf { Some(p) if p != this => return None, _ => rbf = Some(this) }
        steps.push(Step::AddInput {
            txid: txin.previous_output.txid.to_string(),
            vout: txin.previous_output.vout,
            amount, address, prev_tx,
        });
    }
    if steps.is_empty() { return None; }
    // Outputs: exactly one payment (the vault) plus at most one OP_RETURN; no change output.
    let mut payment: Option<(String, u64)> = None;
    let mut memo_hex: Option<String> = None;
    for o in resolved.get("outputs")?.as_array()? {
        let script = blocktools_core::hex_dec(o.get("script")?.as_str()?)?;
        let value: u64 = o.get("value")?.as_str()?.parse().ok()?;
        if script.first() == Some(&0x6a) {
            if memo_hex.is_some() || value != 0 { return None; }
            memo_hex = Some(blocktools_core::hex_enc(op_return_payload(&script)?));
        } else {
            if payment.is_some() { return None; } // a second payment output => change, not a clean sweep
            payment = Some((o.get("address")?.as_str()?.to_string(), value));
        }
    }
    let (to, pay_value) = payment?;
    let fee: u64 = resolved.get("fee")?.as_str()?.parse().ok()?;
    // Pure sweep: the single payment takes everything less the fee (no change output).
    if pay_value != total_in.checked_sub(fee)? { return None; }
    if rbf == Some(true) { steps.push(Step::Rbf { enabled: true }); }
    steps.push(Step::AddOutput { to: to.clone(), amount: String::new() });
    if let Some(m) = &memo_hex { steps.push(Step::OpReturn { memo: m.clone() }); }
    steps.push(Step::ExpectTo { address: to });
    if let Some(ascii) = memo_hex.as_ref()
        .and_then(|m| blocktools_core::hex_dec(m))
        .and_then(|b| String::from_utf8(b).ok())
    {
        steps.push(Step::ExpectMemo { memo: ascii });
    }
    Some(Plan { chain: chain.into(), chain_id: None, steps })
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
