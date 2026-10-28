//! UTXO family: resolve a `Plan` to an unsigned PSBT (THORChain-inbound style) by orchestrating
//! `blocktools::psbtmemo::build_with` -- no encoding and no coin selection of its own, per the RFC #15
//! "orchestrate, never duplicate" rule. `check` reuses the SIGNER's own `blocktools_tx::policy::check`
//! verbatim (the exact function `tx-sign --plan` runs), so pass-check <=> sign can never disagree. Live
//! facts come via `context::Utxo`.
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
            Step::AddInput { txid, vout, amount, address, prev_tx, witness_script } => {
                let mut line = json!({"txid": txid, "vout": vout, "amount": amount, "address": address});
                if let Some(h) = prev_tx { line["prev_tx"] = json!(h.trim_start_matches("0x")); }
                if let Some(h) = witness_script { line["witness_script"] = json!(h.trim_start_matches("0x")); }
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
        // resolve rebuilds each input from a full prev_tx (non_witness_utxo); a witness_utxo-only input
        // carries no prev_tx, so the exact bytes can't be reproduced -- fall to Raw.
        let nwu = inp.non_witness_utxo.as_ref()?;
        let prevout = nwu.output.get(txin.previous_output.vout as usize).cloned()?;
        let amount = prevout.value.to_sat();
        total_in = total_in.checked_add(amount)?;
        let address = blocktools_core::chains::script_to_address(c, prevout.script_pubkey.as_bytes())?.1;
        let prev_tx = Some(format!("0x{}", blocktools_core::hex_enc(bitcoin::consensus::serialize(nwu))));
        let this = match txin.sequence.0 { 0xffff_fffd => true, 0xffff_ffff => false, _ => return None };
        match rbf { Some(p) if p != this => return None, _ => rbf = Some(this) }
        let witness_script = inp
            .witness_script
            .as_ref()
            .map(|s| format!("0x{}", blocktools_core::hex_enc(s.as_bytes())));
        steps.push(Step::AddInput {
            txid: txin.previous_output.txid.to_string(),
            vout: txin.previous_output.vout,
            amount, address, prev_tx, witness_script,
        });
    }
    if steps.is_empty() { return None; }
    // Outputs: exactly one payment (the vault) at VOUT0 plus at most one OP_RETURN as the final output
    // (resolve/build_with emit the vault first and the memo last); no change output.
    let outs = resolved.get("outputs")?.as_array()?;
    let last = outs.len().checked_sub(1)?;
    let mut payment: Option<(String, u64)> = None;
    let mut memo_hex: Option<String> = None;
    for (i, o) in outs.iter().enumerate() {
        let script = blocktools_core::hex_dec(o.get("script")?.as_str()?)?;
        let value: u64 = o.get("value")?.as_str()?.parse().ok()?;
        if script.first() == Some(&0x6a) {
            // Only one OP_RETURN, zero-value, and it must be the last output (ordering resolve rebuilds).
            if memo_hex.is_some() || value != 0 || i != last { return None; }
            let payload = op_return_payload(&script)?;
            // Non-minimal push or an over-limit payload can't be reproduced by op_return_for: re-encode
            // and compare to the exact script bytes (mirrors the acct decoders' re-encode self-check).
            if payload.len() > blocktools::psbtmemo::op_return_limit(chain) { return None; }
            if blocktools::psbtmemo::op_return_for(chain, &payload).ok()? != script { return None; }
            memo_hex = Some(blocktools_core::hex_enc(payload));
        } else {
            // The single payment (vault) must be VOUT0, and there is no change output in a clean sweep.
            if payment.is_some() || i != 0 { return None; }
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

/// The UTXO signer guard set (a `blocktools_tx::policy::Policy`) derived from the plan's assertions: the
/// same assertion steps `check` consults -- `ExpectTo` (the vault) into `expect_to`, `Change` into
/// `change`, `ExpectMemo` into `expect_memo`, `CapFee` into `max_fee` -- mapped into the Policy the signer
/// path (`policy::check`, via `tx-sign --plan`) consumes, so what `tx-sign --plan` enforces is exactly the
/// guard set `tx-plan check` asserts (RFC #15).
pub fn guards(plan: &Plan) -> (blocktools_tx::policy::Policy, Vec<Finding>) {
    let mut p = blocktools_tx::policy::Policy::default();
    let mut findings: Vec<Finding> = vec![];
    for s in &plan.steps {
        match s {
            Step::ExpectTo { address } => p.expect_to.push(address.clone()),
            Step::Change { address } => p.change.push(address.clone()),
            Step::ExpectMemo { memo } => p.expect_memo = Some(memo.clone().into_bytes()),
            // A CapFee the author set must never be silently dropped for the looser chain default: an
            // unparsable cap (or one wider than the u64 UTXO fee width) is a finding, never a fall-through.
            Step::CapFee { max } => match max.parse::<u64>() {
                Ok(v) => p.max_fee = Some(v as u128),
                Err(_) => findings.push(Finding { code: "cap_fee_unparsable".into() }),
            },
            _ => {}
        }
    }
    (p, findings)
}

pub fn check(plan: &Plan, resolved: &Value) -> Vec<Finding> {
    let f = |c: &str| vec![Finding { code: c.into() }];
    // Delegate to the SIGNER's own check: decode the resolved PSBT and apply `policy::check` with the
    // `guards()` Policy -- the exact function `tx-sign --plan` runs (tools/tx-sign/src/main.rs: the
    // `full` closure over `check(d, &p)`). So `tx-plan check` passes IFF `tx-sign --plan` would sign:
    // pass-check <=> sign holds by construction for EVERY UTXO shape -- a THORChain inbound (memo +
    // ExpectMemo, accepted as the one non-destination OP_RETURN), a plain payment, or an m-of-n multisig
    // P2WSH spend -- not only THORChain inbounds. (It previously used `thor::verify_send`, which demanded
    // a memo and so flagged a memo-less multisig spend the signer signs happily.)
    let (g, cap_findings) = guards(plan);
    // The signer requires a destination assertion (--expect-to); mirror that so an assertion-less plan
    // is a `vault` finding here rather than a silently-accepted anything-goes spend.
    if g.expect_to.is_empty() { return f("vault"); }
    let txt = resolved.to_string();
    let Ok(d) = blocktools_tx::decode(&txt, &plan.chain) else { return f("tx"); };
    let mut out: Vec<Finding> = blocktools_tx::policy::check(&d, &g)
        .into_iter().map(|c| Finding { code: c.into() }).collect();
    // The UTXO family enforces ExpectTo (vault), ExpectMemo and CapFee; ExpectOut it cannot, so report it.
    out.extend(crate::unsupported_assertions(plan, &["expect-to", "expect-memo", "cap-fee"]));
    out.extend(cap_findings);
    out
}
