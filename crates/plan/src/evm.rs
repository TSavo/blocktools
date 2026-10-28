//! EVM family: resolve a `Plan` to an unsigned EIP-1559 transaction, decode a tx back into a `Plan`
//! (`represent`), and assert a tx against the plan's assertions (`check`). Orchestrates blocktools-evm
//! (ABI calldata) and blocktools-tx (the unsigned tx, its canonical encoding, the policy verifier) --
//! no encoding, no crypto and no policy of its own, per the RFC #15 "orchestrate, never duplicate" rule.
//! Live facts come in via `context::Evm`.
use crate::{context, Finding, Plan, Step};
use blocktools_tx::evm::{Kind, Tx};
use blocktools_tx::rlp::Rlp;
use serde_json::json;

fn addr20(s: &str) -> Result<[u8; 20], String> {
    let b = blocktools_core::hex_dec(s.trim_start_matches("0x")).ok_or("bad address hex")?;
    b.try_into().map_err(|_| "address must be 20 bytes".to_string())
}
fn calldata(sig: &str, args: &[String]) -> Result<Vec<u8>, String> {
    let v = blocktools_evm::api::encode_json(&json!({ "sig": sig, "args": args }))?;
    let hex = v["data"].as_str().ok_or("ABI encode produced no data")?;
    blocktools_core::hex_dec(hex.trim_start_matches("0x")).ok_or_else(|| "bad calldata hex".to_string())
}
fn hex0x(b: &[u8]) -> String { format!("0x{}", blocktools_core::hex_enc(b)) }
/// Chain name as the CLIs use it for an EVM chain id (the inverse of the `family_of` EVM slugs).
fn chain_slug(id: Option<u64>) -> String {
    match id {
        Some(56) => "bsc", Some(8453) => "base", Some(43114) => "avax",
        Some(42161) => "arbitrum", Some(10) => "optimism", Some(137) => "polygon",
        _ => "eth",
    }
    .to_string()
}

/// Compile the EVM plan's structural steps (Call/Create/Approve/Value, plus a `Raw{kind:"evm.call"}`)
/// into one unsigned type-2 tx. Assertion steps and non-evm `Raw` are ignored here (they belong to
/// `check`). A step from another family errors.
pub fn resolve(plan: &Plan, cx: &context::Evm) -> Result<Tx, String> {
    let chain_id = plan.chain_id.ok_or("evm plan needs chain_id")?;
    let (mut to, mut data, mut value, mut acted) = (None, Vec::<u8>::new(), 0u128, false);
    // The call/create/approve/evm.call slot is single-shot; a second structural step would silently
    // overwrite the first (last-write-wins). Value may accompany one call, so it does not take the slot.
    let mut slot = false;
    let mut take_slot = || -> Result<(), String> {
        if slot { return Err("evm plan has more than one structural step".into()); }
        slot = true; Ok(())
    };
    for s in &plan.steps {
        match s {
            Step::Call { to: t, sig, args } => { take_slot()?; to = Some(addr20(t)?); data = calldata(sig, args)?; acted = true }
            Step::Approve { token, spender, amount } => {
                take_slot()?;
                to = Some(addr20(token)?);
                data = calldata("approve(address,uint256)", &[spender.clone(), amount.clone()])?;
                acted = true
            }
            Step::Create { initcode } => {
                take_slot()?;
                to = None;
                data = blocktools_core::hex_dec(initcode.trim_start_matches("0x")).ok_or("bad initcode hex")?;
                acted = true
            }
            Step::Value { amount } => { value = amount.parse().map_err(|_| "bad value")?; acted = true }
            // Totality: an opaque call whose selector isn't modelled, rebuilt verbatim so
            // resolve(represent(tx)) == tx holds for every EVM call (see `represent`).
            Step::Raw { kind, fields } if kind == "evm.call" => {
                take_slot()?;
                to = Some(addr20(fields["to"].as_str().ok_or("evm.call raw needs a to field")?)?);
                data = blocktools_core::hex_dec(fields["data"].as_str().ok_or("evm.call raw needs a data field")?.trim_start_matches("0x"))
                    .ok_or("bad evm.call raw data hex")?;
                value = fields["value"].as_str().ok_or("evm.call raw needs a value field")?.parse().map_err(|_| "bad evm.call raw value")?;
                acted = true
            }
            Step::ExpectTo { .. } | Step::ExpectOut { .. } | Step::ExpectMemo { .. } | Step::CapFee { .. } | Step::Raw { .. } => {}
            other => return Err(format!("step not valid for the evm family: {other:?}")),
        }
    }
    if !acted { return Err("evm plan has no Call/Create/Approve/Value step".into()) }
    Ok(Tx {
        kind: Kind::Eip1559, chain_id: Some(chain_id), nonce: cx.nonce,
        max_fee_per_gas: cx.max_fee_per_gas, max_priority_fee_per_gas: Some(cx.priority_fee),
        gas: cx.gas, to, value, data, access_list: Rlp::L(vec![]), sig: None,
    })
}

/// The inverse of `resolve`: decode an unsigned/signed tx into the IR (what `tx-decode` emits). A
/// recognized ERC-20 `approve` lifts to a structured `Step::Approve`; a contract creation to
/// `Step::Create`; any other call is held verbatim in `Step::Raw{kind:"evm.call"}` so representability
/// is total and the bytes round-trip through `resolve`. The live facts (nonce/gas/fee) are not part of
/// the IR and are dropped here -- they come back in via `context::Evm` at resolve time.
pub fn represent(tx: &Tx) -> Plan {
    let step = match tx.to {
        None => Step::Create { initcode: hex0x(&tx.data) },
        Some(to) => match blocktools_tx::evm::token_call(&tx.data) {
            // approve carries no native value; lift it only when value is zero so totality holds.
            Some(tc) if tc.method == "approve" && tx.value == 0 => Step::Approve {
                token: hex0x(&to),
                spender: hex0x(&tc.to),
                amount: blocktools_tx::evm::dec(&tc.amount),
            },
            _ => Step::Raw {
                kind: "evm.call".into(),
                fields: json!({ "to": hex0x(&to), "data": hex0x(&tx.data), "value": tx.value.to_string() }),
            },
        },
    };
    Plan { chain: chain_slug(tx.chain_id), chain_id: tx.chain_id, steps: vec![step] }
}

/// Assert a resolved/decoded tx satisfies the plan's assertion steps. Thin: it builds a
/// `blocktools_tx::policy::Policy` from the plan (`expect_to` from `ExpectTo`, `max_fee` from `CapFee`,
/// `chain_id` from `plan.chain_id`), decodes the tx through the one shared decode path, runs
/// `policy::check`, and lifts the string codes into `Finding`. By going through the same verifier as
/// tx-verify, `check` and the raw tool can never disagree.
/// Build the EVM signer guard set (a `blocktools_tx::policy::Policy`) from the plan's assertions, plus any
/// fail-closed finding the mapping itself raises (an unparsable `CapFee`). This is the exact construction
/// `check` consumes; `check` and `crate::sign_guards` share it, so a passing `tx-plan check` and what
/// `tx-sign --plan` enforces are the same guard set by construction (RFC #15).
pub fn guards(plan: &Plan) -> (blocktools_tx::policy::Policy, Vec<Finding>) {
    let mut findings: Vec<Finding> = vec![];
    let mut policy = blocktools_tx::policy::Policy { chain_id: plan.chain_id, ..Default::default() };
    for s in &plan.steps {
        match s {
            Step::ExpectTo { address } => policy.expect_to.push(address.clone()),
            // A CapFee the author set must never be silently dropped for the looser default: an
            // unparsable cap is a finding, and the cap stays unset only as a failure, not a fall-through.
            Step::CapFee { max } => match max.parse::<u128>() {
                Ok(v) => policy.max_fee = Some(v),
                Err(_) => findings.push(Finding { code: "cap_fee_unparsable".into() }),
            },
            _ => {}
        }
    }
    (policy, findings)
}

pub fn check(plan: &Plan, tx: &Tx) -> Vec<Finding> {
    let (policy, mut findings) = guards(plan);
    let bytes = tx.encode_signed().unwrap_or_else(|| tx.encode_unsigned());
    let decoded = match blocktools_tx::decode_bytes(&bytes, "eth") {
        Ok(d) => d,
        Err(e) => return vec![Finding { code: e.to_string() }],
    };
    findings.extend(blocktools_tx::policy::check(&decoded, &policy).into_iter().map(|c| Finding { code: c.to_string() }));
    // The EVM family enforces ExpectTo and CapFee; ExpectOut/ExpectMemo it cannot, so report them.
    findings.extend(crate::unsupported_assertions(plan, &["expect-to", "cap-fee"]));
    findings
}
