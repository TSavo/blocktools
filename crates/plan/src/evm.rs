//! EVM family: resolve a `Plan` to an unsigned EIP-1559 transaction. Orchestrates blocktools-evm
//! (ABI calldata) and blocktools-tx (the unsigned tx and its canonical encoding) -- no encoding of
//! its own, per the RFC #15 "orchestrate, never duplicate" rule. Live facts come in via `context::Evm`.
use crate::{context, Plan, Step};
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

/// Compile the EVM plan's structural steps (Call/Create/Approve/Value) into one unsigned type-2 tx.
/// Assertion steps and `Raw` are ignored here (they belong to `check`). A step from another family errors.
pub fn resolve(plan: &Plan, cx: &context::Evm) -> Result<Tx, String> {
    let chain_id = plan.chain_id.ok_or("evm plan needs chain_id")?;
    let (mut to, mut data, mut value, mut acted) = (None, Vec::<u8>::new(), 0u128, false);
    for s in &plan.steps {
        match s {
            Step::Call { to: t, sig, args } => { to = Some(addr20(t)?); data = calldata(sig, args)?; acted = true }
            Step::Approve { token, spender, amount } => {
                to = Some(addr20(token)?);
                data = calldata("approve(address,uint256)", &[spender.clone(), amount.clone()])?;
                acted = true
            }
            Step::Create { initcode } => {
                to = None;
                data = blocktools_core::hex_dec(initcode.trim_start_matches("0x")).ok_or("bad initcode hex")?;
                acted = true
            }
            Step::Value { amount } => { value = amount.parse().map_err(|_| "bad value")?; acted = true }
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
