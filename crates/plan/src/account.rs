//! Account family: resolve a `Plan` to an unsigned Cosmos **SignDoc** (SIGN_MODE_DIRECT). Orchestrates
//! blocktools-acct (the THORChain `MsgDeposit` and Cosmos `MsgSend` builders) -- no protobuf encoding and
//! no crypto of its own, per the RFC #15 "orchestrate, never duplicate" rule. Live facts (sequence,
//! account_number, gas, and the signer pubkey) come in via `context::Account`.
use crate::{context, Finding, Plan, Step};
use blocktools_acct::{atom, thor};

/// Decode the 33-byte compressed signer pubkey from its hex string in the context.
fn pubkey33(hex: &str) -> Result<[u8; 33], String> {
    let b = blocktools_core::hex_dec(hex.trim_start_matches("0x")).ok_or("bad pubkey hex")?;
    b.try_into().map_err(|_| "pubkey must be 33 bytes (compressed)".to_string())
}

/// "THOR.RUNE" -> ("THOR", "RUNE"); a bare "RUNE" -> ("RUNE", "RUNE"). The ticker doubles as the symbol
/// for native RUNE, matching the mainnet-accepted `swapchan` register tx (crates/acct/tests/thorchain.rs).
fn parse_asset(asset: &str) -> (String, String) {
    match asset.split_once('.') {
        Some((chain, ticker)) => (chain.to_string(), ticker.to_string()),
        None => (asset.to_string(), asset.to_string()),
    }
}

/// Compile the Account plan's one structural step into unsigned SignDoc bytes.
///   - `Deposit` -> THORChain `MsgDeposit` (chain_id `thorchain-1`)
///   - `Transfer` -> Cosmos bank `MsgSend` (chain/denom from the recipient hrp)
/// Assertion steps and `Raw` are ignored here (they belong to `check`). A step from another family errors.
pub fn resolve(plan: &Plan, cx: &context::Account) -> Result<Vec<u8>, String> {
    let pubkey = pubkey33(&cx.pubkey)?;
    let mut doc: Option<Vec<u8>> = None;
    for s in &plan.steps {
        match s {
            Step::Deposit { asset, amount, memo } => {
                if doc.is_some() { return Err("account plan: more than one structural step".into()) }
                let (asset_chain, ticker) = parse_asset(asset);
                let d = thor::Deposit {
                    asset_chain, asset_symbol: ticker.clone(), asset_ticker: ticker,
                    amount: amount.parse().map_err(|_| "bad deposit amount")?,
                    memo: memo.clone(), pubkey,
                    sequence: cx.sequence, gas: cx.gas,
                    chain_id: thor::CHAIN_ID.to_string(), account_number: cx.account_number,
                };
                doc = Some(d.sign_doc());
            }
            Step::Transfer { to, amount } => {
                if doc.is_some() { return Err("account plan: more than one structural step".into()) }
                let row = atom::chain_of(to).ok_or("transfer recipient hrp has no cosmos MsgSend vector (see atom::CHAINS)")?;
                let send = atom::Send {
                    from: atom::address_hrp(row.0, &pubkey), to: to.clone(),
                    denom: row.3.to_string(), amount: amount.parse().map_err(|_| "bad transfer amount")?,
                    memo: String::new(), pubkey,
                    sequence: cx.sequence, fee: 0, gas: cx.gas,
                    chain_id: row.2.to_string(), account_number: cx.account_number,
                };
                doc = Some(send.sign_doc());
            }
            Step::ExpectTo { .. } | Step::ExpectOut { .. } | Step::ExpectMemo { .. } | Step::CapFee { .. } | Step::Raw { .. } => {}
            other => return Err(format!("step not valid for the account family: {other:?}")),
        }
    }
    doc.ok_or_else(|| "account plan has no Deposit/Transfer step".into())
}

/// Assert the plan's assertion steps agree with its structural step: `ExpectMemo` must match the
/// `Deposit` memo, `ExpectTo` the `Transfer` recipient. Findings reuse the tools' string codes so
/// `check` and the raw guards stay in lockstep. Thin by construction; the bytes are built by `resolve`.
pub fn check(plan: &Plan) -> Vec<Finding> {
    let mut f = vec![];
    let memo = plan.steps.iter().find_map(|s| match s { Step::Deposit { memo, .. } => Some(memo.as_str()), _ => None });
    let recipient = plan.steps.iter().find_map(|s| match s { Step::Transfer { to, .. } => Some(to.as_str()), _ => None });
    for s in &plan.steps {
        match s {
            Step::ExpectMemo { memo: want } => {
                if memo != Some(want.as_str()) { f.push(Finding { code: "memo_not_expected".into() }) }
            }
            Step::ExpectTo { address } => {
                if recipient != Some(address.as_str()) { f.push(Finding { code: "destination_not_expected".into() }) }
            }
            _ => {}
        }
    }
    f
}
