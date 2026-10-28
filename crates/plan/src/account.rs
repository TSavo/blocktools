//! Account family: resolve a `Plan` to an unsigned Cosmos **SignDoc** (SIGN_MODE_DIRECT). Orchestrates
//! blocktools-acct (the THORChain `MsgDeposit` and Cosmos `MsgSend` builders) -- no protobuf encoding and
//! no crypto of its own, per the RFC #15 "orchestrate, never duplicate" rule. Live facts (sequence,
//! account_number, gas, and the signer pubkey) come in via `context::Account`.
use crate::{context, Finding, Plan, Step};
use blocktools_acct::{atom, thor};
use serde_json::json;

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
///   - `Raw{kind:"account.sign_doc"}` -> opaque SignDoc bytes rebuilt verbatim (the totality escape
///     hatch, inverse of `represent`'s fallback, so `resolve(represent(doc)) == doc` holds for every doc)
/// Assertion steps and other `Raw` are ignored here (they belong to `check`). A step from another family errors.
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
            Step::Raw { kind, fields } if kind == "account.sign_doc" => {
                if doc.is_some() { return Err("account plan: more than one structural step".into()) }
                let h = fields["doc"].as_str().ok_or("account.sign_doc raw needs a doc field")?;
                doc = Some(blocktools_core::hex_dec(h.trim_start_matches("0x")).ok_or("bad account.sign_doc raw hex")?);
            }
            Step::ExpectTo { .. } | Step::ExpectOut { .. } | Step::ExpectMemo { .. } | Step::CapFee { .. } | Step::Raw { .. } => {}
            other => return Err(format!("step not valid for the account family: {other:?}")),
        }
    }
    doc.ok_or_else(|| "account plan has no Deposit/Transfer step".into())
}

/// The inverse of `resolve`: decode an unsigned SignDoc back into the IR (what `tx-decode` emits for the
/// Account family), reusing the acct crate's own canonical decoders so nothing is re-implemented. A
/// THORChain `MsgDeposit` lifts to `Step::Deposit`; a Cosmos bank `MsgSend` to `Step::Transfer`; anything
/// else -- including a doc the structured steps cannot reproduce byte-for-byte -- is held verbatim in
/// `Raw{kind:"account.sign_doc"}` so representability is total and the bytes round-trip through `resolve`.
/// The live facts (sequence/account_number/gas/pubkey) are not part of the IR and are dropped here; they
/// come back in via `context::Account` at resolve time.
pub fn represent(sign_doc: &[u8]) -> Plan {
    // THORChain MsgDeposit. `resolve` sets asset_symbol == asset_ticker and chain_id == thorchain-1, so a
    // doc outside that shape must round-trip through Raw, not a lossy Deposit.
    if let Ok(d) = thor::Deposit::decode_sign_doc(sign_doc) {
        if d.chain_id == thor::CHAIN_ID && d.asset_symbol == d.asset_ticker {
            return Plan { chain: "rune".into(), chain_id: None, steps: vec![
                Step::Deposit {
                    asset: format!("{}.{}", d.asset_chain, d.asset_ticker),
                    amount: d.amount.to_string(), memo: d.memo,
                },
            ]};
        }
    }
    // Cosmos bank MsgSend. `resolve` rebuilds it with the base denom, no fee coin and an empty memo, so a
    // Send outside that shape (custom denom, fee coin, memo) round-trips through Raw instead.
    if let Ok(s) = atom::Send::decode_sign_doc(sign_doc) {
        if let Some(row) = atom::chain_of(&s.to) {
            if s.fee == 0 && s.memo.is_empty() && s.denom == row.3 {
                return Plan { chain: row.0.into(), chain_id: None, steps: vec![
                    Step::Transfer { to: s.to, amount: s.amount.to_string() },
                ]};
            }
        }
    }
    Plan { chain: String::new(), chain_id: None, steps: vec![
        Step::Raw { kind: "account.sign_doc".into(), fields: json!({"doc": format!("0x{}", blocktools_core::hex_enc(sign_doc))}) },
    ]}
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
