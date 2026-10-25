//! SwapChan lift 7: EVM transfer builder (ethforks `forkSweep` / extraevm `evmSweep`) and UTXO coin selection
//! (utxochains `selectUtxos`). No secrets: the builder returns the unsigned tx and its signing hash.
use crate::tx::evm::{transfer_calldata, Kind, Tx};
use crate::tx::rlp::Rlp;
use serde_json::{json, Value};

fn num(v: &Value, k: &str) -> Result<Option<u128>, String> {
    match &v[k] {
        Value::Null => Ok(None),
        Value::Number(n) => n.as_u64().map(|x| Some(x as u128)).ok_or(format!("bad_{k}")),
        Value::String(s) => {
            let s = s.trim();
            let r = if let Some(h) = s.strip_prefix("0x") { u128::from_str_radix(h, 16) } else if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) { s.parse() } else { return Err(format!("bad_{k}")) };
            r.map(Some).map_err(|_| format!("bad_{k}"))
        }
        _ => Err(format!("bad_{k}")),
    }
}
fn need(v: &Value, k: &str) -> Result<u128, String> { num(v, k)?.ok_or(format!("missing_{k}")) }
fn addr(v: &Value, k: &str) -> Result<[u8; 20], String> {
    let s = v[k].as_str().ok_or(format!("missing_{k}"))?;
    let h = s.strip_prefix("0x").filter(|h| h.len() == 40).ok_or(format!("bad_{k}"))?;
    crate::hex_dec(h).and_then(|b| b.try_into().ok()).ok_or(format!("bad_{k}"))
}
fn hx(b: &[u8]) -> String { format!("0x{}", crate::hex_enc(b)) }

/// Build an unsigned EIP-155 transfer. Input JSON (integers as decimal / 0x strings or JSON numbers):
/// `{chainId, nonce, gas, gasPrice, to, value | balance, token?, maxPriorityFeePerGas?, from?}`.
/// `balance` (instead of `value`) = sweep: native value = balance − gas × gasPrice (`insufficient_balance` if ≤ 0);
/// with `token`, `value` is the token amount and the native value is 0 (balance is then the token balance).
/// `maxPriorityFeePerGas` present → type-2 tx with maxFeePerGas = gasPrice; else legacy.
pub fn build_evm_transfer(req: &Value) -> Result<Value, String> {
    let chain_id = need(req, "chainId")?;
    if chain_id == 0 || chain_id > u64::MAX as u128 { return Err("bad_chainId".into()) }
    let nonce = need(req, "nonce")?; let gas = need(req, "gas")?; let price = need(req, "gasPrice")?;
    if nonce > u64::MAX as u128 { return Err("bad_nonce".into()) }
    if gas < 21000 || gas > 30_000_000 { return Err("bad_gas".into()) }
    let to = addr(req, "to")?;
    let token = if req["token"].is_null() || req["token"] == "" { None } else { Some(addr(req, "token")?) };
    let fee = gas.checked_mul(price).ok_or("fee_overflow")?;
    let (val, bal) = (num(req, "value")?, num(req, "balance")?);
    let amount = match (val, bal) {
        (Some(_), Some(_)) => return Err("value_and_balance".into()),
        (Some(v), None) => v,
        (None, Some(b)) if token.is_some() => b,
        (None, Some(b)) => b.checked_sub(fee).filter(|&v| v > 0).ok_or("insufficient_balance")?,
        (None, None) => return Err("missing_value".into()),
    };
    if amount == 0 { return Err("zero_value".into()) }
    let tip = num(req, "maxPriorityFeePerGas")?;
    if tip.is_some_and(|t| t > price) { return Err("tip_above_max_fee".into()) }
    let (tx_to, value, data) = match token { Some(t) => (t, 0, transfer_calldata(&to, amount)), None => (to, amount, vec![]) };
    let tx = Tx { kind: if tip.is_some() { Kind::Eip1559 } else { Kind::Legacy }, chain_id: Some(chain_id as u64), nonce: nonce as u64,
        max_fee_per_gas: price, max_priority_fee_per_gas: tip, gas: gas as u64, to: Some(tx_to), value, data: data.clone(),
        access_list: Rlp::L(vec![]), sig: None };
    let mut o = json!({ "unsigned": hx(&tx.encode_unsigned()), "sighash": hx(&tx.sighash()),
        "kind": if tip.is_some() { "eip1559" } else { "legacy" }, "chainId": chain_id as u64, "nonce": nonce.to_string(),
        "gas": gas.to_string(), "gasPrice": price.to_string(), "to": hx(&tx_to), "value": value.to_string(),
        "data": hx(&data), "fee": fee.to_string() });
    if let Some(t) = tip { o["maxPriorityFeePerGas"] = t.to_string().into() }
    if token.is_some() { o["token"] = hx(&tx_to).into(); o["recipient"] = hx(&to).into(); o["amount"] = amount.to_string().into() }
    if let Some(f) = req["from"].as_str() { o["from"] = f.into() }
    Ok(o)
}

/// Estimated vbytes to spend one P2PKH-sized input (SwapChan's constant).
pub const INPUT_VBYTES: u128 = 148;
/// An input is uneconomic when its spend fee exceeds 5% of its value: value < rate × 148 × 20.
pub const ECON_FACTOR: u128 = 20;
pub const MAX_INPUTS: usize = 200;

/// Coin selection: keep UTXOs whose `script` equals `script_hex` (case-insensitive), drop those with
/// value < rate × 148 × 20, sort largest-first (stable on input order), cap at 200.
/// Input: `[{txid, vout, value, script, ...}]` (extra fields are passed through).
/// Output: `{selected:[...], total, count, dropped_foreign, dropped_uneconomic, dropped_cap, min_value}`.
pub fn select_utxos(utxos: &Value, script_hex: &str, rate: u128) -> Result<Value, String> {
    let list = utxos.as_array().ok_or("bad_utxos")?;
    let own = script_hex.trim_start_matches("0x").to_ascii_lowercase();
    let min = rate.checked_mul(INPUT_VBYTES * ECON_FACTOR).ok_or("bad_rate")?;
    let (mut foreign, mut unecon) = (0usize, 0usize);
    let mut keep: Vec<(u128, &Value)> = vec![];
    for u in list {
        let v = need(u, "value").map_err(|_| "bad_utxo_value")?;
        if u["txid"].as_str().is_none() || u["vout"].as_u64().is_none() { return Err("bad_utxo".into()) }
        if u["script"].as_str().map(|s| s.trim_start_matches("0x").to_ascii_lowercase()) != Some(own.clone()) { foreign += 1; continue }
        if v < min { unecon += 1; continue }
        keep.push((v, u));
    }
    keep.sort_by(|a, b| b.0.cmp(&a.0));
    let cap = keep.len().saturating_sub(MAX_INPUTS);
    keep.truncate(MAX_INPUTS);
    let total: u128 = keep.iter().map(|k| k.0).sum();
    Ok(json!({ "selected": keep.iter().map(|k| k.1.clone()).collect::<Vec<_>>(), "total": total.to_string(), "count": keep.len(),
        "dropped_foreign": foreign, "dropped_uneconomic": unecon, "dropped_cap": cap, "min_value": min.to_string() }))
}
