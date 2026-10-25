//! JS/TS surface. Inputs are strings / arrays; outputs are JSON strings (callers `JSON.parse`).
//! Errors are thrown as short strings. Nothing here accepts private key material.
#![forbid(unsafe_code)]
use blocktools::tx::policy::{check, Policy};
use blocktools::{chains, plan, tx, validate as v, xpub};
use serde_json::json;
use wasm_bindgen::prelude::*;

fn err(e: impl AsRef<str>) -> JsError { JsError::new(e.as_ref()) }

/// Address kind ("P2pkh", "SegwitV0", "Eth", ...) if `address` is valid for `chain`; throws otherwise.
#[wasm_bindgen(js_name = validateAddress)]
pub fn validate_address(chain: &str, address: &str) -> Result<String, JsError> {
    v::validate(chain, address).map(|k| format!("{k:?}")).map_err(err)
}

/// Chains this build knows: JSON array of names.
#[wasm_bindgen(js_name = listChains)]
pub fn list_chains() -> String { json!(chains::CHAINS.iter().map(|c| c.name).collect::<Vec<_>>()).to_string() }

/// Watch-only addresses from an account-level xpub: JSON [{chain,kind,path,address}].
#[wasm_bindgen(js_name = addressesFromXpub)]
pub fn addresses_from_xpub(xpub_str: &str, chain: &str, kinds: Vec<String>, branches: Vec<u32>, indices: Vec<u32>) -> Result<String, JsError> {
    let c = chains::chain(chain).ok_or_else(|| err("unknown chain"))?;
    let k: Vec<&str> = kinds.iter().map(|s| s.as_str()).collect();
    let rows = xpub::from_xpub(xpub_str, c, &k, &branches, &indices).map_err(err)?;
    Ok(json!(rows.iter().map(|r| json!({"chain": r.chain, "kind": r.kind, "path": r.path, "address": r.address})).collect::<Vec<_>>()).to_string())
}

/// `derive --explain` for the given derive flags: JSON [{chain,kind,template,path,count}]. No keys.
#[wasm_bindgen(js_name = explainPlan)]
pub fn explain_plan(args: Vec<String>) -> Result<String, JsError> {
    let o = plan::from_args(&args).map_err(err)?;
    Ok(json!(plan::explain(&o).iter().map(|e| json!({"chain": e.chain, "kind": e.kind, "template": e.template, "path": e.path, "count": e.count})).collect::<Vec<_>>()).to_string())
}

/// Decode a transaction (hex/base64 raw, PSBT, EVM RLP, or a JSON line): JSON array of the tx-decode lines.
#[wasm_bindgen(js_name = decodeTx)]
pub fn decode_tx(input: &str, chain: &str) -> Result<String, JsError> {
    Ok(json!(tx::decode(input, chain).map_err(err)?.json_lines()).to_string())
}

/// Plain-text summary of a transaction (what tx-decode --text prints).
#[wasm_bindgen(js_name = describeTx)]
pub fn describe_tx(input: &str, chain: &str) -> Result<String, JsError> { Ok(tx::decode(input, chain).map_err(err)?.text()) }

/// tx-verify: JSON {ok, failures, warnings}. `max_fee` is a decimal string (sats or wei) or "".
#[wasm_bindgen(js_name = verifyTx)]
pub fn verify_tx(input: &str, chain: &str, expect_to: Vec<String>, change: Vec<String>, chain_id: Option<u32>, max_fee: &str, allow_warnings: bool) -> Result<String, JsError> {
    let d = tx::decode(input, chain).map_err(err)?;
    let max_fee = if max_fee.is_empty() { None } else { Some(max_fee.parse::<u128>().map_err(|_| err("max_fee"))?) };
    let p = Policy { expect_to, change, chain_id: chain_id.map(u64::from), max_fee, allow_warnings };
    let f = check(&d, &p);
    Ok(json!({"ok": f.is_empty(), "failures": f, "warnings": d.warnings}).to_string())
}
