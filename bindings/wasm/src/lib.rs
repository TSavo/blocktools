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
pub fn list_chains() -> String { let mut v: Vec<&str> = chains::CHAINS.iter().map(|c| c.name).collect(); v.push("zec"); json!(v).to_string() }

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

// ---- Stable API (EXPORTS.md). Everything below refuses unverified chains. ----

/// Library version (semver string, same as the `blocktools` crate).
#[wasm_bindgen]
pub fn version() -> String { blocktools::VERSION.to_string() }

fn row(c: &chains::Chain) -> serde_json::Value {
    json!({"name": c.name, "ticker": c.ticker, "title": c.title, "slip44": c.coin, "verified": c.verified,
           "sources": c.sources.iter().map(|s| json!({"name": s.name, "url": s.url, "api": s.api, "checked": s.checked})).collect::<Vec<_>>()})
}
/// Verified (supported) chains: JSON [{name,ticker,title,slip44,verified:true,sources:[{name,url,api,checked}]}].
#[wasm_bindgen(js_name = supportedChains)]
pub fn supported_chains() -> String {
    let mut v: Vec<serde_json::Value> = chains::CHAINS.iter().filter(|c| c.verified).map(row).collect();
    // Zcash transparent lives outside the table (two-byte prefixes). Verified: ZIP-243/244 official
    // txid+sighash vectors, 7 mainnet txs, 21 mainnet script->address pairs from blockchair.
    v.push(json!({"name": "zec", "ticker": "ZEC", "title": "Zcash (transparent)", "slip44": 133, "verified": true, "scope": "transparent", "sources": []}));
    json!(v).to_string()
}
/// Known but unverified chains (NOT supported by the other calls): same shape, verified:false.
#[wasm_bindgen(js_name = unverifiedChains)]
pub fn unverified_chains() -> String { json!(chains::CHAINS.iter().filter(|c| !c.verified).map(row).collect::<Vec<_>>()).to_string() }

/// `derive::from_xpub(chain, xpub, path, index)`: JSON [{chain,kind,path,address}] for every script kind.
#[wasm_bindgen(js_name = deriveFromXpub)]
pub fn derive_from_xpub(chain: &str, xpub_str: &str, path: &str, index: u32) -> Result<String, JsError> {
    let rows = blocktools::derive::from_xpub(chain, xpub_str, path, index).map_err(err)?;
    Ok(json!(rows.iter().map(|r| json!({"chain": r.chain, "kind": r.kind, "path": r.path, "address": r.address})).collect::<Vec<_>>()).to_string())
}
/// `address::validate(chain, addr)`: address kind string; throws on invalid / unverified chain.
#[wasm_bindgen(js_name = addressValidate)]
pub fn address_validate(chain: &str, addr: &str) -> Result<String, JsError> {
    blocktools::address::validate(chain, addr).map(|k| format!("{k:?}")).map_err(err)
}
/// Fail-closed tx check, JSON in / JSON out; never throws. See EXPORTS.md for the schema.
#[wasm_bindgen(js_name = checkTx)]
pub fn check_tx(input_json: &str) -> String { blocktools::check::tx_json(input_json) }

/// Every verified chain (and `zec`) on which `addr` is valid: JSON [{chain,kind}]. Collisions
/// (DGB/DOGE, VIA/VTC, version 50/0 ...) return all candidates; an empty list = unrecognised.
#[wasm_bindgen(js_name = detectAddress)]
pub fn detect_address(addr: &str) -> String {
    json!(blocktools::address::detect(addr).iter().map(|(c, k)| json!({"chain": c, "kind": format!("{k:?}")})).collect::<Vec<_>>()).to_string()
}
/// Additive to detectAddress (whose shape is unchanged): JSON {candidates:[{chain,kind}], ambiguous, kinds_agree}.
/// `ambiguous` = more than one chain; `kinds_agree` = every candidate has the same script kind.
#[wasm_bindgen(js_name = detectAddressInfo)]
pub fn detect_address_info(addr: &str) -> String {
    let d = blocktools::address::detect(addr);
    let kinds: Vec<String> = d.iter().map(|(_, k)| format!("{k:?}")).collect();
    json!({"candidates": d.iter().zip(&kinds).map(|((c, _), k)| json!({"chain": c, "kind": k})).collect::<Vec<_>>(),
           "ambiguous": d.len() > 1, "kinds_agree": kinds.windows(2).all(|w| w[0] == w[1])}).to_string()
}
/// Same hash, re-encoded for `to`; throws `ambiguous_address` when candidates disagree on the script type.
#[wasm_bindgen(js_name = convertAddress)]
pub fn convert_address(addr: &str, to: &str) -> Result<String, JsError> { blocktools::address::convert(addr, to).map_err(err) }
/// As convertAddress with the source chain stated.
#[wasm_bindgen(js_name = convertAddressFrom)]
pub fn convert_address_from(from: &str, addr: &str, to: &str) -> Result<String, JsError> { blocktools::address::convert_from(from, addr, to).map_err(err) }
/// Full parameter table: JSON [{name,ticker,title,slip44,verified,p2pkh[],p2sh[],hrp,wif,checksum,decimals,forkid,tx_format,sweep_build,sources}].
#[wasm_bindgen(js_name = chainParams)]
pub fn chain_params() -> String { blocktools::address::params_json().to_string() }
/// Unsigned sweep of all `utxos` (JSON lines {txid,vout,amount,address[,prev_tx]}) to `to`:
/// JSON {chain,tx_format,psbt,unsigned_tx,inputs,amount,fee}. Legacy, legacy-sha256 and forkid
/// formats; pos-ntime chains need `buildUnsignedSweepAt` (a tx timestamp).
#[wasm_bindgen(js_name = buildUnsignedSweep)]
pub fn build_unsigned_sweep(chain: &str, utxos: &str, to: &str, fee_rate: u32) -> Result<String, JsError> {
    blocktools::sweep::build_unsigned_sweep(chain, utxos, to, fee_rate as u64).map(|v| v.to_string()).map_err(err)
}
/// As `buildUnsignedSweep` with tx timestamp `time` (unix seconds). For pos-ntime chains
/// (ppc/nvc/clam/rdd) returns {chain,tx_format:"pos-ntime",unsigned_tx,time,pos_prevouts,inputs,amount,fee}
/// (no PSBT exists for that format); other chains ignore `time`.
#[wasm_bindgen(js_name = buildUnsignedSweepAt)]
pub fn build_unsigned_sweep_at(chain: &str, utxos: &str, to: &str, fee_rate: u32, time: u32) -> Result<String, JsError> {
    blocktools::sweep::build_unsigned_sweep_at(chain, utxos, to, fee_rate as u64, time).map(|v| v.to_string()).map_err(err)
}
