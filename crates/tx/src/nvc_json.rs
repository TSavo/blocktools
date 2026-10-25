//! Novacoin: rebuild raw tx bytes from api.novaco.in `/gettransaction/<txid>` decoded JSON.
//! Layout (see `pos::layout("nvc")`): version i32, nTime u32, vin, vout (sorted by `index`),
//! locktime u32. Fails closed: the result is returned only if reverse(sha256d(raw)) equals both
//! `expected_txid` and the JSON's own `txid`. Values are integer base units (1 NVC = 1e6); a
//! decimal string/number with a '.' is read as NVC with at most 6 decimals (exact integer math).
//! A coinbase vin carries `coinbase`: the scriptSig hex, itself hex-encoded again by the API.
use crate::pos::{layout, PIn, PosTx};
use serde_json::Value;

fn hexb(s: &str) -> Result<Vec<u8>, &'static str> { blocktools_core::hex_dec(&s.to_ascii_lowercase()).ok_or("nvc_json_bad_hex") }
fn uint(v: &Value, max: u64) -> Result<u64, &'static str> {
    let n = match v {
        Value::Number(n) => n.as_u64().ok_or("nvc_json_bad_integer")?,
        Value::String(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => s.parse().map_err(|_| "nvc_json_bad_integer")?,
        _ => return Err("nvc_json_bad_integer"),
    };
    if n > max { return Err("nvc_json_integer_out_of_range") }
    Ok(n)
}
/// Amount in base units. Integers are base units; "x.y" is NVC (<= 6 decimals).
pub fn amount_units(v: &Value) -> Result<u64, &'static str> {
    let s = match v { Value::Number(n) => n.to_string(), Value::String(s) => s.clone(), _ => return Err("nvc_json_bad_value") };
    match s.split_once('.') {
        None => uint(&Value::String(s), i64::MAX as u64),
        Some((w, f)) => {
            if w.is_empty() || f.is_empty() || f.len() > 6 || !w.bytes().chain(f.bytes()).all(|b| b.is_ascii_digit()) { return Err("nvc_json_bad_value") }
            let w: u64 = w.parse().map_err(|_| "nvc_json_bad_value")?;
            let f: u64 = format!("{f:0<6}").parse().map_err(|_| "nvc_json_bad_value")?;
            w.checked_mul(1_000_000).and_then(|x| x.checked_add(f)).filter(|&x| x <= i64::MAX as u64).ok_or("nvc_json_bad_value")
        }
    }
}
fn txid_bytes(s: &str) -> Result<[u8; 32], &'static str> {
    let mut b: [u8; 32] = hexb(s)?.try_into().map_err(|_| "nvc_json_bad_txid")?; b.reverse(); Ok(b)
}
fn norm_txid(s: &str) -> Result<String, &'static str> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("nvc_json_bad_txid") }
    Ok(s.to_ascii_lowercase())
}

/// Parse the JSON into a PosTx (no hash check; use `serialize_nvc_tx_from_json`).
pub fn parse_nvc_json(v: &Value) -> Result<PosTx, &'static str> {
    let version = uint(v.get("version").ok_or("nvc_json_missing_version")?, i32::MAX as u64)? as i32;
    let time = uint(v.get("time").ok_or("nvc_json_missing_time")?, u32::MAX as u64)? as u32;
    let locktime = uint(v.get("locktime").ok_or("nvc_json_missing_locktime")?, u32::MAX as u64)? as u32;
    let mut l = layout("nvc").ok_or("nvc_layout")?; l.version = version;
    let mut inputs = vec![];
    for i in v.get("vin").and_then(Value::as_array).ok_or("nvc_json_missing_vin")? {
        let sequence = uint(i.get("sequence").ok_or("nvc_json_missing_sequence")?, u32::MAX as u64)? as u32;
        if let Some(cb) = i.get("coinbase") {
            // api.novaco.in hex-encodes the coinbase script's uppercase hex text a second time
            // (verified on 72b702b1..., block 1106297); decode both layers when the inner is hex.
            let outer = hexb(cb.as_str().ok_or("nvc_json_bad_coinbase")?)?;
            let script_sig = std::str::from_utf8(&outer).ok().filter(|t| !t.is_empty() && t.len() % 2 == 0 && t.bytes().all(|b| b.is_ascii_hexdigit()))
                .map_or(Ok(outer.clone()), hexb)?;
            inputs.push(PIn { txid: [0; 32], vout: u32::MAX, script_sig, sequence });
        } else {
            let txid = txid_bytes(i.get("txid").and_then(Value::as_str).ok_or("nvc_json_missing_vin_txid")?)?;
            let vout = uint(i.get("vout").ok_or("nvc_json_missing_vin_vout")?, u32::MAX as u64)? as u32;
            let ss = i.get("scriptSig").and_then(|s| s.get("hex")).and_then(Value::as_str).ok_or("nvc_json_missing_scriptsig")?;
            inputs.push(PIn { txid, vout, script_sig: hexb(ss)?, sequence });
        }
    }
    let mut outs = vec![];
    for o in v.get("vout").and_then(Value::as_array).ok_or("nvc_json_missing_vout")? {
        let idx = uint(o.get("index").ok_or("nvc_json_missing_vout_index")?, u32::MAX as u64)?;
        let val = amount_units(o.get("value").ok_or("nvc_json_missing_value")?)?;
        let spk = o.get("scriptPubKey").and_then(|s| s.get("hex")).and_then(Value::as_str).ok_or("nvc_json_missing_scriptpubkey")?;
        outs.push((idx, val, hexb(spk)?));
    }
    outs.sort_by_key(|o| o.0);
    if outs.iter().enumerate().any(|(n, o)| o.0 != n as u64) { return Err("nvc_json_vout_index_gap") }
    Ok(PosTx { layout: l, time, inputs, outputs: outs.into_iter().map(|o| (o.1, o.2)).collect(), locktime, speech: vec![] })
}

/// Raw tx hex from api.novaco.in decoded JSON; Err unless the hash equals `expected_txid` and
/// the JSON `txid` (and the byte length equals `size` when present).
pub fn serialize_nvc_tx_from_json(json: &str, expected_txid: &str) -> Result<String, &'static str> {
    let v: Value = serde_json::from_str(json).map_err(|_| "nvc_json_parse")?;
    let want = norm_txid(expected_txid)?;
    if norm_txid(v.get("txid").and_then(Value::as_str).ok_or("nvc_json_missing_txid")?)? != want { return Err("nvc_json_txid_not_expected") }
    let tx = parse_nvc_json(&v)?;
    let raw = tx.serialize();
    if let Some(sz) = v.get("size") { if uint(sz, u32::MAX as u64)? != raw.len() as u64 { return Err("nvc_json_size_mismatch") } }
    if tx.txid_hex() != want { return Err("nvc_json_hash_mismatch") }
    Ok(blocktools_core::hex_enc(raw))
}
