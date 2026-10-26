//! Host-side HTTP for utxo-fetch, tx-broadcast and rpc ONLY. Offline tools must never depend on this
//! crate (scripts/check-deps.sh enforces it) and these binaries are not copied into the sealed image.
//! Bounded: 30 s timeout, no redirects, 8 KiB headers, MAX_BODY response bytes.
use serde_json::{json, Value};

pub const MAX_BODY: usize = 8 << 20;

fn finish(r: minreq::Request) -> Result<(i32, Vec<u8>), String> {
    let lazy = r.with_timeout(30).with_max_redirects(0).with_max_headers_size(8192).with_max_status_line_length(512)
        .send_lazy().map_err(|e| format!("http: {e}"))?;
    let code = lazy.status_code;
    let mut body = Vec::new();
    for b in lazy { let (b, _) = b.map_err(|e| format!("http: {e}"))?; body.push(b); if body.len() > MAX_BODY { return Err("response too large".into()) } }
    Ok((code, body))
}
fn ok(r: Result<(i32, Vec<u8>), String>) -> Result<Vec<u8>, String> {
    let (c, b) = r?;
    if !(200..300).contains(&c) { return Err(format!("http status {c}: {}", String::from_utf8_lossy(&b[..b.len().min(200)]).replace(|ch: char| ch.is_control(), " "))) }
    Ok(b)
}
pub fn check_url(u: &str) -> Result<(), String> {
    if u.starts_with("https://") || u.starts_with("http://127.0.0.1") || u.starts_with("http://localhost") { Ok(()) }
    else { Err("url must be https:// (plain http only for localhost test servers)".into()) }
}
/// Default public endpoints, one table shared by utxo-fetch, tx-broadcast and rpc.
/// (chain, base url, kind) where kind is "esplora", "evm", "koios", "substrate", "toncenter", "cosmos", "horizon", "algod".
pub const ENDPOINTS: &[(&str, &str, &str)] = &[
    ("btc", "https://blockstream.info/api", "esplora"),
    ("ltc", "https://litecoinspace.org/api", "esplora"),
    ("eth", "https://ethereum-rpc.publicnode.com", "evm"),
    ("ada", "https://api.koios.rest/api/v1", "koios"),
    ("dot", "https://polkadot-asset-hub-rpc.polkadot.io", "substrate"),
    ("ton", "https://toncenter.com/api/v2", "toncenter"),
    ("atom", "https://cosmos-rest.publicnode.com", "cosmos"),
    ("xlm", "https://horizon.stellar.org", "horizon"),
    ("algo", "https://mainnet-api.algonode.cloud", "algod"),
];
pub fn default_endpoint(chain: &str) -> Option<&'static str> { ENDPOINTS.iter().find(|e| e.0 == chain).map(|e| e.1) }

/// General request for `rpc`: any status is returned (JSON-RPC servers put errors in 4xx/5xx bodies).
/// Same bounds as get/post (no redirects, MAX_BODY, header limits); `timeout` in seconds.
/// Header VALUES are never included in any error string this returns.
pub fn send(method: &str, url: &str, body: Option<&[u8]>, headers: &[(String, String)], timeout: u64) -> Result<(i32, Vec<u8>), String> {
    check_url(url)?;
    let mut r = match method { "GET" => minreq::get(url), "POST" => minreq::post(url), _ => return Err("method must be GET or POST".into()) };
    for (k, v) in headers { r = r.with_header(k.as_str(), v.as_str()) }
    if let Some(b) = body { r = r.with_header("Content-Type", "application/json").with_body(b.to_vec()) }
    let lazy = r.with_timeout(timeout).with_max_redirects(0).with_max_headers_size(8192).with_max_status_line_length(512)
        .send_lazy().map_err(|e| match e { minreq::Error::TooManyRedirections => "redirect refused (rpc never follows redirects)".to_string(), e => format!("http: {e}") })?;
    let code = lazy.status_code;
    if (300..400).contains(&code) { return Err(format!("redirect refused (status {code}; rpc never follows redirects)")) }
    let mut out = Vec::new();
    for b in lazy { let (b, _) = b.map_err(|e| format!("http: {e}"))?; out.push(b); if out.len() > MAX_BODY { return Err("response too large".into()) } }
    Ok((code, out))
}
/// Esplora UTXOs of one address as utxo-fetch lines {"txid","vout","amount","address"[,"prev_tx"]}.
/// `legacy`: fetch prev_tx (the caller decides from the script type). Server data is re-checked.
pub fn esplora_utxos(base: &str, ad: &str, legacy: bool) -> Result<Vec<Value>, String> {
    let base = base.trim_end_matches('/');
    let body = get(&format!("{base}/address/{ad}/utxo"))?;
    let list: Vec<Value> = serde_json::from_slice(&body).map_err(|_| "bad utxo response".to_string())?;
    let mut out = vec![];
    for u in list {
        let txid = u["txid"].as_str().filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())).ok_or("bad txid from server")?;
        let vout = u["vout"].as_u64().filter(|&v| v <= u32::MAX as u64).ok_or("bad vout from server")?;
        let value = u["value"].as_u64().filter(|&v| v > 0 && v <= i64::MAX as u64).ok_or("bad value from server")?;
        let mut o = json!({"txid":txid,"vout":vout,"amount":value,"address":ad});
        if legacy {
            let hex = get(&format!("{base}/tx/{txid}/hex"))?;
            let hex = String::from_utf8(hex).ok().map(|s| s.trim().to_string()).filter(|s| s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())).ok_or("bad tx hex from server")?;
            o["prev_tx"] = json!(hex);
        }
        out.push(o);
        if out.len() > 2000 { return Err("more than 2000 utxos".into()) }
    }
    Ok(out)
}
pub fn get(url: &str) -> Result<Vec<u8>, String> { check_url(url)?; ok(finish(minreq::get(url))) }
pub fn post(url: &str, body: &[u8], ctype: &str) -> Result<Vec<u8>, String> {
    check_url(url)?; ok(finish(minreq::post(url).with_header("Content-Type", ctype).with_body(body.to_vec())))
}
/// One JSON-RPC 2.0 call; returns "result" or the error message.
pub fn rpc(url: &str, method: &str, params: Value) -> Result<Value, String> {
    let b = post(url, json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string().as_bytes(), "application/json")?;
    let v: Value = serde_json::from_slice(&b).map_err(|_| "bad json-rpc response".to_string())?;
    if let Some(e) = v.get("error") { return Err(format!("rpc error: {}", e["message"].as_str().unwrap_or("?").chars().take(200).collect::<String>())) }
    v.get("result").cloned().ok_or_else(|| "rpc: no result".into())
}
/// "0x1a" -> 26 (up to u128)
pub fn qty(v: &Value) -> Result<u128, String> {
    let s = v.as_str().and_then(|s| s.strip_prefix("0x")).ok_or("bad quantity")?;
    if s.is_empty() || s.len() > 32 { return Err("bad quantity".into()) }
    u128::from_str_radix(s, 16).map_err(|_| "bad quantity".into())
}
