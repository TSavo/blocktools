//! Host-side HTTP for utxo-fetch and tx-broadcast ONLY. Offline tools must never depend on this
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
