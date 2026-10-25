//! tx-broadcast (HOST-SIDE, network): send ONE already-signed transaction, after the human reads
//! its summary on the terminal and types a code. Irreversible.
//!   tx-broadcast --chain btc|ltc|doge|eth [--url URL] < tx-sign output (or signed hex)
//! UTXO chains: POST {esplora}/tx; EVM: eth_sendRawTransaction. The id the server returns must
//! equal the id computed locally, or status is "error". Defaults as utxo-fetch.
use bitcoin::psbt::Psbt;
use serde_json::{json, Value};
use std::io::Read;

fn out(status: &str, extra: Value) -> ! {
    let mut v = json!({"tool":"tx-broadcast","status":status}); v.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    blocktools_io::outln!("{v}"); std::process::exit(if status == "ok" { 0 } else { 1 })
}
fn main() {
    blocktools_io::help("tx-broadcast --chain btc|ltc|doge|eth [--url URL] < signed tx  (asks for a code on the terminal)");
    let a: Vec<String> = std::env::args().collect();
    let one = |k: &str| a.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).last();
    let chain = one("--chain").unwrap_or("btc".into());
    let mut s = String::new();
    if std::io::stdin().take(blocktools_tx::MAX_INPUT as u64 + 1).read_to_string(&mut s).is_err() { out("bad_input", json!({})) }
    let shown = blocktools_tx::decode(&s, if chain == "eth" { "btc" } else { &chain }).unwrap_or_else(|e| out("bad_input", json!({"error":e})));
    if !shown.signed { out("refused", json!({"error":"not_signed"})) }
    // network bytes: the "signed_tx" field if present, else the input (a finalized PSBT is extracted)
    let raw = match serde_json::from_str::<Value>(s.trim()).ok().and_then(|v| v["signed_tx"].as_str().map(String::from)) {
        Some(h) => blocktools_core::hex_dec(&h).unwrap_or_else(|| out("bad_input", json!({"error":"signed_tx hex"}))),
        None => { let b = blocktools_tx::input_bytes(&s).unwrap_or_else(|e| out("bad_input", json!({"error":e})));
            match Psbt::deserialize(&b) { Ok(p) => bitcoin::consensus::serialize(&blocktools_tx::sign::extract(&p).unwrap_or_else(|e| out("refused", json!({"error":e})))), Err(_) => b } }
    };
    let d = blocktools_tx::decode_bytes(&raw, if chain == "eth" { "btc" } else { &chain }).unwrap_or_else(|e| out("bad_input", json!({"error":e})));
    if !d.signed || (d.evm.is_some() != (chain == "eth")) { out("refused", json!({"error":"chain_or_signature_mismatch"})) }
    if d.outputs.iter().map(|o| (&o.address, o.amount)).ne(shown.outputs.iter().map(|o| (&o.address, o.amount))) { out("refused", json!({"error":"signed_tx_differs_from_psbt"})) }
    let local = d.txid.clone().unwrap_or_default();
    let url = one("--url").unwrap_or_else(|| match chain.as_str() { "btc" => "https://blockstream.info/api".into(), "ltc" => "https://litecoinspace.org/api".into(),
        "eth" => "https://ethereum-rpc.publicnode.com".into(), _ => out("bad_input", json!({"error":"--url required"})) });
    let summary = format!("{}\nBROADCAST to {url}\nThis is irreversible.\n", shown.text().trim_end());
    if !blocktools_tty::confirm(&summary) { out("aborted", json!({})) }
    let hexs = blocktools_core::hex_enc(&raw);
    let got = if chain == "eth" {
        blocktools_net::rpc(&url, "eth_sendRawTransaction", json!([format!("0x{hexs}")])).map(|v| v.as_str().unwrap_or("").trim_start_matches("0x").to_ascii_lowercase())
    } else {
        blocktools_net::post(&format!("{}/tx", url.trim_end_matches('/')), hexs.as_bytes(), "text/plain").map(|b| String::from_utf8_lossy(&b).trim().to_ascii_lowercase())
    }.unwrap_or_else(|e| out("error", json!({"error":e})));
    let want = local.trim_start_matches("0x").to_ascii_lowercase();
    if let Some(mut t) = blocktools_tty::open() { use std::io::Write; let _ = writeln!(t, "server accepted; id {got}"); }
    if got != want { out("error", json!({"error":"server_id_differs_from_local","txid":want})) }
    out("ok", json!({"chain":chain,"txid":want}))
}
