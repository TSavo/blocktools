//! utxo-fetch (HOST-SIDE, network): public chain data for addresses -> files tx-build reads.
//!   utxo-fetch --chain btc|ltc|doge [--url ESPLORA_BASE] [--no-prev-tx] [ADDR...]  (or addresses on stdin)
//!       stdout: UTXO JSON lines {"txid","vout","amount","address"[,"prev_tx"]}  (tx-build --utxos FILE)
//!   utxo-fetch --chain eth [--url RPC] ADDR
//!       stdout: one account object {"nonce","balance","max_fee_per_gas","max_priority_fee_per_gas","chain_id"}
//! Only ADDRESSES go in (bare, or JSON lines with an "address" field, e.g. kr-redact output).
//! Server data is untrusted: txids are re-checked here, prev_tx is re-hashed by tx-build.
//! A summary goes to stderr. Defaults: btc blockstream.info, ltc litecoinspace.org, eth publicnode.
use serde_json::{json, Value};
use std::io::{BufRead, Read};

fn die(e: &str) -> ! { eprintln!("{}", json!({"tool":"utxo-fetch","status":"error","error":e})); std::process::exit(1) }
fn main() {
    kr_io::help("utxo-fetch --chain btc|ltc|doge|eth [--url URL] [--no-prev-tx] [ADDR...] -> UTXO lines / account object");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut chain = "btc".to_string(); let mut url = None; let mut prev = true; let mut addrs = Vec::new();
    let mut it = a.into_iter();
    while let Some(x) = it.next() { match x.as_str() {
        "--chain" => chain = it.next().unwrap_or_else(|| die("--chain")), "--url" => url = it.next(), "--no-prev-tx" => prev = false,
        s if s.starts_with('-') => die("unknown flag"), _ => addrs.push(x) } }
    if addrs.is_empty() {
        for l in std::io::stdin().lock().take(4 << 20).lines().map_while(Result::ok) {
            let t = l.trim(); if t.is_empty() { continue }
            match serde_json::from_str::<Value>(t) { Ok(v) if v.is_object() => if let Some(s) = v["address"].as_str() { addrs.push(s.to_string()) }, _ => addrs.push(t.to_string()) }
        }
    }
    addrs.sort(); addrs.dedup();
    if addrs.is_empty() || addrs.len() > 1000 { die("give 1..1000 addresses") }
    let vchain = if chain == "eth" { "eth" } else { chain.as_str() };
    for x in &addrs { if kr_core::validate::validate(vchain, x).is_err() { die("invalid address for chain") } }
    if chain == "eth" { return eth(url.as_deref().unwrap_or("https://ethereum-rpc.publicnode.com"), &addrs) }
    let base = url.unwrap_or_else(|| match chain.as_str() { "btc" => "https://blockstream.info/api".into(), "ltc" => "https://litecoinspace.org/api".into(), _ => die("--url ESPLORA_BASE required for this chain") });
    let base = base.trim_end_matches('/');
    let (mut n, mut total) = (0u64, 0u64);
    for ad in &addrs {
        let body = kr_net::get(&format!("{base}/address/{ad}/utxo")).unwrap_or_else(|e| die(&e));
        let list: Vec<Value> = serde_json::from_slice(&body).unwrap_or_else(|_| die("bad utxo response"));
        let legacy = !(ad.starts_with("bc1") || ad.starts_with("ltc1") || ad.starts_with("tb1"));
        for u in list {
            let txid = u["txid"].as_str().filter(|t| t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())).unwrap_or_else(|| die("bad txid from server"));
            let vout = u["vout"].as_u64().filter(|&v| v <= u32::MAX as u64).unwrap_or_else(|| die("bad vout from server"));
            let value = u["value"].as_u64().filter(|&v| v > 0 && v <= 21_000_000 * 100_000_000).unwrap_or_else(|| die("bad value from server"));
            let mut o = json!({"txid":txid,"vout":vout,"amount":value,"address":ad});
            if prev && legacy {
                let hex = kr_net::get(&format!("{base}/tx/{txid}/hex")).unwrap_or_else(|e| die(&e));
                let hex = String::from_utf8(hex).ok().map(|s| s.trim().to_string()).filter(|s| s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())).unwrap_or_else(|| die("bad tx hex from server"));
                o["prev_tx"] = json!(hex);
            }
            kr_io::outln!("{o}"); n += 1; total = total.saturating_add(value);
            if n > 2000 { die("more than 2000 utxos") }
        }
    }
    eprintln!("{}", json!({"tool":"utxo-fetch","status":"done","chain":chain,"count":n,"amount":total}));
}
fn eth(url: &str, addrs: &[String]) {
    if addrs.len() != 1 { die("eth: give exactly one address") }
    let ad = &addrs[0];
    let q = |m: &str, p: Value| kr_net::rpc(url, m, p).and_then(|v| kr_net::qty(&v)).unwrap_or_else(|e| die(&e));
    let chain_id = q("eth_chainId", json!([]));
    let nonce = q("eth_getTransactionCount", json!([ad, "pending"]));
    let balance = q("eth_getBalance", json!([ad, "latest"]));
    let gas_price = q("eth_gasPrice", json!([]));
    let prio = kr_net::rpc(url, "eth_maxPriorityFeePerGas", json!([])).and_then(|v| kr_net::qty(&v)).unwrap_or(1_000_000_000);
    // maxFee = 2 x current gas price (+ tip): headroom for base-fee rises; unused fee is not charged.
    kr_io::outln!("{}", json!({"chain_id":chain_id as u64,"nonce":nonce as u64,"balance":balance.to_string(),
        "max_fee_per_gas":gas_price.saturating_mul(2).saturating_add(prio).to_string(),"max_priority_fee_per_gas":prio.to_string()}));
    eprintln!("{}", json!({"tool":"utxo-fetch","status":"done","chain":"eth","count":1}));
}
