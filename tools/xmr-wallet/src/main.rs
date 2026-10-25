//! xmr-wallet: host-side driver for a LOCAL monero-wallet-rpc (loopback only; never runs in the sealed image).
//!   xmr-wallet scan  --rpc http://127.0.0.1:PORT --scan-req FILE [--open NAME]
//!       FILE = the 0600 `generate_from_keys` request written by `xmr-keys --scan-out` (view key, no spend key).
//!       Restores the view-only wallet (or opens NAME), refreshes, prints balance + received outputs (public).
//!   xmr-wallet sweep --rpc URL --to ADDR [--net main|stage|test] [--restore-height N] [--relay] < 25-word seed
//!       Restores the seed inside wallet-rpc, refreshes, builds sweep_all with do_not_relay, checks the plan
//!       (destination network, amount + fee == unlocked balance), prints it. --relay needs a human at a TTY
//!       typing the shown code; then relay_tx. Without --relay nothing is broadcast.
//! Seed and view key go only into the HTTP body sent to loopback; never to stdout/stderr.
use std::io::{Read, Write};
use blocktools_monero::*;
use serde_json::{json, Value};
use zeroize::Zeroizing;

fn die(code: i32, e: &str) -> ! { eprintln!("{}", json!({"tool":"xmr-wallet","status":"error","error":e})); std::process::exit(code) }
fn arg<'a>(a: &'a [String], k: &str) -> Option<&'a str> { a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).map(|s| s.as_str()) }

/// Accept only plain-HTTP loopback endpoints: the wallet RPC holds keys, it must not be remote.
pub fn loopback(url: &str) -> Option<String> {
    let rest = url.strip_prefix("http://")?;
    let hostport = rest.split('/').next()?;
    let (host, port) = hostport.rsplit_once(':')?;
    if !matches!(host, "127.0.0.1" | "localhost" | "[::1]") { return None; }
    let p: u16 = port.parse().ok()?;
    Some(format!("{}:{}", if host == "localhost" { "127.0.0.1" } else { host.trim_matches(|c| c == '[' || c == ']') }, p))
}

fn post(addr: &str, body: &[u8]) -> Value {
    let mut s = std::net::TcpStream::connect(addr).unwrap_or_else(|_| die(4, "rpc_connect"));
    s.set_read_timeout(Some(std::time::Duration::from_secs(3600))).ok();
    let head = format!("POST /json_rpc HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    s.write_all(head.as_bytes()).and_then(|_| s.write_all(body)).unwrap_or_else(|_| die(4, "rpc_write"));
    let mut r = Vec::new(); s.read_to_end(&mut r).unwrap_or_else(|_| die(4, "rpc_read"));
    let i = r.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or_else(|| die(4, "rpc_http"));
    if r.starts_with(b"HTTP/1.1 401") { die(4, "rpc_auth_required (run wallet-rpc on loopback with --disable-rpc-login)") }
    let v: Value = serde_json::from_slice(&r[i + 4..]).unwrap_or_else(|_| die(4, "rpc_json"));
    if let Some(e) = v.get("error") { die(5, &format!("rpc_error {}", e.get("code").and_then(|c| c.as_i64()).unwrap_or(0))) }
    v.get("result").cloned().unwrap_or(Value::Null)
}
fn call(addr: &str, m: &str, p: Value) -> Value { post(addr, json!({"jsonrpc":"2.0","id":"0","method":m,"params":p}).to_string().as_bytes()) }
fn u(v: &Value, k: &str) -> u64 { v.get(k).and_then(|x| x.as_u64()).unwrap_or(0) }

fn report_balance(rpc: &str, kind: &str) -> (String, u64, u64) {
    let addr = call(rpc, "get_address", json!({"account_index":0}))["address"].as_str().unwrap_or("").to_string();
    let b = call(rpc, "get_balance", json!({"account_index":0}));
    let h = u(&call(rpc, "get_height", json!({})), "height");
    println!("{}", json!({"tool":"xmr-wallet","status":"ok","chain":"xmr","kind":kind,"address":addr,
        "balance":u(&b,"balance"),"unlocked":u(&b,"unlocked_balance"),"wallet_height":h}));
    (addr, u(&b, "balance"), u(&b, "unlocked_balance"))
}

fn code() -> String {
    let mut b = [0u8; 4]; std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).unwrap_or_else(|_| die(1, "rng"));
    format!("{:06}", u32::from_le_bytes(b) % 1_000_000)
}
fn tty_confirm(summary: &str) -> bool {
    let mut t = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") { Ok(t) => t, Err(_) => return false };
    let c = code();
    let _ = write!(t, "{summary}\nType {c} to broadcast, anything else aborts: ");
    let mut line = String::new(); let mut byte = [0u8; 1];
    while t.read(&mut byte).map(|n| n == 1).unwrap_or(false) && byte[0] != b'\n' { line.push(byte[0] as char) }
    line.trim() == c
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let rpc = loopback(arg(&a, "--rpc").unwrap_or("")).unwrap_or_else(|| die(2, "rpc must be http://127.0.0.1:PORT (loopback only)"));
    let _ = call(&rpc, "get_version", json!({}));
    match a.first().map(|s| s.as_str()) {
        Some("scan") => {
            if let Some(name) = arg(&a, "--open") { call(&rpc, "open_wallet", json!({"filename":name,"password":""})); }
            else {
                let p = arg(&a, "--scan-req").unwrap_or_else(|| die(2, "need --scan-req FILE or --open NAME"));
                let body = Zeroizing::new(std::fs::read(p).unwrap_or_else(|_| die(1, "scan_req_read")));
                post(&rpc, &body);
            }
            call(&rpc, "refresh", json!({}));
            report_balance(&rpc, "scan");
            // get_transfers works for view-only wallets (incoming_transfers needs key images).
            let t = call(&rpc, "get_transfers", json!({"in":true,"pool":true,"account_index":0}));
            for k in ["in", "pool"] { for o in t.get(k).and_then(|x| x.as_array()).cloned().unwrap_or_default() {
                println!("{}", json!({"tool":"xmr-wallet","status":"ok","chain":"xmr","kind":"received","txid":o["txid"],
                    "amount":u(&o,"amount"),"height":u(&o,"height"),"confirmations":u(&o,"confirmations"),"pool":k=="pool"}));
            } }
            call(&rpc, "close_wallet", json!({}));
        }
        Some("sweep") => {
            let net = match arg(&a, "--net") { None | Some("main") => Net::Main, Some("stage") => Net::Stage, Some("test") => Net::Test, _ => die(2, "bad_net") };
            let to = arg(&a, "--to").unwrap_or_else(|| die(2, "need --to ADDR"));
            match validate(to) { Ok((n, _, _)) if n == net => {}, Ok(_) => die(2, "to_wrong_network"), Err(_) => die(2, "to_invalid") }
            let mut s = Zeroizing::new(String::new()); std::io::stdin().read_to_string(&mut s).ok();
            let seed = Zeroizing::new(s.split_whitespace().collect::<Vec<_>>().join(" "));
            if !is_seed_shape(&seed) || seed_to_spend(&seed).is_err() { die(2, "not_a_monero_seed") }
            let height: u64 = arg(&a, "--restore-height").map(|h| h.parse().unwrap_or_else(|_| die(2, "bad_restore_height"))).unwrap_or(0);
            let name = format!("blocktools-sweep-{}", code());
            let body = Zeroizing::new(json!({"jsonrpc":"2.0","id":"0","method":"restore_deterministic_wallet","params":
                {"filename":name,"seed":seed.as_str(),"restore_height":height,"password":"","language":"English","autosave_current":true}}).to_string());
            post(&rpc, body.as_bytes());
            call(&rpc, "refresh", json!({}));
            let (_, _, unlocked) = report_balance(&rpc, "sweep-source");
            if unlocked == 0 { call(&rpc, "close_wallet", json!({})); die(3, "nothing_unlocked_to_sweep") }
            let r = call(&rpc, "sweep_all", json!({"address":to,"account_index":0,"do_not_relay":true,"get_tx_metadata":true,"get_tx_hex":false}));
            let amts: Vec<u64> = r["amount_list"].as_array().cloned().unwrap_or_default().iter().filter_map(|x| x.as_u64()).collect();
            let fees: Vec<u64> = r["fee_list"].as_array().cloned().unwrap_or_default().iter().filter_map(|x| x.as_u64()).collect();
            let hashes = r["tx_hash_list"].clone();
            let meta: Vec<String> = r["tx_metadata_list"].as_array().cloned().unwrap_or_default().iter().filter_map(|x| x.as_str().map(String::from)).collect();
            let (sa, sf) = (amts.iter().sum::<u64>(), fees.iter().sum::<u64>());
            let ok = sa + sf == unlocked && !meta.is_empty() && meta.len() == amts.len();
            println!("{}", json!({"tool":"xmr-wallet","status": if ok {"ok"} else {"error"},"chain":"xmr","kind":"sweep-plan","to":to,
                "amount":sa,"fee":sf,"txs":meta.len(),"tx_hashes":hashes,"amount_plus_fee_equals_unlocked":ok,"relayed":false}));
            if !ok { call(&rpc, "close_wallet", json!({})); die(3, "plan_check_failed") }
            if a.iter().any(|x| x == "--relay") {
                if !tty_confirm(&format!("Sweep {sa} atomic units (fee {sf}) to {to}")) { call(&rpc, "close_wallet", json!({})); die(3, "not_confirmed (needs a human at a TTY)") }
                let mut sent = Vec::new();
                for m in &meta { sent.push(call(&rpc, "relay_tx", json!({"hex":m}))["tx_hash"].clone()); }
                println!("{}", json!({"tool":"xmr-wallet","status":"ok","chain":"xmr","kind":"sweep-relayed","to":to,"tx_hashes":sent,"relayed":true}));
            }
            call(&rpc, "close_wallet", json!({}));
        }
        _ => die(2, "usage: xmr-wallet scan|sweep --rpc http://127.0.0.1:PORT ..."),
    }
}

#[cfg(test)]
mod t {
    use super::*;
    #[test] fn only_loopback() {
        assert_eq!(loopback("http://127.0.0.1:38083").as_deref(), Some("127.0.0.1:38083"));
        assert_eq!(loopback("http://localhost:1/json_rpc").as_deref(), Some("127.0.0.1:1"));
        for bad in ["https://127.0.0.1:1", "http://10.0.0.2:38083", "http://evil.com:38083", "http://127.0.0.1", "http://127.0.0.1.evil.com:1"] { assert!(loopback(bad).is_none(), "{bad}") }
    }
}
