//! xpub-addresses: extended public key (xpub/ypub/zpub/tpub..., stdin, one per line) -> watch-only
//! addresses. No secrets in or out: an xpub can't sign, so nothing found here can be swept.
//!   xpub-addresses [--chain btc] [--kind p2wpkh,...] [--change 0,1] [--count 20]
//! Paths in the output are relative to the xpub (m/{change}/{i}); only non-hardened steps exist.
use blocktools_core::{chains, xpub};
use serde_json::json;
use std::io::BufRead;
fn main() {
    blocktools_io::help("xpub-addresses [--chain btc] [--kind p2wpkh,..] [--change 0,1] [--count 20] < xpub -> address lines");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let arg = |k: &str| a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).cloned();
    let fail = |e: &str| -> ! { blocktools_io::outln!("{}", json!({"tool":"xpub-addresses","status":"error","error":e})); std::process::exit(2) };
    let chain = chains::chain(&arg("--chain").unwrap_or_else(|| "btc".into())).unwrap_or_else(|| fail("unknown chain"));
    let kinds_s = arg("--kind").unwrap_or_default();
    let kinds: Vec<&str> = kinds_s.split(',').filter(|s| !s.is_empty()).collect();
    let branches: Vec<u32> = arg("--change").unwrap_or_else(|| "0".into()).split(',').map(|s| s.parse().unwrap_or_else(|_| fail("bad --change"))).collect();
    let count: u32 = arg("--count").map(|s| s.parse().unwrap_or_else(|_| fail("bad --count"))).unwrap_or(20);
    if count == 0 || count > 10_000 { fail("--count must be 1..10000") }
    let idx: Vec<u32> = (0..count).collect();
    let mut n = 0;
    for line in std::io::stdin().lock().lines().map_while(Result::ok) {
        let x = line.trim(); if x.is_empty() { continue }
        match xpub::from_xpub(x, chain, &kinds, &branches, &idx) {
            Ok(rows) => for r in rows { n += 1;
                blocktools_io::outln!("{}", json!({"tool":"xpub-addresses","status":"ok","chain":r.chain,"kind":r.kind,"path":r.path,"address":r.address})) },
            Err(e) => fail(e),
        }
    }
    blocktools_io::outln!("{}", json!({"tool":"xpub-addresses","status":"done","count":n}));
}
