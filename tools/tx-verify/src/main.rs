//! tx-verify: check a transaction (stdin; any format tx-decode reads) against what you expect.
//!   tx-verify [--chain btc|ltc|doge] [--expect-to ADDR]... [--change ADDR]... [--chain-id N]
//!             [--max-fee SATS_OR_WEI] [--allow-warnings] [--allow-value-with-token]
//! EVM default fee cap: 0.01 ETH (same as tx-sign); UTXO: no cap unless --max-fee.
//! Exit 0 and status "ok" only when every check passes; otherwise status "failed", exit 1.
use blocktools_tx::policy::{self, check, Policy};
use serde_json::json;
use std::io::Read;
fn main() {
    blocktools_io::help("tx-verify [--chain C] [--expect-to ADDR]... [--change ADDR]... [--chain-id N] [--max-fee N] [--allow-warnings] [--allow-value-with-token] < tx");
    let a: Vec<String> = std::env::args().collect();
    let all = |k: &str| a.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).collect::<Vec<_>>();
    let one = |k: &str| all(k).pop();
    let bad = |e: &str| -> ! { blocktools_io::outln!("{}", json!({"tool":"tx-verify","status":"bad_input","error":e})); std::process::exit(2) };
    let p = Policy { expect_to: all("--expect-to"), change: all("--change"),
        chain_id: one("--chain-id").map(|s| s.parse().unwrap_or_else(|_| bad("--chain-id"))),
        max_fee: one("--max-fee").map(|s| s.parse().unwrap_or_else(|_| bad("--max-fee"))), allow_warnings: a.iter().any(|x| x == "--allow-warnings"),
        allow_value_with_token: a.iter().any(|x| x == "--allow-value-with-token") };
    let mut s = String::new();
    if std::io::stdin().take(blocktools_tx::MAX_INPUT as u64 + 1).read_to_string(&mut s).is_err() { bad("bad_input") }
    let chain = blocktools_tx::resolve_chain(&s, one("--chain")).unwrap_or_else(|e| bad(e));
    let d = blocktools_tx::decode(&s, &chain).unwrap_or_else(|e| bad(e));
    // EVM: same default total-fee cap as tx-sign (gas * maxFeePerGas <= 0.01 ETH) unless --max-fee is given.
    let mut p = p; if p.max_fee.is_none() && d.evm.is_some() { p.max_fee = Some(policy::default_max_fee(&d)) }
    let f = check(&d, &p);
    blocktools_io::outln!("{}", json!({"tool":"tx-verify","status":if f.is_empty() {"ok"} else {"failed"},"failures":f,"warnings":d.warnings}));
    if !f.is_empty() { std::process::exit(1) }
}
