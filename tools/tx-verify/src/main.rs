//! tx-verify: check a transaction (stdin; any format tx-decode reads) against what you expect.
//!   tx-verify [--chain btc|ltc|doge] [--expect-to ADDR]... [--change ADDR]... [--chain-id N (required for EVM)]
//!             [--max-fee SATS_OR_WEI] [--allow-warnings] [--allow-value-with-token] [--policy FILE]
//! --policy FILE: offline policy file (docs/POLICY.md); its findings are added and its sha256 is reported.
//! EVM default fee cap: 0.01 ETH (same as tx-sign); UTXO: no cap unless --max-fee.
//! Exit 0 and status "ok" only when every check passes; otherwise status "failed", exit 1.
use blocktools_tx::policy::{check, Policy};
use serde_json::json;
use std::io::Read;
fn main() {
    blocktools_io::help("tx-verify [--chain C] [--expect-to ADDR]... [--change ADDR]... [--chain-id N (required for EVM)] [--max-fee N] [--allow-warnings] [--allow-value-with-token] [--policy FILE] < tx");
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
    // Default fee cap (same as tx-sign) is applied inside policy::check unless --max-fee is given.
    let mut f: Vec<String> = check(&d, &p).into_iter().map(String::from).collect();
    let mut o = json!({"tool":"tx-verify"});
    if let Some(file) = one("--policy") {
        let pf = blocktools_tx::policy_file::parse(&std::fs::read_to_string(file).unwrap_or_else(|_| bad("cannot read --policy file"))).unwrap_or_else(|e| bad(e));
        // Flags still apply; the file only adds findings. Without --expect-to/--chain-id flags, the file decides.
        if one("--chain-id").is_none() { f.retain(|x| x != "chain_id_not_pinned") }
        for x in blocktools_tx::policy_file::check(&d, &one("--chain").unwrap_or(chain.clone()), &pf) { if !f.contains(&x) { f.push(x) } }
        o["policy_sha256"] = json!(pf.sha256);
    }
    o["status"] = json!(if f.is_empty() {"ok"} else {"failed"}); o["failures"] = json!(f); o["warnings"] = json!(d.warnings);
    blocktools_io::outln!("{o}");
    if !f.is_empty() { std::process::exit(1) }
}
