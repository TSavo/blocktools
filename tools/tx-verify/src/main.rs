//! tx-verify: check a transaction (stdin; any format tx-decode reads) against what you expect.
//!   tx-verify [--chain btc|ltc|doge] [--expect-to ADDR]... [--change ADDR]... [--chain-id N (required for EVM)]
//!             [--max-fee SATS_OR_WEI] [--allow-warnings] [--allow-value-with-token] [--policy FILE]
//! --policy FILE: offline policy file (docs/POLICY.md); its findings are added and its sha256 is reported.
//! --call SIGNATURE (repeatable) / --abi FILE: EVM contract call. The calldata is decoded strictly against these
//!   function signatures (it must re-encode byte-for-byte) and reported as "call" {signature, selector, args};
//!   only an exact match lifts unknown_contract_call. Unknown selectors are reported as "unknown_selector".
//! --create-hash KECCAK: EVM contract creation (no "to"): approved only when keccak256(init code) equals KECCAK.
//! EVM default fee cap: 0.01 ETH (same as tx-sign); UTXO: no cap unless --max-fee.
//! Exit 0 and status "ok" only when every check passes; otherwise status "failed", exit 1.
use blocktools_tx::policy::{check, Policy};
use serde_json::json;
use std::io::Read;
fn main() {
    blocktools_io::help("tx-verify [--chain C] [--expect-to ADDR]... [--change ADDR]... [--chain-id N (required for EVM)] [--max-fee N] [--allow-warnings] [--allow-value-with-token] [--policy FILE] [--call SIGNATURE]... [--abi FILE] [--create-hash KECCAK] < tx");
    let a: Vec<String> = blocktools_core::chain_spec::args_or_exit("tx-verify");
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
    if let Some(c) = approve(&d, &mut f, &a) { o["call"] = c }
    if let Some(s) = blocktools_core::chain_spec::get().filter(|s| s.name == chain) { o["chain_spec"] = json!("unverified chain spec"); o["chain_spec_sha256"] = json!(s.sha256) }
    o["status"] = json!(if f.is_empty() {"ok"} else {"failed"}); o["failures"] = json!(f); o["warnings"] = json!(d.warnings); o["fee_cap"] = blocktools_tx::policy::fee_cap(&d, &p).json();
    blocktools_io::outln!("{o}");
    if !f.is_empty() { std::process::exit(1) }
}

/// --call SIGNATURE / --abi FILE / --create-hash KECCAK: decode an EVM tx's calldata and,
/// only when it matches exactly, lift the generic unknown-contract-call refusal (all other checks stay).
/// Returns the decoded call (or creation) for display; None for non-contract txs.
fn approve(d: &blocktools_tx::Decoded, f: &mut Vec<String>, a: &[String]) -> Option<serde_json::Value> {
    let bad = |e: &str| -> ! { blocktools_io::outln!("{}", serde_json::json!({"tool":"tx-verify","status":"bad_input","error":e})); std::process::exit(2) };
    let t = d.evm.as_ref()?;
    if t.to.is_some() && (t.data.is_empty() || blocktools_tx::evm::token_call(&t.data).is_some()) { return None }
    let mut sigs = vec![];
    for w in a.windows(2) {
        match w[0].as_str() {
            "--call" => sigs.push(blocktools_evm::sig::Sig::parse(&w[1]).unwrap_or_else(|e| bad(&format!("--call: {e}")))),
            "--abi" => sigs.extend(blocktools_evm::sig::parse_abi_json(&std::fs::read_to_string(&w[1]).unwrap_or_else(|_| bad("cannot read --abi file"))).unwrap_or_else(|e| bad(&format!("--abi: {e}")))),
            _ => {}
        }
    }
    let ch = a.windows(2).filter(|w| w[0] == "--create-hash").map(|w| &w[1]).last().map(|h| {
        let b = blocktools_core::hex_dec(h.trim_start_matches("0x")).unwrap_or_default();
        <[u8; 32]>::try_from(b.as_slice()).unwrap_or_else(|_| bad("--create-hash: 32-byte keccak256 hex"))
    });
    let o = blocktools_evm::api::approve_call(t.to.as_ref().map(|x| &x[..]), &t.data, &sigs, ch.as_ref());
    if o["status"] == "ok" {
        f.retain(|x| x != "unknown_contract_call");
        // The destination of an approved call is the contract itself.
        if let Some(to) = t.to.map(|x| blocktools_tx::addr(&x)) {
            if a.windows(2).any(|w| w[0] == "--expect-to" && w[1].eq_ignore_ascii_case(&to)) { f.retain(|x| x != "destination_not_expected") }
        }
        if d.warnings.iter().all(|w| ["unsigned", "unknown_calldata", "contract_creation"].contains(w)) { f.retain(|x| x != "has_warnings") }
    }
    Some(o)
}
