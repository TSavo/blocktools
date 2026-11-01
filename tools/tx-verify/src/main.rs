//! tx-verify: check a transaction (stdin; any format tx-decode reads) against what you expect.
//!   tx-verify [--chain btc|ltc|doge] [--expect-to ADDR]... [--change ADDR]... [--chain-id N (required for EVM)]
//!             [--max-fee SATS_OR_WEI] [--allow-warnings] [--allow-value-with-token] [--expect-memo MEMO] [--policy FILE]
//! --expect-memo MEMO: UTXO THORChain-style memo. A single zero-value OP_RETURN is accepted only when its payload
//!   equals MEMO byte-for-byte (UTF-8); without it every OP_RETURN is refused (unexpected_output).
//! --policy FILE: offline policy file (docs/POLICY.md); its findings are added and its sha256 is reported.
//! --call SIGNATURE (repeatable) / --abi FILE: EVM contract call. The calldata is decoded strictly against these
//!   function signatures (it must re-encode byte-for-byte) and reported as "call" {signature, selector, args};
//!   only an exact match lifts unknown_contract_call. Unknown selectors are reported as "unknown_selector".
//! --create-hash KECCAK: EVM contract creation (no "to"): approved only when keccak256(init code) equals KECCAK.
//! EVM content checks (blocktools_evm::approval; deny by default, opt-in exact assertions):
//!   approvals (approve, increaseAllowance, EIP-2612/DAI permit calldata, Permit2 approve/permit, setApprovalForAll)
//!   are reported as "approvals" [{path, signature, token, spender, amount, unlimited}]; an amount >= 2^128 or an
//!   all-tokens approval fails "unlimited_approval" unless --expect-unlimited (which requires --expect-spender).
//!   --expect-spender ADDR / --expect-amount N / --expect-recipient ADDR / --expect-value WEI: every decoded
//!   approval / transfer / native value must equal these, else spender_/amount_/recipient_/value_not_expected.
//!   Batches (multicall, Multicall3 aggregate*, Universal Router execute, Safe execTransaction / multiSend) are
//!   reported as "inner_calls"; each must be named by --allow-inner-call TO:SELECTOR (else inner_calls_not_asserted),
//!   and a delegatecall target by --allow-delegatecall TO (else delegatecall).
//!   An approve/permit whose token (--expect-to), spender and amount (--expect-amount or --expect-unlimited) are all
//!   asserted and match lifts token_call_not_transfer / unknown_contract_call and its approve warning.
//! EVM default fee cap: 0.01 ETH (same as tx-sign); UTXO: no cap unless --max-fee.
//! Exit 0 and status "ok" only when every check passes; otherwise status "failed", exit 1.
use blocktools_tx::policy::{check, Policy};
use serde_json::json;
use std::io::Read;
fn main() {
    blocktools_io::help("tx-verify [--chain C] (--plan FILE | [--expect-to ADDR]... [--change ADDR]... [--chain-id N] [--max-fee N] [--expect-memo MEMO] [--policy FILE]) [--allow-warnings] [--allow-value-with-token] [--call SIGNATURE]... [--abi FILE] [--create-hash KECCAK] [--expect-spender ADDR] [--expect-amount N | --expect-unlimited] [--expect-recipient ADDR] [--expect-value WEI] [--allow-inner-call TO:SELECTOR]... [--allow-delegatecall TO]... < tx");
    let a: Vec<String> = blocktools_core::chain_spec::args_or_exit("tx-verify");
    let all = |k: &str| a.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).collect::<Vec<_>>();
    let one = |k: &str| all(k).pop();
    let bad = |e: &str| -> ! { blocktools_io::outln!("{}", json!({"tool":"tx-verify","status":"bad_input","error":e})); std::process::exit(2) };
    // --plan FILE: the Plan (RFC #15) carries the assertions; `blocktools_plan::sign_guards` derives the
    // SAME policy::Policy the flags build (plus fail-closed findings), so a passing `tx-verify --plan` and a
    // `tx-sign --plan` enforce the identical assertions. Opt-in and exclusive with the manual assertion flags.
    // UTXO plans name their chain; the tx being verified/signed must be on that same chain.
    let mut plan_chain: Option<String> = None;
    let (p, mut plan_findings): (Policy, Vec<String>) = if let Some(plan_file) = one("--plan") {
        for k in ["--expect-to", "--expect-memo", "--max-fee", "--chain-id", "--change", "--policy"] {
            if a.iter().any(|x| x == k) { bad("--plan carries the assertions; do not also pass --expect-to/--expect-memo/--max-fee/--chain-id/--change/--policy") }
        }
        let plan: blocktools_plan::Plan = serde_json::from_str(&std::fs::read_to_string(&plan_file).unwrap_or_else(|_| bad("cannot read --plan file"))).unwrap_or_else(|e| bad(&format!("bad Plan JSON: {e}")));
        let g = blocktools_plan::sign_guards(&plan);
        plan_chain = (g.family == Some(blocktools_plan::Family::Utxo)).then(|| plan.chain.to_ascii_lowercase());
        match g.family {
            Some(blocktools_plan::Family::Evm) | Some(blocktools_plan::Family::Utxo) => {}
            _ => bad("tx-verify --plan supports EVM and UTXO plans only"),
        }
        let mut pol = g.policy;
        pol.allow_warnings = a.iter().any(|x| x == "--allow-warnings");
        pol.allow_value_with_token = a.iter().any(|x| x == "--allow-value-with-token");
        (pol, g.findings.into_iter().map(|f| f.code).collect())
    } else {
        (Policy { expect_to: all("--expect-to"), change: all("--change"),
            chain_id: one("--chain-id").map(|s| s.parse().unwrap_or_else(|_| bad("--chain-id"))),
            max_fee: one("--max-fee").map(|s| s.parse().unwrap_or_else(|_| bad("--max-fee"))), allow_warnings: a.iter().any(|x| x == "--allow-warnings"),
            allow_value_with_token: a.iter().any(|x| x == "--allow-value-with-token"),
            expect_memo: one("--expect-memo").map(String::into_bytes) }, Vec::new())
    };
    let mut s = String::new();
    if std::io::stdin().take(blocktools_tx::MAX_INPUT as u64 + 1).read_to_string(&mut s).is_err() { bad("bad_input") }
    let chain = blocktools_tx::resolve_chain(&s, one("--chain")).unwrap_or_else(|e| bad(e));
    let d = blocktools_tx::decode(&s, &chain).unwrap_or_else(|e| bad(e));
    if plan_chain.as_ref().is_some_and(|pc| *pc != chain.to_ascii_lowercase()) { plan_findings.push("plan_chain_mismatch".into()) }
    // Default fee cap (same as tx-sign) is applied inside policy::check unless --max-fee is given.
    let mut f: Vec<String> = check(&d, &p).into_iter().map(String::from).collect();
    f.extend(plan_findings.iter().cloned());
    let mut o = json!({"tool":"tx-verify"});
    if let Some(file) = one("--policy") {
        let pf = blocktools_tx::policy_file::parse(&std::fs::read_to_string(file).unwrap_or_else(|_| bad("cannot read --policy file"))).unwrap_or_else(|e| bad(e));
        // Flags still apply; the file only adds findings. Without --expect-to/--chain-id flags, the file decides.
        if one("--chain-id").is_none() { f.retain(|x| x != "chain_id_not_pinned") }
        blocktools_tx::policy_file::apply(&d, &one("--chain").unwrap_or(chain.clone()), &pf, &mut f);
        o["policy_sha256"] = json!(pf.sha256);
    }
    if let Some(c) = approve(&d, &mut f, &a) { o["call"] = c }
    content(&d, &mut f, &mut o, &a, &p.expect_to);
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
    let expect: Vec<String> = a.windows(2).filter(|w| w[0] == "--expect-to").map(|w| w[1].clone()).collect();
    let warn: Vec<String> = d.warnings.iter().map(|w| w.to_string()).collect();
    blocktools_evm::api::lift_approved(&o, t.to.map(|x| blocktools_tx::addr(&x)).as_deref(), &expect, &warn, f);
    Some(o)
}

/// Approval / transfer / batch content checks (blocktools_evm::approval). EVM only; adds findings.
fn content(d: &blocktools_tx::Decoded, f: &mut Vec<String>, o: &mut serde_json::Value, a: &[String], expect_to: &[String]) {
    let bad = |e: &str| -> ! { blocktools_io::outln!("{}", serde_json::json!({"tool":"tx-verify","status":"bad_input","error":e})); std::process::exit(2) };
    let all = |k: &str| a.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).collect::<Vec<_>>();
    let one = |k: &str| { let v = all(k); if v.len() > 1 { bad(&format!("{k} given twice")) } v.into_iter().next() };
    let e = blocktools_evm::approval::Expect {
        spender: one("--expect-spender"), amount: one("--expect-amount"), unlimited: a.iter().any(|x| x == "--expect-unlimited"),
        recipient: one("--expect-recipient"), value: one("--expect-value"),
        inner: all("--allow-inner-call").iter().map(|s| blocktools_evm::approval::Expect::inner_arg(s).unwrap_or_else(|e| bad(&e))).collect(),
        delegatecall: all("--allow-delegatecall"),
    };
    let asserted = e.spender.is_some() || e.amount.is_some() || e.unlimited || e.recipient.is_some() || e.value.is_some() || !e.inner.is_empty() || !e.delegatecall.is_empty();
    let e = e.normalized().unwrap_or_else(|x| bad(&x));
    let Some(t) = d.evm.as_ref() else { if asserted { bad("approval/transfer assertions are EVM only") } return };
    let (r, mut g) = blocktools_evm::approval::check(t.to.as_ref(), &t.value.to_string(), &t.data, &e);
    if let Some(to) = t.to.as_ref() {
        if blocktools_evm::approval::fully_asserted_approval(&r, &g, &e, expect_to, to) {
            f.retain(|x| !["token_call_not_transfer", "unknown_contract_call", "destination_not_expected"].contains(&x.as_str()));
            if d.warnings.iter().all(|w| ["unsigned", "token_approve", "unlimited_approve", "unknown_calldata"].contains(w)) { f.retain(|x| x != "has_warnings") }
        }
    }
    for k in ["approvals", "transfers", "inner_calls"] { if let Some(v) = r.get(k) { o[k] = v.clone() } }
    f.append(&mut g); f.dedup();
}
