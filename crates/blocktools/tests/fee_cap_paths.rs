// finding:R1-1 (docs/FINDINGS.md): every route to a signature applies the default fee cap.
//! Security regression (T review 2026-10-25): a plain ETH transfer whose fee is 9.99 ETH passed the
//! envelope verify path while tx-verify refused it. Every route to a signature must reject it with the
//! default cap, and every route must go through `blocktools_tx::policy::check` (the one verifier).
use serde_json::{json, Value};

const TX: &str = include_str!("data/evm-fee-9.99eth.txt");
const TO: &str = "0x3535353535353535353535353535353535353535";

#[test] fn fee_9_99_eth_rejected_by_shared_verifier() {
    let d = blocktools_tx::decode(TX, "eth").unwrap();
    let p = blocktools_tx::policy::Policy { expect_to: vec![TO.into()], chain_id: Some(1), ..Default::default() };
    let v = blocktools_tx::policy::verify(&d, &p);
    assert!(v.findings.contains(&"fee_above_cap"), "{:?}", v.findings);
    assert!(v.check_these.contains("CHECK THESE"));
    // explicit cap above the fee is the only way through, and it's the human's flag
    let ok = blocktools_tx::policy::check(&d, &blocktools_tx::policy::Policy { max_fee: Some(10_000_000_000_000_000_000), allow_warnings: true, ..p });
    assert!(ok.is_empty(), "{ok:?}");
}

#[test] fn fee_9_99_eth_rejected_by_envelope() {
    let r: Value = serde_json::from_str(&blocktools::envelope::run(&json!({"envelope":"blocktools.sign/v1","op":"verify","chain":"eth","tx":TX,"expect_to":TO,"chain_id":1}).to_string())).unwrap();
    let res = &r["result"];
    assert_eq!(res["ok"], false, "{r}");
    assert!(res["findings"].as_array().unwrap().iter().any(|f| f == "fee_above_cap"), "{r}");
    assert!(res["check_these"].as_str().unwrap().contains("CHECK THESE"));
    // chain id pin stays mandatory on this path too
    let r: Value = serde_json::from_str(&blocktools::envelope::run(&json!({"op":"verify","chain":"eth","tx":TX,"expect_to":TO,"max_fee":"99000000000000000000"}).to_string())).unwrap();
    assert!(r["result"]["findings"].as_array().unwrap().iter().any(|f| f == "chain_id_not_pinned"), "{r}");
}

#[test] fn fee_9_99_eth_rejected_by_check_tx() {
    let r: Value = serde_json::from_str(&blocktools::check::tx_json(&json!({"chain":"eth","raw_tx_hex":TX,"expected_outputs":[{"address":TO}],"owner_addr":TO,"max_fee":"10000000000000000","chain_id":1}).to_string())).unwrap();
    assert_eq!(r["ok"], false, "{r}");
}

/// Enumerate the entry points: every non-test source that builds a `Policy` must hand it to the shared
/// verifier, and the list of such files is pinned so a new route can't appear unreviewed.
#[test] fn every_policy_entry_point_uses_shared_verifier() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out = std::process::Command::new("git").args(["grep", "-l", "Policy {", "--", "*.rs", ":!*/tests/*", ":!crates/tx/src/policy.rs", ":!crates/tx/src/policy_file.rs"]).current_dir(&root).output().unwrap();
    let files: Vec<String> = String::from_utf8(out.stdout).unwrap().lines().map(String::from).collect();
    let pinned = ["bindings/wasm/src/lib.rs", "crates/blocktools/src/check.rs", "crates/blocktools/src/envelope.rs", "crates/plan/src/evm.rs", "tools/tx-sign/src/main.rs", "tools/tx-verify/src/main.rs"];
    assert_eq!(files, pinned, "new Policy entry point: route it through policy::check/verify and add it here + to fee_cap_paths tests");
    for f in &files {
        let s = std::fs::read_to_string(root.join(f)).unwrap();
        assert!(s.contains("policy::verify(") || s.contains("policy::check(") || s.contains("check(&d, &p)") || s.contains("check(d, &p)"), "{f} builds a Policy but never calls the shared verifier");
        assert!(!s.contains("default_max_fee"), "{f}: fee default must live only in policy::check");
    }
}
