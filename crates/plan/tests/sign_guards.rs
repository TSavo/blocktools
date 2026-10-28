//! `sign_guards` (RFC #15): a Plan's assertions BECOME the signer's guards (one shared mapping per family). These assert
//! the library mapping directly -- the per-family guard set `tx-sign --plan` feeds to `policy::check`, and
//! the fail-closed findings that refuse a sign. The full resolve -> `tx-plan check` passes -> `tx-sign
//! --plan` signs -> tamper -> `tx-sign --plan` refuses invariant runs end to end in
//! `scripts/e2e.d/tx-sign-plan.sh`.
use blocktools_plan::{evm, sign_guards, Family, Plan, Step};

const ROUTER: &str = "0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b";

fn evm_deposit_plan(cap: &str) -> Plan {
    let memo = "=:d:DTWd9kMm3EULnVRmkVFehaDTzPQJ3nqQ5r/0xeb0eC7a28E4B6B175806E21D9D3afE45792C5c7B:50080186199/1/0";
    Plan {
        chain: "bsc".into(),
        chain_id: Some(56),
        steps: vec![
            Step::Call {
                to: ROUTER.into(),
                sig: "depositWithExpiry(address,address,uint256,string,uint256)".into(),
                args: vec![
                    "0x718f6C9df785BC4e323086De024CA822efbE8aB9".into(),
                    "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c".into(),
                    "500112480000000".into(),
                    memo.into(),
                    "1793139980".into(),
                ],
            },
            Step::ExpectTo { address: ROUTER.into() },
            Step::CapFee { max: cap.into() },
        ],
    }
}

/// The EVM guard set `sign_guards` derives is exactly the Policy `evm::check` builds and the signer
/// consumes: chain_id, the expect_to list, and the fee cap -- no findings on a clean plan.
#[test]
fn sign_guards_evm_mirrors_check() {
    let plan = evm_deposit_plan("250000000000000");
    let g = sign_guards(&plan);
    assert_eq!(g.family, Some(Family::Evm));
    assert_eq!(g.policy.chain_id, Some(56));
    assert_eq!(g.policy.expect_to, vec![ROUTER.to_string()]);
    assert_eq!(g.policy.max_fee, Some(250_000_000_000_000));
    assert!(g.findings.is_empty(), "clean plan has no fail-closed findings: {:?}", g.findings);
    // The Policy sign_guards hands the signer is byte-for-byte what evm::check constructs internally.
    let (check_policy, check_findings) = evm::guards(&plan);
    assert_eq!(g.policy.chain_id, check_policy.chain_id);
    assert_eq!(g.policy.expect_to, check_policy.expect_to);
    assert_eq!(g.policy.max_fee, check_policy.max_fee);
    assert!(check_findings.is_empty());
}

/// Fail-closed: an unparsable CapFee and a missing destination assertion both surface as findings that
/// `tx-sign --plan` refuses on -- the cap never silently falls through to the looser default.
#[test]
fn tampered_plan_is_refused() {
    // (a) unparsable fee cap -> cap_fee_unparsable
    let g = sign_guards(&evm_deposit_plan("not-a-number"));
    assert!(g.findings.iter().any(|f| f.code == "cap_fee_unparsable"), "{:?}", g.findings);

    // (b) a value-bearing EVM call with no ExpectTo -> destination_not_asserted (the signer never signs an
    // unasserted destination).
    let mut plan = evm_deposit_plan("250000000000000");
    plan.steps.retain(|s| !matches!(s, Step::ExpectTo { .. }));
    let g = sign_guards(&plan);
    assert!(g.policy.expect_to.is_empty());
    assert!(g.findings.iter().any(|f| f.code == "destination_not_asserted"), "{:?}", g.findings);
}

/// UTXO (THORChain inbound): ExpectTo -> vault, ExpectMemo -> memo, CapFee -> fee cap, all mapped into the
/// Policy the signer consumes; an OP_RETURN with no ExpectMemo, or a payment with no ExpectTo, fail closed.
#[test]
fn sign_guards_utxo_vault_memo_and_fail_closed() {
    let vault = "D5kTEGxmas71USKAcAaJptKjq8NJc6EK8C";
    let memo = "=:r:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu";
    let clean = Plan {
        chain: "doge".into(),
        chain_id: None,
        steps: vec![
            Step::AddOutput { to: vault.into(), amount: "100000000".into() },
            Step::OpReturn { memo: format!("0x{}", blocktools_core::hex_enc(memo.as_bytes())) },
            Step::ExpectTo { address: vault.into() },
            Step::ExpectMemo { memo: memo.into() },
            Step::CapFee { max: "100000".into() },
        ],
    };
    let g = sign_guards(&clean);
    assert_eq!(g.family, Some(Family::Utxo));
    assert_eq!(g.policy.expect_to, vec![vault.to_string()]);
    assert_eq!(g.policy.expect_memo.as_deref(), Some(memo.as_bytes()));
    assert_eq!(g.policy.max_fee, Some(100_000));
    assert!(g.findings.is_empty(), "clean inbound: {:?}", g.findings);

    // Drop the memo assertion while the OP_RETURN stays -> memo_not_asserted.
    let mut no_memo = clean.clone();
    no_memo.steps.retain(|s| !matches!(s, Step::ExpectMemo { .. }));
    assert!(sign_guards(&no_memo).findings.iter().any(|f| f.code == "memo_not_asserted"));

    // Drop the destination assertion while the payment stays -> destination_not_asserted.
    let mut no_to = clean.clone();
    no_to.steps.retain(|s| !matches!(s, Step::ExpectTo { .. }));
    assert!(sign_guards(&no_to).findings.iter().any(|f| f.code == "destination_not_asserted"));

    // An unparsable CapFee fails closed on the signer path too (never the looser chain default).
    for bad in ["abc", "", "-1", "18446744073709551616"] {
        let mut abc = clean.clone();
        for s in abc.steps.iter_mut() { if let Step::CapFee { max } = s { *max = bad.into(); } }
        let g = sign_guards(&abc);
        assert!(g.findings.iter().any(|f| f.code == "cap_fee_unparsable"), "{bad:?}: {:?}", g.findings);
        assert_eq!(g.policy.max_fee, None);
    }
}
