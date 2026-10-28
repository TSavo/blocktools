//! UTXO family golden: the real DOGE->RUNE THORChain inbound we built and broadcast on 2026-10-27,
//! mainnet tx 6d0a0978df7782ce418e777e435406c7c2b9bab88225cd0c543894ed8c80dfdb. The RFC #15 round-trip
//! law for the UTXO family: a Plan of the inbound's steps, resolved against the live fee-rate, must
//! reproduce the exact outputs (vault address+amount, OP_RETURN memo script, fee) psbtmemo produced and
//! we signed; and `check` must pass for it and fail when the asserted vault or memo is tampered.
use blocktools_plan::{context, Plan, Step};

const TXID: &str = "6b83d91caf63b051dd87d9b0c6ea015ee348800938f15f79f4f6617cd8e56db0";
const FROM: &str = "DTWd9kMm3EULnVRmkVFehaDTzPQJ3nqQ5r";
const VAULT: &str = "DF5ndBX4Fd6yUcPvAs9SkbH5r4VaZE6huG";
// OP_RETURN payload = ascii "=:r:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu", stored as hex in the step.
const MEMO_HEX: &str = "3d3a723a74686f723137346a737535616774677a74636d636c7939366163396d727466356e326b393864686d756e75";
const MEMO_ASCII: &str = "=:r:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu";
const PREV_TX: &str = "01000000015d617876656247159a9f52b9eec1a34b410e6b0d2a2370535c73d7df4ef986db010000006a4730440220733177a4354651c2d60aea9d0163528d6f24bde7b2c23e21e71ea2022d21fa87022046b6e54fa029ec3d10c31f20d8d3698e8d7f75649ab07b4d627c86b0419909080121033baa59523499d4ef4de24d738b1d522fccd6f01b9065796291254cc79d402dcfffffffff03f3981ee80b0000001976a914f5650e53a85a04bc6f1f2175dc17635a693558a788ac3657690ed39900001976a914f3ebdb5160752be983fadea83913a040c80d5e9588ac0000000000000000466a444f55543a3146343146303346464231463546383138464630373339433735353345444336323635313838443939464146433441413546323031343235313342343846304300000000";

const VAULT_SPK: &str = "76a9146d110e1fd4fe6d97633f7874e6732c550939fb3988ac";
const OPRET_SPK: &str = "6a2f3d3a723a74686f723137346a737535616774677a74636d636c7939366163396d727466356e326b393864686d756e75";

fn inbound_plan() -> Plan {
    Plan {
        chain: "doge".into(),
        chain_id: None,
        steps: vec![
            Step::AddInput { txid: TXID.into(), vout: 0, amount: 51138959603, address: FROM.into(), prev_tx: Some(PREV_TX.into()), witness_script: None },
            Step::AddOutput { to: VAULT.into(), amount: String::new() }, // empty amount => sweep
            Step::OpReturn { memo: MEMO_HEX.into() },
            Step::ExpectTo { address: VAULT.into() },
            Step::ExpectMemo { memo: MEMO_ASCII.into() },
        ],
    }
}

#[test]
fn doge_rune_inbound_round_trips() {
    let v = blocktools_plan::utxo::resolve(&inbound_plan(), &context::Utxo { fee_rate: 750000 }).unwrap();
    let outs = v["outputs"].as_array().unwrap();
    assert_eq!(outs.len(), 2, "sweep + OP_RETURN");
    assert_eq!(outs[0]["address"], VAULT);
    assert_eq!(outs[0]["value"], "50950709603");
    assert_eq!(outs[0]["script"], VAULT_SPK);
    assert_eq!(outs[1]["value"], "0");
    assert_eq!(outs[1]["script"], OPRET_SPK);
    assert_eq!(v["fee"], "188250000");
    assert_eq!(v["rbf"], false);
}

#[test]
fn check_passes_for_the_inbound() {
    let v = blocktools_plan::utxo::resolve(&inbound_plan(), &context::Utxo { fee_rate: 750000 }).unwrap();
    let findings = blocktools_plan::utxo::check(&inbound_plan(), &v);
    assert!(findings.is_empty(), "clean inbound should verify: {findings:?}");
}

#[test]
fn check_fails_on_tampered_vault() {
    let v = blocktools_plan::utxo::resolve(&inbound_plan(), &context::Utxo { fee_rate: 750000 }).unwrap();
    let mut p = inbound_plan();
    // Point the asserted vault at the sender's own address: the resolved output[0] no longer matches.
    for s in &mut p.steps { if let Step::ExpectTo { address } = s { *address = FROM.into(); } }
    let findings = blocktools_plan::utxo::check(&p, &v);
    // check() now runs the signer's own policy::check: an output to a vault the plan no longer asserts
    // is an `unexpected_output` (same code the signer would refuse on).
    assert!(findings.iter().any(|f| f.code == "unexpected_output"), "wrong vault must be caught: {findings:?}");
}

#[test]
fn check_fails_on_tampered_memo() {
    let v = blocktools_plan::utxo::resolve(&inbound_plan(), &context::Utxo { fee_rate: 750000 }).unwrap();
    let mut p = inbound_plan();
    for s in &mut p.steps { if let Step::ExpectMemo { memo } = s { *memo = "=:r:thor1deadbeef".into(); } }
    let findings = blocktools_plan::utxo::check(&p, &v);
    // The resolved OP_RETURN no longer equals the (tampered) ExpectMemo, so it is no longer the accepted
    // zero-value memo output and policy::check refuses it as an `unexpected_output` (and `has_warnings`).
    assert!(findings.iter().any(|f| f.code == "unexpected_output"), "wrong memo must be caught: {findings:?}");
}

#[test]
fn doge_rune_inbound_represent_round_trips() {
    // RFC #15 round-trip for the UTXO family: build the inbound, lift the built result back to a Plan
    // with `represent`, then recompile against the SAME context. The bytes (psbt + outputs + fee) must
    // be reproduced exactly. The clean sweep-with-memo inbound recovers structurally (no Raw).
    let cx = context::Utxo { fee_rate: 750000 };
    let built = blocktools_plan::utxo::resolve(&inbound_plan(), &cx).unwrap();
    let represented = blocktools_plan::utxo::represent(&built, "doge");

    // Every input lifted to AddInput (with its prev_tx recovered), the vault swept, the memo recovered.
    let inputs: Vec<&Step> = represented.steps.iter().filter(|s| matches!(s, Step::AddInput { .. })).collect();
    assert_eq!(inputs.len(), 1, "the single inbound input is recovered");
    assert!(matches!(inputs[0], Step::AddInput { txid, vout: 0, amount: 51138959603, prev_tx: Some(_), .. } if txid == TXID));
    assert!(represented.steps.iter().any(|s| matches!(s, Step::AddOutput { amount, .. } if amount.is_empty())), "swept (empty amount)");
    assert!(represented.steps.iter().any(|s| matches!(s, Step::OpReturn { memo } if memo == MEMO_HEX)), "memo recovered");
    assert!(!represented.steps.iter().any(|s| matches!(s, Step::Raw { .. })), "clean inbound recovers structurally, no Raw");

    let rebuilt = blocktools_plan::utxo::resolve(&represented, &cx).unwrap();
    assert_eq!(rebuilt, built, "resolve(represent(tx)) == tx, byte for byte (psbt + outputs + fee)");
    // The recovered assertions (ExpectTo/ExpectMemo) still verify against the rebuilt bytes.
    assert!(blocktools_plan::utxo::check(&represented, &rebuilt).is_empty(), "recovered plan verifies");
}

#[test]
fn nonminimal_op_return_push_breaks_round_trip_silently() {
    // FIX (HIGH): a non-minimal OP_RETURN push (6a 4c <len> payload, len<=75) is not what op_return_for
    // emits, so lifting it to an OpReturn step would resolve to the MINIMAL push and not round-trip.
    // represent must re-encode-and-compare, see the mismatch, and fall to Raw (exact bytes preserved).
    let cx = context::Utxo { fee_rate: 750000 };
    let built = blocktools_plan::utxo::resolve(&inbound_plan(), &cx).unwrap();
    let mut m = built.clone();
    let nonmin = OPRET_SPK.replacen("6a2f", "6a4c2f", 1); // PUSHDATA1 over the same 47-byte payload
    for o in m["outputs"].as_array_mut().unwrap() {
        if o["script"].as_str().unwrap().starts_with("6a") { o["script"] = serde_json::json!(nonmin); }
    }
    let represented = blocktools_plan::utxo::represent(&m, "doge");
    assert!(represented.steps.iter().any(|s| matches!(s, Step::Raw { .. })),
        "non-minimal OP_RETURN must fall to Raw: {represented:?}");
    assert!(!represented.steps.iter().any(|s| matches!(s, Step::OpReturn { .. })),
        "must NOT lift to a (lossy) OpReturn step");
    let rebuilt = blocktools_plan::utxo::resolve(&represented, &cx).unwrap();
    assert_eq!(rebuilt, m, "Raw round-trips to the exact bytes");
}

#[test]
fn overlong_op_return_makes_resolve_error() {
    // FIX (HIGH): an 81-byte OP_RETURN payload exceeds the relay limit; lifting it to OpReturn would make
    // resolve error (memo_length). represent must fall to Raw so the exact bytes still round-trip.
    let cx = context::Utxo { fee_rate: 750000 };
    let built = blocktools_plan::utxo::resolve(&inbound_plan(), &cx).unwrap();
    let mut m = built.clone();
    let overlong = format!("6a4c51{}", "ab".repeat(81)); // PUSHDATA1, 0x51 = 81 payload bytes
    for o in m["outputs"].as_array_mut().unwrap() {
        if o["script"].as_str().unwrap().starts_with("6a") { o["script"] = serde_json::json!(overlong); }
    }
    let represented = blocktools_plan::utxo::represent(&m, "doge");
    assert!(represented.steps.iter().any(|s| matches!(s, Step::Raw { .. })),
        "over-limit OP_RETURN must fall to Raw: {represented:?}");
    let rebuilt = blocktools_plan::utxo::resolve(&represented, &cx).unwrap();
    assert_eq!(rebuilt, m, "Raw round-trips to the exact bytes (resolve never errors memo_length)");
}

#[test]
fn check_flags_unsupported_expect_out() {
    // FIX (HIGH): the UTXO family does not consult ExpectOut; a plan carrying one must not verify clean.
    let v = blocktools_plan::utxo::resolve(&inbound_plan(), &context::Utxo { fee_rate: 750000 }).unwrap();
    let mut p = inbound_plan();
    p.steps.push(Step::ExpectOut { token: None, min: "1".into() });
    let findings = blocktools_plan::utxo::check(&p, &v);
    assert!(findings.iter().any(|f| f.code == "assertion_unsupported"),
        "ExpectOut must be reported as unsupported: {findings:?}");
}

#[test]
fn check_enforces_cap_fee() {
    // A plan CapFee below the resolved fee is threaded into the Policy (max_fee) and flagged by the
    // signer's policy::check as `fee_above_cap` -- the same refusal tx-sign --plan would raise.
    let v = blocktools_plan::utxo::resolve(&inbound_plan(), &context::Utxo { fee_rate: 750000 }).unwrap();
    let mut p = inbound_plan();
    p.steps.push(Step::CapFee { max: "1".into() }); // the golden fee is 188_250_000 sats, far over 1
    let findings = blocktools_plan::utxo::check(&p, &v);
    assert!(findings.iter().any(|f| f.code == "fee_above_cap"), "a tight CapFee must be enforced: {findings:?}");
}

#[test]
fn check_flags_unparsable_cap_fee() {
    // FIX: an unparsable CapFee must not silently fall through to the chain default cap (verify_send
    // then applies a looser cap and check returns ok). Mirror evm::check: emit a cap_fee_unparsable finding.
    let v = blocktools_plan::utxo::resolve(&inbound_plan(), &context::Utxo { fee_rate: 750000 }).unwrap();
    let mut p = inbound_plan();
    p.steps.push(Step::CapFee { max: "abc".into() });
    let findings = blocktools_plan::utxo::check(&p, &v);
    assert!(findings.iter().any(|f| f.code == "cap_fee_unparsable"),
        "an unparsable CapFee must be flagged, not silently dropped: {findings:?}");
}
