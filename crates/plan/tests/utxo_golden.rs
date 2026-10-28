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
            Step::AddInput { txid: TXID.into(), vout: 0, amount: 51138959603, address: FROM.into(), prev_tx: Some(PREV_TX.into()) },
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
    assert!(findings.iter().any(|f| f.code == "vault"), "wrong vault must be caught: {findings:?}");
}

#[test]
fn check_fails_on_tampered_memo() {
    let v = blocktools_plan::utxo::resolve(&inbound_plan(), &context::Utxo { fee_rate: 750000 }).unwrap();
    let mut p = inbound_plan();
    for s in &mut p.steps { if let Step::ExpectMemo { memo } = s { *memo = "=:r:thor1deadbeef".into(); } }
    let findings = blocktools_plan::utxo::check(&p, &v);
    assert!(findings.iter().any(|f| f.code == "memo"), "wrong memo must be caught: {findings:?}");
}
