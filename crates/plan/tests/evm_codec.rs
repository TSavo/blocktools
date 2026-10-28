//! EVM family codec goldens: the `represent`/`resolve` totality round-trip and `check` pass/fail.
//! These sit beside `evm_golden.rs` (resolve goldens) and enforce the RFC #15 laws for the EVM family:
//!   totality:   resolve(represent(tx)) == tx           (bytes, modulo the signature)
//!   agreement:  Plan::check mirrors policy::check / tx-verify
use blocktools_plan::{context, evm, Plan, Step};

// The same unsigned BTCB -> DOGE THORChain deposit as evm_golden.rs; its selector 0x44bc937b is NOT a
// known ERC-20 call, so `represent` must hold it verbatim in a `Raw{kind:"evm.call"}` step.
const UNSIGNED: &str = "02f9016e380e843b9aca00843b9aca008303d09094b30ec53f98ff5947ede720d32ac2da7e52a5f56b80b9014444bc937b000000000000000000000000718f6c9df785bc4e323086de024ca822efbe8ab90000000000000000000000007130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c0000000000000000000000000000000000000000000000000001c6d982b7d80000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000006ae1250c00000000000000000000000000000000000000000000000000000000000000613d3a643a44545764396b4d6d3345554c6e56526d6b564665686144547a50514a336e715135722f3078656230654337613238453442364231373538303645323144394433616645343537393243356337423a35303038303138363139392f312f3000000000000000000000000000000000000000000000000000000000000000c0";

fn bytes(hex: &str) -> Vec<u8> {
    (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn deposit_represent_resolve_round_trips_through_raw() {
    // Decode the on-chain unsigned bytes into a Tx, lift to a Plan, then recompile with the SAME
    // Context. resolve(represent(tx)) must equal the original unsigned bytes for the whole EVM family,
    // even for a selector the IR does not model (here it lands in Step::Raw{kind:"evm.call"}).
    let tx = blocktools_tx::evm::Tx::parse(&bytes(UNSIGNED)).expect("parse unsigned");
    let plan = evm::represent(&tx);

    // The unmodelled call is held verbatim, not dropped.
    assert_eq!(plan.chain, "bsc");
    assert_eq!(plan.chain_id, Some(56));
    assert!(matches!(plan.steps.as_slice(), [Step::Raw { kind, .. }] if kind == "evm.call"));

    let cx = context::Evm { nonce: 14, gas: 250000, max_fee_per_gas: 1_000_000_000, priority_fee: 1_000_000_000 };
    let rebuilt = evm::resolve(&plan, &cx).expect("resolve represented plan");
    let hex: String = rebuilt.encode_unsigned().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, UNSIGNED, "resolve(represent(tx)) must equal the original unsigned bytes");
}

#[test]
fn approve_tx_represents_as_structured_step() {
    // Build a real approve tx via resolve, then represent it back: it must lift to a structured
    // Step::Approve (not Raw), recovering token/spender/amount.
    let plan = Plan {
        chain: "bsc".into(), chain_id: Some(56),
        steps: vec![Step::Approve {
            token: "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c".into(),
            spender: "0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b".into(),
            amount: "500112480000000".into(),
        }],
    };
    let cx = context::Evm { nonce: 13, gas: 60000, max_fee_per_gas: 1_000_000_000, priority_fee: 1_000_000_000 };
    let tx = evm::resolve(&plan, &cx).expect("resolve approve");
    match evm::represent(&tx).steps.as_slice() {
        [Step::Approve { token, spender, amount }] => {
            assert_eq!(token, "0x7130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c");
            assert_eq!(spender, "0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b");
            assert_eq!(amount, "500112480000000");
        }
        other => panic!("expected a single Approve step, got {other:?}"),
    }
}

#[test]
fn create_tx_represents_as_create_step() {
    // A contract creation (to == None) lifts to Step::Create holding the initcode.
    let tx = blocktools_tx::evm::Tx {
        kind: blocktools_tx::evm::Kind::Eip1559, chain_id: Some(1), nonce: 0,
        max_fee_per_gas: 1_000_000_000, max_priority_fee_per_gas: Some(1_000_000_000), gas: 100000,
        to: None, value: 0, data: vec![0x60, 0x80, 0x60, 0x40], access_list: blocktools_tx::rlp::Rlp::L(vec![]), sig: None,
    };
    let plan = evm::represent(&tx);
    assert_eq!(plan.chain, "eth");
    assert!(matches!(plan.steps.as_slice(), [Step::Create { initcode }] if initcode == "0x60806040"));
}

// A clean ERC-20 transfer plan: policy decodes the recipient from the transfer calldata, so an
// ExpectTo on that recipient is satisfied. (The deposit's unknown selector would always draw
// unknown_contract_call + destination_not_expected from policy::check -- that's what tx-verify reports
// too -- so the pass case is demonstrated on a call policy can read, keeping check and the tool aligned.)
fn transfer_plan(expect: &str) -> Plan {
    Plan {
        chain: "bsc".into(), chain_id: Some(56),
        steps: vec![
            Step::Call {
                to: "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c".into(),
                sig: "transfer(address,uint256)".into(),
                args: vec!["0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b".into(), "500112480000000".into()],
            },
            Step::ExpectTo { address: expect.into() },
            Step::CapFee { max: "250000000000000".into() },
        ],
    }
}

#[test]
fn check_passes_when_assertions_hold() {
    let plan = transfer_plan("0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b");
    let cx = context::Evm { nonce: 1, gas: 60000, max_fee_per_gas: 1_000_000_000, priority_fee: 1_000_000_000 };
    let tx = evm::resolve(&plan, &cx).expect("resolve");
    assert!(evm::check(&plan, &tx).is_empty(), "a tx that meets every assertion has no findings");
}

#[test]
fn check_flags_wrong_destination() {
    let plan = transfer_plan("0x000000000000000000000000000000000000dead");
    let cx = context::Evm { nonce: 1, gas: 60000, max_fee_per_gas: 1_000_000_000, priority_fee: 1_000_000_000 };
    let tx = evm::resolve(&plan, &cx).expect("resolve");
    let codes: Vec<String> = evm::check(&plan, &tx).into_iter().map(|f| f.code).collect();
    assert!(codes.iter().any(|c| c == "destination_not_expected"), "expected destination_not_expected, got {codes:?}");
}
