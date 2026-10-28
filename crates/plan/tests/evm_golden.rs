//! EVM family golden test: the real mainnet BTCB -> DOGE THORChain deposit (BNB Chain tx
//! 0x1f41f03ffb1f5f818ff0739c7553edc6265188d99fafc4aa5f20142513b48f0c, 2026-10-27) reconstructed as
//! a `Plan` and resolved. The RFC #15 round-trip law: resolve(plan, ctx) == the exact unsigned bytes.
use blocktools_plan::{context, evm, Plan, Step};

// The unsigned EIP-1559 tx `tx-build` produced for that deposit (what we signed + broadcast).
const UNSIGNED: &str = "02f9016e380e843b9aca00843b9aca008303d09094b30ec53f98ff5947ede720d32ac2da7e52a5f56b80b9014444bc937b000000000000000000000000718f6c9df785bc4e323086de024ca822efbe8ab90000000000000000000000007130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c0000000000000000000000000000000000000000000000000001c6d982b7d80000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000006ae1250c00000000000000000000000000000000000000000000000000000000000000613d3a643a44545764396b4d6d3345554c6e56526d6b564665686144547a50514a336e715135722f3078656230654337613238453442364231373538303645323144394433616645343537393243356337423a35303038303138363139392f312f3000000000000000000000000000000000000000000000000000000000000000c0";

#[test]
fn btcb_to_doge_deposit_round_trips() {
    // Intent: one depositWithExpiry call on the THORChain BSC router. The live facts (nonce, gas,
    // fee) are supplied as Context, never stored in the Plan.
    let memo = "=:d:DTWd9kMm3EULnVRmkVFehaDTzPQJ3nqQ5r/0xeb0eC7a28E4B6B175806E21D9D3afE45792C5c7B:50080186199/1/0";
    let plan = Plan {
        chain: "bsc".into(),
        chain_id: Some(56),
        steps: vec![
            Step::Call {
                to: "0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b".into(),
                sig: "depositWithExpiry(address,address,uint256,string,uint256)".into(),
                args: vec![
                    "0x718f6C9df785BC4e323086De024CA822efbE8aB9".into(), // THORChain vault
                    "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c".into(), // BTCB
                    "500112480000000".into(),                           // 0.00050011248 BTCB
                    memo.into(),
                    "1793139980".into(),                                // expiry
                ],
            },
            // assertions ride along but don't change the resolved bytes:
            Step::ExpectTo { address: "0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b".into() },
            Step::CapFee { max: "250000000000000".into() },
        ],
    };
    let cx = context::Evm { nonce: 14, gas: 250000, max_fee_per_gas: 1_000_000_000, priority_fee: 1_000_000_000 };

    let tx = evm::resolve(&plan, &cx).expect("resolve");
    let hex: String = tx.encode_unsigned().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, UNSIGNED, "resolved unsigned tx must equal the on-chain bytes");
}

#[test]
fn approve_step_resolves_to_approve_calldata() {
    // The approve we sent before the deposit, via the structured Approve step.
    let plan = Plan {
        chain: "bsc".into(), chain_id: Some(56),
        steps: vec![Step::Approve {
            token: "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c".into(),
            spender: "0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b".into(),
            amount: "500112480000000".into(),
        }],
    };
    let cx = context::Evm { nonce: 13, gas: 60000, max_fee_per_gas: 1_000_000_000, priority_fee: 1_000_000_000 };
    let tx = evm::resolve(&plan, &cx).expect("resolve");
    let data: String = tx.data.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(data, "095ea7b3000000000000000000000000b30ec53f98ff5947ede720d32ac2da7e52a5f56b0000000000000000000000000000000000000000000000000001c6d982b7d800");
}

#[test]
fn foreign_family_step_is_rejected() {
    let plan = Plan { chain: "bsc".into(), chain_id: Some(56),
        steps: vec![Step::OpReturn { memo: "deadbeef".into() }] };
    let cx = context::Evm::default();
    assert!(evm::resolve(&plan, &cx).is_err(), "a UTXO step in an EVM plan must be rejected");
}
