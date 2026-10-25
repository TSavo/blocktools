//! Solana unsigned transfer builder vs @solana/kit 8.5 (scripts/sol-build-gen.mjs): byte-identical
//! wire transactions for native send, balance sweep, SPL transfer_checked (Token and Token-2022,
//! with/without idempotent ATA create), with/without compute-budget priority fee.
use blocktools::sol::{self, build_transfer, SolAmount, SolPlan};
use serde_json::Value;

#[test] fn kit_corpus_byte_identical() {
    let v: Vec<Value> = serde_json::from_str(include_str!("data/sol-build-corpus.json")).unwrap();
    assert_eq!(v.len(), 120);
    let pk = |c: &Value, k: &str| sol::pubkey(c[k].as_str().unwrap()).unwrap();
    let n = |c: &Value, k: &str| c[k].as_str().unwrap().parse::<u64>().unwrap();
    for (i, c) in v.iter().enumerate() {
        let amount = match c["kind"].as_str().unwrap() {
            "send" => SolAmount::Send(n(c, "lamports")),
            "sweep" => SolAmount::Sweep { balance: n(c, "balance") },
            _ => SolAmount::Token { mint: pk(c, "mint"), amount: n(c, "amount"), decimals: c["decimals"].as_u64().unwrap() as u8,
                token_program: pk(c, "token_program"), create_ata: c["create_ata"].as_bool().unwrap() },
        };
        let priority = c["priority"].as_array().map(|p| (p[0].as_str().unwrap().parse().unwrap(), p[1].as_u64().unwrap() as u32));
        let p = SolPlan { from: pk(c, "from"), to: pk(c, "to"), blockhash: pk(c, "blockhash"), amount, priority };
        let got = blocktools::hex_enc(build_transfer(&p).unwrap());
        assert_eq!(got, c["tx"].as_str().unwrap(), "case {i} {}", c["kind"]);
        // our own decoder reads it back as an unsigned transfer to the right place
        let d = sol::decode_tx(&build_transfer(&p).unwrap()).unwrap();
        let last = d["instructions"].as_array().unwrap().last().unwrap().clone();
        match c["kind"].as_str().unwrap() {
            "token" => {
                assert_eq!(last["kind"], "token_transfer_checked");
                // destination is the recipient's ATA (kit-derived in the corpus); verify by wallet and by ATA
                let tx = build_transfer(&p).unwrap();
                for to in [c["to"].as_str().unwrap().to_string(), last["destination"].as_str().unwrap().to_string()] {
                    let v = sol::verify_tx(&tx, &serde_json::json!({"owner": c["from"], "to": to, "mint": c["mint"], "amount": c["amount"]})).unwrap();
                    assert_eq!(v["failures"], serde_json::json!([]), "case {i}");
                }
                let v = sol::verify_tx(&tx, &serde_json::json!({"to": c["from"], "mint": c["mint"]})).unwrap();
                assert!(v["failures"].as_array().unwrap().iter().any(|f| f.as_str().unwrap().starts_with("unexpected_token_destination")));
            }
            _ => { assert_eq!(last["kind"], "system_transfer"); assert_eq!(last["lamports"], c["expect_lamports"]); }
        }
    }
}

#[test] fn errors_and_address_order() {
    use std::cmp::Ordering::*;
    assert_eq!(sol::address_cmp("a", "B"), Less); assert_eq!(sol::address_cmp("b", "A"), Greater);
    assert_eq!(sol::address_cmp("a", "A"), Less); assert_eq!(sol::address_cmp("9", "a"), Less);
    let k = [7u8; 32];
    let p = SolPlan { from: k, to: k, blockhash: [1; 32], amount: SolAmount::Send(1), priority: None };
    assert_eq!(build_transfer(&p).unwrap_err(), "from_equals_to");
    let p = SolPlan { to: [8; 32], amount: SolAmount::Sweep { balance: 5000 }, ..p };
    assert_eq!(build_transfer(&p).unwrap_err(), "balance does not cover fee");
    assert_eq!(build_transfer(&SolPlan { amount: SolAmount::Send(0), ..p }).unwrap_err(), "zero_amount");
}
