//! docs/ROADMAP-PARITY.md item 1: offline policy file, deny by default.
use blocktools_tx::build::{build_evm, EvmAmount, EvmPlan};
use blocktools_tx::policy_file::{check, parse};
use blocktools_tx::{addr, decode, Decoded, Io};

fn evm(amount: EvmAmount, data: Option<Vec<u8>>) -> Decoded {
    let p = EvmPlan { chain_id: 56, nonce: 0, max_fee: 1_000_000_000, priority_fee: Some(1), gas: None, to: [0x11; 20], amount };
    let mut t = build_evm(&p).unwrap();
    if let Some(d) = data { t.data = d; t.to = Some([0x33; 20]); t.gas = 60_000 }
    decode(&blocktools_core::hex_enc(t.encode_unsigned()), "eth").unwrap()
}
fn pf(rule: &str) -> blocktools_tx::policy_file::PolicyFile { parse(&format!(r#"{{"version":1,"chains":{{"bsc":{rule}}}}}"#)).unwrap() }

#[test] fn evm_native_rules() {
    let to = addr(&[0x11; 20]);
    let d = evm(EvmAmount::Send(1_000_000_000_000_000_000), None);
    let ok = pf(&format!(r#"{{"chain_id":56,"allow_to":["{to}"],"max_value":"1000000000000000000"}}"#));
    assert!(check(&d, "bsc", &ok).is_empty(), "{:?}", check(&d, "bsc", &ok));
    assert_eq!(ok.sha256.len(), 64);
    assert_eq!(check(&d, "eth", &ok), ["policy:no_rule_for_chain"]);
    assert!(check(&d, "bsc", &pf(&format!(r#"{{"chain_id":56,"allow_to":["{to}"],"max_value":"999999999999999999"}}"#))).contains(&"policy:max_value".into()));
    assert!(check(&d, "bsc", &pf(r#"{"chain_id":56,"allow_to":[]}"#)).contains(&"policy:allow_to".into()));
    assert!(check(&d, "bsc", &pf(&format!(r#"{{"chain_id":1,"allow_to":["{to}"]}}"#))).contains(&"policy:chain_id".into()));
    assert!(check(&d, "bsc", &pf(&format!(r#"{{"allow_to":["{to}"]}}"#))).contains(&"policy:chain_id".into()));
    assert!(check(&d, "bsc", &pf(&format!(r#"{{"chain_id":56,"allow_to":["{to}"],"max_fee":"1"}}"#))).contains(&"policy:max_fee".into()));
}

#[test] fn evm_token_and_calls() {
    let (to, tok) = (addr(&[0x11; 20]), addr(&[0x22; 20]));
    let d = evm(EvmAmount::Token { token: [0x22; 20], amount: 5 }, None);
    let base = format!(r#""chain_id":56,"allow_to":["{to}"],"max_value":"5""#);
    assert_eq!(check(&d, "bsc", &pf(&format!("{{{base}}}"))), ["policy:allow_tokens"]);
    assert!(check(&d, "bsc", &pf(&format!(r#"{{{base},"allow_tokens":["{tok}"]}}"#))).is_empty());
    // approve(spender, amount) is refused unless (contract, selector) is listed.
    let mut data = vec![0x09, 0x5e, 0xa7, 0xb3]; data.extend([0u8; 64]);
    let d = evm(EvmAmount::Send(0), Some(data));
    let c = addr(&[0x33; 20]);
    assert!(check(&d, "bsc", &pf(&format!("{{{base}}}"))).contains(&"policy:allow_calls".into()));
    let r = check(&d, "bsc", &pf(&format!(r#"{{{base},"allow_calls":[{{"to":"{c}","selector":"0x095ea7b3"}}]}}"#)));
    assert!(r.is_empty(), "{r:?}");
}

#[test] fn utxo_rules_and_parse_errors() {
    let io = |a: &str, v| Io { data: None, txid: None, vout: None, address: Some(a.into()), kind: "p2wpkh", amount: Some(v) };
    let d = Decoded { chain: "btc".into(), ty: "psbt", signed: false, txid: None, inputs: vec![], outputs: vec![io("A", 700), io("C", 300)],
        fee: Some(200), vsize: None, locktime: None, rbf: None, evm: None, warnings: vec![], unproven_inputs: 0 };
    let p = |r: &str| parse(&format!(r#"{{"version":1,"chains":{{"btc":{r}}}}}"#)).unwrap();
    assert!(check(&d, "btc", &p(r#"{"allow_to":["A"],"change":["C"],"max_value":700,"max_fee":200,"max_outputs":2}"#)).is_empty());
    assert_eq!(check(&d, "btc", &p(r#"{"allow_to":["A"],"max_value":700}"#)), ["policy:allow_to", "policy:max_value"]);
    assert_eq!(check(&d, "btc", &p(r#"{"allow_to":["A"],"change":["C"],"max_fee":199,"max_outputs":1}"#)), ["policy:max_outputs", "policy:max_fee"]);
    for (t, e) in [("{", "policy_bad_json"), (r#"{"version":2,"chains":{}}"#, "policy_bad_version"), (r#"{"version":1}"#, "policy_missing_chains"),
        (r#"{"version":1,"chains":{"btc":{"max_vaule":1}}}"#, "policy_unknown_key"), (r#"{"version":1,"chains":{"btc":{"max_fee":"-1"}}}"#, "policy_bad_number")] {
        assert_eq!(parse(t).unwrap_err(), e);
    }
}
