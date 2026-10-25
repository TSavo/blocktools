//! Parity of blocktools::build against tools/build-parity/gen.ts (viem serializeTransaction + keccak256 oracle
//! for buildEvmTransfer; transcribed SwapChan selection policy for selectUtxos).
use blocktools::build::*;
use serde_json::Value;
#[test] fn corpus() {
    let c: Value = serde_json::from_str(include_str!("data/build-corpus.json")).unwrap();
    let mut bad = vec![];
    for k in c["evm"].as_array().unwrap() {
        let got = build_evm_transfer(&k["req"]);
        match (&got, k.get("error")) {
            (Err(e), Some(w)) if w == e.as_str() => {}
            (Ok(o), None) => for f in ["unsigned", "sighash", "value", "fee"] {
                if o[f] != k["expect"][f] { bad.push(format!("{} {f}: {} vs {}", k["name"], o[f], k["expect"][f])) }
            },
            _ => bad.push(format!("{}: got {got:?} want {:?}", k["name"], k.get("error"))),
        }
    }
    for k in c["select"].as_array().unwrap() {
        let got = select_utxos(&k["utxos"], k["script"].as_str().unwrap(), k["rate"].as_u64().unwrap() as u128).unwrap();
        if got != k["expect"] { bad.push(format!("{}: differs", k["name"])) }
    }
    assert!(c["evm"].as_array().unwrap().len() > 100 && c["select"].as_array().unwrap().len() >= 40);
    assert!(bad.is_empty(), "{}", bad[..bad.len().min(10)].join("\n"));
}
#[test] fn select_errors() {
    assert_eq!(select_utxos(&serde_json::json!({}), "00", 1).unwrap_err(), "bad_utxos");
    assert_eq!(select_utxos(&serde_json::json!([{"txid":"00","vout":0,"value":"x","script":"00"}]), "00", 1).unwrap_err(), "bad_utxo_value");
    assert_eq!(select_utxos(&serde_json::json!([{"vout":0,"value":1,"script":"00"}]), "00", 0).unwrap_err(), "bad_utxo");
}
