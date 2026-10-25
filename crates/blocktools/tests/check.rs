//! check::tx_json, address::validate, derive::from_xpub on public vectors only.
use blocktools::{address, check::tx_json, derive};
use serde_json::{json, Value};

// Bitcoin block 170 transaction (Satoshi -> Hal Finney): 10 BTC to Hal, 40 BTC change back.
const TX170: &str = include_str!("../../tx/tests/vectors/block170.hex");
const HAL: &str = "1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3";
const SATOSHI: &str = "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S";
fn run(v: Value) -> Value { serde_json::from_str(&tx_json(&v.to_string())).unwrap() }
fn base() -> Value { json!({"chain": "btc", "raw_tx_hex": TX170.trim(), "expected_outputs": [{"address": HAL, "amount": "1000000000"}], "max_fee": 0, "owner_addr": SATOSHI, "input_values": [5000000000u64]}) }

#[test] fn block170_passes_with_exact_expectations() {
    let r = run(base());
    assert_eq!(r["reasons"], json!([]), "{r}"); assert_eq!(r["ok"], true);
    assert_eq!(r["fee"], "0"); assert_eq!(r["outputs"].as_array().unwrap().len(), 2);
}
#[test] fn fails_closed() {
    let mut v = base(); v["expected_outputs"][0]["amount"] = json!("999"); assert_eq!(run(v)["reasons"], json!(["expected_amount_mismatch"]));
    let mut v = base(); v["owner_addr"] = json!(HAL); assert!(run(v)["reasons"].as_array().unwrap().contains(&json!("unexpected_output")));
    let mut v = base(); v.as_object_mut().unwrap().remove("input_values"); assert_eq!(run(v)["reasons"], json!(["fee_unknown"]));
    let mut v = base(); v.as_object_mut().unwrap().remove("max_fee"); assert_eq!(run(v)["reasons"], json!(["max_fee_missing"]));
    let mut v = base(); v["input_values"] = json!([5000000001u64]); assert_eq!(run(v)["reasons"], json!(["fee_above_max"]));
    let mut v = base(); v["chain"] = json!("wdc"); assert_eq!(run(v)["reasons"], json!(["unverified_chain"]));
    let mut v = base(); v["chain"] = json!("nope"); assert_eq!(run(v)["ok"], false);
    let mut v = base(); v["raw_tx_hex"] = json!("00"); assert_eq!(run(v)["ok"], false);
    let mut v = base(); v["expected_outputs"] = json!([]); assert!(run(v)["reasons"].as_array().unwrap().contains(&json!("expected_outputs_missing")));
    assert_eq!(serde_json::from_str::<Value>(&tx_json("not json")).unwrap()["ok"], false);
}
#[test] fn validate_and_from_xpub() {
    assert!(address::validate("btc", HAL).is_ok());
    assert_eq!(address::validate("wdc", "WZMJS5eeCEgiqxNK1QRbE1HR4wFQwmCjJV"), Err("unverified_chain"));
    assert!(address::validate("ltc", HAL).is_err());
    // BIP84 public vector, account xpub of "abandon x11 about".
    let x = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
    let r = derive::from_xpub("btc", x, "m/0", 0).unwrap();
    assert!(r.iter().any(|r| r.kind == "p2wpkh" && r.address == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" && r.path == "m/0/0"));
    assert_eq!(derive::from_xpub("btc", x, "0'", 0).unwrap_err(), "bad_path");
    assert!(derive::from_xpub("wdc", x, "0", 0).is_err());
}
