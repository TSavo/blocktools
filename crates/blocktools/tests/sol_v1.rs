//! Solana v1 (SIMD-0385) transactions built and signed by @solana/kit 8.5 (tools/sol-v1/gen.mjs).
use blocktools::sol;
use serde_json::{json, Value};
#[test] fn kit_v1() {
    let c: Value = serde_json::from_str(include_str!("data/sol-v1.json")).unwrap();
    for k in c.as_array().unwrap() {
        let raw = blocktools::hex_dec(k["hex"].as_str().unwrap()).unwrap();
        let d = sol::decode_tx(&raw).unwrap();
        assert_eq!(d["version"], 1, "{}", k["name"]); assert_eq!(d["fee_payer"], k["fee_payer"]);
        assert_eq!(d["message_hex"], k["message_hex"]);
        let sigs = d["signatures"].as_array().unwrap();
        assert_eq!(sigs.len(), k["signers"].as_array().unwrap().len());
        assert!(sigs.iter().all(|s| s["status"] == "valid"), "{d}");
        for s in k["signers"].as_array().unwrap() { assert!(sigs.iter().any(|x| &x["signer"] == s)) }
        let mut bad = raw.clone(); let n = bad.len(); bad[n - 1] ^= 1;
        assert_eq!(sol::verify_tx(&bad, &json!({})).unwrap()["ok"], false);
        let mut tr = raw.clone(); tr.push(0); assert!(sol::parse_tx(&tr).is_err());
        let mut m = raw.clone(); m[4] |= 0x40; assert_eq!(sol::parse_tx(&m).unwrap_err(), "v1_unknown_config_bits");
    }
    let all = sol::decode_tx(&blocktools::hex_dec(c[1]["hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(all["config"], json!({"mask": 31, "priority_fee_lamports": "7777", "compute_unit_limit": 200000, "loaded_accounts_data_size_limit": 65536, "heap_size": 65536}));
    assert_eq!(all["instructions"][0]["kind"], "system_transfer"); assert_eq!(all["instructions"][0]["lamports"], "5000");
    let v = sol::verify_tx(&blocktools::hex_dec(c[1]["hex"].as_str().unwrap()).unwrap(), &json!({"lamports": "5000"})).unwrap();
    assert_eq!(v["ok"], true, "{v}"); assert_eq!(v["fully_signed"], true);
    let two = sol::decode_tx(&blocktools::hex_dec(c[2]["hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(two["instructions"][1]["kind"], "memo"); assert_eq!(two["instructions"][1]["text"], "hello v1");
    assert_eq!(two["config"]["compute_unit_limit"], 1400);
    assert_eq!(sol::parse_tx(&[0x82, 0, 0, 0]).unwrap_err(), "unsupported_version");
}
