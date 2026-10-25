//! api.novaco.in `/gettransaction/<txid>` JSON -> raw hex, fail-closed on the txid.
//! Fixtures fetched 2026-10-25 from https://api.novaco.in/gettransaction/<txid> (public chain data).
use blocktools_tx::nvc_json::{amount_units, parse_nvc_json, serialize_nvc_tx_from_json};
use serde_json::{json, Value};

const COINSTAKE: &str = "c053a3fddd508df8cadd90bf8c987c35802c2779a8a19b4efc8c83124d11df20";
const REGULAR: &str = "cdced5fa03d9651443deea305e09290b925794ed3836de21ef30e13f42f83bd7";
fn fixture(t: &str) -> &'static str {
    match t { COINSTAKE => include_str!("data/nvc_c053a3fd.json"), REGULAR => include_str!("data/nvc_cdced5fa.json"), _ => unreachable!() }
}
fn edit(t: &str, f: impl Fn(&mut Value)) -> String { let mut v: Value = serde_json::from_str(fixture(t)).unwrap(); f(&mut v); v.to_string() }

#[test] fn mainnet_json_reserializes_to_txid() {
    for t in [COINSTAKE, REGULAR] {
        let hex = serialize_nvc_tx_from_json(fixture(t), t).unwrap();
        let tx = blocktools_tx::pos::PosTx::parse("nvc", &blocktools_core::hex_dec(&hex).unwrap()).unwrap();
        assert_eq!(tx.txid_hex(), t);
        assert_eq!(blocktools_tx::pos::PosTx::parse("nvc", &blocktools_core::hex_dec(&hex).unwrap()).unwrap().serialize().len() * 2, hex.len());
        assert_eq!(serialize_nvc_tx_from_json(fixture(t), &t.to_uppercase()).unwrap(), hex);
    }
    // coinstake: empty PoS marker output first, nTime after the version
    let raw = blocktools_core::hex_dec(&serialize_nvc_tx_from_json(fixture(COINSTAKE), COINSTAKE).unwrap()).unwrap();
    let tx = blocktools_tx::pos::PosTx::parse("nvc", &raw).unwrap();
    assert_eq!(tx.outputs[0], (0, vec![]));
    assert_eq!(&raw[4..8], &1792953281u32.to_le_bytes());
}

#[test] fn any_altered_field_is_refused() {
    let t = REGULAR;
    assert_eq!(serialize_nvc_tx_from_json(fixture(t), COINSTAKE), Err("nvc_json_txid_not_expected"));
    assert!(serialize_nvc_tx_from_json(&edit(t, |v| v["time"] = json!(v["time"].as_str().map(|s| s.parse::<u64>().unwrap()).or(v["time"].as_u64()).unwrap() + 1)), t).is_err());
    assert!(serialize_nvc_tx_from_json(&edit(t, |v| v["vout"][0]["value"] = json!(v["vout"][0]["value"].as_u64().unwrap() + 1)), t).is_err());
    assert!(serialize_nvc_tx_from_json(&edit(t, |v| v["vin"][0]["sequence"] = json!("0")), t).is_err());
    assert!(serialize_nvc_tx_from_json(&edit(t, |v| v["locktime"] = json!("1")), t).is_err());
    assert!(serialize_nvc_tx_from_json(&edit(t, |v| v["vin"][0]["vout"] = json!(v["vin"][0]["vout"].as_u64().unwrap() ^ 1)), t).is_err());
    assert_eq!(serialize_nvc_tx_from_json(&edit(t, |v| v["size"] = json!(1)), t), Err("nvc_json_size_mismatch"));
    // json txid swapped to match expected, but content unchanged -> the hash still refuses
    assert_eq!(serialize_nvc_tx_from_json(&edit(t, |v| v["txid"] = json!(COINSTAKE)), COINSTAKE), Err("nvc_json_hash_mismatch"));
    // output order comes from `index`, not array order
    let swapped = edit(COINSTAKE, |v| { let a = v["vout"].as_array_mut().unwrap(); a.swap(0, 1) });
    assert!(serialize_nvc_tx_from_json(&swapped, COINSTAKE).is_ok());
    assert_eq!(serialize_nvc_tx_from_json(&edit(COINSTAKE, |v| v["vout"][1]["index"] = json!(5)), COINSTAKE), Err("nvc_json_vout_index_gap"));
    assert!(serialize_nvc_tx_from_json("not json", t).is_err());
    assert!(serialize_nvc_tx_from_json(fixture(t), "zz").is_err());
}

#[test] fn amounts_are_exact() {
    assert_eq!(amount_units(&json!(155721245)), Ok(155721245));
    assert_eq!(amount_units(&json!("155721245")), Ok(155721245));
    assert_eq!(amount_units(&json!("155.721245")), Ok(155721245));
    assert_eq!(amount_units(&json!("0.1")), Ok(100000));
    assert!(amount_units(&json!("0.1234567")).is_err());
    assert!(amount_units(&json!("-1")).is_err());
    assert!(amount_units(&json!("1e6")).is_err());
    assert!(amount_units(&json!(1.5e300)).is_err());
    // decimal-NVC form of the same output reserializes identically
    let dec = edit(COINSTAKE, |v| v["vout"][1]["value"] = json!("158.389281"));
    assert!(serialize_nvc_tx_from_json(&dec, COINSTAKE).is_ok());
}

#[test] fn coinbase_input_layout() {
    // real PoS coinbase (block 1106297) from the API: `coinbase` is double hex-encoded
    let cb = "72b702b14a9ef0bdab7aca4ac70cb4005c2176d36a77806c77815e99cb000ef7";
    assert_eq!(serialize_nvc_tx_from_json(include_str!("data/nvc_72b702b1.json"), cb).unwrap().len(), 77 * 2);
    let v = json!({"version":"1","time":"7","locktime":"0","vin":[{"coinbase":"303341424344","sequence":"4294967295"}],"vout":[{"index":0,"value":0,"scriptPubKey":{"hex":""}}]});
    let tx = parse_nvc_json(&v).unwrap();
    assert_eq!((tx.inputs[0].txid, tx.inputs[0].vout, tx.inputs[0].script_sig.clone()), ([0; 32], u32::MAX, vec![3, 0xab, 0xcd]));
    let raw = tx.serialize();
    assert_eq!(&raw[..8], &[1, 0, 0, 0, 7, 0, 0, 0]);
}

#[test] fn varint_boundaries() {
    for n in [0xfcusize, 0xfd, 0x100] {
        let v = json!({"version":1,"time":0,"locktime":0,"vin":[{"txid":REGULAR,"vout":0,"scriptSig":{"hex":"00".repeat(n)},"sequence":0}],"vout":[]});
        let raw = parse_nvc_json(&v).unwrap().serialize();
        let p = 4 + 4 + 1 + 32 + 4;
        if n < 0xfd { assert_eq!(raw[p] as usize, n) } else { assert_eq!(raw[p], 0xfd); assert_eq!(u16::from_le_bytes([raw[p + 1], raw[p + 2]]) as usize, n) }
    }
}
