//! abi.encodePacked against the Solidity docs (docs/abi-spec.rst, "Non-standard Packed Mode").
use blocktools_evm::api::encode_packed_json;
use serde_json::json;

fn data(t: &str, a: serde_json::Value) -> String {
    encode_packed_json(&json!({"types": t, "args": a})).unwrap()["data"].as_str().unwrap().to_string()
}

#[test]
fn solidity_docs_example() {
    // int16(-1), bytes1(0x42), uint16(0x03), string("Hello, world!")
    assert_eq!(data("(int16,bytes1,uint16,string)", json!(["-1", "0x42", "3", "Hello, world!"])), "0xffff42000348656c6c6f2c20776f726c6421");
    // abi.encodePacked(uint16(0x12)) == hex"0012"
    assert_eq!(data("(uint16)", json!(["0x12"])), "0x0012");
}

#[test]
fn spec_rules() {
    // "ambiguous as soon as there are two dynamically-sized elements": ("a","bc") == ("ab","c")
    assert_eq!(data("(string,string)", json!(["a", "bc"])), data("(string,string)", json!(["ab", "c"])));
    // array elements are padded, no length field
    assert_eq!(data("(uint8[])", json!([["1", "2"]])), format!("0x{}01{}02", "00".repeat(31), "00".repeat(31)));
    // address 20 bytes, bool 1 byte
    assert_eq!(data("(address,bool)", json!(["0x00000000000000000000000000000000000000ff", true])), format!("0x{}ff01", "00".repeat(19)));
}

#[test]
fn refusals() {
    for (t, a) in [("((uint8,uint8))", json!([["1", "2"]])), ("(uint8[][])", json!([[["1"]]])), ("(string[])", json!([["a"]]))] {
        assert!(encode_packed_json(&json!({"types": t, "args": a})).is_err(), "{t}");
    }
    assert!(encode_packed_json(&json!({"types": "(uint8)", "args": ["256"]})).is_err());
}
