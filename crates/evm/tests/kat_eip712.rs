//! Known-answer vectors for EIP-712 hashing and signer recovery: the specification Mail example.
use blocktools_evm::{eip712, hex, unhex};
use serde_json::{json, Value};

fn mail() -> Value {
    // EIP-712 specification example (assets/eip-712/Example.js)
    serde_json::from_str(r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
    "Person":[{"name":"name","type":"string"},{"name":"wallet","type":"address"}],
    "Mail":[{"name":"from","type":"Person"},{"name":"to","type":"Person"},{"name":"contents","type":"string"}]},
    "primaryType":"Mail","domain":{"name":"Ether Mail","version":"1","chainId":1,"verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"},
    "message":{"from":{"name":"Cow","wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},"to":{"name":"Bob","wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},"contents":"Hello, Bob!"}}"#).unwrap()
}

#[test]
fn eip712_spec_example() {
    let td = mail();
    let types = td["types"].as_object().unwrap();
    assert_eq!(eip712::encode_type(types, "Mail").unwrap(), "Mail(Person from,Person to,string contents)Person(string name,address wallet)");
    assert_eq!(hex(&eip712::type_hash(types, "Mail").unwrap()), "0xa0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2");
    let (ds, mh, d) = eip712::digest(&td).unwrap();
    assert_eq!(hex(&ds), "0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");
    assert_eq!(hex(&mh), "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e");
    assert_eq!(hex(&d), "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
    // spec signature (key keccak256("cow")): v=28 r=0x4355…1c9d s=0x0729…1562
    let sig = "0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c";
    let v = eip712::verify(&td, Some(sig), Some("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")).unwrap();
    assert_eq!(v["status"], "valid"); assert_eq!(v["low_s"], true);
    let w = eip712::verify(&td, Some(sig), Some("0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB")).unwrap();
    assert_eq!(w["status"], "signer_mismatch");
    // EIP-2098 compact form of the same signature (v=28 -> top bit of s set)
    let mut c = unhex(sig).unwrap(); c.pop(); c[32] |= 0x80;
    assert_eq!(eip712::verify(&td, Some(&hex(&c)), Some("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")).unwrap()["status"], "valid");
    // tampered message -> different signer
    let mut t = td.clone(); t["message"]["contents"] = json!("Hello, Bob?");
    assert_eq!(eip712::verify(&t, Some(sig), Some("0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826")).unwrap()["status"], "signer_mismatch");
    // refusals
    let mut m = td.clone(); m["message"].as_object_mut().unwrap().remove("contents");
    assert!(eip712::digest(&m).is_err());
    assert!(eip712::verify(&td, Some("0x00"), None).is_err());
}
