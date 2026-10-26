//! Known-answer vectors for bytecode-inspect, from the EIPs (1167, 7702, 3540, 170).
use blocktools_evm::{bytecode, unhex};
use serde_json::json;

#[test]
fn eip1167_reference_and_7702() {
    // EIP-1167 reference runtime code with implementation 0xbebe...be
    let c = unhex("0x363d3d373d3d3d363d73bebebebebebebebebebebebebebebebebebebebe5af43d82803e903d91602b57fd5bf3").unwrap();
    let v = bytecode::inspect(&c); assert_eq!(v["kind"], "eip1167_proxy");
    assert_eq!(v["implementation"].as_str().unwrap().to_lowercase(), "0xbebebebebebebebebebebebebebebebebebebebe");
    let mut d = vec![0xef, 0x01, 0x00]; d.extend([0x11u8; 20]);
    assert_eq!(bytecode::inspect(&d)["kind"], "eip7702_delegation");
    assert_eq!(bytecode::inspect(&[0xef, 0x00, 0x01])["kind"], "eof");
    assert_eq!(bytecode::inspect(&[])["kind"], "empty");
    assert_eq!(bytecode::inspect(&vec![0u8; bytecode::EIP170_LIMIT + 1])["exceeds_eip170"], true);
}

#[test]
fn dispatcher_and_metadata() {
    // PUSH1 0 CALLDATALOAD PUSH1 0xe0 SHR DUP1 PUSH4 a9059cbb EQ PUSH1 x JUMPI ; PUSH32 with 0x63..14 inside data ignored
    let mut c = unhex("0x60003560e01c8063a9059cbb14601057").unwrap();
    c.extend(unhex("0x7f").unwrap()); c.extend([0x63, 1, 2, 3, 4, 0x14]); c.extend([0u8; 26]);
    // CBOR {"solc": 0.8.26} + length
    let m = unhex("0xa164736f6c634300081a").unwrap(); c.extend(&m); c.extend((m.len() as u16).to_be_bytes());
    let v = bytecode::inspect(&c);
    assert_eq!(v["selector_candidates"], json!(["0xa9059cbb"]));
    assert_eq!(v["metadata"]["solc"], "0.8.26");
}
