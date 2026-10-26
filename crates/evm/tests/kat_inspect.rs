//! Known-answer vectors for abi-inspect, from the EIPs.
use blocktools_evm::{hex, inspect};

#[test]
fn erc165_interface_ids_match_the_eips() {
    // EIP-165, EIP-721 (+Metadata, Enumerable), EIP-1155 print these ids.
    for (n, id, fs) in inspect::INTERFACES { if let Some(id) = id { assert_eq!(&hex(&inspect::interface_id(fs)), id, "{n}"); } }
}

#[test]
fn abi_inspect_erc20_and_collision() {
    let abi = "function totalSupply() view returns (uint256)\nfunction balanceOf(address) view returns (uint256)\nfunction transfer(address,uint256) returns (bool)\nfunction transferFrom(address,address,uint256) returns (bool)\nfunction approve(address,uint256) returns (bool)\nfunction allowance(address,address) view returns (uint256)\nevent Transfer(address indexed from, address indexed to, uint256 value)\n# collides with transferFrom (0x23b872dd), a well-known pair\nfunction gasprice_bit_ether(int128)";
    let v = inspect::inspect(abi).unwrap();
    assert_eq!(v["functions"], 7); assert_eq!(v["events"], 1);
    let c = &v["selector_collisions"][0]; assert_eq!(c["selector"], "0x23b872dd");
    assert!(v["interfaces"].as_array().unwrap().iter().any(|i| i["interface"] == "ERC-20" && i["complete"] == true));
    let j = inspect::inspect(r#"[{"type":"function","name":"name","inputs":[],"outputs":[{"type":"string"}],"stateMutability":"view"},{"type":"fallback"}]"#).unwrap();
    assert_eq!(j["items"][0]["state_mutability"], "view"); assert_eq!(j["items"][0]["selector"], "0x06fdde03");
    assert_eq!(j["interfaces"][0]["complete"], false);
}
