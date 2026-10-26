//! ABI inspection: every item's canonical signature with its selector or topic, selector collisions
//! (two different signatures with the same 4 bytes), and ERC-165 interface ids computed from the
//! interfaces' published function lists (EIP-165, EIP-721, EIP-1155) plus the EIP-20 function set.
use crate::sig::{Kind, Sig};
use crate::hex;
use serde_json::{json, Value};

/// (name, published interface id or None, function signatures). The ids are the ones printed in
/// the EIPs; `interface_id` is recomputed (XOR of selectors) and tested against them.
pub const INTERFACES: &[(&str, Option<&str>, &[&str])] = &[
    ("ERC-165", Some("0x01ffc9a7"), &["supportsInterface(bytes4)"]),
    ("ERC-20", None, &["totalSupply()", "balanceOf(address)", "transfer(address,uint256)", "transferFrom(address,address,uint256)", "approve(address,uint256)", "allowance(address,address)"]),
    ("ERC-721", Some("0x80ac58cd"), &["balanceOf(address)", "ownerOf(uint256)", "safeTransferFrom(address,address,uint256,bytes)", "safeTransferFrom(address,address,uint256)", "transferFrom(address,address,uint256)", "approve(address,uint256)", "setApprovalForAll(address,bool)", "getApproved(uint256)", "isApprovedForAll(address,address)"]),
    ("ERC-721 Metadata", Some("0x5b5e139f"), &["name()", "symbol()", "tokenURI(uint256)"]),
    ("ERC-721 Enumerable", Some("0x780e9d63"), &["totalSupply()", "tokenOfOwnerByIndex(address,uint256)", "tokenByIndex(uint256)"]),
    ("ERC-1155", Some("0xd9b67a26"), &["safeTransferFrom(address,address,uint256,uint256,bytes)", "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)", "balanceOf(address,uint256)", "balanceOfBatch(address[],uint256[])", "setApprovalForAll(address,bool)", "isApprovedForAll(address,address)"]),
];

fn sel(sig: &str) -> [u8; 4] { let h = crate::keccak(sig.as_bytes()); [h[0], h[1], h[2], h[3]] }

/// XOR of the selectors (EIP-165 interface identifier).
pub fn interface_id(sigs: &[&str]) -> [u8; 4] {
    sigs.iter().fold([0u8; 4], |mut a, s| { let b = sel(s); for i in 0..4 { a[i] ^= b[i] } a })
}

/// Inspect an ABI. `abi_text` is ABI JSON (array or {abi:[..]}) or one signature per line.
pub fn inspect(abi_text: &str) -> Result<Value, String> {
    let sigs = crate::api::load_sigs(abi_text)?;
    // stateMutability is only in JSON ABIs; keep it by item position when present.
    let muts: Vec<Option<String>> = match serde_json::from_str::<Value>(abi_text.trim()) {
        Ok(v) => {
            let arr = v.as_array().cloned().or_else(|| v.get("abi").and_then(Value::as_array).cloned()).unwrap_or_default();
            arr.iter().filter(|i| !matches!(i.get("type").and_then(Value::as_str), Some("fallback" | "receive")))
                .map(|i| i.get("stateMutability").and_then(Value::as_str).map(str::to_string)).collect()
        }
        Err(_) => vec![None; sigs.len()],
    };
    let mut items = vec![];
    let mut fsel: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for (i, s) in sigs.iter().enumerate() {
        let mut o = crate::api::sig_info(s);
        o.as_object_mut().unwrap().remove("status");
        if !s.name.is_empty() { o["name"] = json!(s.name); }
        if let Some(Some(m)) = muts.get(i) { o["state_mutability"] = json!(m); }
        if !s.outputs.is_empty() { o["outputs"] = json!(s.outputs.iter().map(|p| p.ty.canon()).collect::<Vec<_>>()); }
        if matches!(s.kind, Kind::Function | Kind::Error) {
            let e = fsel.entry(hex(&s.selector())).or_default();
            let c = s.canonical(); if !e.contains(&c) { e.push(c) }
        }
        items.push(o);
    }
    let collisions: Vec<Value> = fsel.iter().filter(|(_, v)| v.len() > 1).map(|(k, v)| json!({"selector": k, "signatures": v})).collect();
    let have: std::collections::BTreeSet<String> = sigs.iter().filter(|s| s.kind == Kind::Function).map(Sig::canonical).collect();
    let interfaces: Vec<Value> = INTERFACES.iter().filter_map(|(n, _, fs)| {
        let missing: Vec<&str> = fs.iter().copied().filter(|f| !have.contains(*f)).collect();
        if missing.len() == fs.len() { return None; }
        let mut o = json!({"interface": n, "complete": missing.is_empty(), "interface_id": hex(&interface_id(fs))});
        if !missing.is_empty() { o["missing"] = json!(missing); }
        Some(o)
    }).collect();
    let count = |k: Kind| sigs.iter().filter(|s| s.kind == k).count();
    Ok(json!({"status": "ok", "functions": count(Kind::Function), "events": count(Kind::Event), "errors": count(Kind::Error),
        "items": items, "selector_collisions": collisions, "interfaces": interfaces}))
}
