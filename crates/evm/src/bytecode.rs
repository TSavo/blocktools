//! Runtime bytecode inspection, offline. Exact pattern checks: EIP-1167 minimal proxy, EIP-7702
//! delegation designator, EOF container magic (EIP-3540), EIP-170 size limit, Solidity CBOR
//! metadata trailer. Heuristic (labelled so): PUSH4 constants compared with EQ in the dispatcher
//! are reported as candidate selectors; opcodes are counted by walking instructions (PUSH data skipped).
use crate::{checksum_address, hex};
use serde_json::{json, Value};

/// EIP-170 runtime code size limit.
pub const EIP170_LIMIT: usize = 0x6000;
const P1167_A: &[u8] = &[0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73];
const P1167_B: &[u8] = &[0x5a, 0xf4, 0x3d, 0x82, 0x80, 0x3e, 0x90, 0x3d, 0x91, 0x60, 0x2b, 0x57, 0xfd, 0x5b, 0xf3];

fn addr(b: &[u8]) -> String { let mut a = [0u8; 20]; a.copy_from_slice(b); checksum_address(&a) }

/// Solidity metadata: CBOR map at the end, followed by its 2-byte big-endian length.
pub fn metadata(code: &[u8]) -> Option<(usize, Value)> {
    if code.len() < 2 { return None; }
    let l = u16::from_be_bytes([code[code.len() - 2], code[code.len() - 1]]) as usize;
    if l == 0 || l + 2 > code.len() { return None; }
    let m = &code[code.len() - 2 - l..code.len() - 2];
    let (n, mut i) = match m.first()? { b @ 0xa1..=0xb7 => ((b - 0xa0) as usize, 1), _ => return None };
    let mut o = serde_json::Map::new();
    let take = |i: &mut usize, major: u8| -> Option<&[u8]> {
        let h = *m.get(*i)?; if h >> 5 != major { return None; }
        let (len, skip) = match h & 0x1f { x @ 0..=23 => (x as usize, 1), 24 => (*m.get(*i + 1)? as usize, 2), _ => return None };
        let s = m.get(*i + skip..*i + skip + len)?; *i += skip + len; Some(s)
    };
    for _ in 0..n {
        let k = String::from_utf8(take(&mut i, 3)?.to_vec()).ok()?;
        let v = match *m.get(i)? {
            0xf4 => { i += 1; json!(false) } 0xf5 => { i += 1; json!(true) }
            h if h >> 5 == 3 => json!(String::from_utf8(take(&mut i, 3)?.to_vec()).ok()?),
            _ => { let b = take(&mut i, 2)?; if k == "solc" && b.len() == 3 { json!(format!("{}.{}.{}", b[0], b[1], b[2])) } else { json!(hex(b)) } }
        };
        o.insert(k, v);
    }
    if i != m.len() { return None; }
    Some((l + 2, Value::Object(o)))
}

pub fn inspect(code: &[u8]) -> Value {
    let mut o = json!({"status": "ok", "size": code.len(), "exceeds_eip170": code.len() > EIP170_LIMIT, "keccak256": hex(&crate::keccak(code))});
    if code.is_empty() { o["kind"] = json!("empty"); return o; }
    if code.len() == 23 && code[..3] == [0xef, 0x01, 0x00] { o["kind"] = json!("eip7702_delegation"); o["delegate"] = json!(addr(&code[3..])); return o; }
    if code.len() >= 2 && code[..2] == [0xef, 0x00] { o["kind"] = json!("eof"); return o; }
    if code.len() == 45 && code[..10] == *P1167_A && code[30..] == *P1167_B { o["kind"] = json!("eip1167_proxy"); o["implementation"] = json!(addr(&code[10..30])); return o; }
    o["kind"] = json!("code");
    let meta = metadata(code);
    let end = code.len() - meta.as_ref().map(|m| m.0).unwrap_or(0);
    if let Some((l, m)) = meta { o["metadata"] = m; o["metadata_bytes"] = json!(l); }
    let (mut i, mut sels, mut ops) = (0usize, vec![], std::collections::BTreeMap::<&str, usize>::new());
    let mut last_push4: Option<(usize, [u8; 4])> = None; let mut n = 0usize;
    while i < end {
        let op = code[i]; n += 1;
        let name = match op { 0x5f => Some("PUSH0"), 0xf0 => Some("CREATE"), 0xf5 => Some("CREATE2"), 0xf4 => Some("DELEGATECALL"), 0xf2 => Some("CALLCODE"), 0xff => Some("SELFDESTRUCT"), 0xfa => Some("STATICCALL"), 0xf1 => Some("CALL"), 0x5c => Some("TLOAD"), 0x5d => Some("TSTORE"), _ => None };
        if let Some(nm) = name { *ops.entry(nm).or_default() += 1; }
        if op == 0x63 && i + 5 <= end { let mut s = [0u8; 4]; s.copy_from_slice(&code[i + 1..i + 5]); last_push4 = Some((n, s)); }
        // PUSH4 sel [DUP/SWAP] EQ: the dispatcher's comparison
        if op == 0x14 { if let Some((k, s)) = last_push4 { if n - k <= 2 && !sels.contains(&hex(&s)) { sels.push(hex(&s)); } } }
        i += 1 + if (0x60..=0x7f).contains(&op) { (op - 0x5f) as usize } else { 0 };
    }
    o["instructions"] = json!(n);
    o["opcodes"] = json!(ops);
    o["selector_candidates"] = json!(sels);
    o
}
