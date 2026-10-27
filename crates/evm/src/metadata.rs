//! Offline check of a Solidity build against the metadata hash embedded in its bytecode (no compiler).
//! The CBOR trailer's `ipfs` entry is the IPFS CIDv0 of the exact metadata.json bytes (sha256 multihash of the
//! single-chunk UnixFS dag-pb node, as `ipfs add` with default settings computes it, files up to 256 KiB).
//! metadata.json names every source with its keccak256 (and dweb:/ipfs URLs); given the sources, each is re-hashed.
//! `bzzr0`/`bzzr1` (Swarm, solc before 0.6) are reported, not verified.
use crate::{bytecode, hex, keccak};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const CHUNK: usize = 262_144;

fn varint(mut n: u64, out: &mut Vec<u8>) { loop { let b = (n & 0x7f) as u8; n >>= 7; if n == 0 { out.push(b); break } out.push(b | 0x80) } }

/// sha2-256 multihash (0x12 0x20 + digest) of a single-chunk UnixFS file node.
pub fn ipfs_multihash(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() > CHUNK { return Err(format!("file over {CHUNK} bytes: multi-chunk IPFS hashing is not implemented")) }
    let mut u = vec![0x08, 0x02];
    if !data.is_empty() { u.push(0x12); varint(data.len() as u64, &mut u); u.extend_from_slice(data); }
    u.push(0x18); varint(data.len() as u64, &mut u);
    let mut n = vec![0x0a]; varint(u.len() as u64, &mut n); n.extend(u);
    let mut m = vec![0x12, 0x20]; m.extend_from_slice(&Sha256::digest(&n)); Ok(m)
}

pub fn base58(b: &[u8]) -> String {
    const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut d: Vec<u8> = vec![];
    for &x in b { let mut c = x as u32; for v in d.iter_mut() { c += (*v as u32) << 8; *v = (c % 58) as u8; c /= 58 } while c > 0 { d.push((c % 58) as u8); c /= 58 } }
    let z = b.iter().take_while(|&&x| x == 0).count();
    std::iter::repeat_n('1', z).chain(d.iter().rev().map(|&v| A[v as usize] as char)).collect()
}

/// The metadata trailer: at the end of runtime code, or (creation code, constructor args appended) the last
/// well-formed CBOR map followed by its own length. Returns (offset, value).
pub fn find(code: &[u8]) -> Option<(usize, Value)> {
    if let Some((l, v)) = bytecode::metadata(code) { return Some((code.len() - l, v)) }
    let mut best = None;
    for p in 0..code.len().saturating_sub(4) {
        if !(0xa1..=0xa5).contains(&code[p]) || !(0x64..=0x6f).contains(&code[p + 1]) { continue }
        for e in p + 4..code.len().saturating_sub(1).min(p + 256) {
            if u16::from_be_bytes([code[e], code[e + 1]]) as usize == e - p {
                if let Some((_, v)) = bytecode::metadata(&code[..e + 2]) { best = Some((p, v)); break }
            }
        }
    }
    best
}

fn safe_rel(p: &str) -> bool { !p.is_empty() && !p.starts_with('/') && !p.contains('\\') && !p.split('/').any(|c| c == ".." || c.is_empty()) }

/// Check `meta` (exact metadata.json bytes) against `code`, and each named source against `read(path)` when given.
/// Returns the report and whether everything checked matched.
pub fn check(code: &[u8], meta: Option<&[u8]>, read: &dyn Fn(&str) -> Option<Vec<u8>>) -> (Value, bool) {
    let mut o = json!({"status":"ok"}); let mut good = true;
    let Some((off, cbor)) = find(code) else { return (json!({"status":"no_metadata","detail":"no Solidity CBOR metadata trailer in the bytecode"}), false) };
    o["metadata_offset"] = json!(off); o["cbor"] = cbor.clone();
    if let Some(v) = cbor.get("solc") { o["solc"] = v.clone() }
    let embedded = cbor.get("ipfs").and_then(Value::as_str).and_then(|h| crate::unhex(h).ok());
    if let Some(e) = &embedded { o["embedded_cid"] = json!(base58(e)) }
    let Some(meta) = meta else { return (o, true) };
    let m: Value = match serde_json::from_slice(meta) { Ok(v) => v, Err(_) => return (json!({"status":"bad_input","error":"metadata is not JSON"}), false) };
    match (&embedded, ipfs_multihash(meta)) {
        (Some(e), Ok(h)) => { o["metadata_cid"] = json!(base58(&h)); o["metadata_match"] = json!(*e == h); good &= *e == h }
        (Some(_), Err(er)) => { o["metadata_match"] = Value::Null; o["metadata_error"] = json!(er); good = false }
        (None, _) => { o["metadata_match"] = Value::Null; o["metadata_error"] = json!(if cbor.get("bzzr0").or(cbor.get("bzzr1")).is_some() { "Swarm (bzzr0/bzzr1) metadata hash: not verified" } else { "no ipfs hash in the trailer" }); good = false }
    }
    o["language"] = m["language"].clone();
    o["compiler"] = m["compiler"]["version"].clone();
    if let (Some(cv), Some(sv)) = (m["compiler"]["version"].as_str(), cbor.get("solc").and_then(Value::as_str)) {
        let ok = cv.split(['+', '-']).next() == Some(sv); o["compiler_matches_trailer"] = json!(ok); good &= ok
    }
    o["target"] = m["settings"]["compilationTarget"].clone();
    o["optimizer"] = m["settings"]["optimizer"].clone();
    let mut srcs = Map::new(); let mut missing = 0;
    for (path, s) in m["sources"].as_object().cloned().unwrap_or_default() {
        let want = s["keccak256"].as_str().unwrap_or("").to_ascii_lowercase();
        let body = s["content"].as_str().map(|c| (c.as_bytes().to_vec(), "inline")).or_else(|| safe_rel(&path).then(|| read(&path)).flatten().map(|b| (b, "file")));
        let r = match body {
            None => { missing += 1; json!({"status":"not_provided","keccak256":want}) }
            Some((b, from)) => {
                let k = hex(&keccak(&b)); let ok = k == want;
                let mut r = json!({"status": if ok { "match" } else { "mismatch" }, "from": from, "keccak256": want});
                if !ok { r["got_keccak256"] = json!(k) }
                if let Ok(h) = ipfs_multihash(&b) {
                    let cid = base58(&h);
                    if let Some(u) = s["urls"].as_array().and_then(|u| u.iter().filter_map(Value::as_str).find(|u| u.starts_with("dweb:/ipfs/"))) {
                        let uok = u == format!("dweb:/ipfs/{cid}"); r["ipfs_url_match"] = json!(uok); if !uok { good = false }
                    }
                }
                good &= ok; r
            }
        };
        srcs.insert(path, r);
    }
    o["sources"] = Value::Object(srcs); o["sources_missing"] = json!(missing);
    if !good { o["status"] = json!("mismatch") }
    (o, good)
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn ipfs_known_vector() {
        // `echo "hello world" | ipfs add` (go-ipfs defaults)
        assert_eq!(base58(&ipfs_multihash(b"hello world\n").unwrap()), "QmT78zSuBmuS4z925WZfrqQ1qHaJ56DQaTfyMUF7F8ff5o");
        assert!(ipfs_multihash(&vec![0; CHUNK + 1]).is_err());
    }
    #[test]
    fn rel_paths() { assert!(safe_rel("src/A.sol")); assert!(!safe_rel("../x")); assert!(!safe_rel("/etc/x")); assert!(!safe_rel("a//b")); }
}
