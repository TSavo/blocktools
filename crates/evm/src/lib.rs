//! blocktools-evm: offline, chain-agnostic EVM contract helpers. Public data only: no keys,
//! no network, no chain list. Every function is pure (bytes/strings in, bytes/JSON out).
//!   sig:    function/event/error signatures -> canonical form, 4-byte selector, 32-byte topic
//!   abi:    Solidity ABI type grammar, strict decoder, encoder
//!   create: CREATE / CREATE2 contract addresses
//!   eip712: typed-data hashing and signer recovery
pub mod abi;
pub mod api;
pub mod approval;
pub mod bytecode;
pub mod create;
pub mod eip712;
pub mod inspect;
pub mod metadata;
pub mod sig;
pub mod u256;

use sha3::{Digest, Keccak256};

/// Keccak-256 (Ethereum's pre-standard SHA-3 padding).
pub fn keccak(data: &[u8]) -> [u8; 32] {
    Keccak256::digest(data).into()
}

pub fn hex(b: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 + b.len() * 2);
    s.push_str("0x");
    for x in b {
        s.push(H[(x >> 4) as usize] as char);
        s.push(H[(x & 15) as usize] as char);
    }
    s
}

/// Parse hex with optional 0x prefix, ignoring surrounding whitespace. Odd length refused.
pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if s.len() % 2 != 0 { return Err("odd_length_hex".into()); }
    let v = |c: u8| match c { b'0'..=b'9' => Some(c - b'0'), b'a'..=b'f' => Some(c - b'a' + 10), b'A'..=b'F' => Some(c - b'A' + 10), _ => None };
    s.as_bytes().chunks(2).map(|p| match (v(p[0]), v(p[1])) { (Some(a), Some(b)) => Ok(a << 4 | b), _ => Err("bad_hex".to_string()) }).collect()
}

/// EIP-55 mixed-case checksum encoding of a 20-byte address.
pub fn checksum_address(a: &[u8; 20]) -> String {
    let lower = &hex(a)[2..];
    let h = keccak(lower.as_bytes());
    let mut s = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let nib = (h[i / 2] >> (if i % 2 == 0 { 4 } else { 0 })) & 15;
        s.push(if c.is_ascii_alphabetic() && nib >= 8 { c.to_ascii_uppercase() } else { c });
    }
    s
}

/// Parse a 20-byte address. All-lower/all-upper hex accepted; mixed case must be a valid EIP-55 checksum.
pub fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let t = s.trim();
    let body = t.strip_prefix("0x").ok_or("address_needs_0x")?;
    if body.len() != 40 { return Err("address_not_20_bytes".into()); }
    let b = unhex(body)?;
    let mut a = [0u8; 20];
    a.copy_from_slice(&b);
    let mixed = body.chars().any(|c| c.is_ascii_lowercase()) && body.chars().any(|c| c.is_ascii_uppercase());
    if mixed && checksum_address(&a) != t { return Err("bad_eip55_checksum".into()); }
    Ok(a)
}
