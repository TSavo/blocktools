//! Message signatures (Trust Wallet Core port: EthMessageSigner legacy/EIP-155/Immutable X and
//! BitcoinMessageSigner). Ethereum: EIP-191 `personal_sign`, keccak256("\x19Ethereum Signed
//! Message:\n" || decimal len || msg), 65-byte r||s||v with v = 27/28, 0/1 (Immutable X) or
//! 35 + 2*chain_id + rec (EIP-155 style). Bitcoin: Bitcoin Core `signmessage`, sha256d(varstr(
//! "Bitcoin Signed Message:\n") || varstr(msg)), base64 of header||r||s with header 27+rec
//! (+4 compressed), P2PKH addresses only. EIP-712 is typed-data-verify's job; it is not signed here.
use bitcoin::hashes::{sha256d, Hash};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, PublicKey, Secp256k1};
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EthV { Legacy, Raw, Eip155(u64) }

pub fn eth_hash(msg: &[u8]) -> [u8; 32] {
    let mut k = Keccak256::new();
    k.update(format!("\x19Ethereum Signed Message:\n{}", msg.len()).as_bytes()); k.update(msg); k.finalize().into()
}
pub fn btc_hash(msg: &[u8]) -> [u8; 32] {
    let mut b = vec![24u8]; b.extend_from_slice(b"Bitcoin Signed Message:\n");
    let n = msg.len();
    if n < 0xfd { b.push(n as u8) } else if n <= 0xffff { b.push(0xfd); b.extend((n as u16).to_le_bytes()) } else { b.push(0xfe); b.extend((n as u32).to_le_bytes()) }
    b.extend_from_slice(msg); sha256d::Hash::hash(&b).to_byte_array()
}
fn recover(d: [u8; 32], rs: &[u8], rec: u8) -> Result<PublicKey, &'static str> {
    let id = RecoveryId::from_i32(rec as i32).map_err(|_| "bad_recovery_id")?;
    let sig = RecoverableSignature::from_compact(rs, id).map_err(|_| "bad_signature")?;
    // high-s is accepted on verify, as Bitcoin Core verifymessage does (TWC vector 1B8Qea.. is high-s); signing is always low-s
    Secp256k1::verification_only().recover_ecdsa(&Message::from_digest(d), &sig).map_err(|_| "bad_signature")
}
/// Recovered checksummed address and the v convention found.
pub fn eth_recover(msg: &[u8], sig: &[u8]) -> Result<(String, EthV), &'static str> {
    if sig.len() != 65 { return Err("signature_not_65_bytes") }
    let v = sig[64] as u64;
    let (rec, kind) = match v { 27 | 28 => (v - 27, EthV::Legacy), 0 | 1 => (v, EthV::Raw), v if v >= 35 => ((v - 35) % 2, EthV::Eip155((v - 35) / 2)), _ => return Err("bad_v") };
    let pk = recover(eth_hash(msg), &sig[..64], rec as u8)?;
    Ok((blocktools_core::eth_address_from_pubkey(&pk.serialize_uncompressed()), kind))
}
/// Recovered P2PKH address (mainnet) from a base64 Bitcoin message signature.
pub fn btc_recover(msg: &[u8], sig_b64: &str) -> Result<String, &'static str> {
    let s = blocktools_core::b64::decode(sig_b64.trim()).ok_or("bad_base64")?;
    if s.len() != 65 { return Err("signature_not_65_bytes") }
    let h = s[0];
    if (35..=42).contains(&h) { return Err("bip137_segwit_header_unsupported") }
    if !(27..=34).contains(&h) { return Err("bad_header_byte") }
    let compressed = h >= 31;
    let pk = recover(btc_hash(msg), &s[1..], (h - 27) & 3)?;
    let ser = if compressed { pk.serialize().to_vec() } else { pk.serialize_uncompressed().to_vec() };
    let h160 = bitcoin::hashes::hash160::Hash::hash(&ser);
    Ok(bitcoin::Address::p2pkh(bitcoin::PubkeyHash::from_raw_hash(h160), bitcoin::Network::Bitcoin).to_string())
}
/// Which chain a message address belongs to: "eth" (0x + 40 hex) or "btc" (base58 P2PKH, version 0).
pub fn detect_chain(addr: &str) -> Result<&'static str, &'static str> {
    if blocktools_core::validate::validate("eth", addr).is_ok() { return Ok("eth") }
    if addr.starts_with('1') && blocktools_core::validate::validate("btc", addr).is_ok() { return Ok("btc") }
    if blocktools_core::validate::validate("btc", addr).is_ok() { return Err("address_not_p2pkh") }
    Err("unrecognised_address")
}
/// Verify a message signature against `addr` (chain from `detect_chain`). Returns `(ok, recovered, v)`:
/// `ok` is the address match (eth case-insensitive), `v` the Ethereum v convention
/// ("legacy" | "raw" | "eip155:<chain_id>"), `None` for Bitcoin. Shared by msg-verify and the wasm `msgVerify`.
pub fn verify(addr: &str, msg: &[u8], sig: &str) -> Result<(&'static str, bool, String, Option<String>), &'static str> {
    let chain = detect_chain(addr)?;
    if chain == "eth" {
        let t = sig.trim(); let t = t.strip_prefix("0x").unwrap_or(t);
        let s = blocktools_core::hex_dec(t).ok_or("bad_hex_signature")?;
        let (r, k) = eth_recover(msg, &s)?;
        let v = match k { EthV::Legacy => "legacy".to_string(), EthV::Raw => "raw".into(), EthV::Eip155(c) => format!("eip155:{c}") };
        Ok((chain, r.eq_ignore_ascii_case(addr), r, Some(v)))
    } else {
        let r = btc_recover(msg, sig)?;
        Ok((chain, r == addr, r, None))
    }
}
/// Messages tx-sign-style tooling must not sign blind: a bare 32-byte hash, or bytes that decode as a transaction.
/// `hex_input`: the message was given as hex bytes (TWC treats hex-decodable text that way; we make it explicit).
pub fn sign_refusal(msg: &[u8], hex_input: bool) -> Option<&'static str> {
    if hex_input && msg.len() == 32 { return Some("blind_hash_message") }
    let t = std::str::from_utf8(msg).ok()?.trim();
    let hx = t.strip_prefix("0x").unwrap_or(t);
    if hx.len() == 64 && hx.bytes().all(|c| c.is_ascii_hexdigit()) { return Some("blind_hash_message") }
    if t.len() > 16 && crate::decode(t, "btc").is_ok() { return Some("message_looks_like_transaction") }
    None
}
#[cfg(feature = "secrets")]
pub fn eth_sign(msg: &[u8], sk: &secp256k1::SecretKey, v: EthV) -> Vec<u8> {
    let (id, rs) = Secp256k1::signing_only().sign_ecdsa_recoverable(&Message::from_digest(eth_hash(msg)), sk).serialize_compact();
    let r = id.to_i32() as u64;
    let mut o = rs.to_vec(); o.push(match v { EthV::Legacy => 27 + r, EthV::Raw => r, EthV::Eip155(c) => 35 + 2 * c + r } as u8); o
}
#[cfg(feature = "secrets")]
pub fn btc_sign(msg: &[u8], sk: &secp256k1::SecretKey, compressed: bool) -> String {
    let (id, rs) = Secp256k1::signing_only().sign_ecdsa_recoverable(&Message::from_digest(btc_hash(msg)), sk).serialize_compact();
    let mut o = vec![27 + id.to_i32() as u8 + if compressed { 4 } else { 0 }]; o.extend(rs);
    blocktools_core::b64::encode(&o)
}
