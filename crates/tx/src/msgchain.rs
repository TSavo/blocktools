//! Per-chain message signatures beyond Ethereum/Bitcoin (those stay in `tx::message`). Keyless verify only;
//! signing for these chains lives in the sealed msg-sign tool, never here or in wasm.
//! Formats, each from a published source (see docs/PROVENANCE-msg.md):
//! - Tron `signMessageV2` (TronWeb; Trust Wallet Core src/Tron/MessageSigner.cpp): keccak256("\x19TRON Signed
//!   Message:\n" || decimal byte length || msg), 65-byte r||s||v, v = 27/28. Address = base58check(0x41 || keccak tail).
//! - Solana, format `raw`: ed25519 over the message bytes as they are (Solana cookbook "sign message";
//!   Trust Wallet Core SolanaMessageSigner MessageType_raw). Signature base58, 64 bytes.
//! - Solana, format `offchain-v0`: ed25519 over solana-sdk `offchain-message` v0 bytes, i.e. what
//!   `solana sign-offchain-message` signs: "\xffsolana offchain" || 0 || format(0 ascii | 1 utf8 <=1212 | 2 utf8) ||
//!   u16le len || msg. NOT the 85-byte Trust Wallet Core proposal layout (application domain + signer list), refused.
//! - Cosmos ADR-036 (draft spec; Keplr signArbitrary): secp256k1 over sha256 of the sorted amino JSON sign doc
//!   {account_number "0", chain_id "", fee {amount [], gas "0"}, memo "", msgs [{type "sign/MsgSignData",
//!   value {data base64(msg), signer}}], sequence "0"}. Signature base64 64 bytes (low-s); the compressed
//!   pubkey (base64, 33 bytes) is required because ECDSA here is not recovered; it must hash to the address.
use bitcoin::hashes::{hash160, sha256, Hash};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};

pub const SOL_FORMATS: &[&str] = &["raw", "offchain-v0"];

pub fn tron_hash(msg: &[u8]) -> [u8; 32] {
    let mut k = Keccak256::new();
    k.update(format!("\x19TRON Signed Message:\n{}", msg.len()).as_bytes()); k.update(msg); k.finalize().into()
}
pub fn tron_address(uncompressed65: &[u8]) -> String {
    let h = Keccak256::digest(&uncompressed65[1..]);
    let mut b = vec![0x41u8]; b.extend_from_slice(&h[12..]); bitcoin::base58::encode_check(&b)
}
/// solana-sdk offchain-message v0 serialization (format byte derived the way solana-sdk derives it).
pub fn sol_offchain_v0(msg: &[u8]) -> Result<Vec<u8>, &'static str> {
    if msg.is_empty() { return Err("empty_message") }
    let ascii = msg.iter().all(|c| (0x20..=0x7e).contains(c));
    let utf8 = std::str::from_utf8(msg).is_ok();
    let f = if msg.len() <= 1212 { if ascii { 0 } else if utf8 { 1 } else { return Err("message_not_utf8") } }
        else if msg.len() <= 65515 { if utf8 { 2 } else { return Err("message_not_utf8") } } else { return Err("message_too_large") };
    let mut o = b"\xffsolana offchain".to_vec(); o.push(0); o.push(f); o.extend((msg.len() as u16).to_le_bytes()); o.extend_from_slice(msg); Ok(o)
}
/// The exact ADR-036 amino sign doc bytes (keys sorted, no whitespace).
pub fn adr036_doc(signer: &str, msg: &[u8]) -> String {
    format!(r#"{{"account_number":"0","chain_id":"","fee":{{"amount":[],"gas":"0"}},"memo":"","msgs":[{{"type":"sign/MsgSignData","value":{{"data":"{}","signer":"{}"}}}}],"sequence":"0"}}"#, blocktools_core::b64::encode(msg), signer)
}
pub fn cosmos_addr(hrp: &str, pk33: &[u8]) -> String { blocktools_core::chains::cosmos_address(hrp, &hash160::Hash::hash(pk33).to_byte_array()) }

/// "eth" | "btc" (from tx::message) | "tron" | "sol" | "cosmos".
pub fn detect_chain(addr: &str) -> Result<&'static str, &'static str> {
    match crate::message::detect_chain(addr) { Ok(c) => return Ok(c), Err("address_not_p2pkh") => return Err("address_not_p2pkh"), Err(_) => {} }
    if addr.starts_with('T') { if let Ok(b) = bitcoin::base58::decode_check(addr) { if b.len() == 21 && b[0] == 0x41 { return Ok("tron") } } }
    if let Ok(k) = sol_pubkey(addr) { if sol_on_curve(&k) && bitcoin::base58::encode(&k) == addr { return Ok("sol") } }
    if let Ok((h, _)) = bitcoin::bech32::decode(addr) { if blocktools_core::chains::cosmos_decode(h.as_str(), addr).is_ok() { return Ok("cosmos") } }
    Err("unrecognised_address")
}
pub struct Opts<'a> { pub format: Option<&'a str>, pub pubkey: Option<&'a str> }
fn hexsig(s: &str) -> Result<Vec<u8>, &'static str> { let t = s.trim(); blocktools_core::hex_dec(t.strip_prefix("0x").unwrap_or(t)).ok_or("bad_hex_signature") }

/// Verify; returns {"status":"ok"|"signer_mismatch","chain","address","recovered"?, "v"?, "format"?, "hrp"?}.
/// Options that do not apply to the detected chain are refused (no silent ignoring).
pub fn verify(addr: &str, msg: &[u8], sig: &str, o: &Opts) -> Result<Value, &'static str> {
    let chain = detect_chain(addr)?;
    if o.format.is_some() && chain != "sol" { return Err("format_only_for_solana") }
    if o.pubkey.is_some() && chain != "cosmos" { return Err("pubkey_only_for_cosmos") }
    if msg.len() > 1 << 20 { return Err("message_too_large") }
    let st = |ok: bool| if ok { "ok" } else { "signer_mismatch" };
    match chain {
        "eth" | "btc" => {
            let (_, ok, rec, v) = crate::message::verify(addr, msg, sig)?;
            let mut r = json!({"status":st(ok),"chain":chain,"address":addr,"recovered":rec}); if let Some(v) = v { r["v"] = json!(v) } Ok(r)
        }
        "tron" => {
            let s = hexsig(sig)?; if s.len() != 65 { return Err("signature_not_65_bytes") }
            if !(27..=28).contains(&s[64]) { return Err("bad_v") }
            let id = bitcoin::secp256k1::ecdsa::RecoveryId::from_i32((s[64] - 27) as i32).map_err(|_| "bad_v")?;
            let rs = bitcoin::secp256k1::ecdsa::RecoverableSignature::from_compact(&s[..64], id).map_err(|_| "bad_signature")?;
            let pk = bitcoin::secp256k1::Secp256k1::verification_only().recover_ecdsa(&bitcoin::secp256k1::Message::from_digest(tron_hash(msg)), &rs).map_err(|_| "bad_signature")?;
            let rec = tron_address(&pk.serialize_uncompressed());
            Ok(json!({"status":st(rec == addr),"chain":"tron","address":addr,"recovered":rec}))
        }
        "sol" => {
            let f = o.format.ok_or("solana_format_required")?;
            let bytes = match f { "raw" => msg.to_vec(), "offchain-v0" => sol_offchain_v0(msg)?, _ => return Err("unknown_solana_format") };
            let s: [u8; 64] = bitcoin::base58::decode(sig.trim()).map_err(|_| "bad_base58_signature")?.try_into().map_err(|_| "signature_not_64_bytes")?;
            let pk = sol_pubkey(addr)?;
            Ok(json!({"status":st(ed25519_verify(&pk, &bytes, &s)),"chain":"sol","address":addr,"format":f}))
        }
        _ => {
            let pk = blocktools_core::b64::decode(o.pubkey.ok_or("cosmos_pubkey_required")?.trim()).ok_or("bad_base64_pubkey")?;
            if pk.len() != 33 { return Err("pubkey_not_33_bytes") }
            let key = bitcoin::secp256k1::PublicKey::from_slice(&pk).map_err(|_| "bad_pubkey")?;
            let hrp = bitcoin::bech32::decode(addr).map_err(|_| "bad_bech32")?.0.as_str().to_string();
            if cosmos_addr(&hrp, &pk) != addr { return Ok(json!({"status":"signer_mismatch","chain":"cosmos","address":addr,"hrp":hrp,"recovered":cosmos_addr(&hrp, &pk),"error":"pubkey_does_not_match_address"})) }
            let s = blocktools_core::b64::decode(sig.trim()).ok_or("bad_base64_signature")?; if s.len() != 64 { return Err("signature_not_64_bytes") }
            let es = bitcoin::secp256k1::ecdsa::Signature::from_compact(&s).map_err(|_| "bad_signature")?;
            let d = sha256::Hash::hash(adr036_doc(addr, msg).as_bytes()).to_byte_array();
            let ok = bitcoin::secp256k1::Secp256k1::verification_only().verify_ecdsa(&bitcoin::secp256k1::Message::from_digest(d), &es, &key).is_ok();
            Ok(json!({"status":st(ok),"chain":"cosmos","address":addr,"hrp":hrp}))
        }
    }
}
fn sol_pubkey(s: &str) -> Result<[u8; 32], &'static str> { bitcoin::base58::decode(s).map_err(|_| "bad_base58")?.try_into().map_err(|_| "bad_length") }
fn sol_on_curve(k: &[u8; 32]) -> bool { curve25519_dalek::edwards::CompressedEdwardsY(*k).decompress().is_some() }
/// Verify-only ed25519 (RFC 8032, cofactorless, strict: canonical S, non-small-order A and R),
/// built on curve25519-dalek so the wasm build carries no signing code. (Moved from blocktools::sol.)
pub fn ed25519_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    use curve25519_dalek::{edwards::{CompressedEdwardsY, EdwardsPoint}, scalar::Scalar};
    use bitcoin::hashes::{sha512, HashEngine};
    let Some(a) = CompressedEdwardsY(*pk).decompress() else { return false };
    let r_bytes: [u8; 32] = sig[..32].try_into().unwrap();
    let Some(r) = CompressedEdwardsY(r_bytes).decompress() else { return false };
    if a.is_small_order() || r.is_small_order() { return false }
    let Some(s) = Option::<Scalar>::from(Scalar::from_canonical_bytes(sig[32..].try_into().unwrap())) else { return false };
    let mut e = sha512::HashEngine::default(); e.input(&r_bytes); e.input(pk); e.input(msg);
    let k = Scalar::from_bytes_mod_order_wide(&sha512::Hash::from_engine(e).to_byte_array());
    EdwardsPoint::vartime_double_scalar_mul_basepoint(&k, &-a, &s).compress().to_bytes() == r_bytes
}
