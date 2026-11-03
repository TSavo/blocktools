//! Tron / Solana / Cosmos ADR-036 signing for msg-sign. Hashing and serialization come from the keyless
//! blocktools_tx::msgchain (the same code msg-verify uses); every signature is re-checked with
//! msgchain::verify before the terminal confirmation, and only the signature (and, for Cosmos, the public
//! key the verifier needs) is printed. Keys come only on stdin; nothing is written anywhere else.
use crate::out;
use blocktools_tx::msgchain::{self, Opts};
use serde_json::json;
use std::io::{BufRead, Read};
use zeroize::{Zeroize, Zeroizing};

/// One stdin key line -> ed25519 signing key: 64-hex seed, or a solana-keygen JSON array of 64 bytes
/// whose second half must be the seed's public key.
fn sol_key(l: &str) -> Option<ed25519_dalek::SigningKey> {
    let t = l.trim();
    let t = t.strip_prefix("0x").unwrap_or(t);
    if t.len() == 64 {
        let mut b: [u8; 32] = Zeroizing::new(blocktools_core::hex_dec(t)?).as_slice().try_into().ok()?;
        let k = ed25519_dalek::SigningKey::from_bytes(&b); b.zeroize(); return Some(k)
    }
    let v: Zeroizing<Vec<u8>> = Zeroizing::new(serde_json::from_str::<Vec<u8>>(t).ok()?);
    if v.len() != 64 { return None }
    let mut b: [u8; 32] = v[..32].try_into().ok()?;
    let k = ed25519_dalek::SigningKey::from_bytes(&b); b.zeroize();
    (k.verifying_key().to_bytes()[..] == v[32..]).then_some(k)
}

pub fn run(chain: &str, addr: &str, msg: &[u8], text: &str, format: Option<&str>) -> ! {
    let bad = |e: &str| -> ! { out("bad_input", json!({"error":e})) };
    let refuse = |e: &str| -> ! { out("refused", json!({"failures":[e]})) };
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let hrp = if chain == "cosmos" { bitcoin::bech32::decode(addr).map(|d| d.0.as_str().to_string()).unwrap_or_else(|_| bad("bad bech32 address")) } else { String::new() };
    let mut sig = None; let mut pubkey = None;
    for l in std::io::stdin().lock().take(4 << 20).lines().map_while(Result::ok) {
        let l = Zeroizing::new(l);
        if l.trim().is_empty() { continue }
        if chain == "sol" {
            let k = sol_key(&l).unwrap_or_else(|| bad("unreadable key line (Solana: 64-hex seed or a 64-byte JSON array)"));
            if bitcoin::base58::encode(&k.verifying_key().to_bytes()) != addr { continue }
            let bytes = if format == Some("raw") { msg.to_vec() } else { msgchain::sol_offchain_v0(msg).unwrap_or_else(|e| refuse(e)) };
            use ed25519_dalek::Signer;
            sig = Some(bitcoin::base58::encode(&k.sign(&bytes).to_bytes())); break
        }
        if let Ok(serde_json::Value::Object(o)) = serde_json::from_str::<serde_json::Value>(&l) {
            if !["wif", "private_key", "key", "secret"].iter().any(|k| o.contains_key(*k)) { continue }
        }
        let mut k = blocktools_secrets::keys::parse_key_line(&l).unwrap_or_else(|| bad("unreadable key line"));
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &k);
        if chain == "tron" {
            if msgchain::tron_address(&pk.serialize_uncompressed()) != addr { k.non_secure_erase(); continue }
            let rs = secp.sign_ecdsa_recoverable(&bitcoin::secp256k1::Message::from_digest(msgchain::tron_hash(msg)), &k);
            k.non_secure_erase();
            let (id, b) = rs.serialize_compact();
            let mut s = b.to_vec(); s.push(27 + id.to_i32() as u8);
            sig = Some(blocktools_core::hex_enc(s)); break
        }
        if msgchain::cosmos_addr(&hrp, &pk.serialize()) != addr { k.non_secure_erase(); continue }
        use bitcoin::hashes::{sha256, Hash};
        let d = sha256::Hash::hash(msgchain::adr036_doc(addr, msg).as_bytes()).to_byte_array();
        let s = secp.sign_ecdsa(&bitcoin::secp256k1::Message::from_digest(d), &k); // rust-secp256k1 signs low-s
        k.non_secure_erase();
        sig = Some(blocktools_core::b64::encode(&s.serialize_compact())); pubkey = Some(blocktools_core::b64::encode(&pk.serialize())); break
    }
    let sig = sig.unwrap_or_else(|| refuse("address_does_not_match_key"));
    let o = Opts { format, pubkey: pubkey.as_deref(), chain: Some(chain) };
    if !msgchain::verify(addr, msg, &sig, &o).map(|v| v["status"] == "ok").unwrap_or(false) { out("error", json!({"error":"signature_failed_recheck"})) }
    let scheme = match (chain, format) { ("tron", _) => "Tron signMessageV2".to_string(), ("sol", Some(f)) => format!("Solana ed25519, format {f}"), _ => format!("Cosmos ADR-036 ({hrp})") };
    let summary = format!("Sign MESSAGE ({scheme}, {} bytes) as {addr}:\n{text:?}\nThis signs text only; it cannot move funds by itself, but whoever asked for it may use it as proof you control this address.\n", msg.len());
    if !blocktools_tty::confirm(&summary) { out("aborted", json!({})) }
    let mut r = json!({"chain":chain,"address":addr,"signature":sig});
    if let Some(f) = format { r["format"] = json!(f) }
    if let Some(p) = pubkey { r["pub_key"] = json!(p); r["hrp"] = json!(hrp) }
    out("ok", r)
}
