//! key-to-addresses: one raw 32-byte private key per line -> addresses on every chain in the
//! table (BTC-family compressed AND uncompressed, ETH, Tron, XRP, and Solana treating the bytes
//! as an ed25519 seed). Accepted encodings: 64 hex (0x optional), base64, base58, WIF,
//! or a JSON line {"key":"..."}. An ambiguous string is tried in every encoding that yields
//! exactly 32 bytes; each decoding is a separate "candidate".
//! Output CONTAINS SECRETS. Flags: --chain a,b (default all).
use blocktools_core::chains::{self, Chain, Enc};
use blocktools_io::outln;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

use blocktools_core::b64::decode as b64;
/// (encoding name, 32 bytes, compressed-hint) for each decoding that works.
fn decodings(s: &str) -> Vec<(&'static str, Zeroizing<Vec<u8>>, Option<bool>)> {
    let mut v = Vec::new();
    if s.len() > 120 { return v }
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.len() == 64 { if let Some(b) = blocktools_core::hex_dec(h) { v.push(("hex", Zeroizing::new(b), None)) } }
    if let Ok(k) = bitcoin::PrivateKey::from_wif(s) { v.push(("wif", Zeroizing::new(k.inner.secret_bytes().to_vec()), Some(k.compressed))) }
    if let Ok(b) = bitcoin::base58::decode(s) { if b.len() == 32 { v.push(("base58", Zeroizing::new(b), None)) } }
    if h.len() != 64 { if let Some(b) = b64(s) { if b.len() == 32 { v.push(("base64", Zeroizing::new(b), None)) } } }
    v
}
fn main() {
    blocktools_io::help(r#"key-to-addresses [--chain LIST] < raw 32-byte key (hex, WIF, base58, base64, {"key":...}) -> addresses on every chain"#);
    let a: Vec<String> = std::env::args().collect();
    let mut sel: Vec<&'static Chain> = chains::CHAINS.iter().collect();
    match a.get(1).map(String::as_str) {
        None => {}
        Some("--chain") if a.len() == 3 => sel = a[2].split(',').filter_map(chains::chain).collect(),
        _ => { outln!(r#"{{"tool":"key-to-addresses","status":"bad_input"}}"#); std::process::exit(2) }
    }
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (mut n, mut lineno) = (0u64, 0u64);
    for line in std::io::stdin().lock().take(16 << 20).lines().map_while(Result::ok) {
        lineno += 1;
        let line = Zeroizing::new(line);
        let t = line.trim();
        let tok = Zeroizing::new(match serde_json::from_str::<serde_json::Value>(t) {
            Ok(v) => match v.get("key").and_then(|k| k.as_str()) { Some(k) => k.to_string(), None => continue },
            Err(_) => t.to_string(),
        });
        if tok.is_empty() { continue }
        let ds = decodings(&tok);
        if ds.is_empty() { outln!(r#"{{"tool":"key-to-addresses","status":"unsupported","line":{lineno}}}"#); continue }
        for (cand, (_enc, bytes, comp)) in ds.iter().enumerate() {
            let seed: [u8; 32] = bytes[..].try_into().unwrap();
            let sk = bitcoin::secp256k1::SecretKey::from_slice(&seed).ok();
            for c in &sel {
                let rows = match (c.enc, sk) {
                    (Enc::Sol, _) => vec![chains::sol_row("", &seed)],
                    (_, Some(sk)) => {
                        let mut r = chains::secp_rows(c, "", &sk, comp != &Some(true), &secp);
                        if comp == &Some(false) { r.retain(|r| r.kind == "p2pkh-uncompressed") }
                        r
                    }
                    _ => vec![],
                };
                for r in rows {
                    outln!(r#"{{"tool":"key-to-addresses","status":"ok","line":{lineno},"candidate":{cand},"chain":"{}","kind":"{}","address":"{}","{}":"{}"}}"#,
                        r.chain, r.kind, r.address, r.secret_field, r.secret);
                    n += 1;
                }
            }
        }
    }
    outln!(r#"{{"tool":"key-to-addresses","status":"done","count":{n}}}"#);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn encodings_of_privkey_one() {
        // private key 1 (textbook value) in several encodings
        let hex = format!("{}01", "0".repeat(62));
        assert_eq!(decodings(&hex)[0].0, "hex");
        assert_eq!(decodings("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=").iter().map(|d| d.0).collect::<Vec<_>>(), vec!["base64"]);
        assert_eq!(decodings("11111111111111111111111111111112")[0].0, "base58");
        let w = decodings("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf");
        assert_eq!((w[0].0, w[0].2), ("wif", Some(false)));
        assert_eq!(w[0].1[31], 1);
    }
}
