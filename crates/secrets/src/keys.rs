//! Raw private-key text: decoding the many encodings people paste, and the address rows
//! (with the key) for each chain.
use blocktools_core::b64::decode as b64;
use blocktools_core::chains::{self, Chain, Enc, Row};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use zeroize::Zeroizing;

/// (encoding name, 32 bytes, compressed-hint) for each decoding that works.
pub fn decodings(s: &str) -> Vec<(&'static str, Zeroizing<Vec<u8>>, Option<bool>)> {
    let mut v = Vec::new();
    if s.len() > 120 { return v }
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.len() == 64 { if let Some(b) = blocktools_core::hex_dec(h) { v.push(("hex", Zeroizing::new(b), None)) } }
    if let Ok(k) = bitcoin::PrivateKey::from_wif(s) { v.push(("wif", Zeroizing::new(k.inner.secret_bytes().to_vec()), Some(k.compressed))) }
    if let Ok(b) = bitcoin::base58::decode(s) { if b.len() == 32 { v.push(("base58", Zeroizing::new(b), None)) } }
    if h.len() != 64 { if let Some(b) = b64(s) { if b.len() == 32 { v.push(("base64", Zeroizing::new(b), None)) } } }
    v
}

/// Rows for one decoded 32-byte key on one chain. `comp` = WIF compression hint.
pub fn rows_for(c: &Chain, bytes: &[u8; 32], comp: Option<bool>) -> Vec<Row> {
    let secp = Secp256k1::new();
    match (c.enc, SecretKey::from_slice(bytes).ok()) {
        #[cfg(feature = "ed25519")]
        (Enc::Sol, _) => vec![chains::sol_row("", bytes)],
        #[cfg(not(feature = "ed25519"))]
        (Enc::Sol, _) => vec![],
        (_, Some(sk)) => {
            let mut r = chains::secp_rows(c, "", &sk, comp != Some(true), &secp);
            if comp == Some(false) { r.retain(|r| r.kind == "p2pkh-uncompressed") }
            r
        }
        _ => vec![],
    }
}

/// One signing key from a line: WIF, 64-hex, or JSON with wif/private_key/key/secret.
pub fn parse_key_line(s: &str) -> Option<SecretKey> {
    let s = s.trim();
    let tok: Zeroizing<String> = Zeroizing::new(match serde_json::from_str::<serde_json::Value>(s) {
        Ok(v) if v.is_object() => ["wif", "private_key", "key", "secret"].iter().find_map(|k| v[*k].as_str().map(String::from))?,
        _ => s.to_string(),
    });
    if let Ok(k) = bitcoin::PrivateKey::from_wif(&tok) { return Some(k.inner) }
    // Altcoin WIF (any version byte: LTC 0xB0, DOGE 0x9E, ...): version + 32 bytes [+ 0x01].
    if let Ok(d) = bitcoin::base58::decode_check(&tok) {
        let d = Zeroizing::new(d);
        if d.len() == 33 || (d.len() == 34 && d[33] == 1) { return SecretKey::from_slice(&d[1..33]).ok() }
    }
    let h = tok.strip_prefix("0x").unwrap_or(&tok);
    if h.len() == 64 { return SecretKey::from_slice(&Zeroizing::new(blocktools_core::hex_dec(h)?)).ok() }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn altcoin_wif_lines() {
        // private key 1 as LTC (0xB0) and DOGE (0x9E) compressed WIF, from the chain table encoder
        let one = SecretKey::from_slice(&[[0u8; 31].as_slice(), &[1]].concat()).unwrap();
        for v in [0xB0u8, 0x9E] {
            let mut p = vec![v]; p.extend([0u8; 31]); p.extend([1, 1]);
            let w = bitcoin::base58::encode_check(&p);
            assert_eq!(parse_key_line(&format!(r#"{{"wif":"{w}"}}"#)), Some(one));
        }
    }
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
