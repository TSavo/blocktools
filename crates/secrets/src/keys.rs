//! Raw private-key text: decoding the many encodings people paste, and the address rows
//! (with the key) for each chain.
use blocktools_core::b64::decode as b64;
use blocktools_core::chains::{self, Chain, Enc, Row};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use zeroize::Zeroizing;

/// (encoding name, 32 bytes, compressed-hint) for each decoding that works.
pub fn decodings(s: &str) -> Vec<(&'static str, Zeroizing<Vec<u8>>, Option<bool>)> {
    let mut v = Vec::new();
    #[cfg(feature = "algo")]
    if let Ok(k) = chains::algo_mnemonic_key(s) { v.push(("algo-mnemonic", Zeroizing::new(k.to_vec()), None)); return v }
    #[cfg(feature = "ton")]
    if let Ok(k) = chains::ton_mnemonic_key(s) { v.push(("ton-mnemonic", Zeroizing::new(k.to_vec()), None)) }
    #[cfg(feature = "cardano")]
    if let Ok(k) = chains::ada_icarus_master(s, "") { v.push(("cardano-mnemonic", Zeroizing::new(k.to_vec()), None)) }
    #[cfg(feature = "sr25519")]
    if let Ok(k) = chains::substrate_mini_secret(s, "") { v.push(("substrate-mnemonic", Zeroizing::new(k.to_vec()), None)) }
    if !v.is_empty() || s.len() > 120 { return v }
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.len() == 64 { if let Some(b) = blocktools_core::hex_dec(h) { v.push(("hex", Zeroizing::new(b), None)) } }
    if let Ok(k) = bitcoin::PrivateKey::from_wif(s) { v.push(("wif", Zeroizing::new(k.inner.secret_bytes().to_vec()), Some(k.compressed))) }
    if let Ok((144, b)) = chains::strkey_decode(s) { if b.len() == 32 { v.push(("strkey", Zeroizing::new(b), None)) } }
    if let Ok(b) = bitcoin::base58::decode(s) { if b.len() == 32 { v.push(("base58", Zeroizing::new(b), None)) } }
    if h.len() != 64 { if let Some(b) = b64(s) { if b.len() == 32 { v.push(("base64", Zeroizing::new(b), None)) } } }
    v
}

/// Cardano rows from a decoded 96-byte Icarus master ("cardano-mnemonic").
#[cfg(feature = "cardano")]
pub fn ada_rows(c: &Chain, master: &[u8]) -> Vec<Row> { match master.try_into() { Ok(m) => chains::ada_rows(m, c.default_count), Err(_) => vec![] } }
/// Rows for one decoded 32-byte key on one chain. `comp` = WIF compression hint.
pub fn rows_for(c: &Chain, bytes: &[u8; 32], comp: Option<bool>) -> Vec<Row> {
    let secp = Secp256k1::new();
    match (c.enc, SecretKey::from_slice(bytes).ok()) {
        #[cfg(feature = "ed25519")]
        (Enc::Algo, _) => vec![chains::algo_row("", bytes)],
        #[cfg(feature = "ed25519")]
        (Enc::Ton, _) => vec![chains::ton_row("", bytes)],
        #[cfg(feature = "sr25519")]
        (Enc::Ss58 { .. }, _) => vec![chains::ss58_row(c, "", bytes)],
        #[cfg(feature = "ed25519")]
        (Enc::Sol | Enc::Xlm, _) => vec![chains::ed_row(c, "", bytes)],
        #[cfg(not(feature = "ed25519"))]
        (Enc::Sol | Enc::Xlm | Enc::Algo | Enc::Ton, _) => vec![],
        (Enc::Ada, _) => vec![], // needs the 96-byte Icarus master: keys::ada_rows
        #[cfg(not(feature = "sr25519"))]
        (Enc::Ss58 { .. }, _) => vec![],
        (_, Some(sk)) => {
            let mut r = chains::secp_rows(c, "", &sk, comp != Some(true), &secp);
            if comp == Some(false) { r.retain(|r| r.kind == "p2pkh-uncompressed") }
            r
        }
        _ => vec![],
    }
}

/// Zcash transparent rows (t1 P2PKH, WIF version 0x80) for one secp256k1 key. zec is not in the
/// chains table (two-byte version), so key-to-addresses calls this for `--chain zec`.
pub fn zec_rows(bytes: &[u8; 32], comp: Option<bool>) -> Vec<Row> {
    use bitcoin::hashes::{hash160, Hash};
    let Ok(sk) = SecretKey::from_slice(bytes) else { return vec![] };
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let mut v = Vec::new();
    for c in [true, false] {
        if comp.is_some_and(|x| x != c) { continue }
        let k = if c { pk.serialize().to_vec() } else { pk.serialize_uncompressed().to_vec() };
        let mut p = vec![0x1c, 0xb8]; p.extend(hash160::Hash::hash(&k).to_byte_array());
        v.push(Row { chain: "zec", kind: if c { "p2pkh" } else { "p2pkh-uncompressed" }, path: String::new(), address: chains::b58check_ck(chains::Ck::Sha256d, &p),
            secret_field: "wif", secret: chains::wif(0x80, &sk, c) });
    }
    v
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
    // Groestlcoin WIF (version 0x80, Groestl-512 double-hash checksum).
    if let Ok(d) = blocktools_core::chains::decode_check_ck(blocktools_core::chains::Ck::Groestl, &tok) {
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

#[cfg(test)]
mod zec_tests {
    /// Throwaway key 1: the t1 payload is 1cb8 + the same hash160 as bitcoin's 1BgGZ9.. (compressed)
    /// and 1EHNa6.. (uncompressed); an explicit WIF hint keeps only its form.
    #[test] fn zec_t1_from_raw_key() {
        let mut k = [0u8; 32]; k[31] = 1;
        let r = super::zec_rows(&k, None);
        assert_eq!(r.len(), 2);
        for (row, btc) in r.iter().zip(["1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"]) {
            let z = bitcoin::base58::decode_check(&row.address).unwrap(); let b = bitcoin::base58::decode_check(btc).unwrap();
            assert_eq!((&z[..2], &z[2..]), (&[0x1c, 0xb8][..], &b[1..])); assert!(row.address.starts_with("t1"));
            assert_eq!(bitcoin::base58::decode_check(&row.secret).unwrap()[0], 0x80);
        }
        assert_eq!(super::zec_rows(&k, Some(true)).len(), 1); assert_eq!(super::zec_rows(&k, Some(false))[0].kind, "p2pkh-uncompressed");
        assert!(super::zec_rows(&[0; 32], None).is_empty());
    }
}
