//! classify: what kind of wallet material is this? Public output only: a class name, the line
//! number, and a fingerprint (first/last 4 hex of SHA-256 of the trimmed text) so two files can
//! be matched without the secret ever being echoed. Addresses and xpubs are public and echoed.
use bitcoin::base58;
use bitcoin::hashes::{hmac, sha256, sha512, Hash, HashEngine};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row { pub class: &'static str, pub line: u64, pub fp: String, pub public: Option<String>, pub chain: Option<&'static str> }

/// Every class name classify can print.
pub const CLASSES: &[&str] = &["mnemonic", "electrum_seed", "wif", "hex_key", "b58_key", "b64_key", "xprv", "xpub", "address", "monero_seed", "monero_address", "xrp_seed",
    "keystore_v3", "wallet_dat", "electrum_wallet", "electrum_wallet_file_encrypted", "multibit_key", "bitcoinj_wallet", "armory_wallet", "unknown"];

pub fn fingerprint(b: &[u8]) -> String {
    let h = crate::hex_enc(sha256::Hash::hash(b).to_byte_array());
    format!("{}..{}", &h[..4], &h[60..])
}
fn row(class: &'static str, line: u64, b: &[u8]) -> Row { Row { class, line, fp: fingerprint(b), public: None, chain: None } }

/// Electrum 2.x seed version (HMAC-SHA512 key "Seed version"): 01 standard, 100 segwit, 101/102 2FA.
pub fn electrum_version(words: &str) -> Option<&'static str> {
    let norm = words.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    let mut e = hmac::HmacEngine::<sha512::Hash>::new(b"Seed version");
    e.input(norm.as_bytes());
    let h = crate::hex_enc(hmac::Hmac::<sha512::Hash>::from_engine(e).to_byte_array());
    [("01", "standard"), ("100", "segwit"), ("101", "2fa"), ("102", "2fa-segwit")].iter().find(|(p, _)| h.starts_with(p)).map(|x| x.1)
}

/// Whole-file formats first (binary magics, JSON wallets); otherwise one row per non-empty line.
pub fn classify(data: &[u8]) -> Vec<Row> {
    let file = |c| vec![row(c, 0, data)];
    if data.starts_with(b"SQLite format 3\0") || data.get(12..16) == Some(&[0x62, 0x31, 0x05, 0x00]) || data.get(12..16) == Some(&[0x00, 0x05, 0x31, 0x62]) { return file("wallet_dat") }
    if data.starts_with(b"\xbaWALLET\x00") { return file("armory_wallet") }
    if data.windows(22).take(64).any(|w| w == b"org.bitcoin.production") { return file("bitcoinj_wallet") }
    let Ok(text) = std::str::from_utf8(data) else { return file("unknown") };
    let t = text.trim();
    if t.starts_with("U2FsdGVkX1") { return file("multibit_key") }
    if t.starts_with("QklFMQ") { return file("electrum_wallet_file_encrypted") }
    if t.starts_with('{') {
        let has = |k: &str| t.contains(&format!("\"{k}\""));
        if has("version") && (has("crypto") || has("Crypto")) { return file("keystore_v3") }
        if has("seed_version") || has("wallet_type") { return file("electrum_wallet") }
    }
    let mut out = vec![];
    for (i, l) in text.lines().enumerate() {
        let l = l.trim();
        if !l.is_empty() { out.push(line(l, i as u64 + 1)) }
    }
    if out.is_empty() { out = file("unknown") }
    out
}

fn line(l: &str, n: u64) -> Row {
    for c in ["btc", "ltc", "doge", "eth", "tron", "xrp"] {
        if crate::validate::validate(c, l).is_ok() { return Row { public: Some(l.into()), chain: crate::chains::chain(c).map(|c| c.name), ..row("address", n, l.as_bytes()) } }
    }
    if blocktools_monero::validate(l).is_ok() { return Row { public: Some(l.into()), chain: Some("xmr"), ..row("monero_address", n, l.as_bytes()) } }
    if crate::validate::is_xrp_seed(l) { return row("xrp_seed", n, l.as_bytes()) }
    if blocktools_monero::is_seed_shape(l) { return row("monero_seed", n, l.as_bytes()) }
    if l.len() == 111 && ["xpub", "ypub", "zpub", "tpub"].iter().any(|p| l.starts_with(p)) && base58::decode_check(l).is_ok() {
        return Row { public: Some(l.into()), ..row("xpub", n, l.as_bytes()) } }
    if ["xprv", "yprv", "zprv", "tprv"].iter().any(|p| l.starts_with(p)) && base58::decode_check(l).map_or(false, |b| b.len() == 78) { return row("xprv", n, l.as_bytes()) }
    if let Ok(b) = base58::decode_check(l) { if (b.len() == 33 || b.len() == 34 && b[33] == 1) && [0x80, 0xb0, 0x9e, 0xef].contains(&b[0]) { return row("wif", n, l.as_bytes()) } }
    let h = l.strip_prefix("0x").unwrap_or(l);
    if h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()) { return row("hex_key", n, l.as_bytes()) }
    let w: Vec<&str> = l.split_whitespace().collect();
    if (12..=24).contains(&w.len()) && w.iter().all(|x| x.bytes().all(|c| c.is_ascii_alphabetic())) {
        return row(if electrum_version(l).is_some() { "electrum_seed" } else { "mnemonic" }, n, l.as_bytes()) }
    if base58::decode(l).map_or(false, |b| b.len() == 32) { return row("b58_key", n, l.as_bytes()) }
    if crate::b64::decode(l).map_or(false, |b| b.len() == 32) { return row("b64_key", n, l.as_bytes()) }
    row("unknown", n, l.as_bytes())
}

#[cfg(test)]
mod t {
    use super::*;
    fn c(s: &str) -> &'static str { classify(s.as_bytes())[0].class }
    #[test] fn xrp() {
        // xrpl.js ripple-keypairs fixtures (public), ripple-address-codec X-address vector
        assert_eq!(c("sp5fghtJtpUorTwvof1NpDXAzNwf5"), "xrp_seed");
        assert_eq!(c("sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r"), "xrp_seed");
        assert_eq!(c("X7AcgcsBL6XDcUb289X4mJ8djcdyKaLFuhLRuNXPrDeJd9A"), "address");
    }
    #[test] fn monero() {
        // public test seed/address from monero-python tests/test_seed.py
        assert_eq!(c("adjust mugged vaults atlas nasty mews damp toenail suddenly toxic possible framed succeed fuzzy return demonstrate nucleus album noises peculiar virtual rowboat inorganic jester fuzzy"), "monero_seed");
        assert_eq!(c("44cWztNFdAqNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH4YtKdH"), "monero_address");
    }
    #[test] fn kinds() {
        assert_eq!(c("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), "mnemonic");
        assert_eq!(c("abandon abandon abandn abandon abandon abandon abandon abandon abandon abandon abandon abuot"), "mnemonic");
        assert_eq!(c("cycle rocket west magnet parrot shuffle foot correct salt library feed song"), "electrum_seed");
        assert_eq!(c("0000000000000000000000000000000000000000000000000000000000000001"), "hex_key");
        assert_eq!(c("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"), "wif");
        assert_eq!(c("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"), "wif");
        assert_eq!(c("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"), "address");
        assert_eq!(c("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"), "address");
        assert_eq!(c("xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"), "xpub");
        assert_eq!(c(r#"{"version":3,"crypto":{}}"#), "keystore_v3");
        assert_eq!(c("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE="), "b64_key");
        assert_eq!(c("hello"), "unknown");
        let r = &classify(b"0000000000000000000000000000000000000000000000000000000000000001")[0];
        assert!(r.public.is_none() && r.fp.len() == 10);
    }
}
