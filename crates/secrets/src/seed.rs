//! Seed phrases: phrase (+ passphrase) -> BIP32 master key,
//! trying BIP39 and Electrum 2.x+ readings. Everything here handles secrets.
use bip39::{Language, Mnemonic};
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::{hmac::{Hmac, HmacEngine}, sha512, Hash, HashEngine};
use bitcoin::Network;
use zeroize::Zeroizing;

const WINDOWS: &[usize] = &[12, 13, 15, 18, 21, 24];

/// Electrum normalisation for ASCII/Latin phrases: lowercase, single spaces.
/// (Electrum also NFKD-normalises and strips accents/CJK spaces: non-ASCII phrases
/// are reported as unsupported for the Electrum scheme rather than guessed.)
pub fn electrum_norm(p: &str) -> Option<String> {
    if !p.is_ascii() { return None }
    Some(p.split_whitespace().map(|w| w.to_ascii_lowercase()).collect::<Vec<_>>().join(" "))
}
/// Electrum seed type from HMAC-SHA512(key "Seed version", phrase) hex prefix.
pub fn electrum_scheme(norm: &str) -> Option<&'static str> {
    let mut e = HmacEngine::<sha512::Hash>::new(b"Seed version");
    e.input(norm.as_bytes());
    let h = Hmac::<sha512::Hash>::from_engine(e).to_byte_array();
    match (h[0], h[1] >> 4) {
        (0x01, _) => Some("electrum-standard"),
        (0x10, 0x0) => Some("electrum-segwit"),
        (0x10, 0x1) => Some("electrum-2fa"),
        (0x10, 0x2) => Some("electrum-2fa-segwit"),
        _ => None,
    }
}
pub fn electrum_seed(norm: &str, passphrase: &str) -> Zeroizing<[u8; 64]> {
    let mut out = Zeroizing::new([0u8; 64]);
    let salt = Zeroizing::new(format!("electrum{}", passphrase.to_lowercase()));
    pbkdf2::pbkdf2_hmac::<sha2::Sha512>(norm.as_bytes(), salt.as_bytes(), 2048, &mut out[..]);
    out
}


/// One reading of a phrase.
pub enum Reading {
    /// scheme: "bip39" | "electrum-standard" | "electrum-segwit"; xprv and 64-byte seed are secrets.
    Master { scheme: &'static str, xprv: Zeroizing<String>, seed: Zeroizing<[u8; 64]> },
    /// Recognised but not supported yet (Electrum 2FA).
    Unsupported { scheme: &'static str },
}
fn master(scheme: &'static str, seed: &[u8]) -> Reading {
    let mut s = Zeroizing::new([0u8; 64]); s.copy_from_slice(&seed[..64]);
    let x = Xpriv::new_master(Network::Bitcoin, &s[..]).expect("64-byte seed");
    Reading::Master { scheme, xprv: Zeroizing::new(x.to_string()), seed: s }
}
fn one(t: &str, passphrase: &str, out: &mut Vec<Reading>) {
    let t = Zeroizing::new(t.to_string());
    if let Ok(mn) = Mnemonic::parse_in_normalized(Language::English, &t) {
        out.push(master("bip39", &Zeroizing::new(mn.to_seed_normalized(passphrase))[..]));
    }
    if let Some(norm) = electrum_norm(&t).map(Zeroizing::new) {
        match electrum_scheme(&norm) {
            Some(s @ ("electrum-2fa" | "electrum-2fa-segwit")) => out.push(Reading::Unsupported { scheme: s }),
            Some(s) => out.push(master(s, &electrum_seed(&norm, passphrase)[..])),
            None => {}
        }
    }
}
/// All readings of one phrase: full phrase first; if it gives no master key, the trailing
/// 12/13/15/18/21/24-word windows (a phrase pasted with a note in front).
pub fn readings(phrase: &str, passphrase: &str) -> Vec<Reading> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let mut out = Vec::new();
    one(&words.join(" "), passphrase, &mut out);
    if !out.iter().any(|r| matches!(r, Reading::Master { .. })) {
        for &w in WINDOWS { if words.len() > w { one(&words[words.len() - w..].join(" "), passphrase, &mut out) } }
    }
    out
}

#[cfg(test)]
mod master_tests {
    use super::*;
    fn hex(b: &[u8]) -> String { b.iter().map(|b| format!("{b:02x}")).collect() }
    #[test] fn abandon_about_root() {
        let mn = Mnemonic::parse_in_normalized(Language::English, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let m = Xpriv::new_master(Network::Bitcoin, &mn.to_seed_normalized("")).unwrap();
        assert_eq!(m.to_string(), "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu");
    }
    // Electrum project test vectors (electrum/tests/test_mnemonic.py), re-checked with Python hashlib.
    #[test] fn electrum_vectors() {
        assert_eq!(hex(&electrum_seed("foobar", "none")[..]), "741b72fd15effece6bfe5a26a52184f66811bd2be363190e07a42cca442b1a5bb22b3ad0eb338197287e6d314866c7fba863ac65d3f156087a5052ebc7157fce");
        let w = "wild father tree among universe such mobile favorite target dynamic credit identify";
        assert_eq!(electrum_scheme(w), Some("electrum-segwit"));
        assert!(hex(&electrum_seed(w, "")[..]).starts_with("aac2a6302e48577ab4b46f23dbae0774"));
        // self-generated (scripts: python hmac search) standard-prefix phrase
        let s = "abandon ability able about above absent absorb abstract absurd abuse ability able";
        assert_eq!(electrum_scheme(s), Some("electrum-standard"));
        assert!(hex(&electrum_seed(s, "")[..]).starts_with("5726b614061d3d6fd63869a7fa730f28"));
        assert_eq!(electrum_scheme(&electrum_norm("  WILD father  tree among universe such mobile favorite target dynamic credit identify ").unwrap()), Some("electrum-segwit"));
        assert_eq!(electrum_scheme("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"), None);
    }
    #[test] fn sliding_window() {
        let r = readings("my seed was: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
        assert_eq!(r.len(), 1);
        assert!(matches!(&r[0], Reading::Master { scheme: "bip39", .. }));
    }
}
