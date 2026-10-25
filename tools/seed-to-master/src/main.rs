//! seed-to-master: seed phrase (+ optional passphrase) -> BIP32 master key(s).
//! stdin JSON lines: optional {"passphrase":"..."} then {"mnemonic":"...","candidate":N}.
//! A phrase is tried as BIP39 AND as an Electrum (2.x+) seed; every valid reading is
//! one output line with its "scheme". If the phrase has extra words (e.g. a note
//! line), the trailing 12/13/15/18/21/24 words are tried too (sliding window).
//! --passphrase-prompt asks the human on /dev/tty with echo off (never argv/env).
//! Output CONTAINS SECRETS ("xprv", "seed"). One job: phrase -> master key.
use bip39::{Language, Mnemonic};
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::{hmac::{Hmac, HmacEngine}, sha512, Hash, HashEngine};
use bitcoin::Network;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

const WINDOWS: &[usize] = &[12, 13, 15, 18, 21, 24];

/// Electrum normalisation for ASCII/Latin phrases: lowercase, single spaces.
/// (Electrum also NFKD-normalises and strips accents/CJK spaces: non-ASCII phrases
/// are reported as unsupported for the Electrum scheme rather than guessed.)
fn electrum_norm(p: &str) -> Option<String> {
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

fn emit(cand: u64, scheme: &str, seed: &[u8], n: &mut u64) {
    let master = Xpriv::new_master(Network::Bitcoin, seed).expect("seed");
    let hex = Zeroizing::new(seed.iter().map(|b| format!("{b:02x}")).collect::<String>());
    kr_io::outln!(r#"{{"tool":"seed-to-master","status":"ok","candidate":{cand},"scheme":"{scheme}","xprv":"{}","seed":"{}"}}"#, master, hex.as_str());
    *n += 1;
}

fn one(t: &str, passphrase: &str, cand: u64, n: &mut u64) {
    let t = Zeroizing::new(t.to_string());
    if let Ok(mn) = Mnemonic::parse_in_normalized(Language::English, &t) {
        emit(cand, "bip39", &Zeroizing::new(mn.to_seed_normalized(passphrase))[..], n);
    }
    if let Some(norm) = electrum_norm(&t).map(Zeroizing::new) {
        match electrum_scheme(&norm) {
            Some(s @ ("electrum-2fa" | "electrum-2fa-segwit")) => kr_io::outln!(r#"{{"tool":"seed-to-master","status":"unsupported","candidate":{cand},"scheme":"{s}"}}"#),
            Some(s) => emit(cand, s, &electrum_seed(&norm, passphrase)[..], n),
            None => {}
        }
    }
}
/// All readings of one phrase (full phrase first; trailing windows only if it gives none). Returns number of valid readings.
fn readings(phrase: &str, passphrase: &str, cand: u64, n: &mut u64) -> u64 {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let before = *n;
    one(&words.join(" "), passphrase, cand, n);
    if *n == before {
        for &w in WINDOWS { if words.len() > w { one(&words[words.len() - w..].join(" "), passphrase, cand, n) } }
    }
    *n - before
}

fn main() {
    kr_io::help("seed-to-master [--passphrase-prompt] < {\"mnemonic\":...} lines -> master keys (BIP39 and Electrum standard/segwit; 2FA and old-Electrum: unsupported, planned)");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut passphrase = Zeroizing::new(String::new());
    match args.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice() {
        [] => {}
        ["--passphrase-prompt"] => match kr_tty::read_secret("BIP39/Electrum passphrase (not echoed, empty = none): ") {
            Some(p) => passphrase = p,
            None => { kr_io::outln!(r#"{{"tool":"seed-to-master","status":"bad_input"}}"#); std::process::exit(2) }
        },
        ["--help"] => { println!("seed-to-master [--passphrase-prompt]  < {{\"mnemonic\":...}} lines\n  tries BIP39 and Electrum (standard/segwit); 2FA and old-Electrum: unsupported (planned)"); return }
        _ => { kr_io::outln!(r#"{{"tool":"seed-to-master","status":"bad_input"}}"#); std::process::exit(2) }
    }
    let mut n = 0u64;
    let reader = std::io::stdin().lock().take(16 << 20);
    for line in reader.lines().map_while(Result::ok) {
        let line = Zeroizing::new(line);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        if let Some(p) = v.get("passphrase").and_then(|m| m.as_str()) {
            if p.len() <= 1024 { passphrase = Zeroizing::new(p.to_string()); }
        }
        let Some(m) = v.get("mnemonic").and_then(|m| m.as_str()) else { continue };
        if m.len() > 4096 { continue }
        let cand = v.get("candidate").and_then(|c| c.as_u64()).unwrap_or(0);
        if readings(m, &passphrase, cand, &mut n) == 0 {
            kr_io::outln!(r#"{{"tool":"seed-to-master","status":"checksum_fail","candidate":{cand}}}"#)
        }
    }
    kr_io::outln!(r#"{{"tool":"seed-to-master","status":"done","count":{n}}}"#);
}

#[cfg(test)]
mod tests {
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
        let mut n = 0;
        assert_eq!(readings("my seed was: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0, &mut n), 1);
    }
}
