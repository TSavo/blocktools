//! derive: mnemonic JSON lines (from seed-repair) or a phrase file -> addresses
//! across BIP44/49/84/86 and Ethereum m/44'/60'. Output CONTAINS SECRETS
//! (fields "wif" / "private_key"). Everything arrives on stdin as JSON lines:
//! {"passphrase":"..."} (optional, applies to following lines) and {"mnemonic":"...","candidate":N}.
use bip39::{Language, Mnemonic};
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::{Secp256k1, All};
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey};
use sha3::{Digest, Keccak256};
use std::io::{BufRead, Read};
use std::str::FromStr;
use zeroize::Zeroizing;

fn hex_enc(b: impl AsRef<[u8]>) -> String { b.as_ref().iter().map(|x| format!("{x:02x}")).collect() }

pub fn eth_address(sk: &bitcoin::secp256k1::SecretKey, secp: &Secp256k1<All>) -> String {
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(secp, sk).serialize_uncompressed();
    let h = Keccak256::digest(&pk[1..]);
    let a = hex_enc(&h[12..]);
    let ch = hex_enc(Keccak256::digest(a.as_bytes()));
    let s: String = a.chars().zip(ch.chars()).map(|(c, k)| if k.to_digit(16).unwrap() >= 8 { c.to_ascii_uppercase() } else { c }).collect();
    format!("0x{s}")
}

pub struct Row { pub kind: &'static str, pub path: String, pub address: String, pub secret: String }

pub fn derive_all(m: &Mnemonic, passphrase: &str, count: u32) -> Vec<Row> {
    let secp = Secp256k1::new();
    let seed = Zeroizing::new(m.to_seed_normalized(passphrase));
    let master = Xpriv::new_master(Network::Bitcoin, &seed[..]).expect("seed");
    let mut rows = Vec::new();
    for (kind, purpose, coin) in [("p2pkh", 44, 0), ("p2sh-p2wpkh", 49, 0), ("p2wpkh", 84, 0), ("p2tr", 86, 0), ("eth", 44, 60)] {
        for i in 0..count {
            let path = format!("m/{purpose}'/{coin}'/0'/0/{i}");
            let xk = master.derive_priv(&secp, &DerivationPath::from_str(&path).unwrap()).unwrap();
            let sk = xk.private_key;
            let (address, secret) = if kind == "eth" {
                (eth_address(&sk, &secp), hex_enc(sk.secret_bytes()))
            } else {
                let cpk = CompressedPublicKey::from_private_key(&secp, &PrivateKey::new(sk, Network::Bitcoin)).unwrap();
                let a = match kind {
                    "p2pkh" => Address::p2pkh(cpk, Network::Bitcoin),
                    "p2sh-p2wpkh" => Address::p2shwpkh(&cpk, Network::Bitcoin),
                    "p2wpkh" => Address::p2wpkh(&cpk, Network::Bitcoin),
                    _ => Address::p2tr(&secp, cpk.0.x_only_public_key().0, None, Network::Bitcoin),
                };
                (a.to_string(), PrivateKey::new(sk, Network::Bitcoin).to_wif())
            };
            rows.push(Row { kind, path, address, secret });
        }
    }
    rows
}

fn fail(s: &str) -> ! { println!(r#"{{"tool":"derive","status":"{s}"}}"#); std::process::exit(2) }

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mut count = 3u32;
    let mut i = 1;
    while i < a.len() {
        let v = a.get(i + 1).cloned();
        match a[i].as_str() {
            "--count" => count = v.and_then(|s| s.parse().ok()).filter(|n| *n <= 1000).unwrap_or_else(|| fail("bad_input")),
            _ => fail("bad_input"),
        }
        i += 2;
    }
    let mut passphrase = Zeroizing::new(String::new());
    let mut phrases: Vec<(u64, Zeroizing<String>, Zeroizing<String>)> = Vec::new();
    for line in std::io::stdin().lock().take(16 << 20).lines().map_while(Result::ok) {
        let line = Zeroizing::new(line);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        if let Some(p) = v.get("passphrase").and_then(|m| m.as_str()) {
            if p.len() <= 1024 { passphrase = Zeroizing::new(p.to_string()); }
        }
        if let Some(m) = v.get("mnemonic").and_then(|m| m.as_str()) {
            phrases.push((v.get("candidate").and_then(|c| c.as_u64()).unwrap_or(0), Zeroizing::new(m.to_string()), passphrase.clone()));
        }
    }
    let mut n = 0;
    for (cand, p, pass) in phrases {
        let Ok(m) = Mnemonic::parse_in_normalized(Language::English, &p) else {
            println!(r#"{{"tool":"derive","status":"checksum_fail","candidate":{cand}}}"#); continue };
        for r in derive_all(&m, &pass, count) {
            let key = if r.kind == "eth" { "private_key" } else { "wif" };
            // All values are fixed enums, paths, addresses or hex/base58: no escaping needed.
            println!(r#"{{"tool":"derive","status":"ok","candidate":{cand},"kind":"{}","path":"{}","address":"{}","{key}":"{}"}}"#, r.kind, r.path, r.address, r.secret);
            n += 1;
        }
    }
    println!(r#"{{"tool":"derive","status":"done","count":{n}}}"#);
}

#[cfg(test)]
mod tests {
    use super::*;
    // Public BIP39/BIP44/49/84/86 test vector, empty passphrase.
    #[test] fn abandon_about() {
        let m = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let rows = derive_all(&m, "", 1);
        let got: Vec<(&str, &str)> = rows.iter().map(|r| (r.kind, r.address.as_str())).collect();
        assert_eq!(got, vec![
            ("p2pkh", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
            ("p2sh-p2wpkh", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"),
            ("p2wpkh", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
            ("p2tr", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
            ("eth", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
        ]);
    }
}
