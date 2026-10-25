//! Electrum wallet files (2.x-4.x JSON, field-level encryption only). With "use_encryption", each
//! secret field is base64(iv16 || AES-256-CBC(sha256d(password), PKCS7)) (pw_hash_version 1).
//! Whole-file encrypted wallets (BIE1, "encrypt file") are NOT supported: classify reports them.
//! Electrum 1.x (seed_version 4, a Python dict literal): the seed is 32 hex chars (same
//! encryption). Its keys come from the "old" scheme: secexp = sha256 stretched 100000x,
//! key_i = secexp + sha256d("i:change:" || mpk) (uncompressed P2PKH). The derived mpk must equal the
//! file's master_public_key, or the wallet is refused.
//! Output: the seed phrase (preferred; seed-to-master knows Electrum versions) or the xprv.
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use bitcoin::hashes::{sha256d, Hash};
use serde_json::Value;
use zeroize::Zeroizing;

pub const MAX_FILE: usize = 16 << 20;
#[derive(Debug, PartialEq, Eq)]
pub enum Item { Mnemonic(Zeroizing<String>), Xprv(Zeroizing<String>), OldSeed(Zeroizing<String>) }

/// Python literal (Electrum 1.x wallet file) -> JSON text. Handles 'str', True/False/None, int keys.
pub fn py_to_json(s: &str) -> Option<String> {
    let b: Vec<char> = s.chars().collect();
    let mut o = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == '\'' || c == '"' {
            let q = c; i += 1; o.push('"');
            while i < b.len() && b[i] != q {
                if b[i] == '\\' { o.push('\\'); i += 1; if i < b.len() { o.push(b[i]); } }
                else if b[i] == '"' { o.push_str("\\\""); } else { o.push(b[i]); }
                i += 1;
            }
            if i >= b.len() { return None }
            o.push('"'); i += 1; continue;
        }
        if c.is_ascii_alphabetic() {
            let st = i; while i < b.len() && b[i].is_ascii_alphanumeric() { i += 1; }
            let w: String = b[st..i].iter().collect();
            o.push_str(match w.as_str() { "True" => "true", "False" => "false", "None" => "null", "u" if i < b.len() && (b[i] == '\'' || b[i] == '"') => "", _ => return None });
            continue;
        }
        if c.is_ascii_digit() || c == '-' {
            let st = i; i += 1; while i < b.len() && (b[i].is_ascii_digit() || b[i] == '.') { i += 1; }
            let n: String = b[st..i].iter().collect();
            let mut j = i; while j < b.len() && b[j] == ' ' { j += 1; }
            let key = j < b.len() && b[j] == ':' && o.trim_end().ends_with(['{', ',']);
            if key { o.push('"'); o.push_str(&n); o.push('"'); } else { o.push_str(&n); }
            continue;
        }
        if c == '(' { o.push('['); } else if c == ')' { o.push(']'); } else { o.push(c); }
        i += 1;
    }
    Some(o)
}

/// Electrum 1.x "old" keys: (WIF uncompressed, P2PKH address) for change 0/1, index 0..count.
pub fn old_keys(seed_hex: &str, mpk_check: Option<&str>, count: u32) -> Result<Vec<(Zeroizing<String>, String, String)>, &'static str> {
    use bitcoin::hashes::sha256;
    use bitcoin::secp256k1::{Scalar, Secp256k1, SecretKey};
    let seed = seed_hex.as_bytes();
    let mut x = Zeroizing::new(seed.to_vec());
    for _ in 0..100_000 { let mut m = Zeroizing::new(x.to_vec()); m.extend_from_slice(seed); *x = sha256::Hash::hash(&m).to_byte_array().to_vec(); }
    let secp = Secp256k1::new();
    let master = SecretKey::from_slice(&x).map_err(|_| "bad_seed")?;
    let mpk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &master).serialize_uncompressed();
    let mpk_hex = blocktools_core::hex_enc(&mpk[1..]);
    if let Some(m) = mpk_check { if !m.eq_ignore_ascii_case(&mpk_hex) { return Err("wrong_password") } }
    let mut out = vec![];
    for ch in 0..2u32 { for n in 0..count {
        let mut m = format!("{n}:{ch}:").into_bytes(); m.extend_from_slice(&mpk[1..]);
        let z = Scalar::from_be_bytes(sha256d::Hash::hash(&m).to_byte_array()).map_err(|_| "bad_tweak")?;
        let k = master.add_tweak(&z).map_err(|_| "bad_tweak")?;
        let pk = bitcoin::PrivateKey { compressed: false, network: bitcoin::NetworkKind::Main, inner: k };
        let addr = bitcoin::Address::p2pkh(pk.public_key(&secp), bitcoin::Network::Bitcoin).to_string();
        out.push((Zeroizing::new(pk.to_wif()), addr, format!("m/{ch}/{n}")));
    } }
    Ok(out)
}

fn dec(key: &[u8; 32], b64: &str) -> Option<Zeroizing<String>> {
    let b = Zeroizing::new(blocktools_core::b64::decode(b64)?);
    if b.len() < 32 || b.len() % 16 != 0 { return None }
    let mut buf = Zeroizing::new(b[16..].to_vec());
    let n = cbc::Decryptor::<aes::Aes256>::new(key.into(), b[..16].into()).decrypt_padded_mut::<Pkcs7>(&mut buf).ok()?.len();
    String::from_utf8(buf[..n].to_vec()).ok().map(Zeroizing::new)
}

/// Err("wrong_password") if the password does not decrypt; Err("unsupported") for other shapes.
pub fn open(json: &str, password: &str) -> Result<Vec<Item>, &'static str> {
    let v: Value = match serde_json::from_str(json) { Ok(v) => v,
        Err(_) => serde_json::from_str(&py_to_json(json.trim()).ok_or("unsupported")?).map_err(|_| "unsupported")? };
    let enc = v.get("use_encryption").and_then(Value::as_bool).unwrap_or(false);
    let key = Zeroizing::new(sha256d::Hash::hash(password.as_bytes()).to_byte_array());
    let get = |s: &str| -> Result<Zeroizing<String>, &'static str> {
        if enc { dec(&key, s).ok_or("wrong_password") } else { Ok(Zeroizing::new(s.to_string())) } };
    let ks = v.get("keystore");
    let seed = ks.and_then(|k| k.get("seed")).or_else(|| v.get("seed")).and_then(Value::as_str);
    let xprv = ks.and_then(|k| k.get("xprv")).and_then(Value::as_str)
        .or_else(|| v.get("master_private_keys").and_then(|m| m.get("x/")).and_then(Value::as_str));
    let mut out = vec![];
    if let Some(s) = seed {
        let p = get(s)?;
        if v.get("seed_version").and_then(Value::as_u64).map_or(false, |n| n < 11) {
            if p.len() != 32 || !p.bytes().all(|c| c.is_ascii_hexdigit()) { return Err("wrong_password") }
            out.push(Item::OldSeed(p)); return Ok(out);
        }
        if !p.split_whitespace().all(|w| w.bytes().all(|c| c.is_ascii_alphabetic())) { return Err("wrong_password") }
        out.push(Item::Mnemonic(p));
    }
    if let Some(x) = xprv {
        let p = get(x)?;
        if !["xprv", "yprv", "zprv", "tprv"].iter().any(|q| p.starts_with(q)) { return Err("wrong_password") }
        out.push(Item::Xprv(p));
    }
    if out.is_empty() { return Err("unsupported") }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// btcrecover's Electrum 1.x test wallet (pw btcr-test-password, fixtures/external, fetched).
    /// Independent vector: the file's own master_public_key and addr lists, written by Electrum 1.x.
    #[test] fn electrum1_wallet_keys_match_file() {
        let Ok(f) = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/external/electrum-wallet")) else { eprintln!("skip: fixture absent"); return };
        let items = open(&f, "btcr-test-password").unwrap();
        let Item::OldSeed(s) = &items[0] else { panic!() };
        let v: Value = serde_json::from_str(&py_to_json(f.trim()).unwrap()).unwrap();
        let ks = old_keys(s, v["master_public_key"].as_str(), 5).unwrap();
        let recv: Vec<&str> = v["accounts"]["0"]["0"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
        let chg: Vec<&str> = v["accounts"]["0"]["1"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
        assert_eq!(ks[..5].iter().map(|k| k.1.as_str()).collect::<Vec<_>>(), recv);
        assert_eq!(ks[5..8].iter().map(|k| k.1.as_str()).collect::<Vec<_>>(), chg);
        assert_eq!(open(&f, "wrong"), Err("wrong_password"));
    }
    #[test] fn py_literal() {
        assert_eq!(py_to_json("{'a': True, 0: [u'x', None], 'b': (1, 2)}").unwrap(), r#"{"a": true, "0": ["x", null], "b": [1, 2]}"#);
    }
}
