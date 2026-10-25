//! Electrum wallet files (2.x-4.x JSON, field-level encryption only). With "use_encryption", each
//! secret field is base64(iv16 || AES-256-CBC(sha256d(password), PKCS7)) (pw_hash_version 1).
//! Whole-file encrypted wallets ("encrypt file", base64 "BIE1..."): ECIES as Electrum's
//! storage.py/crypto.py: privkey = PBKDF2-HMAC-SHA512(password, "", 1024) mod n; ephemeral pubkey
//! at [4..37]; k = sha512(compressed(eph * priv)); iv k[0..16], AES-128-CBC key k[16..32], HMAC-SHA256
//! key k[32..] over everything but the trailing 32-byte mac; plaintext is zlib. BIE2 (xpub/hardware
//! password) is refused as "unsupported_bie2".
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

/// Decrypt an Electrum BIE1 whole-file-encrypted wallet to its JSON text.
pub fn decrypt_bie1(file: &str, password: &str) -> Result<Zeroizing<String>, &'static str> {
    use bitcoin::hashes::{hmac::{Hmac, HmacEngine}, sha256, sha512, HashEngine};
    use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1};
    let t = file.trim();
    if t.starts_with("QklFMg") { return Err("unsupported_bie2") }
    let raw = blocktools_core::b64::decode(t).ok_or("unsupported")?;
    if raw.len() < 85 || &raw[..4] != b"BIE1" { return Err("unsupported") }
    // PBKDF2-HMAC-SHA512, one 64-byte block, 1024 iterations, empty salt.
    let prf = |m: &[u8]| { let mut e = HmacEngine::<sha512::Hash>::new(password.as_bytes()); e.input(m); Hmac::<sha512::Hash>::from_engine(e).to_byte_array() };
    let mut u = Zeroizing::new(prf(&[0, 0, 0, 1])); let mut acc = Zeroizing::new(*u);
    for _ in 1..1024 { *u = prf(&u[..]); for (a, b) in acc.iter_mut().zip(u.iter()) { *a ^= b } }
    let sk = reduce_mod_n(&acc).ok_or("wrong_password")?;
    let secp = Secp256k1::verification_only();
    let eph = PublicKey::from_slice(&raw[4..37]).map_err(|_| "unsupported")?;
    let shared = eph.mul_tweak(&secp, &Scalar::from(sk)).map_err(|_| "wrong_password")?;
    let k = Zeroizing::new(sha512::Hash::hash(&shared.serialize()).to_byte_array());
    let (body, mac) = raw.split_at(raw.len() - 32);
    let mut e = HmacEngine::<sha256::Hash>::new(&k[32..]); e.input(body);
    let want = Hmac::<sha256::Hash>::from_engine(e).to_byte_array();
    if want.iter().zip(mac).fold(0u8, |a, (x, y)| a | (x ^ y)) != 0 { return Err("wrong_password") }
    let mut buf = Zeroizing::new(body[37..].to_vec());
    let key: [u8; 16] = k[16..32].try_into().unwrap(); let iv: [u8; 16] = k[..16].try_into().unwrap();
    let n = cbc::Decryptor::<aes::Aes128>::new(&key.into(), &iv.into()).decrypt_padded_mut::<Pkcs7>(&mut buf).map_err(|_| "corrupt")?.len();
    let plain = Zeroizing::new(miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&buf[..n], MAX_FILE).map_err(|_| "corrupt")?);
    String::from_utf8(plain.to_vec()).map(Zeroizing::new).map_err(|_| "corrupt")
}
/// 512-bit big-endian value mod the secp256k1 order, as a key (None if 0).
fn reduce_mod_n(x: &[u8; 64]) -> Option<bitcoin::secp256k1::SecretKey> {
    const N: [u64; 4] = [0xBFD25E8CD0364141, 0xBAAEDCE6AF48A03B, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF]; // little-endian limbs
    // schoolbook: r = (r * 256 + byte) mod n, r < n < 2^256, kept in 5 limbs
    let mut r = [0u64; 5];
    for &b in x.iter() {
        let mut c = b as u128;
        for l in r.iter_mut() { let v = ((*l as u128) << 8) | c; *l = v as u64; c = v >> 64; }
        // r < 2^264; subtract n while r >= n (at most 256 times; constant shape not needed for an offline tool)
        loop {
            let ge = r[4] != 0 || (0..4).rev().map(|i| r[i].cmp(&N[i])).find(|o| o.is_ne()).map_or(true, |o| o.is_gt());
            if !ge { break }
            let mut br = 0i128;
            for i in 0..5 { let v = r[i] as i128 - *N.get(i).unwrap_or(&0) as i128 - br; br = (v < 0) as i128; r[i] = (v + (br << 64)) as u64; }
        }
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for i in 0..4 { out[(3 - i) * 8..(4 - i) * 8].copy_from_slice(&r[i].to_be_bytes()) }
    bitcoin::secp256k1::SecretKey::from_slice(&out[..]).ok()
}

/// Err("wrong_password") if the password does not decrypt; Err("unsupported") for other shapes.
/// A BIE1 whole-file-encrypted wallet is decrypted with the same password first.
pub fn open(json: &str, password: &str) -> Result<Vec<Item>, &'static str> {
    if json.trim_start().starts_with("QklF") { let d = decrypt_bie1(json, password)?; return open(&d, password) }
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
    /// Independent vector from scripts/electrum-bie1-gen.py (python `cryptography`, public password).
    #[test] fn bie1_vector() {
        const V: &str = "QklFMQP5c6C4cGLDidEl2BmegDuDK2rGv3hnpPbNh1BgYPxMWK0baBcm30a4MYvrXX0n8QXwd98GGE3NTj0ntXbfB5FfKdhKhYV7otO7SQiFvUrSzMzAeC9MQG+4FdNhjn9Ohxmuk9m1ZjliG6izoUXpBl2U9E7iSbSKl7oy7tiYBdCERiVq/YlWwbsqlyW7cLcfZRp5NhbVfpwiHEA/qfv+aPNJ";
        let d = decrypt_bie1(V, "blocktools-bie1-test").unwrap();
        assert_eq!(d.as_str(), r#"{"seed_version": 18, "wallet_type": "standard", "note": "blocktools BIE1 vector"}"#);
        assert_eq!(decrypt_bie1(V, "wrong").unwrap_err(), "wrong_password");
        assert_eq!(decrypt_bie1(&V.replacen("QklFMQ", "QklFMg", 1), "x").unwrap_err(), "unsupported_bie2");
        assert_eq!(open(V, "blocktools-bie1-test"), Err("unsupported")); // decrypts, but holds no keystore
        let mut n = [0xffu8; 64]; n[0] = 0; assert!(reduce_mod_n(&n).is_some());
    }
    /// btcrecover's Electrum 2.8 / 4.1 "encrypt file" wallets (fixtures/external, fetched; pw btcr-test-password),
    /// written by Electrum itself: decrypt, then yield their seed (not printed).
    #[test] fn bie1_btcrecover_fixtures() {
        for f in ["electrum28-wallet", "electrum41-wallet"] {
            let Ok(t) = std::fs::read_to_string(format!("{}/../../fixtures/external/{f}", env!("CARGO_MANIFEST_DIR"))) else { eprintln!("skip: fixture absent"); return };
            let d = decrypt_bie1(&t, "btcr-test-password").unwrap();
            assert!(serde_json::from_str::<Value>(&d).unwrap()["seed_version"].as_u64().unwrap() >= 11, "{f}");
            assert!(matches!(open(&t, "btcr-test-password").unwrap()[0], Item::Mnemonic(_) | Item::Xprv(_)), "{f}");
            assert_eq!(open(&t, "nope"), Err("wrong_password"));
        }
    }
    #[test] fn py_literal() {
        assert_eq!(py_to_json("{'a': True, 0: [u'x', None], 'b': (1, 2)}").unwrap(), r#"{"a": true, "0": ["x", null], "b": [1, 2]}"#);
    }
}
