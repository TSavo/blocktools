//! Electrum wallet files (2.x-4.x JSON, field-level encryption only). With "use_encryption", each
//! secret field is base64(iv16 || AES-256-CBC(sha256d(password), PKCS7)) (pw_hash_version 1).
//! Whole-file encrypted wallets (BIE1, "encrypt file") are NOT supported: classify reports them.
//! Output: the seed phrase (preferred; seed-to-master knows Electrum versions) or the xprv.
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use bitcoin::hashes::{sha256d, Hash};
use serde_json::Value;
use zeroize::Zeroizing;

pub const MAX_FILE: usize = 16 << 20;
#[derive(Debug, PartialEq, Eq)]
pub enum Item { Mnemonic(Zeroizing<String>), Xprv(Zeroizing<String>) }

fn dec(key: &[u8; 32], b64: &str) -> Option<Zeroizing<String>> {
    let b = Zeroizing::new(blocktools_core::b64::decode(b64)?);
    if b.len() < 32 || b.len() % 16 != 0 { return None }
    let mut buf = Zeroizing::new(b[16..].to_vec());
    let n = cbc::Decryptor::<aes::Aes256>::new(key.into(), b[..16].into()).decrypt_padded_mut::<Pkcs7>(&mut buf).ok()?.len();
    String::from_utf8(buf[..n].to_vec()).ok().map(Zeroizing::new)
}

/// Err("wrong_password") if the password does not decrypt; Err("unsupported") for other shapes.
pub fn open(json: &str, password: &str) -> Result<Vec<Item>, &'static str> {
    let v: Value = serde_json::from_str(json).map_err(|_| "unsupported")?;
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
