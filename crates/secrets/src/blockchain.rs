//! Blockchain.com / Blockchain.info wallet.aes.json (v2/v3 wrapper). Public format:
//! `{"version":N,"pbkdf2_iterations":I,"payload":"<base64>"}`; payload = IV(16) || ciphertext;
//! key = PBKDF2-HMAC-SHA1(password, IV, I, 32); AES-256-CBC, ISO 10126 padding. After decrypt,
//! the JSON has `keys` (legacy) or `hd_wallets` (HD). We emit WIFs / xprvs found.
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use bitcoin::base58;
use pbkdf2::pbkdf2_hmac;
use serde_json::Value;
use sha1::Sha1;
use zeroize::Zeroizing;

pub const MAX_FILE: usize = 8 << 20;
const MAX_ITERS: u32 = 100_000;

fn b64_decode(s: &str) -> Result<Vec<u8>, &'static str> {
    blocktools_core::b64::decode(s).ok_or("bad_base64")
}

fn iso10126_unpad(buf: &mut [u8]) -> Result<&[u8], &'static str> {
    if buf.is_empty() { return Err("empty"); }
    let pad = buf[buf.len() - 1] as usize;
    if pad == 0 || pad > 16 || pad > buf.len() { return Err("bad_padding"); }
    Ok(&buf[..buf.len() - pad])
}

/// Decrypt the outer wrapper; returns the inner wallet JSON string.
pub fn decrypt_wrapper(json: &str, password: &[u8]) -> Result<Zeroizing<String>, &'static str> {
    let v: Value = serde_json::from_str(json).map_err(|_| "bad_input")?;
    let version = v.get("version").and_then(|x| x.as_u64()).ok_or("bad_input")?;
    if version < 2 || version > 3 { return Err("unsupported_version"); }
    let iters = v.get("pbkdf2_iterations").and_then(|x| x.as_u64()).ok_or("bad_input")? as u32;
    if iters == 0 || iters > MAX_ITERS { return Err("unsupported_iters"); }
    let payload_b64 = v.get("payload").and_then(|x| x.as_str()).ok_or("bad_input")?;
    if payload_b64.len() > MAX_FILE { return Err("too_large"); }
    let raw = b64_decode(payload_b64)?;
    if raw.len() < 32 || raw.len() % 16 != 0 { return Err("bad_payload"); }
    let (iv, ct) = raw.split_at(16);
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha1>(password, iv, iters, &mut *key);
    let mut buf = ct.to_vec();
    let n = cbc::Decryptor::<aes::Aes256>::new((&*key).into(), iv.into())
        .decrypt_padded_mut::<NoPadding>(&mut buf).map_err(|_| "decrypt")?.len();
    let plain = iso10126_unpad(&mut buf[..n])?;
    let s = std::str::from_utf8(plain).map_err(|_| "wrong_password")?;
    // Cheap sanity: must be JSON object.
    if !s.trim_start().starts_with('{') { return Err("wrong_password"); }
    Ok(Zeroizing::new(s.to_string()))
}

/// One recovered secret line: either a WIF or an xprv (already base58check).
#[derive(Debug)]
pub enum KeyOut { Wif(String), Xprv(String) }

/// Pull private keys / xprvs from the decrypted wallet JSON (public schema of Blockchain.com).
pub fn extract_keys(inner: &str) -> Result<Vec<KeyOut>, &'static str> {
    let v: Value = serde_json::from_str(inner).map_err(|_| "bad_wallet")?;
    let mut out = Vec::new();
    if let Some(keys) = v.get("keys").and_then(|x| x.as_array()) {
        for k in keys {
            if let Some(priv_b58) = k.get("priv").and_then(|x| x.as_str()) {
                // Blockchain stores Bitcoin private keys as base58 (sometimes without version);
                // accept WIF-shaped or 32-byte payload and re-encode as WIF.
                if let Ok(d) = base58::decode_check(priv_b58) {
                    if d.len() == 33 && d[0] == 0x80 { out.push(KeyOut::Wif(priv_b58.to_string())); }
                    else if d.len() == 34 && d[0] == 0x80 && d[33] == 0x01 { out.push(KeyOut::Wif(priv_b58.to_string())); }
                    else if d.len() == 32 {
                        let mut p = vec![0x80]; p.extend_from_slice(&d);
                        out.push(KeyOut::Wif(base58::encode_check(&p)));
                    }
                } else if let Ok(d) = base58::decode(priv_b58) {
                    if d.len() == 32 {
                        let mut p = vec![0x80]; p.extend_from_slice(&d);
                        out.push(KeyOut::Wif(base58::encode_check(&p)));
                    }
                }
            }
        }
    }
    if let Some(hd) = v.get("hd_wallets").and_then(|x| x.as_array()) {
        for w in hd {
            if let Some(accounts) = w.get("accounts").and_then(|x| x.as_array()) {
                for a in accounts {
                    if let Some(xprv) = a.get("xpriv").and_then(|x| x.as_str()) {
                        if xprv.starts_with("xprv") { out.push(KeyOut::Xprv(xprv.to_string())); }
                    }
                }
            }
        }
    }
    if out.is_empty() { return Err("no_keys"); }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stretch_password_public_vector() {
        // My-Wallet-V3 wallet-crypto.spec.js stretchPassword (public)
        let salt = (0..16).map(|i| u8::from_str_radix(&"a633e05b567f64482d7620170bd45201"[i*2..i*2+2], 16).unwrap()).collect::<Vec<_>>();
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha1>(b"1234567890", &salt, 10, &mut key);
        let got: String = key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, "4be158806522094dd184bc9c093ea185c6a4ec003bdc6323108e3f5eeb7e388d");
    }

    #[test]
    fn roundtrip_own_vector() {
        use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
        let password = b"blocktools-bc-test";
        let iv = [7u8; 16];
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha1>(password, &iv, 10, &mut key);
        let inner = r#"{"guid":"test","keys":[{"priv":"5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"}]}"#;
        let mut plain = inner.as_bytes().to_vec();
        let pad = 16 - (plain.len() % 16);
        plain.extend(std::iter::repeat(0xAAu8).take(pad - 1));
        plain.push(pad as u8);
        let mut buf = plain;
        let n = buf.len();
        cbc::Encryptor::<aes::Aes256>::new((&key).into(), (&iv).into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, n).unwrap();
        let mut payload = iv.to_vec();
        payload.extend_from_slice(&buf);
        let wrapper = format!(
            r#"{{"version":3,"pbkdf2_iterations":10,"payload":"{}"}}"#,
            blocktools_core::b64::encode(&payload)
        );
        let got = decrypt_wrapper(&wrapper, password).unwrap();
        assert!(got.contains("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf"));
        let keys = extract_keys(&got).unwrap();
        assert!(matches!(&keys[0], KeyOut::Wif(w) if w.starts_with('5')));
        assert!(decrypt_wrapper(&wrapper, b"wrong").is_err());
    }
}
