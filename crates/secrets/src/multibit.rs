//! MultiBit Classic private-key export (.key): OpenSSL "Salted__" AES-256-CBC, key/iv from
//! EVP_BytesToKey(MD5, 1 round), base64 text. Plaintext: '#' comments and "WIF date" lines.
//! Output: the WIF keys. bitcoinj .wallet protobufs and MultiBit HD are in `bitcoinj`.
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use md5::{Digest, Md5};
use zeroize::Zeroizing;

pub const MAX_FILE: usize = 1 << 20;
/// Err("wrong_password") if padding or the plaintext shape is wrong.
pub fn open(b64_text: &str, password: &str) -> Result<Vec<Zeroizing<String>>, &'static str> {
    let clean: String = b64_text.split_whitespace().collect();
    let raw = Zeroizing::new(blocktools_core::b64::decode(&clean).ok_or("unsupported")?);
    if raw.len() < 32 || &raw[..8] != b"Salted__" || raw.len() % 16 != 0 { return Err("unsupported") }
    let salt = &raw[8..16];
    let mut kiv = Zeroizing::new(Vec::with_capacity(48));
    let mut prev: Vec<u8> = vec![];
    while kiv.len() < 48 {
        let mut h = Md5::new(); h.update(&prev); h.update(password.as_bytes()); h.update(salt);
        prev = h.finalize().to_vec(); kiv.extend_from_slice(&prev);
    }
    let mut buf = Zeroizing::new(raw[16..].to_vec());
    let n = cbc::Decryptor::<aes::Aes256>::new(kiv[..32].into(), kiv[32..48].into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf).map_err(|_| "wrong_password")?.len();
    let text = Zeroizing::new(String::from_utf8(buf[..n].to_vec()).map_err(|_| "wrong_password")?);
    let keys: Vec<Zeroizing<String>> = text.lines().filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().next()).filter(|w| bitcoin::PrivateKey::from_wif(w).is_ok())
        .map(|w| Zeroizing::new(w.to_string())).collect();
    if keys.is_empty() { Err("wrong_password") } else { Ok(keys) }
}
