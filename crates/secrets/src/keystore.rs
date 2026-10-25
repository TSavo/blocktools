//! Ethereum Web3 Secret Storage v3 keystore: JSON + password -> private key.
use aes::cipher::{KeyIvInit, StreamCipher};
use blocktools_core::{hex_dec, hex_enc};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

type Ctr = ctr::Ctr128BE<aes::Aes128>;
pub const MAX_FILE: u64 = 64 * 1024;

fn hexf(v: &Value, k: &str) -> Result<Vec<u8>, &'static str> {
    let s = v.get(k).and_then(|x| x.as_str()).ok_or("bad_input")?;
    if s.len() > 512 { return Err("bad_input"); }
    if s.starts_with("0x") { return Err("bad_input") }
    hex_dec(s).ok_or("bad_input")
}

/// scrypt memory is 128*N*r bytes; work scales with N*r*p. Bound both instead of each knob, so
/// real wallets pass (geth standard N=2^18 r=8 p=1, --lightkdf N=4096 r=8 p=6, spec N=2^18 r=1 p=8)
/// and a hostile file can't ask for more than MAX_SCRYPT_MEM of RAM or ~8x geth-standard work.
pub const MAX_SCRYPT_MEM: u64 = 256 << 20;
pub const MAX_SCRYPT_WORK: u64 = 1 << 24; // N*r*p
pub fn scrypt_ok(n: u64, r: u64, p: u64) -> bool {
    n >= 2 && n.is_power_of_two() && r >= 1 && p >= 1 && r <= 1024 && p <= 1024
        && n.checked_mul(r).and_then(|x| x.checked_mul(128)).is_some_and(|m| m <= MAX_SCRYPT_MEM)
        && n.checked_mul(r).and_then(|x| x.checked_mul(p)).is_some_and(|w| w <= MAX_SCRYPT_WORK)
}

fn salsa8(b: &mut [u32; 16]) {
    let mut x = *b;
    macro_rules! q { ($a:expr,$b:expr,$c:expr,$d:expr) => {
        x[$b] ^= x[$a].wrapping_add(x[$d]).rotate_left(7); x[$c] ^= x[$b].wrapping_add(x[$a]).rotate_left(9);
        x[$d] ^= x[$c].wrapping_add(x[$b]).rotate_left(13); x[$a] ^= x[$d].wrapping_add(x[$c]).rotate_left(18);
    } }
    for _ in 0..4 {
        q!(0, 4, 8, 12); q!(5, 9, 13, 1); q!(10, 14, 2, 6); q!(15, 3, 7, 11);
        q!(0, 1, 2, 3); q!(5, 6, 7, 4); q!(10, 11, 8, 9); q!(15, 12, 13, 14);
    }
    for i in 0..16 { b[i] = b[i].wrapping_add(x[i]); }
}
fn block_mix(b: &[u32], out: &mut [u32], r: usize) {
    let mut x = [0u32; 16]; x.copy_from_slice(&b[(2 * r - 1) * 16..]);
    for i in 0..2 * r {
        for j in 0..16 { x[j] ^= b[i * 16 + j]; }
        salsa8(&mut x);
        let o = if i % 2 == 0 { i / 2 } else { r + i / 2 };
        out[o * 16..o * 16 + 16].copy_from_slice(&x);
    }
}
/// RFC 7914 scrypt without the N < 2^(16r) restriction. Callers bound N, r, p via scrypt_ok.
fn scrypt_raw(pw: &[u8], salt: &[u8], n: usize, r: usize, p: usize, out: &mut [u8]) {
    let w = 32 * r; // u32 words per block
    let mut b = Zeroizing::new(vec![0u8; 128 * r * p]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, salt, 1, &mut b);
    let mut v = Zeroizing::new(vec![0u32; w * n]);
    let (mut x, mut t) = (Zeroizing::new(vec![0u32; w]), Zeroizing::new(vec![0u32; w]));
    for chunk in b.chunks_mut(128 * r) {
        for (i, c) in chunk.chunks(4).enumerate() { x[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]); }
        for i in 0..n { v[i * w..(i + 1) * w].copy_from_slice(&x); block_mix(&x, &mut t, r); std::mem::swap(&mut x, &mut t); }
        for _ in 0..n {
            let j = (x[w - 16] as usize) & (n - 1);
            for k in 0..w { x[k] ^= v[j * w + k]; }
            block_mix(&x, &mut t, r); std::mem::swap(&mut x, &mut t);
        }
        for (i, c) in chunk.chunks_mut(4).enumerate() { c.copy_from_slice(&x[i].to_le_bytes()); }
    }
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(pw, &b, 1, out);
}

pub fn open(json: &str, password: &[u8]) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let v: Value = serde_json::from_str(json).map_err(|_| "bad_input")?;
    let c = v.get("crypto").or_else(|| v.get("Crypto")).ok_or("bad_input")?;
    if c.get("cipher").and_then(|x| x.as_str()) != Some("aes-128-ctr") { return Err("unsupported"); }
    let kp = c.get("kdfparams").ok_or("bad_input")?;
    let num = |k: &str| kp.get(k).and_then(|x| x.as_u64()).ok_or("bad_input");
    let salt = hexf(kp, "salt")?;
    let dklen = num("dklen")? as usize;
    if dklen != 32 { return Err("unsupported"); }
    let mut dk = Zeroizing::new([0u8; 32]);
    match c.get("kdf").and_then(|x| x.as_str()) {
        Some("scrypt") => {
            let n = num("n")?; let (r, p) = (num("r")? as u32, num("p")? as u32);
            if !scrypt_ok(n, r as u64, p as u64) { return Err("unsupported"); }
            match scrypt::Params::new(n.trailing_zeros() as u8, r, p, 32) {
                Ok(params) => scrypt::scrypt(password, &salt, &params, &mut dk[..]).map_err(|_| "error")?,
                // The scrypt crate enforces RFC 7914's N < 2^(16r); geth and the Web3 spec vector
                // (N=2^18, r=1) don't. Same algorithm, own implementation, same memory/work bounds.
                Err(_) => scrypt_raw(password, &salt, n as usize, r as usize, p as usize, &mut dk[..]),
            }
        }
        Some("pbkdf2") => {
            if kp.get("prf").and_then(|x| x.as_str()) != Some("hmac-sha256") { return Err("unsupported"); }
            let iters = num("c")?; if iters == 0 || iters > 10_000_000 { return Err("unsupported"); }
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, &salt, iters as u32, &mut dk[..]);
        }
        _ => return Err("unsupported"),
    }
    let ct = hexf(c, "ciphertext")?;
    let iv = hexf(c.get("cipherparams").ok_or("bad_input")?, "iv")?;
    let mac = hexf(c, "mac")?;
    if ct.len() != 32 || iv.len() != 16 { return Err("unsupported"); }
    let mut h = Keccak256::new(); h.update(&dk[16..32]); h.update(&ct);
    if h.finalize().as_slice() != mac.as_slice() { return Err("wrong_password"); }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&ct);
    Ctr::new(dk[..16].into(), iv.as_slice().into()).apply_keystream(&mut key[..]);
    Ok(key)
}

/// EIP-55 address of the decrypted key.
pub fn eth_address(k: &[u8; 32]) -> Result<String, &'static str> {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let sk = SecretKey::from_slice(k).map_err(|_| "error")?;
    Ok(blocktools_core::eth_address(&sk, &Secp256k1::new()))
}
/// open + address: (address, private key hex).
pub fn open_v3(json: &str, password: &[u8]) -> Result<(String, Zeroizing<String>), &'static str> {
    let k = open(json, password)?;
    Ok((eth_address(&k)?, Zeroizing::new(hex_enc(&k[..]))))
}


#[cfg(test)]
mod tests {
    use super::*;
    // Public test vector from the Web3 Secret Storage Definition (PBKDF2).
    const V: &str = r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},"ciphertext":"5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46","kdf":"pbkdf2","kdfparams":{"c":262144,"dklen":32,"prf":"hmac-sha256","salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},"mac":"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}"#;
    #[test] fn spec_vector() {
        let k = open(V, b"testpassword").unwrap();
        assert_eq!(hex_enc(&k[..]), "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d");
    }
    #[test] fn wrong_pw() { assert_eq!(open(V, b"nope").unwrap_err(), "wrong_password"); }
    // Web3 Secret Storage Definition scrypt vector (N=262144, r=1, p=8): p=8 must be accepted.
    const VS: &str = r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"83dbcc02d8ccb40e466191a123791e0e"},"ciphertext":"d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c","kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"r":1,"p":8,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"},"mac":"2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}"#;
    // geth --lightkdf parameters (N=4096, r=8, p=6), same public spec key/password; built with Python hashlib.scrypt.
    const VL: &str = r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"22222222222222222222222222222222"},"ciphertext":"c82312528902fd0681481c15cfd8f8ebc26cf29c5c675d9d8946bed1662dc686","kdf":"scrypt","kdfparams":{"dklen":32,"n":4096,"r":8,"p":6,"salt":"1111111111111111111111111111111111111111111111111111111111111111"},"mac":"d5dde1edbd54a2c562a038bffee74b15c35ff88a258408182170dcfd21d21778"},"version":3}"#;
    const K: &str = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d";
    #[test] fn spec_scrypt_p8() { assert_eq!(hex_enc(&open(VS, b"testpassword").unwrap()[..]), K); }
    #[test] fn geth_lightkdf() { assert_eq!(hex_enc(&open(VL, b"testpassword").unwrap()[..]), K); }
    #[test] fn scrypt_raw_matches_crate() {
        for (ln, r, p) in [(4u8, 1usize, 1usize), (10, 8, 2), (12, 2, 3)] {
            let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
            scrypt::scrypt(b"pw", b"salt", &scrypt::Params::new(ln, r as u32, p as u32, 32).unwrap(), &mut a).unwrap();
            scrypt_raw(b"pw", b"salt", 1 << ln, r, p, &mut b);
            assert_eq!(a, b);
        }
        // RFC 7914 section 12 vector 2 (N=1024, r=8, p=16).
        let mut o = [0u8; 64]; scrypt_raw(b"password", b"NaCl", 1024, 8, 16, &mut o);
        assert_eq!(hex_enc(&o[..8]), "fdbabe1c9d347200");
    }
    #[test] fn scrypt_bounds() {
        assert!(scrypt_ok(1 << 18, 8, 1) && scrypt_ok(4096, 8, 6) && scrypt_ok(1 << 18, 1, 8));
        assert!(!scrypt_ok(1 << 20, 8, 1)); // 1 GiB
        assert!(!scrypt_ok(1 << 18, 8, 16)); // work 2^25
        assert!(!scrypt_ok(3000, 8, 1) && !scrypt_ok(1 << 18, 0, 1) && !scrypt_ok(u64::MAX / 2 + 1, u64::MAX, 1));
        // Hostile memory request is refused before any allocation.
        let h = VL.replace(r#""n":4096,"r":8"#, r#""n":1048576,"r":64"#);
        assert_eq!(open(&h, b"x").unwrap_err(), "unsupported");
    }
    #[test] fn hostile_kdf() {
        let h = V.replace(r#""kdf":"pbkdf2""#, r#""kdf":"evil""#);
        assert_eq!(open(&h, b"x").unwrap_err(), "unsupported");
    }
}
