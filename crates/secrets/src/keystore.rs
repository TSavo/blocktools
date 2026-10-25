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
            // Bound attacker-chosen cost: n <= 2^20, r <= 16, p <= 4.
            if !n.is_power_of_two() || n > 1 << 20 || r == 0 || r > 16 || p == 0 || p > 4 { return Err("unsupported"); }
            let params = scrypt::Params::new(n.trailing_zeros() as u8, r, p, 32).map_err(|_| "unsupported")?;
            scrypt::scrypt(password, &salt, &params, &mut dk[..]).map_err(|_| "error")?;
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
    #[test] fn hostile_kdf() {
        let h = V.replace(r#""kdf":"pbkdf2""#, r#""kdf":"evil""#);
        assert_eq!(open(&h, b"x").unwrap_err(), "unsupported");
    }
}
