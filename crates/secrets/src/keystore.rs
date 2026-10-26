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
            // RustCrypto scrypt >= 0.12 (no RFC 7914 N < 2^(16r) erratum check), so geth and the
            // Web3 spec vector (N=2^18, r=1) go through the audited crate; our bounds are scrypt_ok.
            let params = scrypt::Params::new(n.trailing_zeros() as u8, r, p).map_err(|_| "unsupported")?;
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

/// Ethereum presale wallet (pyethsaletool, 2014): {"encseed","ethaddr",...}. Same algorithm as geth
/// accounts/keystore/presale.go: key = PBKDF2-HMAC-SHA256(pw, salt = pw, 2000, 16); encseed = iv(16) ||
/// AES-128-CBC(seed), PKCS#7; private key = keccak256(seed); its address must equal ethaddr (otherwise
/// wrong_password: no MAC in the format, the address is the check).
pub fn open_presale(json: &str, password: &[u8]) -> Result<(String, Zeroizing<String>), &'static str> {
    use aes::cipher::{BlockDecryptMut, block_padding::Pkcs7};
    let v: Value = serde_json::from_str(json).map_err(|_| "bad_input")?;
    let enc = v.get("encseed").and_then(|x| x.as_str()).ok_or("bad_input")?;
    if enc.len() > 1024 { return Err("bad_input"); }
    let enc = hex_dec(enc).ok_or("bad_input")?;
    let want = v.get("ethaddr").and_then(|x| x.as_str()).ok_or("bad_input")?.trim_start_matches("0x").to_ascii_lowercase();
    if want.len() != 40 || hex_dec(&want).is_none() { return Err("bad_input"); }
    if enc.len() < 32 || enc.len() % 16 != 0 { return Err("bad_input"); }
    let mut dk = Zeroizing::new([0u8; 16]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, password, 2000, &mut dk[..]);
    let mut buf = Zeroizing::new(enc[16..].to_vec());
    let seed = cbc::Decryptor::<aes::Aes128>::new(dk[..].into(), enc[..16].into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf[..]).map_err(|_| "wrong_password")?;
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&Keccak256::digest(&*seed));
    let addr = eth_address(&key)?;
    if addr[2..].to_ascii_lowercase() != want { return Err("wrong_password"); }
    Ok((addr, Zeroizing::new(hex_enc(&key[..]))))
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
    // go-ethereum accounts/keystore/plain_test.go TestImportPreSaleKey (pyethsaletool genwallet, password "foo"); email field replaced (unused by the algorithm).
    const PRESALE: &str = r#"{"encseed": "26d87f5f2bf9835f9a47eefae571bc09f9107bb13d54ff12a4ec095d01f83897494cf34f7bed2ed34126ecba9db7b62de56c9d7cd136520a0427bfb11b8954ba7ac39b90d4650d3448e31185affcd74226a68f1e94b1108e6e0a4a91cdd83eba", "ethaddr": "d4584b5f6229b7be90727b0fc8c6b91bb427821f", "email": "redacted@example.invalid", "btcaddr": "1EVknXyFC68kKNLkh6YnKzW41svSRoaAcx"}"#;
    #[test] fn presale_geth_vector() {
        let (a, _k) = open_presale(PRESALE, b"foo").unwrap();
        assert_eq!(a.to_ascii_lowercase(), "0xd4584b5f6229b7be90727b0fc8c6b91bb427821f");
        assert_eq!(open_presale(PRESALE, b"wrong").unwrap_err(), "wrong_password");
        assert_eq!(open_presale(&PRESALE.replace("d4584b5f", "d4584b5e"), b"foo").unwrap_err(), "wrong_password");
        assert_eq!(open_presale(r#"{"encseed":"00","ethaddr":"d4584b5f6229b7be90727b0fc8c6b91bb427821f"}"#, b"foo").unwrap_err(), "bad_input");
    }
    // Independent vector: pycryptodome + pure-Python secp256k1 (see recipes/input-keystore.md), UTF-8 password.
    #[test] fn presale_python_vector() {
        let j = r#"{"encseed": "000102030405060708090a0b0c0d0e0fde0eef35a53455395542b1afa0b2c2977320c21483f5f3ea7beae6018c2f0fd79af2e8cc819d0d263c4fc6a21c99b27c", "ethaddr": "db3f1aab7a6c6b14cf2ba4ae43c14444cf008bd0", "email": "test@example.invalid", "btcaddr": ""}"#;
        let (a, k) = open_presale(j, "pässwörd presale".as_bytes()).unwrap();
        assert_eq!(a.to_ascii_lowercase(), "0xdb3f1aab7a6c6b14cf2ba4ae43c14444cf008bd0");
        assert_eq!(k.as_str(), "8f0f1e46c96b6f8b176b3dae1e9b654c1f28c8ad57c820c5577e94241ea5f638");
    }
    #[test] fn wrong_pw() { assert_eq!(open(V, b"nope").unwrap_err(), "wrong_password"); }
    // Web3 Secret Storage Definition scrypt vector (N=262144, r=1, p=8): p=8 must be accepted.
    const VS: &str = r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"83dbcc02d8ccb40e466191a123791e0e"},"ciphertext":"d172bf743a674da9cdad04534d56926ef8358534d458fffccd4e6ad2fbde479c","kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"r":1,"p":8,"salt":"ab0c7876052600dd703518d6fc3fe8984592145b591fc8fb5c6d43190334ba19"},"mac":"2103ac29920d71da29f15d75b4a16dbe95cfd7ff8faea1056c33131d846e3097"},"id":"3198bc9c-6672-5ab3-d995-4942343ae5b6","version":3}"#;
    // geth --lightkdf parameters (N=4096, r=8, p=6), same public spec key/password; built with Python hashlib.scrypt.
    const VL: &str = r#"{"crypto":{"cipher":"aes-128-ctr","cipherparams":{"iv":"22222222222222222222222222222222"},"ciphertext":"c82312528902fd0681481c15cfd8f8ebc26cf29c5c675d9d8946bed1662dc686","kdf":"scrypt","kdfparams":{"dklen":32,"n":4096,"r":8,"p":6,"salt":"1111111111111111111111111111111111111111111111111111111111111111"},"mac":"d5dde1edbd54a2c562a038bffee74b15c35ff88a258408182170dcfd21d21778"},"version":3}"#;
    const K: &str = "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d";
    #[test] fn spec_scrypt_p8() { assert_eq!(hex_enc(&open(VS, b"testpassword").unwrap()[..]), K); }
    #[test] fn geth_lightkdf() { assert_eq!(hex_enc(&open(VL, b"testpassword").unwrap()[..]), K); }
    #[test] fn scrypt_crate_rfc7914() {
        // RFC 7914 section 12 vector 2 (N=1024, r=8, p=16) through the crate we depend on.
        let mut o = [0u8; 64];
        scrypt::scrypt(b"password", b"NaCl", &scrypt::Params::new(10, 8, 16).unwrap(), &mut o).unwrap();
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
