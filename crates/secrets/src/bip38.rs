//! BIP38 passphrase-protected private keys (bitcoin/bips bip-0038). Public domain spec.
//! Non-EC-multiplied decrypt only (6PR/6PY). Output is a 32-byte secret + compression flag.
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use aes::Aes256;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use scrypt::{scrypt, Params};
use zeroize::{Zeroize, Zeroizing};

/// Decrypt a BIP38 non-EC-multiplied encrypted key (`6PR...` / `6PY...`).
/// Returns (32-byte private key, compressed). Err on bad encoding, wrong passphrase, or EC-multiply form.
pub fn decrypt(encrypted: &str, passphrase: &str) -> Result<(Zeroizing<[u8; 32]>, bool), &'static str> {
    let raw = bitcoin::base58::decode_check(encrypted.trim()).map_err(|_| "bad_base58")?;
    if raw.len() != 39 { return Err("bad_length"); }
    if raw[0] != 0x01 || raw[1] != 0x42 { return Err(if raw[1] == 0x43 { "ec_multiply_unsupported" } else { "bad_prefix" }); }
    let flag = raw[2];
    if flag & 0xc0 != 0xc0 { return Err("bad_flag"); } // non-EC bits must be 11
    let compressed = flag & 0x20 != 0;
    let salt = &raw[3..7];
    let mut derived = Zeroizing::new([0u8; 64]);
    let params = Params::new(14, 8, 8).map_err(|_| "scrypt_params")?; // n=2^14=16384, r=8, p=8
    scrypt(passphrase.as_bytes(), salt, &params, &mut *derived).map_err(|_| "scrypt")?;
    let (dh1, dh2) = derived.split_at(32);
    let cipher = Aes256::new(GenericArray::from_slice(dh2));
    let mut b1 = GenericArray::clone_from_slice(&raw[7..23]);
    let mut b2 = GenericArray::clone_from_slice(&raw[23..39]);
    cipher.decrypt_block(&mut b1);
    cipher.decrypt_block(&mut b2);
    let mut key = Zeroizing::new([0u8; 32]);
    for i in 0..16 { key[i] = b1[i] ^ dh1[i]; key[16 + i] = b2[i] ^ dh1[16 + i]; }
    b1.zeroize(); b2.zeroize();
    let sk = SecretKey::from_slice(&key[..]).map_err(|_| "bad_key")?;
    let secp = Secp256k1::new();
    let pk = bitcoin::PublicKey { compressed, inner: sk.public_key(&secp) };
    let addr = bitcoin::Address::p2pkh(pk, bitcoin::Network::Bitcoin).to_string();
    let ah = sha256d::Hash::hash(addr.as_bytes());
    if &ah[..4] != salt { return Err("wrong_passphrase"); }
    Ok((key, compressed))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
    #[test]
    fn bip_vectors_uncompressed() {
        let (k, c) = decrypt("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg", "TestingOneTwoThree").unwrap();
        assert!(!c);
        assert_eq!(hex(&k[..]), "cbf4b9f70470856bb4f40f80b87edb90865997ffee6df315ab166d713af433a5");
        let (k, c) = decrypt("6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq", "Satoshi").unwrap();
        assert!(!c);
        assert_eq!(hex(&k[..]), "09c2686880095b1a4c249ee3ac4eea8a014f11e6f986d0b5025ac1f39afbd9ae");
        assert!(decrypt("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg", "wrong").is_err());
    }
    #[test]
    fn bip_vectors_compressed() {
        let (k, c) = decrypt("6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo", "TestingOneTwoThree").unwrap();
        assert!(c);
        assert_eq!(hex(&k[..]), "cbf4b9f70470856bb4f40f80b87edb90865997ffee6df315ab166d713af433a5");
        let (k, c) = decrypt("6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7", "Satoshi").unwrap();
        assert!(c);
        assert_eq!(hex(&k[..]), "09c2686880095b1a4c249ee3ac4eea8a014f11e6f986d0b5025ac1f39afbd9ae");
    }
}
