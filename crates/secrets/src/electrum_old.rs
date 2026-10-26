//! Electrum 1.x "old" scheme keys (non-BIP32): secexp = sha256 stretched 100,000x over the hex
//! seed text, mpk = uncompressed pubkey(secexp)[1..], key(change, n) = secexp + sha256d("n:change:" || mpk).
//! Addresses are uncompressed P2PKH on Bitcoin mainnet (the only chain Electrum 1.x served).
//! The word <-> hex arithmetic is public and lives in blocktools_core::electrum_old.
use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use zeroize::Zeroizing;

/// Master secret exponent and the 64-byte master public key for a hex seed (32 or 64 hex chars).
/// The SecretKey is a copy of the stretched bytes; the intermediate buffers are zeroized, the key is dropped by the caller.
pub fn master(seed_hex: &str) -> Result<(SecretKey, [u8; 64]), &'static str> {
    if (seed_hex.len() != 32 && seed_hex.len() != 64) || !seed_hex.bytes().all(|b| b.is_ascii_hexdigit()) { return Err("bad_seed") }
    let seed = Zeroizing::new(seed_hex.to_ascii_lowercase().into_bytes());
    let mut x = Zeroizing::new(seed.to_vec());
    for _ in 0..100_000 { let mut m = Zeroizing::new(x.to_vec()); m.extend_from_slice(&seed); *x = sha256::Hash::hash(&m).to_byte_array().to_vec(); }
    let sk = SecretKey::from_slice(&x).map_err(|_| "bad_seed")?;
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk).serialize_uncompressed();
    let mut mpk = [0u8; 64]; mpk.copy_from_slice(&pk[1..]);
    Ok((sk, mpk))
}
/// Key for branch `change` (0 receive, 1 change), index `n`.
pub fn key(master: &SecretKey, mpk: &[u8; 64], change: u32, n: u32) -> Result<SecretKey, &'static str> {
    let mut m = format!("{n}:{change}:").into_bytes(); m.extend_from_slice(mpk);
    let z = Scalar::from_be_bytes(sha256d::Hash::hash(&m).to_byte_array()).map_err(|_| "bad_tweak")?;
    master.add_tweak(&z).map_err(|_| "bad_tweak")
}
/// (WIF uncompressed, P2PKH address, "m/change/n") for change 0 and 1, index 0..count; checks mpk if given.
pub fn keys(seed_hex: &str, mpk_check: Option<&str>, count: u32) -> Result<Vec<(Zeroizing<String>, String, String)>, &'static str> {
    let (sk, mpk) = master(seed_hex)?;
    if let Some(m) = mpk_check { if !m.eq_ignore_ascii_case(&blocktools_core::hex_enc(mpk)) { return Err("wrong_password") } }
    let secp = Secp256k1::new();
    let mut out = vec![];
    for ch in 0..2u32 { for n in 0..count {
        let k = key(&sk, &mpk, ch, n)?;
        let pk = bitcoin::PrivateKey { compressed: false, network: bitcoin::NetworkKind::Main, inner: k };
        let addr = bitcoin::Address::p2pkh(pk.public_key(&secp), bitcoin::Network::Bitcoin).to_string();
        out.push((Zeroizing::new(pk.to_wif()), addr, format!("m/{ch}/{n}")));
    } }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Electrum's tests/test_wallet_vertical.py test_electrum_seed_old (public test vector):
    /// hex seed -> mpk, first receive and change addresses.
    #[test] fn electrum_old_vector() {
        let (_, mpk) = master("acb740e454c3134901d7c8f16497cc1c").unwrap();
        assert_eq!(blocktools_core::hex_enc(mpk), "e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3");
        let ks = keys("acb740e454c3134901d7c8f16497cc1c", None, 1).unwrap();
        assert_eq!((ks[0].1.as_str(), ks[0].2.as_str()), ("1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo", "m/0/0"));
        assert_eq!((ks[1].1.as_str(), ks[1].2.as_str()), ("1KRW8pH6HFHZh889VDq6fEKvmrsmApwNfe", "m/1/0"));
        assert_eq!(keys("acb740e454c3134901d7c8f16497cc1c", Some("00"), 1), Err("wrong_password"));
        assert_eq!(master("acb740e4").unwrap_err(), "bad_seed");
        assert_eq!(master("zcb740e454c3134901d7c8f16497cc1c").unwrap_err(), "bad_seed");
    }
}
