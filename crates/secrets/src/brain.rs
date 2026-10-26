//! Brainwallets (pre-BIP39 "turn a phrase into a key"):
//! * `sha256`: key = SHA-256(UTF-8 phrase), as brainwallet.org and bitaddress.org's Brain Wallet tab did
//!   (2011-2015). The phrase is used byte-for-byte: no trimming, no case folding.
//! * `warpwallet` (keybase, 2014): s1 = scrypt(phrase||0x01, salt||0x01, N=2^18, r=8, p=1, 32 bytes),
//!   s2 = PBKDF2-HMAC-SHA256(phrase||0x02, salt||0x02, 65536, 32 bytes), key = s1 XOR s2. The salt is
//!   the e-mail address (may be empty). scrypt needs 256 MiB and a few seconds per phrase.
//! Neither scheme has a checksum: every phrase yields a key, so a wrong phrase yields a wrong (empty) address.
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub const SCHEMES: &[&str] = &["sha256", "warpwallet"];

pub fn sha256_key(phrase: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(phrase).into())
}

/// WarpWallet key. Err only if the scrypt parameters are rejected by the crate (they are constants).
pub fn warpwallet_key(phrase: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut p1 = Zeroizing::new(phrase.to_vec()); p1.push(1);
    let mut s1 = salt.to_vec(); s1.push(1);
    let mut p2 = Zeroizing::new(phrase.to_vec()); p2.push(2);
    let mut s2 = salt.to_vec(); s2.push(2);
    let params = scrypt::Params::new(18, 8, 1).map_err(|_| "error")?;
    let mut a = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(&p1, &s1, &params, &mut a[..]).map_err(|_| "error")?;
    let mut b = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(&p2, &s2, 65536, &mut b[..]);
    for (x, y) in a.iter_mut().zip(b.iter()) { *x ^= y }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(b: &[u8]) -> String { b.iter().map(|b| format!("{b:02x}")).collect() }
    /// The brainwallet.org vector everyone knows (xkcd 936 phrase; public test vector, long since drained).
    #[test] fn correct_horse() {
        assert_eq!(hex(&sha256_key(b"correct horse battery staple")[..]), "c4bbcb1fbec99d65bf59d85c8cb62ee2db963f0fe106f483d9afa73bd4e39a8a");
        assert_ne!(hex(&sha256_key(b"correct horse battery staple ")[..]), hex(&sha256_key(b"correct horse battery staple")[..]));
    }
    /// keybase/warpwallet test/spec.json vectors 1 and 2 (public test vectors): scrypt half, pbkdf2 half, xor.
    #[test] fn warpwallet_spec_vectors() {
        let k = warpwallet_key(b"ER8FT+HFjk0", b"7DpniYifN6c").unwrap();
        assert_eq!(hex(&k[..]), "6f2552e159f2a1e1e26c2262da459818fd56c81c363fcc70b94c423def42e59f");
        let k = warpwallet_key(b"YqIDBApDYME", b"G34HqIgjrIc").unwrap();
        assert_eq!(hex(&k[..]), "da009602a5781a8795d55c6e68a4b4d52969a75955ea70255869dd17c3398592");
    }
}
