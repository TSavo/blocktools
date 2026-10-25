//! Account-model payment builders: encode an unsigned transfer, decode it back, sign it.
//! Each chain module is checked against vectors from that chain's own SDK (tests/kat.rs).
pub mod xlm;
pub mod algo;
pub mod atom;
pub mod ton;
pub mod ada;
pub mod dot;
pub mod pb;

pub fn ed_sign(seed: &[u8; 32], msg: &[u8]) -> ([u8; 32], [u8; 64]) {
    use ed25519_dalek::Signer;
    let k = ed25519_dalek::SigningKey::from_bytes(seed);
    (k.verifying_key().to_bytes(), k.sign(msg).to_bytes())
}
pub fn ed_verify(pk: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    ed25519_dalek::VerifyingKey::from_bytes(pk).map(|k| k.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig)).is_ok()).unwrap_or(false)
}
/// Fixed-point amount as a decimal string ("12.5000000" style trimmed to "12.5").
pub fn fmt_units(v: u128, dec: u32) -> String {
    let p = 10u128.pow(dec);
    let f = format!("{:0w$}", v % p, w = dec as usize);
    let f = f.trim_end_matches('0');
    if f.is_empty() { format!("{}", v / p) } else { format!("{}.{f}", v / p) }
}
