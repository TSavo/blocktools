//! Substrate/Polkadot public-data helpers: BLAKE2b, xxHash (twox), SS58 any-prefix encode/decode,
//! System.Account storage key, SCALE AccountInfo decode. Public inputs only.
use blocktools_core::blake2b::blake2b;

const P1: u64 = 0x9E3779B185EBCA87; const P2: u64 = 0xC2B2AE3D27D4EB4F; const P3: u64 = 0x165667B19E3779F9;
const P4: u64 = 0x85EBCA77C2B2AE63; const P5: u64 = 0x27D4EB2F165667C5;
fn rd64(b: &[u8]) -> u64 { u64::from_le_bytes(b[..8].try_into().unwrap()) }
fn round(a: u64, x: u64) -> u64 { a.wrapping_add(x.wrapping_mul(P2)).rotate_left(31).wrapping_mul(P1) }
fn merge(a: u64, v: u64) -> u64 { (a ^ round(0, v)).wrapping_mul(P1).wrapping_add(P4) }
/// xxHash64 (the reference algorithm).
pub fn xxh64(d: &[u8], seed: u64) -> u64 {
    let n = d.len(); let mut i = 0;
    let mut h = if n >= 32 {
        let mut v = [seed.wrapping_add(P1).wrapping_add(P2), seed.wrapping_add(P2), seed, seed.wrapping_sub(P1)];
        while i + 32 <= n { for k in 0..4 { v[k] = round(v[k], rd64(&d[i + 8 * k..])) } i += 32 }
        let mut h = v[0].rotate_left(1).wrapping_add(v[1].rotate_left(7)).wrapping_add(v[2].rotate_left(12)).wrapping_add(v[3].rotate_left(18));
        for x in v { h = merge(h, x) } h
    } else { seed.wrapping_add(P5) };
    h = h.wrapping_add(n as u64);
    while i + 8 <= n { h = (h ^ round(0, rd64(&d[i..]))).rotate_left(27).wrapping_mul(P1).wrapping_add(P4); i += 8 }
    if i + 4 <= n { h = (h ^ (u32::from_le_bytes(d[i..i + 4].try_into().unwrap()) as u64).wrapping_mul(P1)).rotate_left(23).wrapping_mul(P2).wrapping_add(P3); i += 4 }
    while i < n { h = (h ^ (d[i] as u64).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1); i += 1 }
    h ^= h >> 33; h = h.wrapping_mul(P2); h ^= h >> 29; h = h.wrapping_mul(P3); h ^ (h >> 32)
}
/// Substrate twox_128: xxh64 seed 0 || seed 1, little-endian.
pub fn twox128(d: &[u8]) -> [u8; 16] { let mut o = [0; 16]; o[..8].copy_from_slice(&xxh64(d, 0).to_le_bytes()); o[8..].copy_from_slice(&xxh64(d, 1).to_le_bytes()); o }
/// BLAKE2b, `out_len` 1..=64 bytes, optional 16-byte personalization (zero-padded if shorter).
pub fn blake2b_hash(data: &[u8], out_len: usize, personal: &[u8]) -> Result<Vec<u8>, &'static str> {
    if !(1..=64).contains(&out_len) { return Err("bad_out_len") }
    if personal.len() > 16 { return Err("bad_personal") }
    let mut p = [0u8; 16]; p[..personal.len()].copy_from_slice(personal);
    Ok(blake2b(out_len, &p, data))
}
fn prefix_bytes(ident: u16) -> Result<Vec<u8>, &'static str> {
    match ident { 0..=63 => Ok(vec![ident as u8]), 64..=16383 => Ok(vec![(((ident & 0xfc) >> 2) as u8) | 0x40, ((ident >> 8) as u8) | (((ident & 3) as u8) << 6)]), _ => Err("bad_prefix") }
}
/// SS58 address for a 32-byte account id (any prefix 0..16383; Polkadot 0, Kusama 2, generic 42).
pub fn ss58_encode(prefix: u16, account: &[u8; 32]) -> Result<String, &'static str> {
    let mut d = prefix_bytes(prefix)?; d.extend_from_slice(account);
    let mut pre = b"SS58PRE".to_vec(); pre.extend_from_slice(&d);
    d.extend_from_slice(&blake2b(64, &[0; 16], &pre)[..2]);
    Ok(bitcoin::base58::encode(&d))
}
/// SS58 address -> (prefix, account id). Checks the checksum by re-encoding.
pub fn ss58_decode(a: &str) -> Result<(u16, [u8; 32]), &'static str> {
    let d = bitcoin::base58::decode(a).map_err(|_| "bad_base58")?;
    let (prefix, pl) = match d.first() {
        Some(&b) if b < 64 => (b as u16, 1),
        Some(&b) if b < 128 && d.len() > 1 => { let (b0, b1) = (b as u16, d[1] as u16); ((((b0 & 0x3f) << 2) | (b1 >> 6)) | ((b1 & 0x3f) << 8), 2) }
        _ => return Err("bad_prefix"),
    };
    if d.len() != pl + 34 { return Err("bad_length") }
    let acc: [u8; 32] = d[pl..pl + 32].try_into().unwrap();
    if ss58_encode(prefix, &acc)? != a { return Err("bad_checksum") }
    Ok((prefix, acc))
}
/// System.Account storage key: twox128("System") || twox128("Account") || blake2_128(id) || id.
pub fn system_account_key(account: &[u8; 32]) -> Vec<u8> {
    let mut k = twox128(b"System").to_vec(); k.extend(twox128(b"Account"));
    k.extend(blake2b(16, &[0; 16], account)); k.extend_from_slice(account); k
}
/// SCALE AccountInfo (nonce, consumers, providers, sufficients: u32; free, reserved, frozen, flags: u128)
/// as JSON with u128 values as decimal strings. Accepts the 80-byte layout (current runtimes).
pub fn decode_account_info(b: &[u8]) -> Result<serde_json::Value, &'static str> {
    if b.len() != 80 { return Err("bad_length") }
    let u32_ = |i: usize| u32::from_le_bytes(b[i..i + 4].try_into().unwrap());
    let u128_ = |i: usize| u128::from_le_bytes(b[i..i + 16].try_into().unwrap()).to_string();
    Ok(serde_json::json!({"nonce": u32_(0), "consumers": u32_(4), "providers": u32_(8), "sufficients": u32_(12),
        "data": {"free": u128_(16), "reserved": u128_(32), "frozen": u128_(48), "flags": u128_(64)}}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use blocktools_core::{hex_dec, hex_enc};
    // Vectors: Python hashlib.blake2b, the `xxhash` package, scalecodec (py-scale-codec), and the
    // well-known Alice dev account (subkey).
    const ALICE: &str = "d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d";
    fn alice() -> [u8; 32] { hex_dec(ALICE).unwrap().try_into().unwrap() }
    #[test] fn blake2b_vectors() {
        assert_eq!(hex_enc(&blake2b_hash(b"abc", 64, b"").unwrap())[..32], *"ba80a53f981c4d0d6a2797b69f12f6e9");
        assert_eq!(hex_enc(blake2b_hash(b"", 32, b"").unwrap()), "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
        assert_eq!(hex_enc(blake2b_hash(b"abc", 32, b"ZcashSigHash").unwrap()), "63d3a98d9443ac4fbad669a9fd31cb2ec8db244e8d27878b19129da671f11ef4");
    }
    #[test] fn twox() {
        assert_eq!(hex_enc(twox128(b"System")), "26aa394eea5630e07c48ae0c9558cef7");
        assert_eq!(hex_enc(twox128(b"Account")), "b99d880ec681799c0cf30e8886371da9");
        assert_eq!(xxh64(b"", 0), 0xEF46DB3751D8E999);
        let long = [7u8; 77]; let _ = xxh64(&long, 3);
    }
    #[test] fn ss58_alice() {
        assert_eq!(ss58_encode(42, &alice()).unwrap(), "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY");
        assert_eq!(ss58_encode(0, &alice()).unwrap(), "15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5");
        assert_eq!(ss58_decode("15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp5").unwrap(), (0, alice()));
        let two = ss58_encode(1284, &alice()).unwrap(); assert_eq!(two, "VdvKmYJfD4VXA9fzz1SbmCo2eYHSzUFbaDCZSuaNKJAe8YNg6"); assert_eq!(ss58_decode(&two).unwrap(), (1284, alice()));
        assert_eq!(ss58_decode("15oF4uVJwmo4TdGW7VfQxNLavjCXviqxT9S1MgbjMNHr6Sp6"), Err("bad_checksum"));
    }
    #[test] fn storage_key_and_account_info() {
        assert_eq!(hex_enc(system_account_key(&alice())), "26aa394eea5630e07c48ae0c9558cef7b99d880ec681799c0cf30e8886371da9de1e86a9a8c739864cf3cc5ec2bea59fd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d");
        let b = hex_dec("07000000010000000100000000000000d20a1feb8ca954ab0000000000000000050000000000000000000000000000000010a5d4e8000000000000000000000000000000000000000000000000000080").unwrap();
        let v = decode_account_info(&b).unwrap();
        assert_eq!(v["nonce"], 7); assert_eq!(v["data"]["free"], "12345678901234567890"); assert_eq!(v["data"]["frozen"], "1000000000000");
        assert_eq!(v["data"]["flags"], "170141183460469231731687303715884105728");
    }
}
