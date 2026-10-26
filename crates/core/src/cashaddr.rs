//! CashAddr codec (bitcoincashorg spec/cashaddr.md). Public spec only.
const CS: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
fn polymod(v: &[u8]) -> u64 {
    let mut c: u64 = 1;
    for &d in v { let c0 = (c >> 35) as u8; c = ((c & 0x07_ffff_ffff) << 5) ^ d as u64;
        for (i, g) in [0x98f2bc8e61u64, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470].iter().enumerate() { if c0 >> i & 1 == 1 { c ^= g } } }
    c ^ 1
}
fn conv(d: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let (mut acc, mut bits, mut o) = (0u32, 0u32, vec![]); let max = (1 << to) - 1;
    for &v in d { if (v as u32) >> from != 0 { return None } acc = (acc << from) | v as u32; bits += from; while bits >= to { bits -= to; o.push(((acc >> bits) & max) as u8) } }
    if pad { if bits > 0 { o.push(((acc << (to - bits)) & max) as u8) } } else if bits >= from || (acc << (to - bits)) & max != 0 { return None }
    Some(o)
}
fn pre5(p: &str) -> Vec<u8> { let mut v: Vec<u8> = p.bytes().map(|b| b & 0x1f).collect(); v.push(0); v }
const SIZES: [usize; 8] = [20, 24, 28, 32, 40, 48, 56, 64];
/// Encode. `kind`: 0 = P2PKH, 1 = P2SH (spec type bits). Hash length must be one of the spec sizes.
pub fn encode(prefix: &str, kind: u8, hash: &[u8]) -> Result<String, &'static str> {
    if kind > 15 { return Err("bad_type") }
    let sz = SIZES.iter().position(|&s| s == hash.len()).ok_or("bad_hash_length")? as u8;
    let mut payload = vec![(kind << 3) | sz]; payload.extend_from_slice(hash);
    let mut d = conv(&payload, 8, 5, true).unwrap();
    let mut m = pre5(prefix); m.extend(&d); m.extend([0u8; 8]);
    let pm = polymod(&m); for i in 0..8 { d.push(((pm >> (5 * (7 - i))) & 31) as u8) }
    Ok(format!("{prefix}:{}", d.iter().map(|&x| CS[x as usize] as char).collect::<String>()))
}
/// Decode "prefix:payload" (or bare payload with `default_prefix`). Returns (prefix, type, hash).
pub fn decode(addr: &str, default_prefix: &str) -> Result<(String, u8, Vec<u8>), &'static str> {
    if addr.bytes().any(|b| b.is_ascii_lowercase()) && addr.bytes().any(|b| b.is_ascii_uppercase()) { return Err("mixed_case") }
    let a = addr.to_ascii_lowercase();
    let (p, body) = match a.split_once(':') { Some((p, b)) => (p.to_string(), b.to_string()), None => (default_prefix.to_string(), a.clone()) };
    let d: Vec<u8> = body.bytes().map(|c| CS.iter().position(|&x| x == c).map(|i| i as u8)).collect::<Option<_>>().ok_or("bad_char")?;
    if d.len() < 9 { return Err("too_short") }
    let mut m = pre5(&p); m.extend(&d); if polymod(&m) != 0 { return Err("bad_checksum") }
    let payload = conv(&d[..d.len() - 8], 5, 8, false).ok_or("bad_padding")?;
    let (v, h) = payload.split_first().ok_or("too_short")?;
    if v & 0x80 != 0 { return Err("bad_version") }
    if SIZES[(v & 7) as usize] != h.len() { return Err("bad_hash_length") }
    Ok((p, (v >> 3) & 15, h.to_vec()))
}
