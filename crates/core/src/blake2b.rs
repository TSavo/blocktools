//! BLAKE2b (RFC 7693) with a 16-byte personalization, unkeyed, no salt. Only what Zcash's
//! ZIP-243/244 digests need. Checked against Python's hashlib.blake2b in tests/zcash.rs.
const IV: [u64; 8] = [0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179];
const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]];

fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() { *w = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap()) }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h); v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64; v[13] ^= (t >> 64) as u64;
    if last { v[14] = !v[14] }
    for s in SIGMA.iter().cycle().take(12) {
        let mut g = |a: usize, b: usize, c: usize, d: usize, x: u64, y: u64| {
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(x); v[d] = (v[d] ^ v[a]).rotate_right(32);
            v[c] = v[c].wrapping_add(v[d]); v[b] = (v[b] ^ v[c]).rotate_right(24);
            v[a] = v[a].wrapping_add(v[b]).wrapping_add(y); v[d] = (v[d] ^ v[a]).rotate_right(16);
            v[c] = v[c].wrapping_add(v[d]); v[b] = (v[b] ^ v[c]).rotate_right(63);
        };
        g(0, 4, 8, 12, m[s[0]], m[s[1]]); g(1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(2, 6, 10, 14, m[s[4]], m[s[5]]); g(3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(0, 5, 10, 15, m[s[8]], m[s[9]]); g(1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(2, 7, 8, 13, m[s[12]], m[s[13]]); g(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 { h[i] ^= v[i] ^ v[i + 8] }
}

/// BLAKE2b with output length `out_len` (1..=64) and personalization `personal`.
pub fn blake2b(out_len: usize, personal: &[u8; 16], data: &[u8]) -> Vec<u8> {
    assert!((1..=64).contains(&out_len));
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ out_len as u64;
    h[6] ^= u64::from_le_bytes(personal[..8].try_into().unwrap());
    h[7] ^= u64::from_le_bytes(personal[8..].try_into().unwrap());
    let n = data.len();
    let full = if n == 0 { 0 } else { (n - 1) / 128 };
    for k in 0..full { compress(&mut h, data[k * 128..k * 128 + 128].try_into().unwrap(), (k as u128 + 1) * 128, false) }
    let mut last = [0u8; 128];
    last[..n - full * 128].copy_from_slice(&data[full * 128..]);
    compress(&mut h, &last, n as u128, true);
    h.iter().flat_map(|w| w.to_le_bytes()).take(out_len).collect()
}
/// 32-byte BLAKE2b with personalization.
pub fn h256(personal: &[u8; 16], data: &[u8]) -> [u8; 32] { blake2b(32, personal, data).try_into().unwrap() }
