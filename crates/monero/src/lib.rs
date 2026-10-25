//! Monero: 25-word (Electrum-style) seed, spend/view keys, standard address encode/validate.
//! Secret material lives in `Zeroizing` buffers and is never formatted by this crate.
#[cfg(feature = "keys")]
use curve25519_dalek::{edwards::{CompressedEdwardsY, EdwardsPoint}, scalar::Scalar};
use sha3::{Digest, Keccak256};
use zeroize::Zeroizing;

const WORDS: &str = include_str!("english.txt");
const PREFIX: usize = 3;

pub fn wordlist() -> Vec<&'static str> { WORDS.lines().collect() }

fn keccak(b: &[u8]) -> [u8; 32] { Keccak256::digest(b).into() }

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xffff_ffffu32;
    for &b in data { c ^= b as u32; for _ in 0..8 { c = if c & 1 != 0 { (c >> 1) ^ 0xedb8_8320 } else { c >> 1 }; } }
    !c
}

fn prefix(w: &str) -> String { w.chars().take(PREFIX).collect() }

/// True when `s` is shaped like a Monero 25-word English seed (24 + checksum, all words in the list).
pub fn is_seed_shape(s: &str) -> bool {
    let ws: Vec<&str> = s.split_whitespace().collect();
    let l = wordlist();
    ws.len() == 25 && ws.iter().all(|w| l.iter().any(|x| prefix(x) == prefix(w)))
}

/// Decode a 25-word seed into the 32-byte secret spend key (as stored; reduced mod l).
pub fn seed_to_spend(s: &str) -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let ws: Vec<String> = s.split_whitespace().map(|w| w.to_lowercase()).collect();
    if ws.len() != 25 { return Err("monero_seed_needs_25_words"); }
    let l = wordlist();
    let n = l.len() as u32;
    let idx = |w: &str| l.iter().position(|x| prefix(x) == prefix(w)).map(|i| i as u32);
    let mut out = Zeroizing::new([0u8; 32]);
    for i in 0..8 {
        let (a, b, c) = match (idx(&ws[3 * i]), idx(&ws[3 * i + 1]), idx(&ws[3 * i + 2])) {
            (Some(a), Some(b), Some(c)) => (a, b, c), _ => return Err("monero_word_not_in_list") };
        let v = a + n * ((n - a + b) % n) + n * n * ((n - b + c) % n);
        if v % n != a { return Err("monero_seed_invalid"); }
        out[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    let joined: String = ws[..24].iter().map(|w| prefix(w)).collect();
    let ck = &ws[(crc32(joined.as_bytes()) % 24) as usize];
    if prefix(ck) != prefix(&ws[24]) { return Err("monero_seed_checksum"); }
    Ok(out)
}

#[cfg(feature = "keys")]
pub struct Keys { pub spend_secret: Zeroizing<[u8; 32]>, pub view_secret: Zeroizing<[u8; 32]>, pub spend_public: [u8; 32], pub view_public: [u8; 32] }

#[cfg(feature = "keys")]
fn public(sk: &[u8; 32]) -> [u8; 32] { EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(*sk)).compress().to_bytes() }

#[cfg(feature = "keys")]
/// Deterministic wallet keys: spend = sc_reduce32(seed), view = sc_reduce32(keccak(spend)).
pub fn keys_from_spend(seed: &[u8; 32]) -> Keys {
    let s = Zeroizing::new(Scalar::from_bytes_mod_order(*seed).to_bytes());
    let v = Zeroizing::new(Scalar::from_bytes_mod_order(keccak(&s[..])).to_bytes());
    Keys { spend_public: public(&s), view_public: public(&v), spend_secret: s, view_secret: v }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Net { Main, Test, Stage }
impl Net { fn byte(self) -> u8 { match self { Net::Main => 18, Net::Test => 53, Net::Stage => 24 } }
           fn from_byte(b: u8) -> Option<Net> { match b { 18 => Some(Net::Main), 53 => Some(Net::Test), 24 => Some(Net::Stage), _ => None } } }

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ENC_LEN: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

fn b58enc(data: &[u8]) -> String {
    let mut s = String::new();
    for ch in data.chunks(8) {
        let mut n = ch.iter().fold(0u128, |a, &b| a * 256 + b as u128);
        let mut blk = vec![b'1'; ENC_LEN[ch.len()]];
        for c in blk.iter_mut().rev() { *c = B58[(n % 58) as usize]; n /= 58; }
        s.push_str(std::str::from_utf8(&blk).unwrap());
    }
    s
}

fn b58dec(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    for ch in b.chunks(11) {
        let len = ENC_LEN.iter().position(|&l| l == ch.len())?;
        let mut n = 0u128;
        for &c in ch { n = n * 58 + B58.iter().position(|&x| x == c)? as u128; }
        if len < 8 && n >> (8 * len) != 0 { return None; }
        if len == 8 && n > u64::MAX as u128 { return None; }
        for i in (0..len).rev() { out.push((n >> (8 * i)) as u8); }
    }
    Some(out)
}

/// Standard address: netbyte || spend_pub || view_pub || keccak[..4].
pub fn address(net: Net, spend_pub: &[u8; 32], view_pub: &[u8; 32]) -> String {
    let mut d = vec![net.byte()];
    d.extend_from_slice(spend_pub); d.extend_from_slice(view_pub);
    let h = keccak(&d); d.extend_from_slice(&h[..4]);
    b58enc(&d)
}

/// Validate a standard Monero address (with `keys`, both public keys must also decompress): returns (net, spend_pub, view_pub). Integrated/subaddresses are refused for now.
pub fn validate(a: &str) -> Result<(Net, [u8; 32], [u8; 32]), &'static str> {
    let d = b58dec(a).ok_or("monero_bad_base58")?;
    if d.len() != 69 { return Err("monero_unsupported_address_type"); }
    let net = Net::from_byte(d[0]).ok_or("monero_unsupported_address_type")?;
    if keccak(&d[..65])[..4] != d[65..] { return Err("monero_bad_checksum"); }
    let (mut s, mut v) = ([0u8; 32], [0u8; 32]);
    s.copy_from_slice(&d[1..33]); v.copy_from_slice(&d[33..65]);
#[cfg(feature = "keys")]
    for k in [&s, &v] { CompressedEdwardsY(*k).decompress().ok_or("monero_key_not_on_curve")?; }
    Ok((net, s, v))
}
