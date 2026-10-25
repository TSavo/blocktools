//! Standard base64 / base64url (encoding only, not cryptography). Bounded by caller.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    let val = |c: u8| -> Option<u32> { Some(match c {
        b'A'..=b'Z' => c - b'A', b'a'..=b'z' => c - b'a' + 26, b'0'..=b'9' => c - b'0' + 52,
        b'+' | b'-' => 62, b'/' | b'_' => 63, _ => return None } as u32) };
    if s.len() % 4 == 1 { return None }
    let (mut acc, mut bits, mut out) = (0u32, 0, Vec::with_capacity(s.len() * 3 / 4));
    for c in s.bytes() { acc = ((acc << 6) | val(c)?) & 0xffff; bits += 6; if bits >= 8 { bits -= 8; out.push((acc >> bits) as u8); } }
    Some(out)
}
pub fn encode(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut o = String::with_capacity(b.len().div_ceil(3) * 4);
    for ch in b.chunks(3) {
        let n = (ch[0] as u32) << 16 | (*ch.get(1).unwrap_or(&0) as u32) << 8 | *ch.get(2).unwrap_or(&0) as u32;
        for i in 0..4 { o.push(if i <= ch.len() { A[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' }) }
    }
    o
}
#[cfg(test)]
mod tests {
    #[test] fn rfc4648() {
        for (p, e) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(super::encode(p.as_bytes()), e); assert_eq!(super::decode(e).unwrap(), p.as_bytes());
        }
        assert!(super::decode("Zm9v!").is_none());
    }
}
