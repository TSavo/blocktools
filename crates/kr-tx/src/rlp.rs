//! Minimal bounded RLP (Ethereum's serialization format; encoding only, not cryptography).
#[derive(Debug, Clone, PartialEq)]
pub enum Rlp { B(Vec<u8>), L(Vec<Rlp>) }
const MAX_DEPTH: usize = 4;
const MAX_ITEMS: usize = 4096;

pub fn decode(b: &[u8]) -> Result<Rlp, &'static str> {
    let mut items = 0;
    let (r, used) = item(b, 0, &mut items)?;
    if used != b.len() { return Err("trailing_bytes") }
    Ok(r)
}
fn be_len(b: &[u8]) -> Result<usize, &'static str> {
    if b.is_empty() || b.len() > 4 || b[0] == 0 { return Err("bad_length") }
    Ok(b.iter().fold(0usize, |a, &x| a << 8 | x as usize))
}
fn item(b: &[u8], depth: usize, items: &mut usize) -> Result<(Rlp, usize), &'static str> {
    *items += 1;
    if depth > MAX_DEPTH || *items > MAX_ITEMS { return Err("too_deep") }
    let p = *b.first().ok_or("truncated")?;
    let (list, hdr, len) = match p {
        0x00..=0x7f => return Ok((Rlp::B(vec![p]), 1)),
        0x80..=0xb7 => (false, 1, (p - 0x80) as usize),
        0xb8..=0xbf => { let n = (p - 0xb7) as usize; (false, 1 + n, be_len(b.get(1..1 + n).ok_or("truncated")?)?) }
        0xc0..=0xf7 => (true, 1, (p - 0xc0) as usize),
        _ => { let n = (p - 0xf7) as usize; (true, 1 + n, be_len(b.get(1..1 + n).ok_or("truncated")?)?) }
    };
    let body = b.get(hdr..hdr.checked_add(len).ok_or("bad_length")?).ok_or("truncated")?;
    if !list {
        if len == 1 && hdr == 1 && body[0] < 0x80 { return Err("non_canonical") }
        return Ok((Rlp::B(body.to_vec()), hdr + len));
    }
    let (mut v, mut i) = (Vec::new(), 0);
    while i < body.len() { let (x, u) = item(&body[i..], depth + 1, items)?; v.push(x); i += u; }
    Ok((Rlp::L(v), hdr + len))
}
fn hdr(out: &mut Vec<u8>, short: u8, len: usize) {
    if len <= 55 { out.push(short + len as u8) } else {
        let lb: Vec<u8> = (len as u64).to_be_bytes().into_iter().skip_while(|&x| x == 0).collect();
        out.push(short + 55 + lb.len() as u8); out.extend(lb);
    }
}
pub fn encode(r: &Rlp) -> Vec<u8> {
    let mut o = Vec::new();
    match r {
        Rlp::B(b) if b.len() == 1 && b[0] < 0x80 => o.push(b[0]),
        Rlp::B(b) => { hdr(&mut o, 0x80, b.len()); o.extend(b) }
        Rlp::L(v) => { let body: Vec<u8> = v.iter().flat_map(encode).collect(); hdr(&mut o, 0xc0, body.len()); o.extend(body) }
    }
    o
}
/// Big-endian minimal integer bytes.
pub fn uint(n: u128) -> Rlp { Rlp::B(n.to_be_bytes().into_iter().skip_while(|&x| x == 0).collect()) }

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn ethereum_wiki_vectors() {
        // From the Ethereum RLP spec examples.
        assert_eq!(encode(&Rlp::B(b"dog".to_vec())), b"\x83dog");
        let cd = Rlp::L(vec![Rlp::B(b"cat".to_vec()), Rlp::B(b"dog".to_vec())]);
        assert_eq!(encode(&cd), b"\xc8\x83cat\x83dog");
        assert_eq!(encode(&Rlp::B(vec![])), [0x80]);
        assert_eq!(encode(&Rlp::L(vec![])), [0xc0]);
        assert_eq!(encode(&uint(0)), [0x80]);
        assert_eq!(encode(&uint(15)), [0x0f]);
        assert_eq!(encode(&uint(1024)), [0x82, 0x04, 0x00]);
        let lorem = b"Lorem ipsum dolor sit amet, consectetur adipisicing elit".to_vec();
        let e = encode(&Rlp::B(lorem.clone()));
        assert_eq!(&e[..2], &[0xb8, 0x38]);
        assert_eq!(decode(&e).unwrap(), Rlp::B(lorem));
        assert_eq!(decode(b"\xc8\x83cat\x83dog").unwrap(), cd);
        assert!(decode(&[0x81, 0x05]).is_err()); // non-canonical
        assert!(decode(&[0xc5, 0x83]).is_err()); // truncated
        assert!(decode(&[0xb9, 0xff, 0xff]).is_err());
    }
}
