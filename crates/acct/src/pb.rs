//! Minimal protobuf writer/reader (varint + length-delimited only) for the Cosmos and Cardano-free paths.
pub fn varint(o: &mut Vec<u8>, mut v: u64) { while v >= 0x80 { o.push(v as u8 | 0x80); v >>= 7 } o.push(v as u8) }
pub fn bytes(o: &mut Vec<u8>, field: u32, b: &[u8]) { varint(o, (field as u64) << 3 | 2); varint(o, b.len() as u64); o.extend_from_slice(b) }
pub fn uint(o: &mut Vec<u8>, field: u32, v: u64) { if v != 0 { varint(o, (field as u64) << 3); varint(o, v) } }
pub enum Val<'a> { U(u64), B(&'a [u8]) }
/// All (field, value) pairs of one message, in order. Refuses wire types other than 0 and 2.
pub fn fields(b: &[u8]) -> Result<Vec<(u32, Val<'_>)>, String> {
    let mut i = 0; let mut out = vec![];
    let rv = |i: &mut usize| -> Result<u64, String> { let mut v = 0u64; for s in 0..10 { let c = *b.get(*i).ok_or("truncated varint")?; *i += 1; v |= ((c & 0x7f) as u64) << (7 * s); if c < 0x80 { return Ok(v) } } Err("varint too long".into()) };
    while i < b.len() {
        let k = rv(&mut i)?; let f = (k >> 3) as u32;
        match k & 7 { 0 => out.push((f, Val::U(rv(&mut i)?))), 2 => { let n = rv(&mut i)? as usize; let s = b.get(i..i + n).ok_or("truncated bytes")?; i += n; out.push((f, Val::B(s))) } w => return Err(format!("unsupported wire type {w}")) }
    }
    Ok(out)
}
pub fn one<'a>(f: &[(u32, Val<'a>)], n: u32) -> Option<&'a [u8]> { f.iter().find_map(|(k, v)| match v { Val::B(b) if *k == n => Some(*b), _ => None }) }
pub fn num(f: &[(u32, Val<'_>)], n: u32) -> u64 { f.iter().find_map(|(k, v)| match v { Val::U(x) if *k == n => Some(*x), _ => None }).unwrap_or(0) }
pub fn count(f: &[(u32, Val<'_>)], n: u32) -> usize { f.iter().filter(|(k, _)| *k == n).count() }
