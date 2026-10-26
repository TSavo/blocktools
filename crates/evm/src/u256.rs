//! Minimal 256-bit big-endian integer helpers for ABI values (decimal <-> word, two's complement).
pub type Word = [u8; 32];

fn mul_add(w: &mut Word, m: u32, a: u32) -> bool {
    let mut carry = a as u64;
    for b in w.iter_mut().rev() {
        let v = *b as u64 * m as u64 + carry;
        *b = v as u8;
        carry = v >> 8;
    }
    carry == 0
}

/// Unsigned decimal or 0x-hex string -> word. Overflow refused.
pub fn parse_uint(s: &str) -> Result<Word, String> {
    let s = s.trim().replace('_', "");
    let mut w = [0u8; 32];
    if let Some(h) = s.strip_prefix("0x") {
        if h.is_empty() || h.len() > 64 { return Err("bad_uint".into()); }
        let p = format!("{}{h}", if h.len() % 2 == 1 { "0" } else { "" });
        let b = crate::unhex(&p).map_err(|_| "bad_uint")?;
        w[32 - b.len()..].copy_from_slice(&b);
        return Ok(w);
    }
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) { return Err("bad_uint".into()); }
    for c in s.bytes() {
        if !mul_add(&mut w, 10, (c - b'0') as u32) { return Err("uint_overflow".into()); }
    }
    Ok(w)
}

pub fn to_dec(w: &Word) -> String {
    let mut w = *w;
    let mut digits = vec![];
    loop {
        let mut rem = 0u32;
        for b in w.iter_mut() {
            let v = (rem << 8) | *b as u32;
            *b = (v / 10) as u8;
            rem = v % 10;
        }
        digits.push(b'0' + rem as u8);
        if w.iter().all(|&b| b == 0) { break; }
    }
    digits.reverse();
    String::from_utf8(digits).unwrap()
}

pub fn neg(w: &Word) -> Word {
    let mut r = [0u8; 32];
    let mut carry = 1u16;
    for i in (0..32).rev() {
        let v = (!w[i]) as u16 + carry;
        r[i] = v as u8;
        carry = v >> 8;
    }
    r
}

/// Bit length of an unsigned word.
pub fn bits(w: &Word) -> usize {
    for (i, b) in w.iter().enumerate() {
        if *b != 0 { return (32 - i) * 8 - b.leading_zeros() as usize; }
    }
    0
}

/// Signed decimal (optional leading '-') or 0x-hex (non-negative) -> two's complement word.
pub fn parse_int(s: &str, m: usize) -> Result<Word, String> {
    let s = s.trim();
    let (negative, mag) = match s.strip_prefix('-') { Some(r) => (true, r), None => (false, s) };
    let w = parse_uint(mag)?;
    let b = bits(&w);
    // range: -2^(m-1) .. 2^(m-1)-1
    let ok = if negative { b < m || (b == m && w.iter().rev().skip_while(|&&x| x == 0).count() > 0 && is_pow2(&w)) } else { b < m };
    if !ok { return Err("int_out_of_range".into()); }
    Ok(if negative { neg(&w) } else { w })
}

fn is_pow2(w: &Word) -> bool {
    w.iter().map(|b| b.count_ones()).sum::<u32>() == 1
}

pub fn int_to_dec(w: &Word) -> String {
    if w[0] & 0x80 != 0 { format!("-{}", to_dec(&neg(w))) } else { to_dec(w) }
}
