//! Minimal, bounded, read-only SQLite reader: enough to list (key, value) rows of
//! Bitcoin Core's `main` table. No SQL, no libsqlite. Hostile input: every offset
//! is checked, pages are visited at most once, depth and row counts are capped.
pub type Kv = (Vec<u8>, Vec<u8>);
const MAX_ROWS: usize = 2_000_000;

struct Db<'a> { b: &'a [u8], ps: usize, usable: usize }

fn varint(b: &[u8], mut i: usize) -> Option<(u64, usize)> {
    let mut v = 0u64;
    for n in 0..9 {
        let c = *b.get(i)?; i += 1;
        if n == 8 { return Some(((v << 8) | c as u64, i)); }
        v = (v << 7) | (c & 0x7f) as u64;
        if c & 0x80 == 0 { return Some((v, i)); }
    }
    None
}
fn be(b: &[u8], i: usize, n: usize) -> Option<u64> {
    Some(b.get(i..i + n)?.iter().fold(0u64, |a, x| (a << 8) | *x as u64))
}

impl<'a> Db<'a> {
    fn page(&self, n: u64) -> Option<&'a [u8]> {
        if n == 0 { return None; }
        let s = (n as usize - 1).checked_mul(self.ps)?;
        self.b.get(s..s + self.ps)
    }
    /// Full payload of a cell whose local part starts at `i` (after the header varints).
    fn payload(&self, pg: &[u8], i: usize, plen: usize) -> Option<Vec<u8>> {
        if plen > 64 << 20 { return None; }
        let u = self.usable;
        let x = u - 35;
        let local = if plen <= x { plen } else {
            let m = ((u - 12) * 32 / 255) - 23;
            let k = m + ((plen - m) % (u - 4));
            if k <= x { k } else { m }
        };
        let mut out = pg.get(i..i + local)?.to_vec();
        if local < plen {
            let mut next = be(pg, i + local, 4)?;
            let mut hops = 0;
            while out.len() < plen {
                hops += 1; if hops > 100_000 { return None; }
                let p = self.page(next)?;
                next = be(p, 0, 4)?;
                let take = (plen - out.len()).min(u - 4);
                out.extend_from_slice(p.get(4..4 + take)?);
            }
        }
        Some(out)
    }
    fn walk(&self, n: u64, depth: u32, seen: &mut Vec<bool>, out: &mut Vec<Vec<u8>>) -> Option<()> {
        if depth > 32 || out.len() > MAX_ROWS { return None; }
        let idx = n as usize;
        if *seen.get(idx)? { return None; }
        seen[idx] = true;
        let pg = self.page(n)?;
        let h = if n == 1 { 100 } else { 0 };
        let t = *pg.get(h)?;
        let cells = be(pg, h + 3, 2)? as usize;
        let hdr = if t == 5 || t == 2 { 12 } else { 8 };
        for c in 0..cells {
            let off = be(pg, h + hdr + 2 * c, 2)? as usize;
            match t {
                13 => {
                    let (plen, i) = varint(pg, off)?;
                    let (_rowid, i) = varint(pg, i)?;
                    out.push(self.payload(pg, i, plen as usize)?);
                }
                5 => { let child = be(pg, off, 4)?; self.walk(child, depth + 1, seen, out)?; }
                _ => return None,
            }
        }
        if t == 5 { self.walk(be(pg, h + 8, 4)?, depth + 1, seen, out)?; }
        Some(())
    }
}

/// Decode a record into columns (only blobs/text/ints are needed).
fn record(p: &[u8]) -> Option<Vec<Vec<u8>>> {
    let (hl, mut i) = varint(p, 0)?;
    let mut body = hl as usize;
    let mut cols = Vec::new();
    while i < hl as usize {
        let (st, j) = varint(p, i)?; i = j;
        let n = match st { 0 | 8 | 9 => 0, 1 => 1, 2 => 2, 3 => 3, 4 => 4, 5 => 6, 6 | 7 => 8,
            s if s >= 12 => ((s - 12) / 2) as usize, _ => return None };
        let v = p.get(body..body + n)?.to_vec();
        body += n;
        cols.push(if st == 8 { vec![0] } else if st == 9 { vec![1] } else { v });
        if cols.len() > 64 { return None; }
    }
    Some(cols)
}

pub fn read(b: &[u8]) -> Option<Vec<Kv>> {
    if !b.starts_with(b"SQLite format 3\0") { return None; }
    let ps = match be(b, 16, 2)? { 1 => 65536, n => n as usize };
    if ps < 512 || !ps.is_power_of_two() { return None; }
    let usable = ps - *b.get(20)? as usize;
    if usable < 480 { return None; }
    let db = Db { b, ps, usable };
    let npages = b.len() / ps + 1;
    let mut seen = vec![false; npages + 1];
    let mut schema = Vec::new();
    db.walk(1, 0, &mut seen, &mut schema)?;
    let root = schema.iter().filter_map(|r| record(r)).find(|c| c.len() >= 5 && c[0] == b"table" && c[1] == b"main")
        .map(|c| c[3].iter().fold(0u64, |a, x| (a << 8) | *x as u64))?;
    let mut rows = Vec::new();
    db.walk(root, 0, &mut seen, &mut rows)?;
    Some(rows.iter().filter_map(|r| record(r)).filter(|c| c.len() == 2).map(|mut c| { let v = c.pop().unwrap(); (c.pop().unwrap(), v) }).collect())
}
