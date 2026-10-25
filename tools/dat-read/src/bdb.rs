//! Minimal, bounded, read-only Berkeley DB btree reader for legacy wallet.dat.
//! It does not walk the tree: it scans every btree leaf page (type 5) and reads
//! its key/data item pairs, following overflow chains (type 7). That covers the
//! `main` sub-database; the sub-database directory entries are simply not
//! wallet records and get ignored by the caller. No libdb.
pub type Kv = (Vec<u8>, Vec<u8>);

struct Db<'a> { b: &'a [u8], ps: usize, le: bool }
impl<'a> Db<'a> {
    fn u(&self, p: &[u8], i: usize, n: usize) -> Option<u64> {
        let s = p.get(i..i + n)?;
        Some(if self.le { s.iter().rev().fold(0, |a, x| (a << 8) | *x as u64) } else { s.iter().fold(0, |a, x| (a << 8) | *x as u64) })
    }
    fn page(&self, n: u64) -> Option<&'a [u8]> { let s = (n as usize).checked_mul(self.ps)?; self.b.get(s..s + self.ps) }
    fn item(&self, p: &[u8], off: usize) -> Option<Vec<u8>> {
        let ty = *p.get(off + 2)? & 0x7f;
        match ty {
            1 => { let len = self.u(p, off, 2)? as usize; Some(p.get(off + 3..off + 3 + len)?.to_vec()) }
            3 => {
                let mut pg = self.u(p, off + 4, 4)?;
                let tlen = self.u(p, off + 8, 4)? as usize;
                if tlen > 64 << 20 { return None; }
                let mut out = Vec::with_capacity(tlen.min(1 << 20));
                let mut hops = 0;
                while out.len() < tlen && pg != 0 {
                    hops += 1; if hops > 100_000 { return None; }
                    let o = self.page(pg)?;
                    if o[25] != 7 { return None; }
                    let n = self.u(o, 22, 2)? as usize;
                    out.extend_from_slice(o.get(26..26 + n)?);
                    pg = self.u(o, 16, 4)?;
                }
                if out.len() != tlen { return None; }
                Some(out)
            }
            _ => None,
        }
    }
}

pub fn read(b: &[u8]) -> Option<Vec<Kv>> {
    let m = b.get(12..16)?;
    let le = match m { [0x62, 0x31, 0x05, 0x00] => true, [0x00, 0x05, 0x31, 0x62] => false, _ => return None };
    let mut db = Db { b, ps: 0, le };
    db.ps = db.u(b, 20, 4)? as usize;
    if !(512..=65536).contains(&db.ps) || !db.ps.is_power_of_two() { return None; }
    let mut out = Vec::new();
    for n in 1..(b.len() / db.ps) as u64 {
        let p = db.page(n)?;
        if p[25] != 5 { continue; }
        let entries = db.u(p, 20, 2)? as usize;
        let mut k = 0;
        while k + 1 < entries {
            let ko = db.u(p, 26 + 2 * k, 2)? as usize;
            let vo = db.u(p, 26 + 2 * (k + 1), 2)? as usize;
            if let (Some(key), Some(val)) = (db.item(p, ko), db.item(p, vo)) { out.push((key, val)); }
            k += 2;
            if out.len() > 2_000_000 { return None; }
        }
    }
    Some(out)
}
