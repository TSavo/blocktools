//! Minimal read-only LevelDB reader (bytewise comparator), enough for a stopped node's chainstate/.
//! Reads CURRENT -> MANIFEST (live table files and log number), every live table (.ldb/.sst) and the
//! live write-ahead log(s), and yields the newest live value of every user key in key order. Opens
//! files read-only; never takes the LOCK, never writes. Block CRCs (masked CRC32C) are checked.
//! Snappy-compressed blocks are refused (Core-family nodes set kNoCompression for their databases).
use std::cmp::{Ordering, Reverse};
use std::collections::{BTreeMap, BinaryHeap};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

fn bad(m: impl Into<String>) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, m.into()) }

fn crc32c(data: &[u8]) -> u32 {
    static T: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let t = T.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 { c = if c & 1 != 0 { 0x82f6_3b78 ^ (c >> 1) } else { c >> 1 } }
            *e = c;
        }
        t
    });
    let mut c = !0u32;
    for &b in data { c = t[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8) }
    !c
}
fn unmask(m: u32) -> u32 { let r = m.wrapping_sub(0xa282_ead8); r.rotate_left(15) }
fn crc_ok(data: &[u8], masked: u32) -> bool { crc32c(data) == unmask(masked) }

fn uvarint(b: &[u8], p: &mut usize) -> io::Result<u64> {
    let mut n = 0u64;
    for s in (0..64).step_by(7) {
        let x = *b.get(*p).ok_or_else(|| bad("varint_truncated"))?;
        *p += 1;
        n |= u64::from(x & 0x7f) << s;
        if x & 0x80 == 0 { return Ok(n) }
    }
    Err(bad("varint_overflow"))
}
fn slice<'a>(b: &'a [u8], p: &mut usize) -> io::Result<&'a [u8]> {
    let n = uvarint(b, p)? as usize;
    let s = b.get(*p..p.checked_add(n).ok_or_else(|| bad("len"))?).ok_or_else(|| bad("slice_truncated"))?;
    *p += n;
    Ok(s)
}

/// One entry: user key, sequence, value (None = deletion).
#[derive(Debug, Clone)]
pub struct Entry { pub key: Vec<u8>, pub seq: u64, pub value: Option<Vec<u8>> }

fn split_internal(ik: &[u8]) -> io::Result<(&[u8], u64, u8)> {
    if ik.len() < 8 { return Err(bad("internal_key_short")) }
    let (u, t) = ik.split_at(ik.len() - 8);
    let tag = u64::from_le_bytes(t.try_into().unwrap());
    Ok((u, tag >> 8, (tag & 0xff) as u8))
}

fn block_entries(b: &[u8]) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    if b.len() < 4 { return Err(bad("block_short")) }
    let nr = u32::from_le_bytes(b[b.len() - 4..].try_into().unwrap()) as usize;
    let end = b.len().checked_sub(4 + 4 * nr).ok_or_else(|| bad("block_restarts"))?;
    let (mut p, mut key, mut out) = (0usize, Vec::new(), Vec::new());
    while p < end {
        let shared = uvarint(b, &mut p)? as usize;
        let ns = uvarint(b, &mut p)? as usize;
        let vl = uvarint(b, &mut p)? as usize;
        if shared > key.len() { return Err(bad("block_shared")) }
        key.truncate(shared);
        key.extend_from_slice(b.get(p..p + ns).ok_or_else(|| bad("block_key"))?);
        p += ns;
        let v = b.get(p..p + vl).ok_or_else(|| bad("block_value"))?.to_vec();
        p += vl;
        out.push((key.clone(), v));
    }
    Ok(out)
}

/// Sorted reader over one table file, block by block (memory: one block).
pub struct Table { f: File, index: Vec<(u64, u64)>, next: usize, cur: std::vec::IntoIter<(Vec<u8>, Vec<u8>)>, pub bytes_read: u64 }
impl Table {
    pub fn open(path: &Path) -> io::Result<Table> {
        let mut f = File::open(path)?;
        let len = f.metadata()?.len();
        if len < 48 { return Err(bad("table_short")) }
        f.seek(SeekFrom::Start(len - 48))?;
        let mut ft = [0u8; 48]; f.read_exact(&mut ft)?;
        if u64::from_le_bytes(ft[40..].try_into().unwrap()) != 0xdb47_7524_8b80_fb57 { return Err(bad("table_magic")) }
        let mut p = 0; let _mo = uvarint(&ft, &mut p)?; let _ms = uvarint(&ft, &mut p)?;
        let io_ = uvarint(&ft, &mut p)?; let is = uvarint(&ft, &mut p)?;
        let mut t = Table { f, index: Vec::new(), next: 0, cur: Vec::new().into_iter(), bytes_read: 48 };
        let ib = t.block(io_, is)?;
        for (_, v) in block_entries(&ib)? { let mut q = 0; let o = uvarint(&v, &mut q)?; let s = uvarint(&v, &mut q)?; t.index.push((o, s)) }
        Ok(t)
    }
    fn block(&mut self, off: u64, size: u64) -> io::Result<Vec<u8>> {
        self.f.seek(SeekFrom::Start(off))?;
        let mut b = vec![0u8; usize::try_from(size + 5).map_err(|_| bad("block_size"))?];
        self.f.read_exact(&mut b)?;
        self.bytes_read += size + 5;
        let crc = u32::from_le_bytes(b[b.len() - 4..].try_into().unwrap());
        let n = b.len() - 4;
        if !crc_ok(&b[..n], crc) { return Err(bad("block_crc_mismatch")) }
        match b[n - 1] { 0 => {}, 1 => return Err(bad("snappy_block_unsupported")), _ => return Err(bad("block_compression_unknown")) }
        b.truncate(n - 1);
        Ok(b)
    }
    pub fn next_entry(&mut self) -> io::Result<Option<Entry>> {
        loop {
            if let Some((ik, v)) = self.cur.next() {
                let (u, seq, ty) = split_internal(&ik)?;
                return Ok(Some(Entry { key: u.to_vec(), seq, value: if ty == 1 { Some(v) } else { None } }));
            }
            let Some(&(o, s)) = self.index.get(self.next) else { return Ok(None) };
            self.next += 1;
            let b = self.block(o, s)?;
            self.cur = block_entries(&b)?.into_iter();
        }
    }
}

/// Records of a LevelDB log file (32 KiB blocks, fragmented records). A torn tail (crash mid-write)
/// ends the file, as LevelDB's own recovery does; a CRC mismatch elsewhere is an error.
pub fn log_records(path: &Path) -> io::Result<Vec<Vec<u8>>> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;
    let (mut out, mut cur, mut p) = (Vec::new(), Vec::<u8>::new(), 0usize);
    while p < data.len() {
        let left = 32768 - (p % 32768);
        if left < 7 { p += left; continue }
        if p + 7 > data.len() { break }
        let h = &data[p..p + 7];
        let crc = u32::from_le_bytes(h[..4].try_into().unwrap());
        let n = usize::from(u16::from_le_bytes([h[4], h[5]]));
        let ty = h[6];
        if ty == 0 && n == 0 { p += left; continue } // zero padding / preallocated tail
        if p + 7 + n > data.len() { break } // torn tail
        let body = &data[p + 7..p + 7 + n];
        if !crc_ok(&data[p + 6..p + 7 + n], crc) {
            if p + 7 + n + 7 > data.len() { break } // torn final record
            return Err(bad("log_crc_mismatch"));
        }
        match ty { 1 => out.push(body.to_vec()), 2 => cur = body.to_vec(), 3 => cur.extend_from_slice(body), 4 => { cur.extend_from_slice(body); out.push(std::mem::take(&mut cur)) }, _ => return Err(bad("log_record_type")) }
        p += 7 + n;
    }
    Ok(out)
}

/// The live files named by CURRENT's manifest.
pub struct Live { pub tables: Vec<PathBuf>, pub logs: Vec<PathBuf>, pub manifest: PathBuf }
pub fn live_files(dir: &Path) -> io::Result<Live> {
    let cur = std::fs::read_to_string(dir.join("CURRENT")).map_err(|e| bad(format!("no_CURRENT:{e}")))?;
    let mname = cur.trim_end_matches('\n');
    if mname.contains('/') || !mname.starts_with("MANIFEST-") { return Err(bad("bad_CURRENT")) }
    let manifest = dir.join(mname);
    let (mut files, mut log_no, mut prev_log) = (std::collections::BTreeSet::new(), 0u64, 0u64);
    for r in log_records(&manifest)? {
        let mut p = 0;
        while p < r.len() {
            match uvarint(&r, &mut p)? {
                1 => { slice(&r, &mut p)?; }
                2 => log_no = uvarint(&r, &mut p)?,
                3 | 4 => { uvarint(&r, &mut p)?; }
                5 => { uvarint(&r, &mut p)?; slice(&r, &mut p)?; }
                6 => { uvarint(&r, &mut p)?; let n = uvarint(&r, &mut p)?; files.retain(|x| *x != n); }
                7 => { uvarint(&r, &mut p)?; let n = uvarint(&r, &mut p)?; uvarint(&r, &mut p)?; slice(&r, &mut p)?; slice(&r, &mut p)?; files.insert(n); }
                9 => prev_log = uvarint(&r, &mut p)?,
                t => return Err(bad(format!("manifest_tag_{t}"))),
            }
        }
    }
    let mut tables = Vec::new();
    for n in files {
        let a = dir.join(format!("{n:06}.ldb")); let b = dir.join(format!("{n:06}.sst"));
        tables.push(if a.exists() { a } else if b.exists() { b } else { return Err(bad(format!("missing_table_{n:06}"))) });
    }
    let mut logs: Vec<(u64, PathBuf)> = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?; let name = e.file_name().to_string_lossy().into_owned();
        if let Some(n) = name.strip_suffix(".log").and_then(|s| s.parse::<u64>().ok()) {
            if n >= log_no || (prev_log != 0 && n == prev_log) { logs.push((n, e.path())) }
        }
    }
    logs.sort();
    Ok(Live { tables, logs: logs.into_iter().map(|x| x.1).collect(), manifest })
}

/// Newest live value per user key, ascending key order, streamed by a k-way merge over the tables
/// (each one block in memory) and the logs (decoded in memory: bounded by the node's write buffer).
pub struct Db { tables: Vec<Table>, heap: BinaryHeap<Reverse<Head>>, log: std::vec::IntoIter<Entry>, pub live: Live, pub entries: u64 }
#[derive(Eq, PartialEq)]
struct Head { key: Vec<u8>, seq: u64, src: usize, value: Option<Vec<u8>> }
impl Ord for Head { fn cmp(&self, o: &Self) -> Ordering { self.key.cmp(&o.key).then(o.seq.cmp(&self.seq)) } }
impl PartialOrd for Head { fn partial_cmp(&self, o: &Self) -> Option<Ordering> { Some(self.cmp(o)) } }

impl Db {
    pub fn open(dir: &Path) -> io::Result<Db> {
        let live = live_files(dir)?;
        let mut m: BTreeMap<Vec<u8>, (u64, Option<Vec<u8>>)> = BTreeMap::new();
        for l in &live.logs {
            for r in log_records(l)? {
                if r.len() < 12 { return Err(bad("batch_short")) }
                let mut seq = u64::from_le_bytes(r[..8].try_into().unwrap());
                let count = u32::from_le_bytes(r[8..12].try_into().unwrap());
                let mut p = 12;
                for _ in 0..count {
                    let t = *r.get(p).ok_or_else(|| bad("batch_truncated"))?; p += 1;
                    let k = slice(&r, &mut p)?.to_vec();
                    let v = match t { 1 => Some(slice(&r, &mut p)?.to_vec()), 0 => None, _ => return Err(bad("batch_tag")) };
                    match m.get(&k) { Some((s, _)) if *s > seq => {}, _ => { m.insert(k, (seq, v)); } }
                    seq += 1;
                }
            }
        }
        let log: Vec<Entry> = m.into_iter().map(|(key, (seq, value))| Entry { key, seq, value }).collect();
        let mut db = Db { tables: Vec::new(), heap: BinaryHeap::new(), log: log.into_iter(), live, entries: 0 };
        for t in db.live.tables.clone() { db.tables.push(Table::open(&t)?) }
        for i in 0..=db.tables.len() { db.refill(i)? }
        Ok(db)
    }
    fn refill(&mut self, src: usize) -> io::Result<()> {
        let e = if src == self.tables.len() { self.log.next() } else { self.tables[src].next_entry()? };
        if let Some(e) = e { self.heap.push(Reverse(Head { key: e.key, seq: e.seq, src, value: e.value })) }
        Ok(())
    }
    /// Bytes of table blocks read so far.
    pub fn table_bytes(&self) -> u64 { self.tables.iter().map(|t| t.bytes_read).sum() }
    /// Next live (key, value), or None at the end.
    pub fn next_live(&mut self) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
        loop {
            let Some(Reverse(h)) = self.heap.pop() else { return Ok(None) };
            self.refill(h.src)?;
            self.entries += 1;
            // drop older versions of the same key
            while let Some(Reverse(n)) = self.heap.peek() {
                if n.key != h.key { break }
                let Reverse(n) = self.heap.pop().unwrap();
                self.refill(n.src)?;
                self.entries += 1;
            }
            if let Some(v) = h.value { return Ok(Some((h.key, v))) }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn crc32c_vector() { assert_eq!(super::crc32c(b"123456789"), 0xe306_9283) }
}
