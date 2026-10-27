//! blocktools-utxo: read a Bitcoin Core `dumptxoutset` file into an in-RAM set of funded output
//! scripts (exact sorted set, with a bloom filter in front), offline. Public data only: a UTXO set
//! holds output scripts and amounts, no keys.
//!
//! File formats (both detected from the first bytes):
//! - Core 25.x .. 27.x: `base_blockhash[32] coins_count:u64le`, then per coin `txid[32] vout:u32le Coin`.
//! - Core 0.21 .. 24 (Litecoin 0.21.x): `base_blockhash[32] coins_count:u64le nChainTx:u32le`, then the
//!   25 per-coin layout (format 21). Not marked in the file: the first coins are trial-decoded in both
//!   legacy layouts and exactly one must parse, otherwise the file is refused (never guessed).
//! - Core 28+: `"utxo" 0xff version:u16le network_magic[4] base_blockhash[32] coins_count:u64le`, then per
//!   txid `txid[32] CompactSize(n)` and n times `CompactSize(vout) Coin`.
//!
//! `Coin` = VARINT(height*2 + coinbase), VARINT(compressed amount), compressed script (Core
//! compressor.cpp: 0 P2PKH, 1 P2SH, 2/3 compressed P2PK, 4/5 uncompressed P2PK, n>=6 raw n-6 bytes).
pub mod chainstate;
pub mod leveldb;
use bitcoin::hashes::{sha256, Hash};
use std::io::{self, Read};

pub const MAX_SCRIPT_SIZE: u64 = 10_000;

/// Snapshot header.
#[derive(Debug, Clone)]
pub struct Header {
    /// 25 (legacy, no magic) or the version field of the 28+ header.
    pub format: u16,
    /// Network magic (28+ only).
    pub network_magic: Option<[u8; 4]>,
    /// Base block hash, display byte order (reversed), hex.
    pub base_blockhash: String,
    pub coins_count: u64,
    /// Chain tx count from the 0.21-24 legacy header (format 21) only.
    pub nchaintx: Option<u32>,
}

impl Header {
    /// Detected file layout, named for the report line.
    pub fn layout(&self) -> &'static str {
        match self.format { 21 => "core-0.21-24 (u32 nChainTx in header)", 25 => "core-25-27", 0 => "chainstate", _ => "core-28+" }
    }
    /// Chain name from the network magic, when the header has one.
    pub fn network(&self) -> Option<&'static str> {
        match self.network_magic? {
            [0xf9, 0xbe, 0xb4, 0xd9] => Some("btc"),
            [0x0b, 0x11, 0x09, 0x07] => Some("btc-testnet3"),
            [0x1c, 0x16, 0x3f, 0x28] => Some("btc-testnet4"),
            [0x0a, 0x03, 0xcf, 0x40] => Some("btc-signet"),
            [0xfa, 0xbf, 0xb5, 0xda] => Some("btc-regtest"),
            _ => None,
        }
    }
}

fn rd<R: Read, const N: usize>(r: &mut R) -> io::Result<[u8; N]> { let mut b = [0u8; N]; r.read_exact(&mut b)?; Ok(b) }
fn bad(m: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, m) }

/// Core serialize.h VARINT (MSB base-128, each continuation byte minus one).
pub fn read_varint<R: Read>(r: &mut R) -> io::Result<u64> {
    let mut n: u64 = 0;
    loop {
        let [b] = rd::<_, 1>(r)?;
        if n > (u64::MAX >> 7) { return Err(bad("varint_overflow")) }
        n = (n << 7) | u64::from(b & 0x7f);
        if b & 0x80 != 0 { n = n.checked_add(1).ok_or_else(|| bad("varint_overflow"))? } else { return Ok(n) }
    }
}
/// Inverse of read_varint (fixtures and tests).
pub fn write_varint(mut n: u64, out: &mut Vec<u8>) {
    let mut tmp = Vec::new();
    loop {
        tmp.push((n & 0x7f) as u8 | if tmp.is_empty() { 0 } else { 0x80 });
        if n <= 0x7f { break }
        n = (n >> 7) - 1;
    }
    out.extend(tmp.iter().rev());
}
/// Bitcoin CompactSize.
pub fn read_compact<R: Read>(r: &mut R) -> io::Result<u64> {
    let [b] = rd::<_, 1>(r)?;
    Ok(match b {
        0xfd => u64::from(u16::from_le_bytes(rd(r)?)),
        0xfe => u64::from(u32::from_le_bytes(rd(r)?)),
        0xff => u64::from_le_bytes(rd(r)?),
        n => u64::from(n),
    })
}
/// Core compressor.cpp DecompressAmount.
pub fn decompress_amount(mut x: u64) -> u64 {
    if x == 0 { return 0 }
    x -= 1;
    let mut e = x % 10;
    x /= 10;
    let mut n = if e < 9 { let d = (x % 9) + 1; x /= 9; x.saturating_mul(10).saturating_add(d) } else { x.saturating_add(1) };
    while e > 0 { n = n.saturating_mul(10); e -= 1 }
    n
}
/// Core compressor.cpp CompressAmount (fixtures and tests).
pub fn compress_amount(mut n: u64) -> u64 {
    if n == 0 { return 0 }
    let mut e = 0;
    while n % 10 == 0 && e < 9 { n /= 10; e += 1 }
    if e < 9 { let d = n % 10; n /= 10; 1 + (n * 9 + d - 1) * 10 + e } else { 1 + (n - 1) * 10 + 9 }
}

/// Read one compressed script; returns the full scriptPubKey bytes.
pub fn read_script<R: Read>(r: &mut R) -> io::Result<Vec<u8>> {
    let n = read_varint(r)?;
    Ok(match n {
        0 => { let h: [u8; 20] = rd(r)?; [&[0x76, 0xa9, 0x14][..], &h, &[0x88, 0xac]].concat() }
        1 => { let h: [u8; 20] = rd(r)?; [&[0xa9, 0x14][..], &h, &[0x87]].concat() }
        2 | 3 => { let x: [u8; 32] = rd(r)?; [&[0x21, n as u8][..], &x, &[0xac]].concat() }
        4 | 5 => {
            let x: [u8; 32] = rd(r)?;
            let c = [&[(n - 2) as u8][..], &x].concat();
            match bitcoin::secp256k1::PublicKey::from_slice(&c) {
                Ok(pk) => [&[0x41][..], &pk.serialize_uncompressed(), &[0xac]].concat(),
                // Core keeps the coin but the script cannot be rebuilt; key it by its compressed form.
                Err(_) => [&[0xff, n as u8][..], &x].concat(),
            }
        }
        _ => {
            let len = n - 6;
            if len > MAX_SCRIPT_SIZE {
                // Core: replaced by OP_RETURN (unspendable), bytes skipped.
                io::copy(&mut r.take(len), &mut io::sink())?;
                vec![0x6a]
            } else {
                let mut s = vec![0u8; len as usize]; r.read_exact(&mut s)?; s
            }
        }
    })
}

/// One unspent output.
#[derive(Debug, Clone)]
pub struct Coin { pub txid: [u8; 32], pub vout: u32, pub height: u32, pub coinbase: bool, pub value: u64, pub script: Vec<u8> }

fn read_coin_body<R: Read>(r: &mut R, txid: [u8; 32], vout: u32) -> io::Result<Coin> {
    let code = read_varint(r)?;
    let value = decompress_amount(read_varint(r)?);
    let script = read_script(r)?;
    Ok(Coin { txid, vout, height: u32::try_from(code >> 1).map_err(|_| bad("height_overflow"))?, coinbase: code & 1 == 1, value, script })
}

/// Streaming reader over a dumptxoutset file.
pub struct Dump<R: Read> { r: io::Chain<io::Cursor<Vec<u8>>, R>, pub header: Header, left: u64, group: Option<([u8; 32], u64)> }

const PROBE_BYTES: usize = 1 << 20;
const PROBE_COINS: u64 = 1000;
/// True when `b` (bytes after the legacy header) decodes as `min(n, PROBE_COINS)` legacy coins with
/// vout < 2^20; when the whole file is in `b` and all n coins fit, they must end exactly at its end.
fn probe_legacy(b: &[u8], n: u64, eof: bool) -> bool {
    let mut r = b;
    for _ in 0..n.min(PROBE_COINS) {
        let ok = (|| -> io::Result<bool> {
            let txid: [u8; 32] = rd(&mut r)?; let vout = u32::from_le_bytes(rd(&mut r)?);
            read_coin_body(&mut r, txid, vout)?; Ok(vout < 1 << 20)
        })();
        match ok {
            Ok(true) => {}
            Ok(false) => return false,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && !eof => return true,
            Err(_) => return false,
        }
    }
    !(eof && n <= PROBE_COINS) || r.is_empty()
}

impl<R: Read> Dump<R> {
    pub fn new(mut r: R) -> io::Result<Self> {
        let first: [u8; 5] = rd(&mut r)?;
        let header = if first == *b"utxo\xff" {
            let ver = u16::from_le_bytes(rd(&mut r)?);
            if ver != 2 { return Err(bad("unsupported_snapshot_version")) }
            let magic: [u8; 4] = rd(&mut r)?;
            let h: [u8; 32] = rd(&mut r)?;
            let n = u64::from_le_bytes(rd(&mut r)?);
            Header { format: ver, network_magic: Some(magic), base_blockhash: hex_rev(&h), coins_count: n, nchaintx: None }
        } else {
            let rest: [u8; 27] = rd(&mut r)?;
            let mut h = [0u8; 32]; h[..5].copy_from_slice(&first); h[5..].copy_from_slice(&rest);
            let n = u64::from_le_bytes(rd(&mut r)?);
            // buffer a prefix and trial-decode it as 25-27 (coins follow) and 0.21-24 (u32 nChainTx first)
            let mut buf = Vec::new();
            (&mut r).take(PROBE_BYTES as u64).read_to_end(&mut buf)?;
            let eof = buf.len() < PROBE_BYTES;
            let (a, b) = (probe_legacy(&buf, n, eof), buf.len() >= 4 && probe_legacy(&buf[4..], n, eof));
            let (format, nchaintx, skip) = match (a, b) {
                (true, false) => (25, None, 0),
                (false, true) => (21, Some(u32::from_le_bytes(buf[..4].try_into().unwrap())), 4),
                (true, true) => return Err(bad("ambiguous_legacy_header:both_25-27_and_0.21-24_layouts_parse")),
                (false, false) => return Err(bad("bad_legacy_dump:neither_25-27_nor_0.21-24_layout_parses")),
            };
            buf.drain(..skip);
            let header = Header { format, network_magic: None, base_blockhash: hex_rev(&h), coins_count: n, nchaintx };
            let left = header.coins_count;
            return Ok(Dump { r: io::Cursor::new(buf).chain(r), header, left, group: None });
        };
        let left = header.coins_count;
        Ok(Dump { r: io::Cursor::new(Vec::new()).chain(r), header, left, group: None })
    }
    /// Next coin, None at the end (exactly coins_count coins).
    pub fn next_coin(&mut self) -> io::Result<Option<Coin>> {
        if self.left == 0 { return Ok(None) }
        self.left -= 1;
        if matches!(self.header.format, 21 | 25) {
            let txid: [u8; 32] = rd(&mut self.r)?;
            let vout = u32::from_le_bytes(rd(&mut self.r)?);
            return read_coin_body(&mut self.r, txid, vout).map(Some);
        }
        let (txid, n) = match self.group {
            Some((t, n)) if n > 0 => (t, n),
            _ => {
                let t: [u8; 32] = rd(&mut self.r)?;
                let n = read_compact(&mut self.r)?;
                if n == 0 { return Err(bad("empty_txid_group")) }
                (t, n)
            }
        };
        self.group = Some((txid, n - 1));
        let vout = u32::try_from(read_compact(&mut self.r)?).map_err(|_| bad("vout_overflow"))?;
        read_coin_body(&mut self.r, txid, vout).map(Some)
    }
    /// True when the file has no bytes after the last coin.
    pub fn at_eof(&mut self) -> bool { let mut b = [0u8; 1]; matches!(self.r.read(&mut b), Ok(0)) }
}

fn hex_rev(h: &[u8; 32]) -> String { h.iter().rev().map(|b| format!("{b:02x}")).collect() }

/// Fixed-size set key for a scriptPubKey. Standard templates keep their program bytes exactly
/// (tag byte + 20 or 32 bytes); every other script is keyed by its SHA-256.
pub type Key = [u8; 33];
pub fn script_key(s: &[u8]) -> Key {
    let mut k = [0u8; 33];
    let (tag, p): (u8, &[u8]) = match s {
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => (1, h),
        [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => (2, h),
        [0x00, 0x14, h @ ..] if h.len() == 20 => (3, h),
        [0x00, 0x20, h @ ..] if h.len() == 32 => (4, h),
        [0x51, 0x20, h @ ..] if h.len() == 32 => (5, h),
        _ => { k[1..].copy_from_slice(&sha256::Hash::hash(s).to_byte_array()); return k }
    };
    k[0] = tag; k[1..1 + p.len()].copy_from_slice(p); k
}

/// Bloom filter over keys. Bits from the key bytes themselves (programs and hashes are already
/// uniform), mixed so that the zero padding of 20-byte programs does not matter.
pub struct Bloom { bits: Vec<u64>, m: u64, k: u32 }
fn mix(mut z: u64) -> u64 { z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9); z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb); z ^ (z >> 31) }
fn hashes(k: &Key) -> (u64, u64) {
    let a = u64::from_le_bytes(k[1..9].try_into().unwrap());
    let b = u64::from_le_bytes(k[9..17].try_into().unwrap());
    let c = u64::from_le_bytes(k[17..25].try_into().unwrap()) ^ u64::from(k[0]);
    (mix(a ^ c.rotate_left(17)), mix(b ^ c) | 1)
}
impl Bloom {
    /// `n` entries, `bits_per_entry` bits each, k = round(bits_per_entry * ln 2).
    pub fn new(n: usize, bits_per_entry: u32) -> Bloom {
        let m = (n as u64 * u64::from(bits_per_entry)).max(64);
        let k = ((f64::from(bits_per_entry) * std::f64::consts::LN_2).round() as u32).max(1);
        Bloom { bits: vec![0; m.div_ceil(64) as usize], m, k }
    }
    pub fn insert(&mut self, key: &Key) {
        let (h1, h2) = hashes(key);
        for i in 0..u64::from(self.k) { let b = h1.wrapping_add(i.wrapping_mul(h2)) % self.m; self.bits[(b / 64) as usize] |= 1 << (b % 64) }
    }
    pub fn maybe(&self, key: &Key) -> bool {
        let (h1, h2) = hashes(key);
        (0..u64::from(self.k)).all(|i| { let b = h1.wrapping_add(i.wrapping_mul(h2)) % self.m; self.bits[(b / 64) as usize] & (1 << (b % 64)) != 0 })
    }
    pub fn bytes(&self) -> usize { self.bits.len() * 8 }
    pub fn k(&self) -> u32 { self.k }
}

/// Funded scripts: exact sorted keys with the summed value and the number of unspent outputs.
struct Entry { value: u64, outputs: u32, key: Key }
pub struct UtxoSet { set: Vec<Entry>, bloom: Bloom, pub coins: u64, pub header: Header }

/// Membership answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// Bloom says no: certainly not in the set.
    Absent,
    /// Bloom said maybe, the exact set says no (a bloom false positive, eliminated).
    BloomFalsePositive,
    /// In the set: summed value (base units) and unspent output count.
    Funded { value: u64, outputs: u32 },
}

impl UtxoSet {
    /// Ingest a whole dump. Fails on a truncated file, a bad header or trailing bytes.
    pub fn ingest<R: Read>(r: R, bits_per_entry: u32) -> io::Result<UtxoSet> {
        let mut d = Dump::new(r)?;
        let cap = usize::try_from(d.header.coins_count.min(1 << 30)).unwrap_or(0);
        // One vector, sorted and merged in place: peak memory is one entry per coin plus the bloom.
        let mut v: Vec<Entry> = Vec::with_capacity(cap);
        while let Some(c) = d.next_coin()? { v.push(Entry { value: c.value, outputs: 1, key: script_key(&c.script) }) }
        if !d.at_eof() { return Err(bad("trailing_bytes_after_coins_count")) }
        Ok(Self::build(v, bits_per_entry, d.header))
    }
    /// Ingest a node's chainstate/ LevelDB directory directly (see [`chainstate`]). The header has
    /// format 0, no network magic, and the chainstate's best block as base_blockhash.
    pub fn ingest_chainstate(dir: &std::path::Path, bits_per_entry: u32) -> io::Result<(UtxoSet, chainstate::Stats)> {
        let mut cs = chainstate::Chainstate::open(dir)?;
        let mut v: Vec<Entry> = Vec::new();
        while let Some(c) = cs.next_coin()? { v.push(Entry { value: c.value, outputs: 1, key: script_key(&c.script) }) }
        let st = cs.stats.clone();
        let h = Header { format: 0, network_magic: None, base_blockhash: st.best_block.clone().unwrap_or_default(), coins_count: v.len() as u64, nchaintx: None };
        Ok((Self::build(v, bits_per_entry, h), st))
    }
    fn build(mut v: Vec<Entry>, bits_per_entry: u32, header: Header) -> UtxoSet {
        let coins = v.len() as u64;
        v.sort_unstable_by(|a, b| a.key.cmp(&b.key));
        v.dedup_by(|b, a| if a.key == b.key { a.value = a.value.saturating_add(b.value); a.outputs += 1; true } else { false });
        v.shrink_to_fit();
        let mut bloom = Bloom::new(v.len(), bits_per_entry);
        for e in &v { bloom.insert(&e.key) }
        UtxoSet { set: v, bloom, coins, header }
    }
    pub fn scripts(&self) -> usize { self.set.len() }
    pub fn bloom(&self) -> &Bloom { &self.bloom }
    /// Bytes held after ingest (keys + values + bloom).
    pub fn resident_bytes(&self) -> usize { self.set.capacity() * std::mem::size_of::<Entry>() + self.bloom.bytes() }
    pub fn query_key(&self, k: &Key) -> Answer {
        if !self.bloom.maybe(k) { return Answer::Absent }
        match self.set.binary_search_by(|e| e.key.cmp(k)) {
            Ok(i) => Answer::Funded { value: self.set[i].value, outputs: self.set[i].outputs },
            Err(_) => Answer::BloomFalsePositive,
        }
    }
    pub fn query_script(&self, s: &[u8]) -> Answer { self.query_key(&script_key(s)) }
    /// Exact lookup only (no bloom), for measuring that the bloom changes no answer.
    pub fn exact_script(&self, s: &[u8]) -> Option<(u64, u32)> { let k = script_key(s); self.set.binary_search_by(|e| e.key.cmp(&k)).ok().map(|i| (self.set[i].value, self.set[i].outputs)) }
}

/// One `Coin` body as Core writes it (P2PKH, P2SH, compressed P2PK compressed; others raw).
pub fn write_coin_body(c: &Coin, o: &mut Vec<u8>) {
    write_varint(u64::from(c.height) * 2 + u64::from(c.coinbase), o);
    write_varint(compress_amount(c.value), o);
    match c.script.as_slice() {
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => { o.push(0); o.extend(h) }
        [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => { o.push(1); o.extend(h) }
        [0x21, p @ (2 | 3), x @ .., 0xac] if x.len() == 32 => { o.push(*p); o.extend(x) }
        s => { write_varint(s.len() as u64 + 6, o); o.extend(s) }
    }
}

/// Write a dump (fixtures and tests): `format` 25 (legacy) or 28 (magic header, grouped by txid).
/// Coins must be grouped by txid for format 28. Scripts are written raw (size+6) except P2PKH/P2SH,
/// which use the compressed forms Core writes.
pub fn write_dump(format: u16, magic: [u8; 4], base: [u8; 32], coins: &[Coin]) -> Vec<u8> {
    let mut o = Vec::new();
    if format != 25 { o.extend(b"utxo\xff"); o.extend(2u16.to_le_bytes()); o.extend(magic) }
    o.extend(base); o.extend((coins.len() as u64).to_le_bytes());
    let body = write_coin_body;
    let mut i = 0;
    while i < coins.len() {
        if format == 25 { o.extend(coins[i].txid); o.extend(coins[i].vout.to_le_bytes()); body(&coins[i], &mut o); i += 1; continue }
        let j = coins[i..].iter().position(|c| c.txid != coins[i].txid).map_or(coins.len(), |p| i + p);
        o.extend(coins[i].txid); o.push((j - i) as u8);
        for c in &coins[i..j] { o.push(c.vout as u8); body(c, &mut o) }
        i = j;
    }
    o
}
