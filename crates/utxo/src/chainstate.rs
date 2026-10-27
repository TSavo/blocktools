//! Coins straight from a Core-family node's `chainstate/` LevelDB directory, for forks without
//! `dumptxoutset` (Dogecoin 1.14.x, older Litecoin, ...). Read-only: the node must be stopped, or the
//! directory copied while it is stopped (LevelDB has no reader isolation against a live writer).
//!
//! Two record layouts, chosen per key:
//! - `'C' txid[32] VARINT(vout)` -> `Coin` (Bitcoin Core 0.15+ per-output layout; Litecoin 0.15+).
//! - `'c' txid[32]` -> `CCoins` (Bitcoin Core 0.8..0.14 per-transaction layout; Dogecoin 1.14.x):
//!   VARINT(version) VARINT(code) mask-bytes {compressed txout for each unspent vout} VARINT(height),
//!   code bit0 coinbase, bit1/bit2 vout 0/1 unspent, code/8 (+1 when bits 1,2 are both clear) = count
//!   of non-zero mask bytes for vout 2.. (coins.h, Unserialize).
//! Values are XORed with the 8-byte key stored under `"\x0e\x00obfuscate_key"` (dbwrapper.cpp);
//! `'B'` holds the best block hash. A `'H'` key (Core 0.15+ partial flush in progress) is refused.
use crate::leveldb::Db;
use crate::{decompress_amount, read_script, read_varint, Coin};
use std::io::{self, Cursor, Read};
use std::path::Path;

fn bad(m: &'static str) -> io::Error { io::Error::new(io::ErrorKind::InvalidData, m) }
const OBF: &[u8] = b"\x0e\x00obfuscate_key";

/// Which layouts were seen.
#[derive(Debug, Default, Clone)]
pub struct Stats { pub per_output_keys: u64, pub per_tx_keys: u64, pub other_keys: u64, pub obfuscated: bool, pub total_value: u64, pub table_files: usize, pub log_files: usize, pub best_block: Option<String> }

/// Overrides, for the discrimination checks: force an era (`b'C'` or `b'c'`): a record of the other
/// layout is then an error, never reinterpreted; force an obfuscation key (hex bytes; empty = none),
/// used instead of the stored one. Defaults detect both from the data and report them in `Stats`.
#[derive(Debug, Default, Clone)]
pub struct Opts { pub era: Option<u8>, pub xor: Option<Vec<u8>> }

pub struct Chainstate { db: Db, xor: Vec<u8>, pending: std::vec::IntoIter<Coin>, pub stats: Stats, opts: Opts }

impl Chainstate {
    pub fn open(dir: &Path) -> io::Result<Chainstate> { Chainstate::open_with(dir, Opts::default()) }
    pub fn open_with(dir: &Path, opts: Opts) -> io::Result<Chainstate> {
        if let Some(e) = opts.era { if e != b'C' && e != b'c' { return Err(bad("era_unknown")) } }
        let db = Db::open(dir)?;
        let stats = Stats { table_files: db.live.tables.len(), log_files: db.live.logs.len(), ..Stats::default() };
        let xor = opts.xor.clone().unwrap_or_else(|| vec![0; 8]);
        Ok(Chainstate { db, xor, pending: Vec::new().into_iter(), stats, opts })
    }
    fn era(&mut self, k: u8) -> io::Result<()> {
        if let Some(e) = self.opts.era { if e != k { return Err(bad("era_mismatch: a record of the other layout; the forced era is wrong for this chainstate")) } }
        let other = if k == b'C' { self.stats.per_tx_keys } else { self.stats.per_output_keys };
        if other > 0 { return Err(bad("layout_mixed: both 'C' and 'c' coin records; not a chainstate one node wrote")) }
        Ok(())
    }
    pub fn db(&self) -> &Db { &self.db }
    fn unxor(&self, mut v: Vec<u8>) -> Vec<u8> {
        if self.xor.iter().any(|b| *b != 0) { for (i, b) in v.iter_mut().enumerate() { *b ^= self.xor[i % self.xor.len()] } }
        v
    }
    pub fn next_coin(&mut self) -> io::Result<Option<Coin>> {
        loop {
            if let Some(c) = self.pending.next() { return Ok(Some(c)) }
            let Some((k, v)) = self.db.next_live()? else { return Ok(None) };
            if k == OBF {
                let (n, x) = v.split_first().ok_or_else(|| bad("obfuscate_key_empty"))?;
                if usize::from(*n) != x.len() || x.is_empty() { return Err(bad("obfuscate_key_bad")) }
                self.stats.obfuscated = x.iter().any(|b| *b != 0);
                if self.opts.xor.is_none() { self.xor = x.to_vec() }
                continue;
            }
            match k.first() {
                Some(b'C') if k.len() > 33 => {
                    self.era(b'C')?;
                    let v = self.unxor(v);
                    let mut txid = [0u8; 32]; txid.copy_from_slice(&k[1..33]);
                    let mut kc = Cursor::new(&k[33..]);
                    let vout = u32::try_from(read_varint(&mut kc)?).map_err(|_| bad("vout_overflow"))?;
                    let mut r = Cursor::new(&v[..]);
                    let code = read_varint(&mut r)?;
                    let value = decompress_amount(read_varint(&mut r)?);
                    let script = read_script(&mut r).map_err(|_| bad("coin_bad_script: wrong obfuscation key or era?"))?;
                    if (r.position() as usize) != v.len() { return Err(bad("coin_trailing_bytes: wrong obfuscation key or era?")) }
                    self.stats.per_output_keys += 1; self.stats.total_value = self.stats.total_value.saturating_add(value);
                    return Ok(Some(Coin { txid, vout, height: u32::try_from(code >> 1).map_err(|_| bad("height_overflow"))?, coinbase: code & 1 == 1, value, script }));
                }
                Some(b'c') if k.len() == 33 => {
                    self.era(b'c')?;
                    let v = self.unxor(v);
                    let mut txid = [0u8; 32]; txid.copy_from_slice(&k[1..33]);
                    let cs = per_tx(txid, &v).map_err(|e| io::Error::new(e.kind(), format!("{e}: wrong obfuscation key or era?")))?;
                    self.stats.total_value = cs.iter().fold(self.stats.total_value, |a, c| a.saturating_add(c.value));
                    self.pending = cs.into_iter();
                    self.stats.per_tx_keys += 1;
                }
                Some(b'B') => { let v = self.unxor(v); if v.len() == 32 { self.stats.best_block = Some(v.iter().rev().map(|b| format!("{b:02x}")).collect()) } }
                Some(b'H') => return Err(bad("chainstate_mid_flush_H_key: let the node finish a clean shutdown")),
                _ => self.stats.other_keys += 1,
            }
        }
    }
}

/// Decode a pre-0.15 `CCoins` record into its unspent outputs.
pub fn per_tx(txid: [u8; 32], v: &[u8]) -> io::Result<Vec<Coin>> {
    let mut r = Cursor::new(v);
    let _version = read_varint(&mut r)?;
    let code = read_varint(&mut r)?;
    let coinbase = code & 1 == 1;
    let mut avail = vec![code & 2 != 0, code & 4 != 0];
    let mut mask = code / 8 + if code & 6 != 0 { 0 } else { 1 };
    while mask > 0 {
        let mut b = [0u8; 1]; r.read_exact(&mut b)?;
        for p in 0..8 { avail.push(b[0] & (1 << p) != 0) }
        if b[0] != 0 { mask -= 1 }
        if avail.len() > 1 << 20 { return Err(bad("mask_too_long")) }
    }
    let mut outs = Vec::new();
    for (i, a) in avail.iter().enumerate() {
        if *a { let value = decompress_amount(read_varint(&mut r)?); let script = read_script(&mut r)?; outs.push((i as u32, value, script)) }
    }
    let height = u32::try_from(read_varint(&mut r)?).map_err(|_| bad("height_overflow"))?;
    if (r.position() as usize) != v.len() { return Err(bad("ccoins_trailing_bytes")) }
    Ok(outs.into_iter().map(|(vout, value, script)| Coin { txid, vout, height, coinbase, value, script }).collect())
}
