//! Stellar: TransactionEnvelope v1 (XDR) with one native Payment or one AccountMerge (sweep).
use sha2::{Digest, Sha256};
pub const PUBLIC: &str = "Public Global Stellar Network ; September 2015";
pub const TESTNET: &str = "Test SDF Network ; September 2015";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Memo { None, Text(String), Id(u64) }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op { Payment { dest: [u8; 32], amount: i64 }, Merge { dest: [u8; 32] } }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx { pub source: [u8; 32], pub fee: u32, pub seq: i64, pub time: Option<(u64, u64)>, pub memo: Memo, pub op: Op, pub sigs: Vec<([u8; 4], [u8; 64])> }

fn u32b(o: &mut Vec<u8>, v: u32) { o.extend_from_slice(&v.to_be_bytes()) }
fn u64b(o: &mut Vec<u8>, v: u64) { o.extend_from_slice(&v.to_be_bytes()) }
fn acct(o: &mut Vec<u8>, k: &[u8; 32]) { u32b(o, 0); o.extend_from_slice(k) }

impl Tx {
    pub fn tx_body(&self) -> Vec<u8> {
        let mut o = vec![];
        acct(&mut o, &self.source); u32b(&mut o, self.fee); u64b(&mut o, self.seq as u64);
        match self.time { None => u32b(&mut o, 0), Some((a, b)) => { u32b(&mut o, 1); u64b(&mut o, a); u64b(&mut o, b) } }
        match &self.memo {
            Memo::None => u32b(&mut o, 0),
            Memo::Text(t) => { u32b(&mut o, 1); u32b(&mut o, t.len() as u32); o.extend_from_slice(t.as_bytes()); o.resize(o.len() + (4 - t.len() % 4) % 4, 0) }
            Memo::Id(i) => { u32b(&mut o, 2); u64b(&mut o, *i) }
        }
        u32b(&mut o, 1); u32b(&mut o, 0);
        match &self.op {
            Op::Payment { dest, amount } => { u32b(&mut o, 1); acct(&mut o, dest); u32b(&mut o, 0); u64b(&mut o, *amount as u64) }
            Op::Merge { dest } => { u32b(&mut o, 8); acct(&mut o, dest) }
        }
        u32b(&mut o, 0);
        o
    }
    pub fn envelope(&self) -> Vec<u8> {
        let mut o = vec![]; u32b(&mut o, 2); o.extend(self.tx_body()); u32b(&mut o, self.sigs.len() as u32);
        for (h, s) in &self.sigs { o.extend_from_slice(h); u32b(&mut o, 64); o.extend_from_slice(s) }
        o
    }
    pub fn hash(&self, passphrase: &str) -> [u8; 32] {
        let mut h = Sha256::new(); h.update(Sha256::digest(passphrase.as_bytes())); h.update(2u32.to_be_bytes()); h.update(self.tx_body()); h.finalize().into()
    }
    pub fn sign(&mut self, seed: &[u8; 32], passphrase: &str) -> Result<(), &'static str> {
        let (pk, sig) = crate::ed_sign(seed, &self.hash(passphrase));
        if pk != self.source { return Err("key_does_not_match_source") }
        self.sigs.push((pk[28..].try_into().unwrap(), sig)); Ok(())
    }
    pub fn verify(&self, passphrase: &str) -> bool {
        let h = self.hash(passphrase);
        !self.sigs.is_empty() && self.sigs.iter().all(|(hint, s)| hint == &self.source[28..] && crate::ed_verify(&self.source, &h, s))
    }
    pub fn decode(b: &[u8]) -> Result<Tx, String> {
        let mut r = R { b, i: 0 };
        if r.u32()? != 2 { return Err("not a v1 transaction envelope".into()) }
        let source = r.acct()?; let fee = r.u32()?; let seq = r.u64()? as i64;
        let time = match r.u32()? { 0 => None, 1 => Some((r.u64()?, r.u64()?)), _ => return Err("unsupported preconditions".into()) };
        let memo = match r.u32()? {
            0 => Memo::None,
            1 => { let n = r.u32()? as usize; if n > 28 { return Err("memo too long".into()) } let t = r.take(n)?.to_vec(); r.take((4 - n % 4) % 4)?; Memo::Text(String::from_utf8(t).map_err(|_| "memo not utf8")?) }
            2 => Memo::Id(r.u64()?),
            _ => return Err("unsupported memo type".into()),
        };
        if r.u32()? != 1 { return Err("only single-operation transactions are supported".into()) }
        if r.u32()? != 0 { return Err("operation source account not supported".into()) }
        let op = match r.u32()? {
            1 => { let dest = r.acct()?; if r.u32()? != 0 { return Err("only native XLM payments are supported".into()) } Op::Payment { dest, amount: r.u64()? as i64 } }
            8 => Op::Merge { dest: r.acct()? },
            t => return Err(format!("unsupported operation type {t}")),
        };
        if r.u32()? != 0 { return Err("unsupported tx ext".into()) }
        let n = r.u32()?; let mut sigs = vec![];
        for _ in 0..n { let h: [u8; 4] = r.take(4)?.try_into().unwrap(); if r.u32()? != 64 { return Err("bad signature length".into()) } sigs.push((h, r.take(64)?.try_into().unwrap())) }
        if r.i != b.len() { return Err("trailing bytes".into()) }
        Ok(Tx { source, fee, seq, time, memo, op, sigs })
    }
}
struct R<'a> { b: &'a [u8], i: usize }
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> { let s = self.b.get(self.i..self.i + n).ok_or("truncated")?; self.i += n; Ok(s) }
    fn u32(&mut self) -> Result<u32, String> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, String> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn acct(&mut self) -> Result<[u8; 32], String> { if self.u32()? != 0 { return Err("muxed (M...) accounts not supported".into()) } Ok(self.take(32)?.try_into().unwrap()) }
}
pub fn address(pk: &[u8; 32]) -> String { blocktools_core::chains::xlm_address(pk) }
pub fn decode_address(a: &str) -> Result<[u8; 32], &'static str> {
    match blocktools_core::chains::strkey_decode(a)? { (v, p) if v == 6 << 3 && p.len() == 32 => Ok(p.try_into().unwrap()), _ => Err("not a G... account id") }
}
/// S... secret -> 32-byte seed.
pub fn decode_secret(s: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, &'static str> {
    match blocktools_core::chains::strkey_decode(s.trim())? { (v, mut p) if v == 18 << 3 && p.len() == 32 => { let k = zeroize::Zeroizing::new(p[..].try_into().unwrap()); zeroize::Zeroize::zeroize(&mut p); Ok(k) } _ => Err("not an S... secret seed") }
}
