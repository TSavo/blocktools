//! Algorand: canonical-msgpack `pay` transaction (amount, or amount 0 + close-to for a sweep).
use bitcoin::hashes::{sha512_256, Hash};
pub const MAINNET_GH: &str = "wGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit8=";
pub const MAINNET_GEN: &str = "mainnet-v1.0";

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Pay { pub snd: [u8; 32], pub rcv: [u8; 32], pub amt: u64, pub close: Option<[u8; 32]>, pub fee: u64, pub fv: u64, pub lv: u64,
    pub gen: String, pub gh: [u8; 32], pub note: Vec<u8>, pub sig: Option<[u8; 64]> }

fn uint(o: &mut Vec<u8>, v: u64) {
    match v { 0..=127 => o.push(v as u8), 128..=0xff => { o.push(0xcc); o.push(v as u8) } 0x100..=0xffff => { o.push(0xcd); o.extend((v as u16).to_be_bytes()) }
        0x1_0000..=0xffff_ffff => { o.push(0xce); o.extend((v as u32).to_be_bytes()) } _ => { o.push(0xcf); o.extend(v.to_be_bytes()) } }
}
fn s(o: &mut Vec<u8>, t: &str) { if t.len() < 32 { o.push(0xa0 | t.len() as u8) } else { o.push(0xd9); o.push(t.len() as u8) } o.extend_from_slice(t.as_bytes()) }
fn bin(o: &mut Vec<u8>, b: &[u8]) { o.push(0xc4); o.push(b.len() as u8); o.extend_from_slice(b) }

impl Pay {
    pub fn msgpack(&self) -> Vec<u8> {
        let mut f: Vec<(&str, Box<dyn Fn(&mut Vec<u8>) + '_>)> = vec![];
        if self.amt != 0 { f.push(("amt", Box::new(|o| uint(o, self.amt)))) }
        if let Some(c) = &self.close { f.push(("close", Box::new(move |o| bin(o, c)))) }
        if self.fee != 0 { f.push(("fee", Box::new(|o| uint(o, self.fee)))) }
        if self.fv != 0 { f.push(("fv", Box::new(|o| uint(o, self.fv)))) }
        if !self.gen.is_empty() { f.push(("gen", Box::new(|o| s(o, &self.gen)))) }
        f.push(("gh", Box::new(|o| bin(o, &self.gh))));
        if self.lv != 0 { f.push(("lv", Box::new(|o| uint(o, self.lv)))) }
        if !self.note.is_empty() { f.push(("note", Box::new(|o| bin(o, &self.note)))) }
        if self.rcv != [0; 32] { f.push(("rcv", Box::new(|o| bin(o, &self.rcv)))) }
        f.push(("snd", Box::new(|o| bin(o, &self.snd))));
        f.push(("type", Box::new(|o| s(o, "pay"))));
        let mut o = vec![0x80 | f.len() as u8];
        for (k, w) in f { s(&mut o, k); w(&mut o) }
        o
    }
    pub fn signing_bytes(&self) -> Vec<u8> { let mut b = b"TX".to_vec(); b.extend(self.msgpack()); b }
    pub fn txid(&self) -> String { blocktools_core::chains::b32_encode(&sha512_256::Hash::hash(&self.signing_bytes()).to_byte_array()) }
    /// Unsigned: the bare txn map (algosdk msgpack_encode(txn)). Signed: {sig, txn}.
    pub fn encode(&self) -> Vec<u8> {
        match &self.sig { None => self.msgpack(), Some(sg) => { let mut o = vec![0x82]; s(&mut o, "sig"); bin(&mut o, sg); s(&mut o, "txn"); o.extend(self.msgpack()); o } }
    }
    pub fn sign(&mut self, seed: &[u8; 32]) -> Result<(), &'static str> {
        let (pk, sig) = crate::ed_sign(seed, &self.signing_bytes());
        if pk != self.snd { return Err("key_does_not_match_sender") }
        self.sig = Some(sig); Ok(())
    }
    pub fn verify(&self) -> bool { self.sig.map_or(false, |sg| crate::ed_verify(&self.snd, &self.signing_bytes(), &sg)) }
    pub fn decode(b: &[u8]) -> Result<Pay, String> {
        let mut r = R { b, i: 0 };
        let mut p = r.txn_or_signed()?;
        if r.i != b.len() { return Err("trailing bytes".into()) }
        if p.encode() != b { return Err("not canonical msgpack (re-encoding differs)".into()) }
        p.gen.shrink_to_fit(); Ok(p)
    }
}
struct R<'a> { b: &'a [u8], i: usize }
impl<'a> R<'a> {
    fn byte(&mut self) -> Result<u8, String> { let v = *self.b.get(self.i).ok_or("truncated")?; self.i += 1; Ok(v) }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> { let s = self.b.get(self.i..self.i + n).ok_or("truncated")?; self.i += n; Ok(s) }
    fn str(&mut self) -> Result<String, String> { let t = self.byte()?; let n = match t { 0xa0..=0xbf => (t & 31) as usize, 0xd9 => self.byte()? as usize, _ => return Err("expected string".into()) }; String::from_utf8(self.take(n)?.to_vec()).map_err(|_| "bad utf8".into()) }
    fn bin(&mut self) -> Result<&'a [u8], String> { if self.byte()? != 0xc4 { return Err("expected bin8".into()) } let n = self.byte()? as usize; self.take(n) }
    fn b32(&mut self) -> Result<[u8; 32], String> { self.bin()?.try_into().map_err(|_| "expected 32 bytes".into()) }
    fn uint(&mut self) -> Result<u64, String> {
        let t = self.byte()?;
        Ok(match t { 0..=127 => t as u64, 0xcc => self.byte()? as u64, 0xcd => u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64,
            0xce => u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64, 0xcf => u64::from_be_bytes(self.take(8)?.try_into().unwrap()), _ => return Err("expected uint".into()) })
    }
    fn map(&mut self) -> Result<usize, String> { let t = self.byte()?; if t & 0xf0 != 0x80 { return Err("expected map".into()) } Ok((t & 15) as usize) }
    fn txn_or_signed(&mut self) -> Result<Pay, String> {
        let save = self.i; let n = self.map()?;
        if self.str()? == "sig" {
            if n != 2 { return Err("only {sig,txn} signed transactions are supported (no msig/lsig)".into()) }
            let sig: [u8; 64] = self.bin()?.try_into().map_err(|_| "bad sig length")?;
            if self.str()? != "txn" { return Err("expected txn".into()) }
            let mut p = self.txn()?; p.sig = Some(sig); return Ok(p)
        }
        self.i = save; self.txn()
    }
    fn txn(&mut self) -> Result<Pay, String> {
        let n = self.map()?; let mut p = Pay::default();
        for _ in 0..n {
            match self.str()?.as_str() {
                "amt" => p.amt = self.uint()?, "close" => p.close = Some(self.b32()?), "fee" => p.fee = self.uint()?, "fv" => p.fv = self.uint()?,
                "gen" => p.gen = self.str()?, "gh" => p.gh = self.b32()?, "lv" => p.lv = self.uint()?, "note" => p.note = self.bin()?.to_vec(),
                "rcv" => p.rcv = self.b32()?, "snd" => p.snd = self.b32()?,
                "type" => if self.str()? != "pay" { return Err("only pay transactions are supported".into()) },
                k => return Err(format!("unsupported field {k} (rekey, lease and group are refused)")),
            }
        }
        Ok(p)
    }
}
pub fn address(pk: &[u8; 32]) -> String { blocktools_core::chains::algo_address(pk) }
pub fn decode_address(a: &str) -> Result<[u8; 32], &'static str> { blocktools_core::chains::algo_decode(a) }
