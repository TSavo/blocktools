//! Polkadot Asset Hub balance transfer (extrinsic v4, sr25519). UNVERIFIED: no official signed vector
//! exists (sr25519 signatures are randomised and the payload depends on the runtime's extensions); the
//! call and signing payload are cross-checked against py-substrate-interface 1.7 (metadata-driven) and
//! signatures verify both ways. Layout is for Polkadot Asset Hub spec 2005000 / tx version 15:
//! extensions AuthorizeCall, CheckNonZeroSender, CheckSpecVersion, CheckTxVersion, CheckGenesis,
//! CheckMortality, CheckNonce, CheckWeight, ChargeAssetTxPayment, PrevalidateAttests, CheckMetadataHash,
//! EthSetOrigin, StorageWeightReclaim. Explicit: era, Compact nonce, Compact tip, Option<asset>=None,
//! metadata-hash mode=0. Implicit: spec, tx version, genesis, era block hash, Option<hash>=None.
//! A runtime upgrade that changes extensions or Balances' index (10) breaks this; build checks spec/tx version.
use blocktools_core::blake2b::blake2b;

pub const PALLET_BALANCES: u8 = 10;
pub const CALL_KEEP_ALIVE: u8 = 3;
pub const CALL_TRANSFER_ALL: u8 = 4;
pub const SPEC: u32 = 2_005_000;
pub const TX_VERSION: u32 = 15;
pub const GENESIS: [u8; 32] = [0x68,0xd5,0x6f,0x15,0xf8,0x5d,0x31,0x36,0x97,0x0e,0xc1,0x69,0x46,0x04,0x0b,0xc1,0x75,0x26,0x54,0xe9,0x06,0x14,0x7f,0x7e,0x43,0xe9,0xd5,0x39,0xd7,0xc3,0xde,0x2f];
pub const DECIMALS: u32 = 10;
/// Existential deposit on Polkadot Asset Hub: 0.01 DOT.
pub const ED: u128 = 100_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind { Pay(u128), Sweep }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    pub from: [u8; 32], pub to: [u8; 32], pub kind: Kind,
    /// None = immortal; Some((period, block_number, block_hash)).
    pub era: Option<(u64, u64, [u8; 32])>,
    pub nonce: u32, pub tip: u128, pub spec: u32, pub tx_version: u32, pub genesis: [u8; 32],
    pub sig: Option<[u8; 64]>,
}

pub fn compact(o: &mut Vec<u8>, v: u128) {
    if v < 1 << 6 { o.push((v as u8) << 2) } else if v < 1 << 14 { o.extend(((v as u16) << 2 | 1).to_le_bytes()) }
    else if v < 1 << 30 { o.extend(((v as u32) << 2 | 2).to_le_bytes()) }
    else { let b = v.to_le_bytes(); let n = 16 - (v.leading_zeros() / 8) as usize; o.push(((n as u8 - 4) << 2) | 3); o.extend_from_slice(&b[..n]) }
}
fn read_compact(b: &[u8], i: &mut usize) -> Result<u128, &'static str> {
    let f = *b.get(*i).ok_or("short")?;
    let (v, n) = match f & 3 {
        0 => ((f >> 2) as u128, 1), 1 => ((u16::from_le_bytes(b.get(*i..*i + 2).ok_or("short")?.try_into().unwrap()) >> 2) as u128, 2),
        2 => ((u32::from_le_bytes(b.get(*i..*i + 4).ok_or("short")?.try_into().unwrap()) >> 2) as u128, 4),
        _ => { let n = (f >> 2) as usize + 4; if n > 16 { return Err("compact too big") } let mut a = [0u8; 16]; a[..n].copy_from_slice(b.get(*i + 1..*i + 1 + n).ok_or("short")?); (u128::from_le_bytes(a), n + 1) }
    };
    *i += n; let mut c = vec![]; compact(&mut c, v); if c.len() != n { return Err("non-canonical compact") } Ok(v)
}
/// Mortal era (period rounded up to a power of two in 4..=65536), substrate `Era::mortal`.
pub fn era_bytes(e: &Option<(u64, u64, [u8; 32])>) -> Vec<u8> {
    match e { None => vec![0], Some((p, cur, _)) => {
        let period = p.checked_next_power_of_two().unwrap_or(1 << 16).clamp(4, 1 << 16);
        let phase = cur % period; let q = (period >> 12).max(1); let qp = phase / q * q;
        let enc = (period.trailing_zeros() - 1).clamp(1, 15) as u16 | ((qp / q) << 4) as u16;
        enc.to_le_bytes().to_vec() } }
}
impl Transfer {
    pub fn call(&self) -> Vec<u8> {
        let mut o = vec![PALLET_BALANCES];
        match self.kind { Kind::Pay(v) => { o.push(CALL_KEEP_ALIVE); o.push(0); o.extend(self.to); compact(&mut o, v) }
            Kind::Sweep => { o.push(CALL_TRANSFER_ALL); o.push(0); o.extend(self.to); o.push(0) } }
        o
    }
    fn extra(&self) -> Vec<u8> { let mut o = era_bytes(&self.era); compact(&mut o, self.nonce as u128); compact(&mut o, self.tip); o.extend([0, 0]); o }
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut o = self.call(); o.extend(self.extra()); o.extend(self.spec.to_le_bytes()); o.extend(self.tx_version.to_le_bytes());
        o.extend(self.genesis); o.extend(self.era.map(|e| e.2).unwrap_or(self.genesis)); o.push(0);
        if o.len() > 256 { blake2b(32, &[0; 16], &o) } else { o }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0x84, 0]; b.extend(self.from); b.push(1); b.extend(self.sig.unwrap_or([0; 64])); b.extend(self.extra()); b.extend(self.call());
        let mut o = vec![]; compact(&mut o, b.len() as u128); o.extend(b); o
    }
    pub fn hash(&self) -> [u8; 32] { blake2b(32, &[0; 16], &self.encode()).try_into().unwrap() }
    pub fn sign(&mut self, mini: &[u8; 32]) -> Result<(), &'static str> {
        let kp = schnorrkel::MiniSecretKey::from_bytes(mini).map_err(|_| "bad key")?.expand_to_keypair(schnorrkel::ExpansionMode::Ed25519);
        if kp.public.to_bytes() != self.from { return Err("key_does_not_match_from") }
        let t = schnorrkel::signing_context(b"substrate").bytes(&self.signing_payload());
        // Witness = transcript keyed by the secret nonce + OS-free fixed rng: deterministic per message, never reused across messages.
        self.sig = Some(kp.sign(schnorrkel::context::attach_rng(t, Zero)).to_bytes()); Ok(())
    }
    pub fn verify(&self) -> bool {
        let (Some(s), Ok(pk)) = (self.sig, schnorrkel::PublicKey::from_bytes(&self.from)) else { return false };
        schnorrkel::Signature::from_bytes(&s).is_ok_and(|s| pk.verify_simple(b"substrate", &self.signing_payload(), &s).is_ok())
    }
    /// Parse a signed extrinsic produced by `encode`, given the implicit fields; re-encodes and compares.
    pub fn decode(b: &[u8], spec: u32, tx_version: u32, genesis: [u8; 32], era_block: Option<(u64, [u8; 32])>) -> Result<Self, &'static str> {
        let mut i = 0; let n = read_compact(b, &mut i)? as usize; if b.len() != i + n { return Err("length mismatch") }
        if b.get(i..i + 2) != Some(&[0x84, 0]) { return Err("not a signed v4 extrinsic with MultiAddress::Id") } i += 2;
        let from: [u8; 32] = b.get(i..i + 32).ok_or("short")?.try_into().unwrap(); i += 32;
        if b.get(i) != Some(&1) { return Err("not sr25519") } i += 1;
        let sig: [u8; 64] = b.get(i..i + 64).ok_or("short")?.try_into().unwrap(); i += 64;
        let era = if b.get(i) == Some(&0) { i += 1; None } else {
            let e = u16::from_le_bytes(b.get(i..i + 2).ok_or("short")?.try_into().unwrap()); i += 2;
            let (num, h) = era_block.ok_or("mortal era needs block number/hash")?; Some((2u64 << (e % 16), num, h)) };
        let nonce = u32::try_from(read_compact(b, &mut i)?).map_err(|_| "nonce")?; let tip = read_compact(b, &mut i)?;
        if b.get(i..i + 2) != Some(&[0, 0]) { return Err("asset/metadata-hash mode not supported") } i += 2;
        if b.get(i) != Some(&PALLET_BALANCES) || b.get(i + 2) != Some(&0) { return Err("not a Balances transfer") }
        let c = b[i + 1]; let to: [u8; 32] = b.get(i + 3..i + 35).ok_or("short")?.try_into().unwrap(); i += 35;
        let kind = match c { CALL_KEEP_ALIVE => Kind::Pay(read_compact(b, &mut i)?), CALL_TRANSFER_ALL => { if b.get(i) != Some(&0) { return Err("keep_alive must be false") } i += 1; Kind::Sweep } _ => return Err("unsupported call") };
        let t = Transfer { from, to, kind, era, nonce, tip, spec, tx_version, genesis, sig: Some(sig) };
        if t.encode() != b { return Err("non-canonical encoding") } Ok(t)
    }
}
struct Zero;
impl rand_core::RngCore for Zero {
    fn next_u32(&mut self) -> u32 { 0 } fn next_u64(&mut self) -> u64 { 0 }
    fn fill_bytes(&mut self, d: &mut [u8]) { d.fill(0) }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_core::Error> { d.fill(0); Ok(()) }
}
impl rand_core::CryptoRng for Zero {}
pub fn parse_address(a: &str) -> Result<[u8; 32], &'static str> { blocktools_core::chains::ss58_decode(0, a) }
pub fn address(pk: &[u8; 32]) -> String { blocktools_core::chains::ss58_address(0, pk) }
