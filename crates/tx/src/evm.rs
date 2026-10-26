//! EVM transactions: legacy (EIP-155) and EIP-1559 (type 2). Parse, encode, signing hash.
//! Primitives: Keccak-256 (sha3 crate) and secp256k1 (recoverable ECDSA). Nothing hand-rolled.
use crate::rlp::{self, Rlp};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
#[cfg(feature = "secrets")]
use secp256k1::SecretKey;
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind { Legacy, Eip1559 }
#[derive(Debug, Clone, PartialEq)]
pub struct Tx {
    pub kind: Kind,
    pub chain_id: Option<u64>,
    pub nonce: u64,
    /// legacy gasPrice, or EIP-1559 maxFeePerGas
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: Option<u128>,
    pub gas: u64,
    pub to: Option<[u8; 20]>,
    /// value in wei (u128 is ~3.4e20 ETH; larger is rejected)
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Rlp,
    /// (v or yParity, r, s)
    pub sig: Option<(u64, [u8; 32], [u8; 32])>,
}
fn bytes(r: &Rlp) -> Result<&[u8], &'static str> { match r { Rlp::B(b) => Ok(b), _ => Err("expected_bytes") } }
fn int(r: &Rlp, max: usize) -> Result<u128, &'static str> {
    let b = bytes(r)?;
    if b.len() > max { return Err("integer_too_large") }
    if b.first() == Some(&0) { return Err("non_canonical") }
    Ok(b.iter().fold(0u128, |a, &x| a << 8 | x as u128))
}
fn b32(r: &Rlp) -> Result<[u8; 32], &'static str> {
    let b = bytes(r)?; if b.len() > 32 { return Err("bad_signature") }
    let mut o = [0u8; 32]; o[32 - b.len()..].copy_from_slice(b); Ok(o)
}
fn to_field(r: &Rlp) -> Result<Option<[u8; 20]>, &'static str> {
    let b = bytes(r)?;
    match b.len() { 0 => Ok(None), 20 => { let mut a = [0; 20]; a.copy_from_slice(b); Ok(Some(a)) }, _ => Err("bad_to_address") }
}
fn tb(b: &[u8]) -> Rlp { Rlp::B(b.to_vec()) }
fn strip(b: &[u8; 32]) -> Rlp { Rlp::B(b.iter().copied().skip_while(|&x| x == 0).collect()) }

impl Tx {
    pub fn parse(raw: &[u8]) -> Result<Tx, &'static str> {
        if raw.len() > 1 << 20 { return Err("too_large") }
        match raw.first() {
            Some(0x02) => {
                let Rlp::L(f) = rlp::decode(&raw[1..])? else { return Err("expected_list") };
                if f.len() != 9 && f.len() != 12 { return Err("bad_field_count") }
                let sig = if f.len() == 12 {
                    let y = int(&f[9], 1)? as u64; if y > 1 { return Err("bad_y_parity") }
                    Some((y, b32(&f[10])?, b32(&f[11])?))
                } else { None };
                if !matches!(f[8], Rlp::L(_)) { return Err("bad_access_list") }
                Ok(Tx { kind: Kind::Eip1559, chain_id: Some(int(&f[0], 8)? as u64), nonce: int(&f[1], 8)? as u64,
                    max_priority_fee_per_gas: Some(int(&f[2], 16)?), max_fee_per_gas: int(&f[3], 16)?, gas: int(&f[4], 8)? as u64,
                    to: to_field(&f[5])?, value: int(&f[6], 16)?, data: bytes(&f[7])?.to_vec(), access_list: f[8].clone(), sig })
            }
            Some(&b) if b >= 0xc0 => {
                let Rlp::L(f) = rlp::decode(raw)? else { return Err("expected_list") };
                if f.len() != 6 && f.len() != 9 { return Err("bad_field_count") }
                let base = |chain_id, sig| -> Result<Tx, &'static str> { Ok(Tx { kind: Kind::Legacy, chain_id, nonce: int(&f[0], 8)? as u64,
                    max_fee_per_gas: int(&f[1], 16)?, max_priority_fee_per_gas: None, gas: int(&f[2], 8)? as u64, to: to_field(&f[3])?,
                    value: int(&f[4], 16)?, data: bytes(&f[5])?.to_vec(), access_list: Rlp::L(vec![]), sig }) };
                if f.len() == 6 { return base(None, None) }
                let v = int(&f[6], 8)? as u64; let (r, s) = (b32(&f[7])?, b32(&f[8])?);
                if r == [0; 32] && s == [0; 32] { return base(Some(v), None) } // unsigned EIP-155 form
                match v { 27 | 28 => base(None, Some((v, r, s))), v if v >= 35 => base(Some((v - 35) / 2), Some((v, r, s))), _ => Err("bad_v") }
            }
            Some(0x01) => Err("eip2930_unsupported"),
            Some(0x03) => Err("eip4844_unsupported"),
            Some(0x04) => Err("eip7702_unsupported"),
            _ => Err("not_evm"),
        }
    }
    fn fields(&self) -> Vec<Rlp> {
        let to = self.to.map_or(Rlp::B(vec![]), |a| tb(&a));
        match self.kind {
            Kind::Eip1559 => vec![rlp::uint(self.chain_id.unwrap_or(0) as u128), rlp::uint(self.nonce as u128),
                rlp::uint(self.max_priority_fee_per_gas.unwrap_or(0)), rlp::uint(self.max_fee_per_gas), rlp::uint(self.gas as u128),
                to, rlp::uint(self.value), tb(&self.data), self.access_list.clone()],
            Kind::Legacy => vec![rlp::uint(self.nonce as u128), rlp::uint(self.max_fee_per_gas), rlp::uint(self.gas as u128),
                to, rlp::uint(self.value), tb(&self.data)],
        }
    }
    /// Unsigned serialization (what tx-build emits and tx-sign consumes).
    pub fn encode_unsigned(&self) -> Vec<u8> {
        let mut f = self.fields();
        match self.kind {
            Kind::Eip1559 => { let mut o = vec![2]; o.extend(rlp::encode(&Rlp::L(f))); o }
            Kind::Legacy => {
                if let Some(c) = self.chain_id { f.extend([rlp::uint(c as u128), Rlp::B(vec![]), Rlp::B(vec![])]) }
                rlp::encode(&Rlp::L(f))
            }
        }
    }
    pub fn encode_signed(&self) -> Option<Vec<u8>> {
        let (v, r, s) = self.sig?;
        let mut f = self.fields(); f.extend([rlp::uint(v as u128), strip(&r), strip(&s)]);
        Some(match self.kind { Kind::Eip1559 => { let mut o = vec![2]; o.extend(rlp::encode(&Rlp::L(f))); o } Kind::Legacy => rlp::encode(&Rlp::L(f)) })
    }
    /// Keccak-256 signing hash (EIP-155 for legacy with chain id, EIP-1559 for type 2).
    pub fn sighash(&self) -> [u8; 32] { Keccak256::digest(self.encode_unsigned()).into() }
    pub fn txhash(&self) -> Option<[u8; 32]> { Some(Keccak256::digest(self.encode_signed()?).into()) }
    /// Sender address recovered from the signature.
    pub fn from(&self) -> Option<[u8; 20]> {
        let (v, r, s) = self.sig?;
        let rec = match (self.kind, self.chain_id) { (Kind::Eip1559, _) => v, (_, Some(c)) => v.checked_sub(35 + 2 * c)?, (_, None) => v.checked_sub(27)? };
        let mut rs = [0u8; 64]; rs[..32].copy_from_slice(&r); rs[32..].copy_from_slice(&s);
        let sig = RecoverableSignature::from_compact(&rs, RecoveryId::from_i32(rec as i32).ok()?).ok()?;
        let pk = Secp256k1::verification_only().recover_ecdsa(&Message::from_digest(self.sighash()), &sig).ok()?;
        let h = Keccak256::digest(&pk.serialize_uncompressed()[1..]);
        let mut a = [0; 20]; a.copy_from_slice(&h[12..]); Some(a)
    }
    /// Sign in place. Feature `secrets` only. (RFC6979 deterministic nonce, low-s, from secp256k1).
    #[cfg(feature = "secrets")]
    pub fn sign(&mut self, sk: &SecretKey) -> Result<(), &'static str> {
        if self.chain_id.is_none() { return Err("refuse_no_chain_id") }
        let sig = Secp256k1::signing_only().sign_ecdsa_recoverable(&Message::from_digest(self.sighash()), sk);
        let (id, rs) = sig.serialize_compact();
        let mut r = [0; 32]; let mut s = [0; 32]; r.copy_from_slice(&rs[..32]); s.copy_from_slice(&rs[32..]);
        let rec = id.to_i32() as u64;
        let v = match self.kind { Kind::Eip1559 => rec, Kind::Legacy => rec + 35 + 2 * self.chain_id.unwrap() };
        self.sig = Some((v, r, s)); Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct TokenCall { pub method: &'static str, pub to: [u8; 20], pub amount: [u8; 32] }
pub const TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
pub const APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
pub const TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
/// Recognise ERC-20 transfer / approve / transferFrom calldata (strict ABI shape).
pub fn token_call(d: &[u8]) -> Option<TokenCall> {
    let word = |i: usize| -> &[u8] { &d[4 + 32 * i..4 + 32 * (i + 1)] };
    let addr = |w: &[u8]| -> Option<[u8; 20]> { if w[..12].iter().any(|&x| x != 0) { return None } let mut a = [0; 20]; a.copy_from_slice(&w[12..]); Some(a) };
    let amt = |w: &[u8]| { let mut a = [0; 32]; a.copy_from_slice(w); a };
    match (d.get(..4)?, d.len()) {
        (s, 68) if s == TRANSFER => Some(TokenCall { method: "transfer", to: addr(word(0))?, amount: amt(word(1)) }),
        (s, 68) if s == APPROVE => Some(TokenCall { method: "approve", to: addr(word(0))?, amount: amt(word(1)) }),
        (s, 100) if s == TRANSFER_FROM => Some(TokenCall { method: "transferFrom", to: addr(word(1))?, amount: amt(word(2)) }),
        _ => None,
    }
}
pub fn transfer_calldata(to: &[u8; 20], amount: u128) -> Vec<u8> {
    let mut d = TRANSFER.to_vec(); d.extend([0u8; 12]); d.extend(to); d.extend([0u8; 16]); d.extend(amount.to_be_bytes()); d
}
/// Big-endian unsigned bytes -> decimal string (any length up to 32 bytes).
pub fn dec(be: &[u8]) -> String {
    let mut n: Vec<u8> = be.iter().copied().skip_while(|&x| x == 0).collect();
    if n.is_empty() { return "0".into() }
    let mut out = Vec::new();
    while !n.is_empty() {
        let mut rem = 0u32;
        for b in n.iter_mut() { let cur = rem << 8 | *b as u32; *b = (cur / 10) as u8; rem = cur % 10; }
        out.push(b'0' + rem as u8);
        while n.first() == Some(&0) { n.remove(0); }
    }
    out.reverse(); String::from_utf8(out).unwrap()
}
/// Native coin symbol for a chain id ("native" when unknown).
pub fn native_symbol(id: Option<u64>) -> &'static str {
    match id { Some(1 | 10 | 8453 | 42161 | 11155111 | 17000) => "ETH", Some(56) => "BNB", Some(137) => "POL", Some(43114) => "AVAX", _ => "native" }
}
pub fn chain_name(id: u64) -> &'static str {
    match id { 1 => "Ethereum mainnet", 10 => "Optimism", 56 => "BNB Smart Chain", 137 => "Polygon", 8453 => "Base",
        42161 => "Arbitrum One", 43114 => "Avalanche C-Chain", 11155111 => "Sepolia testnet", 17000 => "Holesky testnet", _ => "unknown chain" }
}
