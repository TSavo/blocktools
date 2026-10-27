//! Decode-only view of every EVM transaction envelope tx-decode reads: legacy (pre- and post-EIP-155),
//! EIP-2930 (type 1), EIP-1559 (type 2), EIP-4844 (type 3, canonical and network/blob-wrapper form)
//! and EIP-7702 (type 4). Used by `tx-decode` only: `evm::Tx::parse` (what tx-verify / tx-sign /
//! tx-broadcast read) still accepts legacy and type 2 only, so widening decoding widens no signing path.
//! The sender is recovered from the signature over the type's signing payload; the hash is the
//! Keccak-256 of the canonical signed envelope (for a 4844 network form, of the unwrapped tx).
use crate::rlp::{self, Rlp};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};
use serde_json::{json, Map, Value};
use sha3::{Digest, Keccak256};

#[derive(Debug, Clone)]
pub struct View {
    /// 0 legacy, 1 EIP-2930, 2 EIP-1559, 3 EIP-4844, 4 EIP-7702
    pub tx_type: u8,
    pub chain_id: Option<u64>,
    pub nonce: u64,
    pub gas_price: Option<u128>,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub gas: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Option<Vec<([u8; 20], Vec<[u8; 32]>)>>,
    pub max_fee_per_blob_gas: Option<u128>,
    pub blob_versioned_hashes: Option<Vec<[u8; 32]>>,
    /// EIP-7702 authorizations: (chain_id, address, nonce, y_parity, r, s)
    pub authorization_list: Option<Vec<([u8; 32], [u8; 20], u64, u64, [u8; 32], [u8; 32])>>,
    /// (v or yParity, r, s)
    pub sig: Option<(u64, [u8; 32], [u8; 32])>,
    pub hash: Option<[u8; 32]>,
    pub from: Option<[u8; 20]>,
    /// blob-carrying 4844 network form (blobs, commitments, proofs not checked, only counted)
    pub blobs: Option<usize>,
}

fn bytes(r: &Rlp) -> Result<&[u8], &'static str> { match r { Rlp::B(b) => Ok(b), _ => Err("expected_bytes") } }
fn list(r: &Rlp) -> Result<&[Rlp], &'static str> { match r { Rlp::L(l) => Ok(l), _ => Err("expected_list") } }
fn int(r: &Rlp, max: usize) -> Result<u128, &'static str> {
    let b = bytes(r)?;
    if b.len() > max { return Err("integer_too_large") }
    if b.first() == Some(&0) { return Err("non_canonical") }
    Ok(b.iter().fold(0u128, |a, &x| a << 8 | x as u128))
}
fn u64f(r: &Rlp) -> Result<u64, &'static str> { Ok(int(r, 8)? as u64) }
fn b32(r: &Rlp) -> Result<[u8; 32], &'static str> {
    let b = bytes(r)?; if b.len() > 32 { return Err("bad_signature") }
    let mut o = [0u8; 32]; o[32 - b.len()..].copy_from_slice(b); Ok(o)
}
fn exact32(r: &Rlp) -> Result<[u8; 32], &'static str> {
    let b = bytes(r)?; if b.len() != 32 { return Err("bad_hash_length") }
    let mut o = [0u8; 32]; o.copy_from_slice(b); Ok(o)
}
fn addr20(r: &Rlp) -> Result<[u8; 20], &'static str> {
    let b = bytes(r)?; if b.len() != 20 { return Err("bad_to_address") }
    let mut a = [0; 20]; a.copy_from_slice(b); Ok(a)
}
fn to_field(r: &Rlp) -> Result<Option<[u8; 20]>, &'static str> { if bytes(r)?.is_empty() { Ok(None) } else { addr20(r).map(Some) } }
fn access_list(r: &Rlp) -> Result<Vec<([u8; 20], Vec<[u8; 32]>)>, &'static str> {
    list(r)?.iter().map(|e| {
        let e = list(e)?; if e.len() != 2 { return Err("bad_access_list") }
        Ok((addr20(&e[0]).map_err(|_| "bad_access_list")?, list(&e[1])?.iter().map(exact32).collect::<Result<_, _>>()?))
    }).collect()
}
fn recover(payload: &[u8], rec: u64, r: &[u8; 32], s: &[u8; 32]) -> Option<[u8; 20]> {
    let mut rs = [0u8; 64]; rs[..32].copy_from_slice(r); rs[32..].copy_from_slice(s);
    let sig = RecoverableSignature::from_compact(&rs, RecoveryId::from_i32(i32::try_from(rec).ok()?).ok()?).ok()?;
    let h: [u8; 32] = Keccak256::digest(payload).into();
    let pk = Secp256k1::verification_only().recover_ecdsa(&Message::from_digest(h), &sig).ok()?;
    let k = Keccak256::digest(&pk.serialize_uncompressed()[1..]);
    let mut a = [0; 20]; a.copy_from_slice(&k[12..]); Some(a)
}
fn typed(t: u8, f: &[Rlp]) -> Vec<u8> { let mut o = vec![t]; o.extend(rlp::encode(&Rlp::L(f.to_vec()))); o }

/// True when the bytes look like an EVM envelope (an RLP list, or a type byte 0x01..=0x04 then a list).
pub fn is_evm(b: &[u8]) -> bool {
    match (b.first(), b.get(1)) { (Some(&x), _) if x >= 0xc0 => true, (Some(1..=4), Some(&x)) => x >= 0xc0, _ => false }
}

/// (offset of payload, payload length) of the RLP item at the start of `b`.
fn header(b: &[u8]) -> Option<(usize, usize, bool)> {
    let p = *b.first()?;
    let be = |n: usize| -> Option<usize> { let l = b.get(1..1 + n)?; if n > 4 || l[0] == 0 { return None } Some(l.iter().fold(0usize, |a, &x| a << 8 | x as usize)) };
    Some(match p { 0..=0x7f => (0, 1, false), 0x80..=0xb7 => (1, (p - 0x80) as usize, false), 0xb8..=0xbf => { let n = (p - 0xb7) as usize; (1 + n, be(n)?, false) }
        0xc0..=0xf7 => (1, (p - 0xc0) as usize, true), _ => { let n = (p - 0xf7) as usize; (1 + n, be(n)?, true) } })
}
/// The four item slices of a blob network wrapper (outer list whose first item is a list), else None.
fn network_items(b: &[u8]) -> Option<Vec<&[u8]>> {
    let (h, len, is_list) = header(b)?;
    if !is_list || h.checked_add(len)? != b.len() { return None }
    let mut body = &b[h..]; let mut v = vec![];
    while !body.is_empty() { let (h, l, _) = header(body)?; let end = h.checked_add(l)?; v.push(body.get(..end)?); body = &body[end..]; }
    (v.len() == 4 && header(v[0])?.2).then_some(v)
}

pub fn parse(raw: &[u8]) -> Result<View, &'static str> {
    if raw.len() > crate::MAX_INPUT { return Err("too_large") }
    let first = *raw.first().ok_or("truncated")?;
    if first >= 0xc0 { return legacy(raw) }
    if !(1..=4).contains(&first) { return Err("not_evm") }
    let mut blobs = None;
    // 4844 network form: 0x03 || rlp([tx_payload_body, blobs, commitments, proofs]). Its items are split here and
    // decoded one by one, so the shared RLP depth bound (also what signing reads) is not raised for the wrapper.
    let f: Vec<Rlp> = match (first, network_items(&raw[1..])) {
        (3, Some(items)) => {
            let n = items[1..].iter().map(|i| rlp::decode(i).and_then(|x| list(&x).map(|l| l.len()))).collect::<Result<Vec<_>, _>>()?;
            if n[0] != n[1] || n[0] != n[2] { return Err("blob_sidecar_count_mismatch") }
            blobs = Some(n[0]);
            list(&rlp::decode(items[0])?)?.to_vec()
        }
        _ => list(&rlp::decode(&raw[1..])?)?.to_vec(),
    };
    let unsigned_len = match first { 1 => 8, 2 => 9, 3 => 11, _ => 10 };
    if f.len() != unsigned_len && f.len() != unsigned_len + 3 { return Err("bad_field_count") }
    let mut v = View { tx_type: first, chain_id: Some(u64f(&f[0])?), nonce: u64f(&f[1])?, gas_price: None, max_fee_per_gas: None,
        max_priority_fee_per_gas: None, gas: 0, to: None, value: 0, data: vec![], access_list: None, max_fee_per_blob_gas: None,
        blob_versioned_hashes: None, authorization_list: None, sig: None, hash: None, from: None, blobs };
    let i = if first == 1 { v.gas_price = Some(int(&f[2], 16)?); 3 } else {
        v.max_priority_fee_per_gas = Some(int(&f[2], 16)?); v.max_fee_per_gas = Some(int(&f[3], 16)?); 4 };
    v.gas = u64f(&f[i])?; v.to = to_field(&f[i + 1])?; v.value = int(&f[i + 2], 16)?; v.data = bytes(&f[i + 3])?.to_vec();
    v.access_list = Some(access_list(&f[i + 4])?);
    if (first == 3 || first == 4) && v.to.is_none() { return Err("to_required") }
    if first == 3 {
        v.max_fee_per_blob_gas = Some(int(&f[9], 16)?);
        let h: Vec<[u8; 32]> = list(&f[10])?.iter().map(exact32).collect::<Result<_, _>>()?;
        if h.is_empty() { return Err("no_blob_hashes") }
        v.blob_versioned_hashes = Some(h);
    }
    if first == 4 {
        let a = list(&f[9])?.iter().map(|e| {
            let e = list(e)?; if e.len() != 6 { return Err("bad_authorization") }
            Ok((b32(&e[0])?, addr20(&e[1])?, u64f(&e[2])?, u64f(&e[3])?, b32(&e[4])?, b32(&e[5])?))
        }).collect::<Result<Vec<_>, _>>()?;
        if a.is_empty() { return Err("empty_authorization_list") }
        v.authorization_list = Some(a);
    }
    if f.len() == unsigned_len + 3 {
        let y = u64f(&f[unsigned_len])?; if y > 1 { return Err("bad_y_parity") }
        let (r, s) = (b32(&f[unsigned_len + 1])?, b32(&f[unsigned_len + 2])?);
        v.sig = Some((y, r, s));
        v.from = recover(&typed(first, &f[..unsigned_len]), y, &r, &s);
        v.hash = Some(Keccak256::digest(typed(first, &f)).into());
    }
    Ok(v)
}

fn legacy(raw: &[u8]) -> Result<View, &'static str> {
    let top = rlp::decode(raw)?;
    let f = list(&top)?;
    if f.len() != 6 && f.len() != 9 { return Err("bad_field_count") }
    let mut v = View { tx_type: 0, chain_id: None, nonce: u64f(&f[0])?, gas_price: Some(int(&f[1], 16)?), max_fee_per_gas: None,
        max_priority_fee_per_gas: None, gas: u64f(&f[2])?, to: to_field(&f[3])?, value: int(&f[4], 16)?, data: bytes(&f[5])?.to_vec(),
        access_list: None, max_fee_per_blob_gas: None, blob_versioned_hashes: None, authorization_list: None, sig: None, hash: None, from: None, blobs: None };
    if f.len() == 9 {
        let n = u64f(&f[6])?; let (r, s) = (b32(&f[7])?, b32(&f[8])?);
        if r == [0; 32] && s == [0; 32] { v.chain_id = Some(n); return Ok(v) } // unsigned EIP-155 form
        let (rec, payload) = match n {
            27 | 28 => (n - 27, rlp::encode(&Rlp::L(f[..6].to_vec()))),
            n if n >= 35 => {
                let c = (n - 35) / 2; v.chain_id = Some(c);
                let mut p = f[..6].to_vec(); p.extend([rlp::uint(c as u128), Rlp::B(vec![]), Rlp::B(vec![])]);
                (n - 35 - 2 * c, rlp::encode(&Rlp::L(p)))
            }
            _ => return Err("bad_v"),
        };
        v.sig = Some((n, r, s));
        v.from = recover(&payload, rec, &r, &s);
        v.hash = Some(Keccak256::digest(raw).into());
    }
    Ok(v)
}

fn hx(b: &[u8]) -> String { format!("0x{}", crate::hex_enc(b)) }
fn checksum(a: &[u8; 20]) -> String { crate::addr(a) }

impl View {
    pub fn type_name(&self) -> &'static str {
        match self.tx_type { 0 => "evm-legacy", 1 => "evm-2930", 2 => "evm-1559", 3 => "evm-4844", _ => "evm-7702" }
    }
    /// Additive keys merged into tx-decode's summary line. Names and encodings follow
    /// eth_getTransactionByHash (hex quantities, 0x data) in snake_case.
    pub fn extra(&self) -> Map<String, Value> {
        let mut o = Map::new();
        o.insert("tx_type".into(), json!(self.tx_type));
        if let Some(p) = self.gas_price { o.insert("gas_price".into(), json!(p.to_string())); }
        o.insert("data".into(), json!(hx(&self.data)));
        if let Some(a) = &self.access_list {
            o.insert("access_list".into(), json!(a.iter().map(|(ad, k)| json!({"address": checksum(ad), "storage_keys": k.iter().map(|x| hx(x)).collect::<Vec<_>>()})).collect::<Vec<_>>()));
        }
        if let Some(p) = self.max_fee_per_blob_gas { o.insert("max_fee_per_blob_gas".into(), json!(p.to_string())); }
        if let Some(h) = &self.blob_versioned_hashes { o.insert("blob_versioned_hashes".into(), json!(h.iter().map(|x| hx(x)).collect::<Vec<_>>())); }
        if let Some(n) = self.blobs { o.insert("blob_sidecar".into(), json!(n)); }
        if let Some(a) = &self.authorization_list {
            o.insert("authorization_list".into(), json!(a.iter().map(|(c, ad, n, y, r, s)| json!({"chain_id": q_bytes(c), "address": checksum(ad), "nonce": n, "y_parity": y, "r": q_bytes(r), "s": q_bytes(s)})).collect::<Vec<_>>()));
        }
        if let Some((v, r, s)) = &self.sig {
            o.insert("v".into(), json!(v)); o.insert("r".into(), json!(q_bytes(r))); o.insert("s".into(), json!(q_bytes(s)));
        }
        o
    }
    /// Display-only `evm::Tx` (fee fields: the effective cap; kind only steers the text summary).
    pub fn as_tx(&self) -> crate::evm::Tx {
        crate::evm::Tx { kind: if self.tx_type == 0 { crate::evm::Kind::Legacy } else { crate::evm::Kind::Eip1559 }, chain_id: self.chain_id, nonce: self.nonce,
            max_fee_per_gas: self.max_fee_per_gas.or(self.gas_price).unwrap_or(0), max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            gas: self.gas, to: self.to, value: self.value, data: self.data.clone(), access_list: Rlp::L(vec![]), sig: self.sig }
    }
}
/// A 32-byte signature scalar as a minimal hex quantity, the eth_getTransactionByHash spelling.
fn q_bytes(b: &[u8; 32]) -> String {
    let s: Vec<u8> = b.iter().copied().skip_while(|&x| x == 0).collect();
    if s.is_empty() { return "0x0".into() }
    let h = crate::hex_enc(&s); format!("0x{}", h.trim_start_matches('0'))
}
