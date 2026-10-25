//! Cardano Shelley-era ADA-only transaction: body {0 inputs, 1 outputs [addr, lovelace], 2 fee, 3 ttl},
//! one vkey witness, tx = [body, {0: [[vkey, sig]]}, true, null] (pycardano 0.19 encoding). txid = blake2b-256(body).
//! Signing uses the BIP32-Ed25519 extended key kL||kR (what `recover` prints as the ada private_key).
use curve25519_dalek::{EdwardsPoint, Scalar};
use sha2::{Digest, Sha512};

pub const MIN_FEE_A: u64 = 44;
pub const MIN_FEE_B: u64 = 155_381;
pub const MIN_OUTPUT: u64 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Tx { pub inputs: Vec<([u8; 32], u32)>, pub outputs: Vec<(Vec<u8>, u64)>, pub fee: u64, pub ttl: u64, pub wit: Option<([u8; 32], [u8; 64])> }

fn head(o: &mut Vec<u8>, major: u8, v: u64) {
    let m = major << 5;
    match v { 0..=23 => o.push(m | v as u8), 24..=0xff => { o.push(m | 24); o.push(v as u8) } 0x100..=0xffff => { o.push(m | 25); o.extend((v as u16).to_be_bytes()) }
        0x1_0000..=0xffff_ffff => { o.push(m | 26); o.extend((v as u32).to_be_bytes()) } _ => { o.push(m | 27); o.extend(v.to_be_bytes()) } }
}
fn bytes(o: &mut Vec<u8>, b: &[u8]) { head(o, 2, b.len() as u64); o.extend_from_slice(b) }

impl Tx {
    pub fn body(&self) -> Vec<u8> {
        let mut o = vec![]; head(&mut o, 5, 4);
        head(&mut o, 0, 0); head(&mut o, 4, self.inputs.len() as u64);
        for (h, i) in &self.inputs { head(&mut o, 4, 2); bytes(&mut o, h); head(&mut o, 0, *i as u64) }
        head(&mut o, 0, 1); head(&mut o, 4, self.outputs.len() as u64);
        for (a, v) in &self.outputs { head(&mut o, 4, 2); bytes(&mut o, a); head(&mut o, 0, *v) }
        head(&mut o, 0, 2); head(&mut o, 0, self.fee);
        head(&mut o, 0, 3); head(&mut o, 0, self.ttl);
        o
    }
    pub fn txid(&self) -> [u8; 32] { blocktools_core::blake2b::blake2b(32, &[0; 16], &self.body()).try_into().unwrap() }
    pub fn encode(&self) -> Vec<u8> {
        let mut o = vec![]; head(&mut o, 4, 4); o.extend(self.body());
        match &self.wit { None => head(&mut o, 5, 0), Some((pk, sg)) => { head(&mut o, 5, 1); head(&mut o, 0, 0); head(&mut o, 4, 1); head(&mut o, 4, 2); bytes(&mut o, pk); bytes(&mut o, sg) } }
        o.push(0xf5); o.push(0xf6); o
    }
    /// Size-based minimum fee with a placeholder witness (44 * bytes + 155381, mainnet params as of 2026).
    pub fn min_fee(&self) -> u64 { let t = Tx { wit: Some(([0; 32], [0; 64])), ..self.clone() }; MIN_FEE_A * t.encode().len() as u64 + MIN_FEE_B }
    pub fn input_total_needed(&self) -> u128 { self.outputs.iter().map(|o| o.1 as u128).sum::<u128>() + self.fee as u128 }
    pub fn sign(&mut self, xk: &[u8; 64]) -> [u8; 32] {
        let (pk, sg) = ext_sign(xk, &self.txid()); self.wit = Some((pk, sg)); pk
    }
    pub fn verify(&self) -> bool { self.wit.as_ref().is_some_and(|(pk, sg)| crate::ed_verify(pk, &self.txid(), sg)) }
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        let mut r = R { b, p: 0 };
        if r.head(4)? != 4 || r.head(5)? != 4 { return Err("not_a_simple_tx (want [body(4 fields), witnesses, true, null])") }
        let mut t = Tx::default();
        if r.head(0)? != 0 { return Err("body_key_0") }
        for _ in 0..r.head(4)? { if r.head(4)? != 2 { return Err("bad_input") } let h = r.bytes()?.try_into().map_err(|_| "bad_input_hash")?; t.inputs.push((h, r.head(0)?.try_into().map_err(|_| "bad_index")?)) }
        if r.head(0)? != 1 { return Err("body_key_1") }
        for _ in 0..r.head(4)? { if r.head(4)? != 2 { return Err("output_not_legacy_ada_only (assets/datum NOT BUILT)") } let a = r.bytes()?.to_vec(); t.outputs.push((a, r.head(0)?)) }
        if r.head(0)? != 2 { return Err("body_key_2") } t.fee = r.head(0)?;
        if r.head(0)? != 3 { return Err("body_key_3") } t.ttl = r.head(0)?;
        match r.head(5)? {
            0 => {}
            1 => { if r.head(0)? != 0 || r.head(4)? != 1 || r.head(4)? != 2 { return Err("witness_not_single_vkey") }
                   let pk = r.bytes()?.try_into().map_err(|_| "bad_vkey")?; let sg = r.bytes()?.try_into().map_err(|_| "bad_sig")?; t.wit = Some((pk, sg)) }
            _ => return Err("witness_not_single_vkey"),
        }
        if r.b.get(r.p..) != Some(&[0xf5, 0xf6][..]) { return Err("trailer_not_true_null (metadata NOT BUILT)") }
        if t.inputs.is_empty() || t.outputs.is_empty() { return Err("empty_inputs_or_outputs") }
        if t.encode() != b { return Err("non_canonical_cbor") }
        Ok(t)
    }
}
struct R<'a> { b: &'a [u8], p: usize }
impl R<'_> {
    fn head(&mut self, major: u8) -> Result<u64, &'static str> {
        let x = *self.b.get(self.p).ok_or("cbor_truncated")?; self.p += 1;
        if x >> 5 != major { return Err("cbor_unexpected_type") }
        let n = match x & 31 { v @ 0..=23 => return Ok(v as u64), 24 => 1, 25 => 2, 26 => 4, 27 => 8, _ => return Err("cbor_indefinite_or_bad") };
        let s = self.b.get(self.p..self.p + n).ok_or("cbor_truncated")?; self.p += n;
        Ok(s.iter().fold(0u64, |a, x| a << 8 | *x as u64))
    }
    fn bytes(&mut self) -> Result<&[u8], &'static str> {
        let n = self.head(2)? as usize; let s = self.b.get(self.p..self.p + n).ok_or("cbor_truncated")?; self.p += n; Ok(s)
    }
}
pub fn ext_pub(xk: &[u8; 64]) -> [u8; 32] { EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(xk[..32].try_into().unwrap())).compress().to_bytes() }
/// Ed25519 signature with an extended secret (kL scalar, kR nonce prefix), as cardano-crypto / pycardano.
pub fn ext_sign(xk: &[u8; 64], m: &[u8]) -> ([u8; 32], [u8; 64]) {
    let a = Scalar::from_bytes_mod_order(xk[..32].try_into().unwrap());
    let pk = EdwardsPoint::mul_base(&a).compress().to_bytes();
    let r = Scalar::from_hash(Sha512::new().chain_update(&xk[32..]).chain_update(m));
    let rr = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let h = Scalar::from_hash(Sha512::new().chain_update(rr).chain_update(pk).chain_update(m));
    let s = r + h * a;
    let mut sg = [0u8; 64]; sg[..32].copy_from_slice(&rr); sg[32..].copy_from_slice(s.as_bytes());
    (pk, sg)
}
pub fn key_hash(pk: &[u8; 32]) -> Vec<u8> { blocktools_core::blake2b::blake2b(28, &[0; 16], pk) }
/// Payment key hash of a base (type 0) or enterprise (type 6) mainnet address with a key payment credential.
pub fn payment_key_hash(addr: &[u8]) -> Result<&[u8], &'static str> {
    match addr.first().map(|h| h >> 4) { Some(0) | Some(6) => Ok(&addr[1..29]), _ => Err("from_address_payment_part_not_a_key (script/pointer NOT BUILT)") }
}
pub fn decode_address(a: &str) -> Result<Vec<u8>, &'static str> { blocktools_core::chains::ada_decode(a) }
pub fn address(b: &[u8]) -> String { blocktools_core::chains::bech32_long("addr", b) }
