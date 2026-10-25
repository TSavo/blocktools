//! Zcash v4 (Sapling, ZIP-243 sighash) and v5 (NU5+, ZIP-244 txid/sighash) transactions.
//! Full parse of both formats (shielded bundles are kept as opaque fixed-size records, enough
//! to compute every digest) so txids and transparent sighashes are exact for any v4/v5 tx;
//! building and signing are transparent-only (P2PKH). Public data only; signing is in `sign`.
//! Checked against the zcash-test-vectors ZIP-243/244 vectors and real mainnet txs
//! (tests/zcash.rs, tests/data/zec_*.txt).
use crate::blake2b::h256;
use bitcoin::hashes::{sha256d, Hash};

pub const V4_GROUP: u32 = 0x892f2085;
pub const V5_GROUP: u32 = 0x26a7270a;
/// Consensus branch id seen in mainnet v5 txs mined at height ~3529742 (2026-10-25 UTC). A tx
/// signed with a stale branch id is rejected after the next network upgrade; pass the current one.
pub const MAINNET_BRANCH_ID: u32 = 0x37a5165b;

#[derive(Clone, PartialEq, Debug)]
pub struct ZIn { pub txid: [u8; 32], pub vout: u32, pub script_sig: Vec<u8>, pub sequence: u32 }
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Sapling { pub value_balance: i64, pub anchor: [u8; 32], pub spends: Vec<Vec<u8>>, pub outputs: Vec<Vec<u8>> }
#[derive(Clone, PartialEq, Debug, Default)]
pub struct Orchard { pub actions: Vec<Vec<u8>>, pub flags: u8, pub value_balance: i64, pub anchor: [u8; 32] }
#[derive(Clone, PartialEq, Debug)]
pub struct ZTx {
    pub version: u32, pub branch_id: u32, pub locktime: u32, pub expiry: u32,
    pub inputs: Vec<ZIn>, pub outputs: Vec<(u64, Vec<u8>)>,
    pub sapling: Sapling, pub orchard: Orchard,
    /// v4 only: JoinSplit descriptions (1698 bytes each) and joinSplitPubKey.
    pub joinsplits: Vec<Vec<u8>>, pub js_pubkey: Vec<u8>,
    /// Raw bytes after the transparent part, re-emitted verbatim (proofs and signatures).
    pub tail: Vec<u8>,
}

fn vi(w: &mut Vec<u8>, n: usize) {
    if n < 0xfd { w.push(n as u8) } else if n <= 0xffff { w.push(0xfd); w.extend((n as u16).to_le_bytes()) } else { w.push(0xfe); w.extend((n as u32).to_le_bytes()) }
}
fn bytes(w: &mut Vec<u8>, b: &[u8]) { vi(w, b.len()); w.extend(b) }
struct R<'a> { b: &'a [u8], p: usize }
impl R<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], &'static str> { let e = self.p.checked_add(n).filter(|&e| e <= self.b.len()).ok_or("zcash_tx_truncated")?; let s = &self.b[self.p..e]; self.p = e; Ok(s) }
    fn u32(&mut self) -> Result<u32, &'static str> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, &'static str> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn vi(&mut self) -> Result<usize, &'static str> {
        let n = match self.take(1)?[0] { 0xfd => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64, 0xfe => self.u32()? as u64, 0xff => self.u64()?, x => x as u64 };
        if n > 4_000_000 { return Err("zcash_tx_bad_length") } Ok(n as usize)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, &'static str> { let n = self.vi()?; Ok(self.take(n)?.to_vec()) }
    fn recs(&mut self, n: usize, size: usize) -> Result<Vec<Vec<u8>>, &'static str> { (0..n).map(|_| self.take(size).map(|s| s.to_vec())).collect() }
}

fn p(s: &[u8; 16]) -> &[u8; 16] { s }
fn cat<'a>(it: impl Iterator<Item = &'a [u8]>) -> Vec<u8> { it.flatten().copied().collect() }

impl ZTx {
    /// Parse a raw v4 or v5 tx. `branch_id` is used for v4 (not serialized there); v5 carries its own.
    pub fn parse(b: &[u8], branch_id_v4: u32) -> Result<Self, &'static str> {
        let mut r = R { b, p: 0 };
        let header = r.u32()?;
        if header & 0x8000_0000 == 0 { return Err("zcash_tx_not_overwintered") }
        let version = header & 0x7fff_ffff;
        let group = r.u32()?;
        let (branch_id, mut locktime, mut expiry) = match (version, group) {
            (4, V4_GROUP) => (branch_id_v4, 0, 0),
            (5, V5_GROUP) => { let b = r.u32()?; (b, r.u32()?, r.u32()?) }
            _ => return Err("zcash_tx_unsupported_version"),
        };
        let n = r.vi()?; let mut inputs = Vec::new();
        for _ in 0..n { let txid: [u8; 32] = r.take(32)?.try_into().unwrap(); let vout = r.u32()?; let script_sig = r.bytes()?; let sequence = r.u32()?; inputs.push(ZIn { txid, vout, script_sig, sequence }) }
        let n = r.vi()?; let mut outputs = Vec::new();
        for _ in 0..n { let v = r.u64()?; outputs.push((v, r.bytes()?)) }
        let tail_start;
        let (mut sapling, mut orchard, mut joinsplits, mut js_pubkey) = (Sapling::default(), Orchard::default(), Vec::new(), Vec::new());
        if version == 4 {
            locktime = r.u32()?; expiry = r.u32()?;
            tail_start = r.p;
            sapling.value_balance = r.u64()? as i64;
            let ns = r.vi()?; sapling.spends = r.recs(ns, 384)?;
            let no = r.vi()?; sapling.outputs = r.recs(no, 948)?;
            let nj = r.vi()?; joinsplits = r.recs(nj, 1698)?;
            if nj > 0 { js_pubkey = r.take(32)?.to_vec(); r.take(64)?; }
            if ns + no > 0 { r.take(64)?; }
        } else {
            tail_start = r.p;
            let ns = r.vi()?; sapling.spends = r.recs(ns, 96)?;
            let no = r.vi()?; sapling.outputs = r.recs(no, 756)?;
            if ns + no > 0 { sapling.value_balance = r.u64()? as i64 }
            if ns > 0 { sapling.anchor = r.take(32)?.try_into().unwrap() }
            r.take(ns * 192 + ns * 64 + no * 192)?;
            if ns + no > 0 { r.take(64)?; }
            let na = r.vi()?;
            if na > 0 {
                orchard.actions = r.recs(na, 820)?; orchard.flags = r.take(1)?[0]; orchard.value_balance = r.u64()? as i64;
                orchard.anchor = r.take(32)?.try_into().unwrap();
                let np = r.vi()?; r.take(np)?; r.take(na * 64 + 64)?;
            }
        }
        if r.p != b.len() { return Err("zcash_tx_trailing_bytes") }
        Ok(ZTx { version, branch_id, locktime, expiry, inputs, outputs, sapling, orchard, joinsplits, js_pubkey, tail: b[tail_start..].to_vec() })
    }
    /// A transparent-only v5 tx (empty Sapling and Orchard bundles).
    pub fn transparent_v5(branch_id: u32, inputs: Vec<ZIn>, outputs: Vec<(u64, Vec<u8>)>, locktime: u32, expiry: u32) -> Self {
        ZTx { version: 5, branch_id, locktime, expiry, inputs, outputs, sapling: Sapling::default(), orchard: Orchard::default(), joinsplits: vec![], js_pubkey: vec![], tail: vec![0, 0, 0] }
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut w = Vec::new();
        w.extend((self.version | 0x8000_0000).to_le_bytes());
        if self.version == 4 { w.extend(V4_GROUP.to_le_bytes()) } else { w.extend(V5_GROUP.to_le_bytes()); w.extend(self.branch_id.to_le_bytes()); w.extend(self.locktime.to_le_bytes()); w.extend(self.expiry.to_le_bytes()) }
        w.extend(self.transparent_bytes());
        if self.version == 4 { w.extend(self.locktime.to_le_bytes()); w.extend(self.expiry.to_le_bytes()) }
        w.extend(&self.tail); w
    }
    fn transparent_bytes(&self) -> Vec<u8> {
        let mut w = Vec::new();
        vi(&mut w, self.inputs.len());
        for i in &self.inputs { w.extend(i.txid); w.extend(i.vout.to_le_bytes()); bytes(&mut w, &i.script_sig); w.extend(i.sequence.to_le_bytes()) }
        vi(&mut w, self.outputs.len());
        for (v, s) in &self.outputs { w.extend(v.to_le_bytes()); bytes(&mut w, s) }
        w
    }
    fn prevouts(&self) -> Vec<u8> { cat(self.inputs.iter().map(|i| [&i.txid[..], &i.vout.to_le_bytes()].concat()).collect::<Vec<_>>().iter().map(|v| v.as_slice())) }
    fn sequences(&self) -> Vec<u8> { self.inputs.iter().flat_map(|i| i.sequence.to_le_bytes()).collect() }
    fn out_bytes(o: &(u64, Vec<u8>)) -> Vec<u8> { let mut w = o.0.to_le_bytes().to_vec(); bytes(&mut w, &o.1); w }
    fn outputs_ser(&self) -> Vec<u8> { self.outputs.iter().flat_map(Self::out_bytes).collect() }

    /// Txid in display (reversed) hex: sha256d for v4, the ZIP-244 digest for v5.
    pub fn txid_hex(&self) -> String { let mut h = self.txid(); h.reverse(); blocktools_core::hex_enc(h) }
    /// Txid in internal byte order.
    pub fn txid(&self) -> [u8; 32] {
        if self.version == 4 { return sha256d::Hash::hash(&self.serialize()).to_byte_array() }
        let t = self.transparent_digest();
        self.v5_root(&t)
    }
    // ---- ZIP-244 ----
    fn header_digest(&self) -> [u8; 32] {
        let mut w = (self.version | 0x8000_0000).to_le_bytes().to_vec();
        for x in [V5_GROUP, self.branch_id, self.locktime, self.expiry] { w.extend(x.to_le_bytes()) }
        h256(p(b"ZTxIdHeadersHash"), &w)
    }
    fn prevouts_digest(&self) -> [u8; 32] { h256(p(b"ZTxIdPrevoutHash"), &self.prevouts()) }
    fn sequence_digest(&self) -> [u8; 32] { h256(p(b"ZTxIdSequencHash"), &self.sequences()) }
    fn outputs_digest(&self) -> [u8; 32] { h256(p(b"ZTxIdOutputsHash"), &self.outputs_ser()) }
    fn transparent_digest(&self) -> [u8; 32] {
        if self.inputs.is_empty() && self.outputs.is_empty() { return h256(p(b"ZTxIdTranspaHash"), &[]) }
        h256(p(b"ZTxIdTranspaHash"), &[self.prevouts_digest(), self.sequence_digest(), self.outputs_digest()].concat())
    }
    fn sapling_digest(&self) -> [u8; 32] {
        let s = &self.sapling;
        if s.spends.is_empty() && s.outputs.is_empty() { return h256(p(b"ZTxIdSaplingHash"), &[]) }
        let spends = if s.spends.is_empty() { h256(p(b"ZTxIdSSpendsHash"), &[]) } else {
            let c = h256(p(b"ZTxIdSSpendCHash"), &cat(s.spends.iter().map(|x| &x[32..64])));
            let n = h256(p(b"ZTxIdSSpendNHash"), &cat(s.spends.iter().map(|x| [&x[0..32], &s.anchor[..], &x[64..96]].concat()).collect::<Vec<_>>().iter().map(|v| v.as_slice())));
            h256(p(b"ZTxIdSSpendsHash"), &[c, n].concat())
        };
        let outs = if s.outputs.is_empty() { h256(p(b"ZTxIdSOutputHash"), &[]) } else {
            let c = h256(p(b"ZTxIdSOutC__Hash"), &cat(s.outputs.iter().map(|x| &x[32..148])));
            let m = h256(p(b"ZTxIdSOutM__Hash"), &cat(s.outputs.iter().map(|x| &x[148..660])));
            let n = h256(p(b"ZTxIdSOutN__Hash"), &cat(s.outputs.iter().map(|x| [&x[0..32], &x[660..756]].concat()).collect::<Vec<_>>().iter().map(|v| v.as_slice())));
            h256(p(b"ZTxIdSOutputHash"), &[c, m, n].concat())
        };
        h256(p(b"ZTxIdSaplingHash"), &[&spends[..], &outs[..], &s.value_balance.to_le_bytes()].concat())
    }
    fn orchard_digest(&self) -> [u8; 32] {
        let o = &self.orchard;
        if o.actions.is_empty() { return h256(p(b"ZTxIdOrchardHash"), &[]) }
        let c = h256(p(b"ZTxIdOrcActCHash"), &cat(o.actions.iter().map(|x| [&x[32..64], &x[96..212]].concat()).collect::<Vec<_>>().iter().map(|v| v.as_slice())));
        let m = h256(p(b"ZTxIdOrcActMHash"), &cat(o.actions.iter().map(|x| &x[212..724])));
        let n = h256(p(b"ZTxIdOrcActNHash"), &cat(o.actions.iter().map(|x| [&x[0..32], &x[64..96], &x[724..820]].concat()).collect::<Vec<_>>().iter().map(|v| v.as_slice())));
        h256(p(b"ZTxIdOrchardHash"), &[&c[..], &m[..], &n[..], &[o.flags], &o.value_balance.to_le_bytes(), &o.anchor[..]].concat())
    }
    fn v5_root(&self, transparent: &[u8; 32]) -> [u8; 32] {
        let mut pers = *b"ZcashTxHash_\0\0\0\0"; pers[12..].copy_from_slice(&self.branch_id.to_le_bytes());
        h256(&pers, &[self.header_digest(), *transparent, self.sapling_digest(), self.orchard_digest()].concat())
    }
    /// Signature digest. `input`: Some((index, amounts of all inputs, scriptPubKeys of all inputs))
    /// for a transparent input (v5 needs every prevout; v4 uses only the signed one, with the
    /// scriptPubKey as script code). None = the shielded/non-transparent digest.
    pub fn sighash(&self, input: Option<(usize, &[u64], &[Vec<u8>])>, hash_type: u8) -> Result<[u8; 32], &'static str> {
        if ![1, 2, 3, 0x81, 0x82, 0x83].contains(&hash_type) { return Err("zcash_bad_hash_type") }
        if let Some((i, a, s)) = input { if i >= self.inputs.len() || a.len() != self.inputs.len() || s.len() != self.inputs.len() { return Err("zcash_sighash_input") } }
        if self.version == 4 { self.sighash_v4(input.map(|(i, a, s)| (i, s[i].as_slice(), a[i])), hash_type) } else { Ok(self.sighash_v5(input, hash_type)) }
    }
    /// v5 digest signed by Sapling/Orchard spend-auth and binding signatures (SIGHASH_ALL, no
    /// transparent input selected). Needs every transparent prevout when the tx has transparent inputs.
    pub fn shielded_sighash_v5(&self, amounts: &[u64], spks: &[Vec<u8>]) -> Result<[u8; 32], &'static str> {
        if self.version != 5 { return Err("zcash_not_v5") }
        if self.inputs.is_empty() { return Ok(self.txid()) }
        if amounts.len() != self.inputs.len() || spks.len() != self.inputs.len() { return Err("zcash_sighash_input") }
        Ok(self.sig_digest_v5(None, amounts, spks, 1))
    }
    fn sighash_v5(&self, input: Option<(usize, &[u64], &[Vec<u8>])>, ht: u8) -> [u8; 32] {
        let Some((i, amounts, spks)) = input else { return self.txid() };
        if self.inputs.is_empty() { return self.txid() }
        self.sig_digest_v5(Some(i), amounts, spks, ht)
    }
    fn sig_digest_v5(&self, input: Option<usize>, amounts: &[u64], spks: &[Vec<u8>], ht: u8) -> [u8; 32] {
        let acp = ht & 0x80 != 0; let base = ht & 0x7f;
        let prevouts = if acp { h256(p(b"ZTxIdPrevoutHash"), &[]) } else { self.prevouts_digest() };
        let am = h256(p(b"ZTxTrAmountsHash"), &if acp { vec![] } else { amounts.iter().flat_map(|a| a.to_le_bytes()).collect() });
        let sc = h256(p(b"ZTxTrScriptsHash"), &if acp { vec![] } else { let mut w = vec![]; for s in spks { bytes(&mut w, s) } w });
        let seq = if acp { h256(p(b"ZTxIdSequencHash"), &[]) } else { self.sequence_digest() };
        let outs = match base {
            2 => h256(p(b"ZTxIdOutputsHash"), &[]),
            3 => h256(p(b"ZTxIdOutputsHash"), &input.and_then(|i| self.outputs.get(i)).map(Self::out_bytes).unwrap_or_default()),
            _ => self.outputs_digest(),
        };
        let txin = match input { None => h256(p(b"Zcash___TxInHash"), &[]), Some(i) => {
            let x = &self.inputs[i];
            let mut t = [&x.txid[..], &x.vout.to_le_bytes()].concat(); t.extend(amounts[i].to_le_bytes()); bytes(&mut t, &spks[i]); t.extend(x.sequence.to_le_bytes());
            h256(p(b"Zcash___TxInHash"), &t) } };
        let t = h256(p(b"ZTxIdTranspaHash"), &[&[ht][..], &prevouts, &am, &sc, &seq, &outs, &txin].concat());
        self.v5_root(&t)
    }
    // ---- ZIP-243 ----
    fn sighash_v4(&self, input: Option<(usize, &[u8], u64)>, ht: u8) -> Result<[u8; 32], &'static str> {
        let acp = ht & 0x80 != 0; let base = ht & 0x1f; let z = [0u8; 32];
        let hp = if acp { z } else { h256(p(b"ZcashPrevoutHash"), &self.prevouts()) };
        let hs = if acp || base == 2 || base == 3 { z } else { h256(p(b"ZcashSequencHash"), &self.sequences()) };
        let ho = if base != 2 && base != 3 { h256(p(b"ZcashOutputsHash"), &self.outputs_ser()) }
            else if base == 3 && input.is_some_and(|(i, _, _)| i < self.outputs.len()) { h256(p(b"ZcashOutputsHash"), &Self::out_bytes(&self.outputs[input.unwrap().0])) } else { z };
        let hj = if self.joinsplits.is_empty() { z } else { h256(p(b"ZcashJSplitsHash"), &[cat(self.joinsplits.iter().map(|v| v.as_slice())), self.js_pubkey.clone()].concat()) };
        let hss = if self.sapling.spends.is_empty() { z } else { h256(p(b"ZcashSSpendsHash"), &cat(self.sapling.spends.iter().map(|x| &x[..320]))) };
        let hso = if self.sapling.outputs.is_empty() { z } else { h256(p(b"ZcashSOutputHash"), &cat(self.sapling.outputs.iter().map(|v| v.as_slice()))) };
        let mut w = (self.version | 0x8000_0000).to_le_bytes().to_vec(); w.extend(V4_GROUP.to_le_bytes());
        for h in [hp, hs, ho, hj, hss, hso] { w.extend(h) }
        w.extend(self.locktime.to_le_bytes()); w.extend(self.expiry.to_le_bytes()); w.extend(self.sapling.value_balance.to_le_bytes()); w.extend((ht as u32).to_le_bytes());
        if let Some((i, code, amount)) = input {
            let x = &self.inputs[i]; w.extend(x.txid); w.extend(x.vout.to_le_bytes()); bytes(&mut w, code); w.extend(amount.to_le_bytes()); w.extend(x.sequence.to_le_bytes());
        }
        let mut pers = *b"ZcashSigHash\0\0\0\0"; pers[12..].copy_from_slice(&self.branch_id.to_le_bytes());
        Ok(h256(&pers, &w))
    }
}

/// Previous outputs (amount in zatoshi, scriptPubKey); Zcash has no PSBT, so they travel with the tx.
pub type Prevouts = Vec<(u64, Vec<u8>)>;
/// JSON envelope emitted by tx-build / build_unsigned_sweep for Zcash.
pub fn envelope(tx: &ZTx, prev: &Prevouts) -> serde_json::Value {
    let k = if tx.inputs.iter().any(|i| !i.script_sig.is_empty()) { "signed_tx" } else { "unsigned_tx" };
    serde_json::json!({"chain": "zec", "tx_format": format!("zcash-v{}", tx.version), k: blocktools_core::hex_enc(tx.serialize()),
        "branch_id": format!("{:08x}", tx.branch_id), "expiry_height": tx.expiry,
        "zec_prevouts": prev.iter().map(|(a, s)| serde_json::json!({"amount": a, "amount_str": a.to_string(), "script": blocktools_core::hex_enc(s)})).collect::<Vec<_>>()})
}
/// (`zec_prevouts`, `branch_id`) from a JSON line, if present.
pub fn envelope_from_json(text: &str) -> Result<Option<(Prevouts, u32)>, &'static str> {
    let Some(v) = text.lines().find_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok().filter(|v| v.get("zec_prevouts").is_some())) else { return Ok(None) };
    let a = v["zec_prevouts"].as_array().filter(|a| a.len() <= 2000).ok_or("bad_zec_prevouts")?;
    let prev = a.iter().map(|p| Some((crate::json_amount(p.get("amount_str").unwrap_or(&p["amount"]), 21_000_000 * 100_000_000)?, blocktools_core::hex_dec(p["script"].as_str()?).filter(|s| s.len() <= 10_000)?)))
        .collect::<Option<Vec<_>>>().ok_or("bad_zec_prevouts")?;
    let b = v["branch_id"].as_str().and_then(|s| u32::from_str_radix(s, 16).ok()).ok_or("bad_branch_id")?;
    Ok(Some((prev, b)))
}
/// ZIP-317 conventional fee for a transparent-only tx: 5000 zat × max(2, logical actions),
/// logical actions = max(ceil(input bytes/150), ceil(output bytes/34)); unsigned P2PKH inputs count as signed (+107).
pub fn zip317_fee(tx: &ZTx) -> u64 {
    let inb: usize = tx.inputs.iter().map(|i| 41 + if i.script_sig.is_empty() { 107 } else { i.script_sig.len() }).sum();
    let outb: usize = tx.outputs.iter().map(|o| ZTx::out_bytes(o).len()).sum();
    5000 * (2u64).max((inb.div_ceil(150)).max(outb.div_ceil(34)) as u64)
}

/// Transparent address prefixes (zcash/zcash src/chainparams.cpp, mainnet).
pub const P2PKH_PREFIX: [u8; 2] = [0x1c, 0xb8];
pub const P2SH_PREFIX: [u8; 2] = [0x1c, 0xbd];
/// (kind, t-address) for a P2PKH/P2SH scriptPubKey.
pub fn script_to_address(s: &[u8]) -> Option<(&'static str, String)> {
    let (kind, pre, h) = match s {
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => ("p2pkh", P2PKH_PREFIX, h),
        [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => ("p2sh", P2SH_PREFIX, h),
        _ => return None,
    };
    let mut b = pre.to_vec(); b.extend(h);
    Some((kind, bitcoin::base58::encode_check(&b)))
}
/// scriptPubKey of a mainnet t-address (t1… P2PKH, t3… P2SH).
pub fn address_to_script(a: &str) -> Option<Vec<u8>> {
    if a.len() > 60 { return None }
    let b = bitcoin::base58::decode_check(a).ok().filter(|b| b.len() == 22)?;
    let h = &b[2..];
    match [b[0], b[1]] {
        P2PKH_PREFIX => Some([&[0x76, 0xa9, 0x14][..], h, &[0x88, 0xac]].concat()),
        P2SH_PREFIX => Some([&[0xa9, 0x14][..], h, &[0x87]].concat()),
        _ => None,
    }
}
/// Size once every unsigned input carries a compressed-key P2PKH signature (+107 bytes each).
pub fn signed_size(tx: &ZTx) -> u64 {
    tx.serialize().len() as u64 + tx.inputs.iter().filter(|i| i.script_sig.is_empty()).count() as u64 * 107
}
/// UTXO JSON lines {"txid","vout","amount","address"} (t-addresses) → (txid internal order, vout, amount, scriptPubKey).
pub fn parse_utxos(text: &str) -> Result<Vec<([u8; 32], u32, u64, Vec<u8>)>, String> {
    let mut v = Vec::new();
    for (n, l) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        if v.len() >= 2000 { return Err("too_many_utxos".into()) }
        let e = |m: &str| format!("utxo line {}: {m}", n + 1);
        let j: serde_json::Value = serde_json::from_str(l).map_err(|_| e("bad_json"))?;
        let mut txid: [u8; 32] = j["txid"].as_str().and_then(blocktools_core::hex_dec).and_then(|b| b.try_into().ok()).ok_or_else(|| e("txid"))?;
        txid.reverse();
        let vout = j["vout"].as_u64().filter(|&x| x <= u32::MAX as u64).ok_or_else(|| e("vout"))? as u32;
        let amount = crate::json_amount(&j["amount"], 21_000_000 * 100_000_000).ok_or_else(|| e("amount"))?;
        let script = address_to_script(j["address"].as_str().ok_or_else(|| e("address"))?).ok_or_else(|| e("address not a zec t-address"))?;
        if j.get("prev_tx").is_some() { return Err(e("prev_tx is not used for zec (ZIP-244 commits to amounts)")) }
        v.push((txid, vout, amount, script));
    }
    if v.is_empty() { return Err("no_utxos".into()) }
    Ok(v)
}
/// Transparent-only v5 sweep of every UTXO (P2PKH only) to `to`. Fee = max(ZIP-317 conventional
/// fee, signed size × `fee_rate`). `expiry` 0 = no expiry height.
pub fn build_sweep(utxos_text: &str, to: &str, fee_rate: u64, branch_id: u32, expiry: u32, dust: u64) -> Result<(ZTx, Prevouts), String> {
    let cap = blocktools_core::chains::fee_warn("zec").rate_cap();
    if fee_rate > cap { return Err(format!("fee_rate must be 0..{cap} per byte for zec")) }
    let u = parse_utxos(utxos_text)?;
    if u.iter().any(|x| script_to_address(&x.3).map(|a| a.0) != Some("p2pkh")) { return Err("zec sweep supports p2pkh inputs only".into()) }
    let to_s = address_to_script(to).ok_or("bad --to address (zec t-address)")?;
    let inputs = u.iter().map(|x| ZIn { txid: x.0, vout: x.1, script_sig: vec![], sequence: 0xffff_ffff }).collect();
    let mut tx = ZTx::transparent_v5(branch_id, inputs, vec![(0, to_s)], 0, expiry);
    let total: u64 = u.iter().map(|x| x.2).sum();
    let fee = zip317_fee(&tx).max(signed_size(&tx) * fee_rate);
    tx.outputs[0].0 = total.checked_sub(fee).filter(|&v| v >= dust).ok_or("balance does not cover the fee (or leaves dust)")?;
    Ok((tx, u.into_iter().map(|x| (x.2, x.3)).collect()))
}
