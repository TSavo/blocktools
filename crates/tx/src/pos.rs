//! Proof-of-stake "nTime" transactions (Peercoin, Novacoin, Clams, Reddcoin). Bitcoin's legacy
//! layout plus a 32-bit timestamp: after the version (PPC v1, NVC, CLAM) or after the locktime
//! (RDD v2, PoSV; RDD leaves it out of the sighash preimage). CLAM v2+ also carries a `clam-speech` string after the locktime.
//! Legacy (pre-segwit) sighash: the same serialisation with script substitution, SIGHASH type
//! appended, sha256d. P2PKH only. Public data only here; signing is in `pos_sign` (secrets).
//! Rules confirmed against real mainnet txs in tests/data/pos_mainnet.txt (txid + signatures).
use bitcoin::hashes::{sha256d, Hash};

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Layout { pub version: i32, pub time_after_version: bool, pub time_after_locktime: bool, pub speech: bool,
    /// Whether the timestamp is part of the sighash preimage (RDD: in the txid, not the sighash).
    pub sighash_time: bool }
/// Layout for chain `id`, or None if the chain is not a supported nTime chain.
pub fn layout(id: &str) -> Option<Layout> {
    Some(match id {
        "ppc" | "nvc" => Layout { version: 1, time_after_version: true, time_after_locktime: false, speech: false, sighash_time: true },
        "clam" => Layout { version: 1, time_after_version: true, time_after_locktime: false, speech: false, sighash_time: true },
        "rdd" => Layout { version: 2, time_after_version: false, time_after_locktime: true, speech: false, sighash_time: false },
        _ => return None,
    })
}
/// Layout of a parsed tx for chain `id` (CLAM speech and RDD time depend on version > 1).
pub fn layout_for_version(id: &str, version: i32) -> Option<Layout> {
    let mut l = layout(id)?; l.version = version;
    if id == "clam" { l.speech = version > 1 }
    if id == "rdd" { l.time_after_locktime = version > 1 }
    Some(l)
}
#[derive(Clone, PartialEq, Debug)]
pub struct PIn { pub txid: [u8; 32], pub vout: u32, pub script_sig: Vec<u8>, pub sequence: u32 }
#[derive(Clone, PartialEq, Debug)]
pub struct PosTx { pub layout: Layout, pub time: u32, pub inputs: Vec<PIn>, pub outputs: Vec<(u64, Vec<u8>)>, pub locktime: u32, pub speech: Vec<u8> }

fn vi(w: &mut Vec<u8>, n: usize) {
    if n < 0xfd { w.push(n as u8) } else if n <= 0xffff { w.push(0xfd); w.extend((n as u16).to_le_bytes()) } else { w.push(0xfe); w.extend((n as u32).to_le_bytes()) }
}
fn bytes(w: &mut Vec<u8>, b: &[u8]) { vi(w, b.len()); w.extend(b) }
struct R<'a> { b: &'a [u8], p: usize }
impl R<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], &'static str> { let e = self.p.checked_add(n).filter(|&e| e <= self.b.len()).ok_or("pos_tx_truncated")?; let s = &self.b[self.p..e]; self.p = e; Ok(s) }
    fn u32(&mut self) -> Result<u32, &'static str> { Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, &'static str> { Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap())) }
    fn vi(&mut self) -> Result<usize, &'static str> {
        let n = match self.take(1)?[0] { 0xfd => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64, 0xfe => self.u32()? as u64, 0xff => self.u64()?, x => x as u64 };
        if n > 4_000_000 { return Err("pos_tx_bad_length") } Ok(n as usize)
    }
    fn bytes(&mut self) -> Result<Vec<u8>, &'static str> { let n = self.vi()?; Ok(self.take(n)?.to_vec()) }
}
impl PosTx {
    pub fn serialize(&self) -> Vec<u8> { self.ser(None) }
    fn ser(&self, subst: Option<(usize, &[u8])>) -> Vec<u8> {
        let l = &self.layout; let mut w = Vec::new();
        w.extend(l.version.to_le_bytes());
        if l.time_after_version { w.extend(self.time.to_le_bytes()) }
        vi(&mut w, self.inputs.len());
        for (k, i) in self.inputs.iter().enumerate() {
            w.extend(i.txid); w.extend(i.vout.to_le_bytes());
            match subst { None => bytes(&mut w, &i.script_sig), Some((j, code)) => bytes(&mut w, if j == k { code } else { &[] }) }
            w.extend(i.sequence.to_le_bytes());
        }
        vi(&mut w, self.outputs.len());
        for (v, s) in &self.outputs { w.extend(v.to_le_bytes()); bytes(&mut w, s) }
        w.extend(self.locktime.to_le_bytes());
        if l.time_after_locktime { w.extend(self.time.to_le_bytes()) }
        if l.speech { bytes(&mut w, &self.speech) }
        w
    }
    /// Parse a raw tx of chain `id`. Rejects segwit-marker txs and trailing bytes.
    pub fn parse(id: &str, b: &[u8]) -> Result<Self, &'static str> {
        let mut r = R { b, p: 0 };
        let version = r.u32()? as i32;
        let layout = layout_for_version(id, version).ok_or("not_pos_ntime_chain")?;
        let time = if layout.time_after_version { r.u32()? } else { 0 };
        let n = r.vi()?; if n == 0 { return Err("pos_tx_no_inputs_or_segwit") }
        let mut inputs = Vec::new();
        for _ in 0..n { let txid: [u8; 32] = r.take(32)?.try_into().unwrap(); let vout = r.u32()?; let script_sig = r.bytes()?; let sequence = r.u32()?; inputs.push(PIn { txid, vout, script_sig, sequence }) }
        let n = r.vi()?; let mut outputs = Vec::new();
        for _ in 0..n { let v = r.u64()?; outputs.push((v, r.bytes()?)) }
        let locktime = r.u32()?;
        let time = if layout.time_after_locktime { r.u32()? } else { time };
        let speech = if layout.speech { r.bytes()? } else { Vec::new() };
        if r.p != b.len() { return Err("pos_tx_trailing_bytes") }
        Ok(PosTx { layout, time, inputs, outputs, locktime, speech })
    }
    /// Txid in display (reversed) hex.
    pub fn txid_hex(&self) -> String { let mut h = sha256d::Hash::hash(&self.serialize()).to_byte_array(); h.reverse(); blocktools_core::hex_enc(h) }
    /// Legacy SIGHASH_ALL digest for input `i` with `script_code` (the prevout's P2PKH script).
    pub fn sighash_all(&self, i: usize, script_code: &[u8]) -> Result<[u8; 32], &'static str> {
        if i >= self.inputs.len() { return Err("sighash") }
        let mut t = self.clone();
        if !t.layout.sighash_time { t.layout.time_after_version = false; t.layout.time_after_locktime = false }
        let mut w = t.ser(Some((i, script_code))); w.extend(1u32.to_le_bytes());
        Ok(sha256d::Hash::hash(&w).to_byte_array())
    }
}

/// Previous outputs being spent (amount in base units, scriptPubKey), carried next to the
/// unsigned tx because the nTime format has no PSBT.
pub type Prevouts = Vec<(u64, Vec<u8>)>;
/// The JSON line tx-build / build_unsigned_sweep emit for an nTime chain.
pub fn envelope(chain: &str, tx: &PosTx, prev: &Prevouts) -> serde_json::Value {
    let k = if tx.inputs.iter().any(|i| !i.script_sig.is_empty()) { "signed_tx" } else { "unsigned_tx" };
    serde_json::json!({"chain": chain, "tx_format": "pos-ntime", k: blocktools_core::hex_enc(tx.serialize()), "time": tx.time,
        "pos_prevouts": prev.iter().map(|(a, s)| serde_json::json!({"amount": a, "amount_str": a.to_string(), "script": blocktools_core::hex_enc(s)})).collect::<Vec<_>>()})
}
/// `pos_prevouts` from a JSON line, if present (bounded; must be well-formed when present).
pub fn prevouts_from_json(text: &str) -> Result<Option<Prevouts>, &'static str> {
    let Some(v) = text.lines().find_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok().filter(|v| v.get("pos_prevouts").is_some())) else { return Ok(None) };
    let a = v["pos_prevouts"].as_array().filter(|a| a.len() <= 2000).ok_or("bad_pos_prevouts")?;
    a.iter().map(|p| Some((crate::json_amount(p.get("amount_str").unwrap_or(&p["amount"]), crate::MAX_AMOUNT)?, blocktools_core::hex_dec(p["script"].as_str()?).filter(|s| s.len() <= 10_000)?)))
        .collect::<Option<Vec<_>>>().map(Some).ok_or("bad_pos_prevouts")
}
/// Fee-estimate size (bytes) once every input carries a compressed-key P2PKH signature.
pub fn signed_size(tx: &PosTx) -> u64 {
    let unsigned_sigs: u64 = tx.inputs.iter().filter(|i| i.script_sig.is_empty()).count() as u64 * 107;
    tx.serialize().len() as u64 + unsigned_sigs
}
