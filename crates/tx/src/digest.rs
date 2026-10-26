//! Transaction digests (txid, legacy and BIP143 sighash) for sha256d and single-SHA-256
//! (Groestlcoin) chains. Public data only: no keys.
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::{ScriptBuf, Transaction, Witness};

/// Transaction digest: Bitcoin's sha256d, or single SHA-256 (Groestlcoin `Sign::Sha256Single`).
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Digest { Sha256d, Sha256 }
impl Digest {
    pub fn for_chain(c: &blocktools_core::chains::Chain) -> Self { if c.sign == blocktools_core::chains::Sign::Sha256Single { Digest::Sha256 } else { Digest::Sha256d } }
    pub fn hash(self, b: &[u8]) -> [u8; 32] {
        use bitcoin::hashes::{sha256, sha256d};
        match self { Digest::Sha256d => sha256d::Hash::hash(b).to_byte_array(), Digest::Sha256 => sha256::Hash::hash(b).to_byte_array() }
    }
}
/// True when an input spending `spk` may be signed with the legacy (pre-segwit) sighash, which
/// does NOT commit to the input amount: such an input needs the full previous transaction, or a
/// lying amount turns into an invisible fee. Only witness programs are amount-committed by the
/// script alone; a bare P2SH may wrap any legacy script (see `p2sh_proven_segwit`).
pub fn amount_uncommitted(spk: &bitcoin::Script) -> bool { !spk.is_witness_program() }
/// True when `redeem` is a witness program and HASH160(redeem) is the P2SH `spk`: the input is
/// wrapped segwit, signed with BIP143/BIP341, which commit to the amount.
pub fn p2sh_proven_segwit(spk: &bitcoin::Script, redeem: Option<&bitcoin::Script>) -> bool {
    use bitcoin::hashes::hash160;
    let Some(r) = redeem else { return false };
    spk.is_p2sh() && r.is_witness_program() && spk.as_bytes()[2..22] == hash160::Hash::hash(r.as_bytes()).to_byte_array()
}
/// `amount_uncommitted`, unless a P2SH input carries a redeem script proving wrapped segwit.
pub fn input_amount_uncommitted(spk: &bitcoin::Script, redeem: Option<&bitcoin::Script>) -> bool {
    amount_uncommitted(spk) && !p2sh_proven_segwit(spk, redeem)
}
/// Check a PSBT input's `non_witness_utxo` proves its prevout: hash = outpoint txid, output
/// exists, and equals `witness_utxo` when that is also present. Returns the proven prevout.
pub fn proven_prevout(inp: &bitcoin::psbt::Input, op: &bitcoin::OutPoint, d: Digest) -> Option<bitcoin::TxOut> {
    let t = inp.non_witness_utxo.as_ref()?;
    if txid(t, d) != op.txid { return None }
    let o = t.output.get(op.vout as usize)?.clone();
    if inp.witness_utxo.as_ref().is_some_and(|w| *w != o) { return None }
    Some(o)
}
/// Txid under a digest (display order, i.e. reversed), from the no-witness serialisation.
pub fn txid_hex(tx: &Transaction, d: Digest) -> String {
    let mut bare = tx.clone();
    for i in &mut bare.input { i.witness = Witness::new() }
    let mut h = d.hash(&bitcoin::consensus::serialize(&bare)); h.reverse();
    blocktools_core::hex_enc(h)
}
pub fn txid(tx: &Transaction, d: Digest) -> bitcoin::Txid {
    match d { Digest::Sha256d => tx.compute_txid(), Digest::Sha256 => { use std::str::FromStr; bitcoin::Txid::from_str(&txid_hex(tx, d)).unwrap() } }
}
/// Legacy (pre-segwit) sighash of input `i`, SIGHASH type `ty`, under digest `d`.
pub fn legacy_sighash(tx: &Transaction, i: usize, script_code: &[u8], ty: u32, d: Digest) -> Result<[u8; 32], &'static str> {
    if d == Digest::Sha256d { return SighashCache::new(tx).legacy_signature_hash(i, &ScriptBuf::from_bytes(script_code.to_vec()), ty).map(|h| h.to_byte_array()).map_err(|_| "sighash") }
    let mut w = Vec::new();
    let r = SighashCache::new(tx).legacy_encode_signing_data_to(&mut w, i, &ScriptBuf::from_bytes(script_code.to_vec()), ty);
    if r.is_sighash_single_bug().map_err(|_| "sighash")? { let mut one = [0u8; 32]; one[0] = 1; return Ok(one) }
    Ok(d.hash(&w))
}
/// Fork-id sighash (BCH/BSV `Sign::ForkId(0)`, BTG `ForkId(79)`): the BIP143 layout, used for
/// every input type (P2PKH included), committed with the full 32-bit type `ty`
/// (low byte = base type | 0x40 FORKID [| 0x80 ANYONECANPAY], bits 8.. = fork id). Commits to the
/// input amount. Known-answer tested against Bitcoin ABC's sighash.json (amount 0).
pub fn forkid_sighash(tx: &Transaction, i: usize, script_code: &[u8], amount: u64, ty: u32) -> Result<[u8; 32], &'static str> {
    use bitcoin::consensus::Encodable;
    if ty & 0x40 == 0 { return Err("sighash_without_forkid") }
    let ti = tx.input.get(i).ok_or("sighash")?;
    let d = Digest::Sha256d;
    let (acp, base) = (ty & 0x80 != 0, ty & 0x1f);
    let mut prev = Vec::new(); let mut seq = Vec::new(); let mut outs = Vec::new();
    for x in &tx.input { x.previous_output.consensus_encode(&mut prev).unwrap(); seq.extend(x.sequence.0.to_le_bytes()) }
    let hp = if acp { [0u8; 32] } else { d.hash(&prev) };
    let hs = if acp || base == 2 || base == 3 { [0u8; 32] } else { d.hash(&seq) };
    let ho = if base != 2 && base != 3 { for o in &tx.output { o.consensus_encode(&mut outs).unwrap(); } d.hash(&outs) }
        else if base == 3 && i < tx.output.len() { tx.output[i].consensus_encode(&mut outs).unwrap(); d.hash(&outs) } else { [0u8; 32] };
    let mut w = Vec::new();
    w.extend(tx.version.0.to_le_bytes()); w.extend(hp); w.extend(hs);
    ti.previous_output.consensus_encode(&mut w).unwrap();
    ScriptBuf::from_bytes(script_code.to_vec()).consensus_encode(&mut w).unwrap();
    w.extend(amount.to_le_bytes()); w.extend(ti.sequence.0.to_le_bytes());
    w.extend(ho);
    w.extend(tx.lock_time.to_consensus_u32().to_le_bytes()); w.extend(ty.to_le_bytes());
    Ok(d.hash(&w))
}
/// BIP143 sighash (SIGHASH_ALL only) with every inner hash under digest `d`.
pub fn bip143_all(tx: &Transaction, i: usize, script_code: &[u8], amount: u64, d: Digest) -> Result<[u8; 32], &'static str> {
    use bitcoin::consensus::Encodable;
    let ti = tx.input.get(i).ok_or("sighash")?;
    let mut prev = Vec::new(); let mut seq = Vec::new(); let mut outs = Vec::new();
    for x in &tx.input { x.previous_output.consensus_encode(&mut prev).unwrap(); seq.extend(x.sequence.0.to_le_bytes()) }
    for o in &tx.output { o.consensus_encode(&mut outs).unwrap(); }
    let mut w = Vec::new();
    w.extend(tx.version.0.to_le_bytes());
    w.extend(d.hash(&prev)); w.extend(d.hash(&seq));
    ti.previous_output.consensus_encode(&mut w).unwrap();
    ScriptBuf::from_bytes(script_code.to_vec()).consensus_encode(&mut w).unwrap();
    w.extend(amount.to_le_bytes()); w.extend(ti.sequence.0.to_le_bytes());
    w.extend(d.hash(&outs));
    w.extend(tx.lock_time.to_consensus_u32().to_le_bytes()); w.extend(1u32.to_le_bytes());
    Ok(d.hash(&w))
}
