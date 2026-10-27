//! Offline, key-free transaction decoding shared by tx-decode, tx-verify and tx-sign.
//! Input: hex or base64 raw tx / PSBT, EVM RLP (legacy, EIP-1559), or a JSON line carrying one
//! of those in "psbt" / "tx" / "unsigned_tx" / "signed_tx". Format is auto-detected.
//! All parsing is bounded; consensus parsing is rust-bitcoin's.
/// A failure code literal, checked at compile time against blocktools_schema::TX_FAILURES
/// (the redact allowlist), so a code that redact would drop cannot be emitted (D1-12).
#[macro_export]
macro_rules! code { ($s:literal) => {{ const _: () = assert!($crate::__schema::is_tx_failure($s), concat!("failure code not in blocktools_schema::TX_FAILURES: ", $s)); $s }} }
#[doc(hidden)]
pub mod __schema { include!("../../schema/src/tx_failures.rs"); }
pub mod build;
pub mod evm;
pub mod evm_decode;
pub mod policy;
pub mod policy_file;
/// Signing (takes private keys). Feature `secrets` only.
pub mod digest;

/// Largest UTXO amount accepted from input files: consensus amounts are signed 64-bit, and
/// coins like RDD and DOGE have UTXOs above Bitcoin's 21M x 1e8 (and above 2^53).
pub const MAX_AMOUNT: u64 = i64::MAX as u64;
/// An amount field given as a JSON integer or a decimal string (JS callers pass strings to
/// keep values above 2^53 exact). Returns None for 0, > `max`, or anything else.
pub fn json_amount(v: &serde_json::Value, max: u64) -> Option<u64> {
    let n = match v { serde_json::Value::String(s) if (1..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) => s.parse().ok(), _ => v.as_u64() }?;
    Some(n).filter(|&x| x > 0 && x <= max)
}
/// Checked sum of amounts.
pub fn sum_amounts(it: impl IntoIterator<Item = u64>) -> Option<u64> { it.into_iter().try_fold(0u64, |a, x| a.checked_add(x)) }
pub mod pos;
pub mod nvc_json;
pub use blocktools_core::blake2b;
pub mod zcash;
/// The `"chain"` field of a tx-build JSON line, if any, and the chain a tool should use given an
/// optional `--chain`: the build's chain wins when no flag is given; a conflicting flag is an
/// error (signing a GRS tx with the BTC sighash would produce an invalid tx).
pub fn resolve_chain(txt: &str, flag: Option<String>) -> Result<String, &'static str> {
    let hint = txt.lines().find_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok()?.get("chain")?.as_str().map(String::from));
    match (flag, hint) {
        (Some(f), Some(h)) if f != h => Err("chain_mismatch: --chain differs from the tx file's chain"),
        (Some(f), _) => Ok(f),
        (None, Some(h)) => Ok(h),
        (None, None) => Ok("btc".into()),
    }
}
#[cfg(feature = "secrets")]
pub mod sign;
pub mod rlp;
pub mod message;
use bitcoin::consensus::deserialize;
use bitcoin::psbt::Psbt;
use bitcoin::{Transaction, TxOut};
use blocktools_core::chains::{self, Chain};
use blocktools_core::{b64, hex_dec, hex_enc};
use serde_json::{json, Value};

pub const MAX_INPUT: usize = 4 << 20;

#[derive(Debug, Clone)]
pub struct Io { pub txid: Option<String>, pub vout: Option<u32>, pub address: Option<String>, pub kind: &'static str, pub amount: Option<u64> }

#[derive(Debug, Clone)]
pub struct Decoded {
    pub chain: String,
    /// "btc-tx" | "psbt" | "pos-ntime" | "evm-legacy" | "evm-1559"
    pub ty: &'static str,
    pub signed: bool,
    pub txid: Option<String>,
    pub inputs: Vec<Io>,
    pub outputs: Vec<Io>,
    pub fee: Option<u64>,
    pub vsize: Option<u64>,
    pub locktime: Option<u32>,
    pub rbf: Option<bool>,
    pub evm: Option<evm::Tx>,
    pub warnings: Vec<&'static str>,
    /// Inputs signed with a sighash that does not commit to the amount (legacy P2PKH, PoS nTime)
    /// whose amount is not proven by the full previous transaction. policy::check refuses > 0.
    pub unproven_inputs: usize,
}

/// Raw bytes from text: JSON line field, base64 PSBT, or hex.
pub fn input_bytes(text: &str) -> Result<Vec<u8>, &'static str> {
    let t = text.trim();
    if t.len() > MAX_INPUT { return Err("too_large") }
    if t.starts_with('{') {
        let v: Value = serde_json::from_str(t).map_err(|_| "bad_json")?;
        for k in ["psbt", "signed_tx", "unsigned_tx", "tx"] {
            if let Some(s) = v.get(k).and_then(|x| x.as_str()) { return input_bytes(s) }
        }
        return Err("no_tx_field");
    }
    if t.starts_with("cHNidP") { return b64::decode(t).ok_or("bad_base64") }
    hex_dec(t).ok_or("bad_hex")
}

pub fn decode(text: &str, utxo_chain: &str) -> Result<Decoded, &'static str> {
    if utxo_chain == "zec" {
        let env = zcash::envelope_from_json(text)?;
        let branch = env.as_ref().map(|e| e.1).unwrap_or(zcash::MAINNET_BRANCH_ID);
        let tx = zcash::ZTx::parse(&input_bytes(text)?, branch)?;
        if env.as_ref().is_some_and(|e| e.0.len() != tx.inputs.len()) { return Err("zec_prevouts_count_mismatch") }
        return Ok(zec_decoded(&tx, env.as_ref().map(|e| e.0.as_slice())));
    }
    if pos::layout(utxo_chain).is_some() {
        let c = chains::chain(utxo_chain).ok_or("unknown_chain")?;
        let tx = pos::PosTx::parse(utxo_chain, &input_bytes(text)?)?;
        let prev = pos::prevouts_from_json(text)?;
        if prev.as_ref().is_some_and(|p| p.len() != tx.inputs.len()) { return Err("pos_prevouts_count_mismatch") }
        let mut d = pos_decoded(c, &tx, prev.as_deref());
        d.unproven_inputs = pos::unproven(utxo_chain, &tx, prev.as_deref().unwrap_or(&[]), &pos::prev_txs_from_json(text));
        return Ok(d);
    }
    decode_bytes(&input_bytes(text)?, utxo_chain)
}

/// Decoded view of a Zcash v4/v5 tx: transparent part only (shielded value flows are reported
/// as a `shielded_components` warning, never summed). Input amounts only when `prev` is given.
pub fn zec_decoded(tx: &zcash::ZTx, prev: Option<&[(u64, Vec<u8>)]>) -> Decoded {
    let mut w = Vec::new(); let fw = chains::fee_warn("zec");
    let signed = tx.inputs.iter().any(|i| !i.script_sig.is_empty());
    let io = |amount: u64, s: &[u8]| -> Io {
        let (kind, address) = match zcash::script_to_address(s) { Some((k, a)) => (k, Some(a)), None if s.first() == Some(&0x6a) => ("op_return", None), None => ("nonstandard", None) };
        Io { txid: None, vout: None, address, kind, amount: Some(amount) }
    };
    let inputs: Vec<Io> = tx.inputs.iter().enumerate().map(|(n, i)| {
        let mut x = prev.and_then(|p| p.get(n)).map(|(a, s)| io(*a, s)).unwrap_or(Io { txid: None, vout: None, address: None, kind: "unknown", amount: None });
        let mut t = i.txid; t.reverse(); x.txid = Some(hex_enc(t)); x.vout = Some(i.vout); x
    }).collect();
    let outputs: Vec<Io> = tx.outputs.iter().map(|(a, s)| io(*a, s)).collect();
    let shielded = !tx.sapling.spends.is_empty() || !tx.sapling.outputs.is_empty() || !tx.orchard.actions.is_empty() || !tx.joinsplits.is_empty();
    let out_sum: u64 = outputs.iter().filter_map(|o| o.amount).sum();
    let in_sum: Option<u64> = inputs.iter().map(|i| i.amount).sum();
    let fee = if shielded { None } else { in_sum.and_then(|i| i.checked_sub(out_sum)) };
    if shielded { w.push("shielded_components") }
    if in_sum.is_none() { w.push("input_amounts_unknown") }
    if !shielded && in_sum.is_some() && fee.is_none() { w.push("outputs_exceed_inputs") }
    if let Some(f) = fee {
        if f > fw.fee_for(zcash::signed_size(tx)) { w.push("high_fee") }
        if out_sum > 0 && f * 100 > out_sum * 5 { w.push("high_fee_pct") }
    }
    if outputs.iter().any(|o| o.kind == "nonstandard") { w.push("nonstandard_output") }
    if outputs.iter().any(|o| o.kind == "op_return") { w.push("op_return_output") }
    if outputs.iter().any(|o| o.kind != "op_return" && o.amount.unwrap_or(0) < 546) { w.push("dust_output") }
    if tx.locktime != 0 { w.push("locktime_set") }
    if !signed { w.push("unsigned") }
    if tx.inputs.is_empty() || tx.outputs.is_empty() { w.push("no_inputs_or_outputs") }
    Decoded { chain: "zec".into(), ty: if tx.version == 4 { "zcash-v4" } else { "zcash-v5" }, signed, txid: Some(tx.txid_hex()), inputs, outputs, fee,
        vsize: Some(zcash::signed_size(tx)), locktime: Some(tx.locktime), rbf: Some(false), evm: None, warnings: w, unproven_inputs: 0 }
}

/// Decoded view of a PoS-nTime tx (amounts of inputs only when `prev` is given).
pub fn pos_decoded(c: &Chain, tx: &pos::PosTx, prev: Option<&[(u64, Vec<u8>)]>) -> Decoded {
    let mut w = Vec::new(); let fw = chains::fee_warn(c.name);
    let signed = tx.inputs.iter().any(|i| !i.script_sig.is_empty());
    let io = |amount: u64, s: &[u8]| -> Io {
        let (kind, address) = match chains::script_to_address(c, s) { Some((k, a)) => (k, Some(a)), None if s.first() == Some(&0x6a) => ("op_return", None), None => ("nonstandard", None) };
        Io { txid: None, vout: None, address, kind, amount: Some(amount) }
    };
    let inputs: Vec<Io> = tx.inputs.iter().enumerate().map(|(n, i)| {
        let mut x = prev.and_then(|p| p.get(n)).map(|(a, s)| io(*a, s)).unwrap_or(Io { txid: None, vout: None, address: None, kind: "unknown", amount: None });
        let mut t = i.txid; t.reverse(); x.txid = Some(hex_enc(t)); x.vout = Some(i.vout); x
    }).collect();
    let outputs: Vec<Io> = tx.outputs.iter().map(|(a, s)| io(*a, s)).collect();
    let out_sum: u64 = outputs.iter().filter_map(|o| o.amount).sum();
    let in_sum: Option<u64> = inputs.iter().map(|i| i.amount).sum();
    let fee = in_sum.and_then(|i| i.checked_sub(out_sum));
    let vsize = pos::signed_size(tx);
    if in_sum.is_none() { w.push("input_amounts_unknown") }
    if in_sum.is_some() && fee.is_none() { w.push("outputs_exceed_inputs") }
    if let Some(f) = fee {
        if f > fw.fee_for(vsize) { w.push("high_fee") }
        if out_sum > 0 && f * 100 > out_sum * 5 { w.push("high_fee_pct") }
    }
    if outputs.iter().any(|o| o.kind == "nonstandard") { w.push("nonstandard_output") }
    if outputs.iter().any(|o| o.kind == "op_return") { w.push("op_return_output") }
    if outputs.iter().any(|o| o.kind != "op_return" && o.amount.unwrap_or(0) < 546) { w.push("dust_output") }
    if tx.locktime != 0 { w.push("locktime_set") }
    if !signed { w.push("unsigned") }
    if tx.inputs.is_empty() || tx.outputs.is_empty() { w.push("no_inputs_or_outputs") }
    Decoded { chain: c.name.into(), ty: "pos-ntime", signed, txid: Some(tx.txid_hex()), inputs, outputs, fee, vsize: Some(vsize),
        locktime: Some(tx.locktime), rbf: Some(false), evm: None, warnings: w, unproven_inputs: 0 }
}

pub fn decode_bytes(b: &[u8], utxo_chain: &str) -> Result<Decoded, &'static str> {
    if utxo_chain == "zec" { return Ok(zec_decoded(&zcash::ZTx::parse(b, zcash::MAINNET_BRANCH_ID)?, None)) }
    let c = chains::chain(utxo_chain).ok_or("unknown_chain")?;
    if pos::layout(utxo_chain).is_some() && !b.starts_with(b"psbt\xff") { return Ok(pos_decoded(c, &pos::PosTx::parse(utxo_chain, b)?, None)) }
    if b.starts_with(b"psbt\xff") {
        let p = Psbt::deserialize(b).map_err(|_| "bad_psbt")?;
        return Ok(psbt(c, &p));
    }
    match (b.first(), b.get(1)) {
        (Some(0x02), Some(&x)) if x >= 0xc0 => return evm_decoded(b),
        (Some(0x01), Some(&x)) if x >= 0xc0 => return Err("eip2930_unsupported"),
        (Some(&x), _) if x >= 0xc0 => return evm_decoded(b),
        _ => {}
    }
    let tx: Transaction = deserialize(b).map_err(|_| "bad_transaction")?;
    Ok(btc_tx(c, &tx, None))
}

/// A raw (non-PSBT, non-EVM, non-PoS, non-Zcash) UTXO tx decoded with input values taken from
/// full previous transactions. Each prev tx is matched by HASHING it: an input gets an amount only
/// when a given prev tx hashes to its outpoint txid and has that vout, so a wrong or forged prev tx
/// can't change the fee (it is ignored and the input stays unknown, warning prevout_missing).
/// Prev txs that match no input are refused (prevtx_unused), so a mixed-up file is visible.
pub fn decode_with_prevtxs(b: &[u8], utxo_chain: &str, prevtxs: &[Vec<u8>]) -> Result<Decoded, &'static str> {
    let c = chains::chain(utxo_chain).ok_or("unknown_chain")?;
    if utxo_chain == "zec" || pos::layout(utxo_chain).is_some() || b.starts_with(b"psbt\xff") || b.first().is_some_and(|&x| x >= 0xc0) || b.get(1).is_some_and(|&x| x >= 0xc0) {
        return Err("prevtxs_raw_utxo_tx_only")
    }
    let tx: Transaction = deserialize(b).map_err(|_| "bad_transaction")?;
    let dg = digest::Digest::for_chain(c);
    let mut parsed = vec![];
    for p in prevtxs { let t: Transaction = deserialize(p).map_err(|_| "bad_prevtx")?; parsed.push((digest::txid(&t, dg), t)) }
    if parsed.iter().any(|(id, _)| !tx.input.iter().any(|i| i.previous_output.txid == *id)) { return Err("prevtx_unused") }
    let prev: Vec<Option<TxOut>> = tx.input.iter().map(|i| parsed.iter().find(|(id, _)| *id == i.previous_output.txid)
        .and_then(|(_, t)| t.output.get(i.previous_output.vout as usize).cloned())).collect();
    let missing = prev.iter().any(|p| p.is_none());
    let mut d = btc_tx(c, &tx, Some(prev));
    if missing { d.warnings.push("prevout_missing") }
    Ok(d)
}

fn out_io(c: &Chain, o: &TxOut) -> Io {
    let s = o.script_pubkey.as_bytes();
    let (kind, address) = match chains::script_to_address(c, s) {
        Some((k, a)) => (k, Some(a)),
        None if s.first() == Some(&0x6a) => ("op_return", None),
        None => ("nonstandard", None),
    };
    Io { txid: None, vout: None, address, kind, amount: Some(o.value.to_sat()) }
}
/// Extra vbytes a signature adds to an unsigned input, by script kind (estimate).
fn sig_vbytes(kind: &str) -> u64 { match kind { "p2wpkh" => 27, "p2sh" => 50, "p2tr" => 17, _ => 107 } }

fn btc_tx(c: &Chain, tx: &Transaction, prev: Option<Vec<Option<TxOut>>>) -> Decoded {
    let mut w = Vec::new(); let fw = chains::fee_warn(c.name);
    let signed = tx.input.iter().any(|i| !i.script_sig.is_empty() || !i.witness.is_empty());
    let inputs: Vec<Io> = tx.input.iter().enumerate().map(|(n, i)| {
        let p = prev.as_ref().and_then(|v| v.get(n).cloned().flatten());
        let mut io = p.as_ref().map(|o| out_io(c, o)).unwrap_or(Io { txid: None, vout: None, address: None, kind: "unknown", amount: None });
        io.txid = Some(i.previous_output.txid.to_string()); io.vout = Some(i.previous_output.vout); io
    }).collect();
    let outputs: Vec<Io> = tx.output.iter().map(|o| out_io(c, o)).collect();
    let out_sum: u64 = outputs.iter().filter_map(|o| o.amount).sum();
    let in_sum: Option<u64> = inputs.iter().map(|i| i.amount).sum();
    let fee = in_sum.and_then(|i| i.checked_sub(out_sum));
    if in_sum.is_none() { w.push("input_amounts_unknown") }
    if in_sum.is_some() && fee.is_none() { w.push("outputs_exceed_inputs") }
    let vsize = tx.vsize() as u64 + if signed { 0 } else { inputs.iter().map(|i| sig_vbytes(i.kind)).sum() };
    if let Some(f) = fee {
        if f > fw.fee_for(vsize) { w.push("high_fee") }
        if out_sum > 0 && f * 100 > out_sum * 5 { w.push("high_fee_pct") }
        if vsize > 0 && f / vsize > fw.rate { w.push("high_fee_rate") }
    }
    if outputs.iter().any(|o| o.kind == "nonstandard") { w.push("nonstandard_output") }
    if outputs.iter().any(|o| o.kind == "op_return") { w.push("op_return_output") }
    if outputs.iter().any(|o| o.kind != "op_return" && o.amount.unwrap_or(0) < 546) { w.push("dust_output") }
    let rbf = tx.input.iter().any(|i| i.sequence.0 < 0xffff_fffe);
    let lt = tx.lock_time.to_consensus_u32();
    if lt != 0 { w.push("locktime_set") }
    if !signed { w.push("unsigned") }
    if tx.input.is_empty() || tx.output.is_empty() { w.push("no_inputs_or_outputs") }
    Decoded { chain: c.name.into(), ty: "btc-tx", signed, txid: Some(digest::txid_hex(tx, digest::Digest::for_chain(c))), inputs, outputs, fee, vsize: Some(vsize),
        locktime: Some(lt), rbf: Some(rbf), evm: None, warnings: w, unproven_inputs: 0 }
}

fn psbt(c: &Chain, p: &Psbt) -> Decoded {
    let mut bad = false;
    let dg = digest::Digest::for_chain(c);
    let unproven = p.inputs.iter().zip(&p.unsigned_tx.input).filter(|(i, ti)| {
        let spk = i.witness_utxo.as_ref().map(|o| o.script_pubkey.clone()).or_else(|| i.non_witness_utxo.as_ref()?.output.get(ti.previous_output.vout as usize).map(|o| o.script_pubkey.clone()));
        match spk { Some(s) => digest::input_amount_uncommitted(&s, i.redeem_script.as_deref()) && digest::proven_prevout(i, &ti.previous_output, dg).is_none(), None => true }
    }).count();
    let prev: Vec<Option<TxOut>> = p.inputs.iter().zip(&p.unsigned_tx.input).map(|(i, ti)| {
        if let Some(o) = &i.witness_utxo { return Some(o.clone()) }
        let t = i.non_witness_utxo.as_ref()?;
        if digest::txid(t, digest::Digest::for_chain(c)) != ti.previous_output.txid { bad = true; return None }
        t.output.get(ti.previous_output.vout as usize).cloned()
    }).collect();
    let mut d = btc_tx(c, &p.unsigned_tx, Some(prev));
    d.ty = "psbt";
    let fin = !p.inputs.is_empty() && p.inputs.iter().all(|i| i.final_script_sig.is_some() || i.final_script_witness.is_some());
    let partial = p.inputs.iter().any(|i| !i.partial_sigs.is_empty() || i.tap_key_sig.is_some());
    d.signed = fin;
    d.warnings.retain(|w| *w != "unsigned");
    if !fin { d.warnings.push(if partial { "partially_signed" } else { "unsigned" }) }
    if bad { d.warnings.push("utxo_txid_mismatch") }
    d.unproven_inputs = unproven;
    d
}

pub fn addr(a: &[u8; 20]) -> String { blocktools_core::validate::checksum_eth(a) }

fn evm_decoded(b: &[u8]) -> Result<Decoded, &'static str> {
    let t = evm::Tx::parse(b)?;
    let mut w = Vec::new();
    if t.chain_id.is_none() { w.push("no_chain_id") }
    if t.to.is_none() { w.push("contract_creation") }
    if t.sig.is_none() { w.push("unsigned") }
    let maxfee = t.max_fee_per_gas.saturating_mul(t.gas as u128);
    if t.max_fee_per_gas > 1_000_000_000_000 { w.push("high_gas_price") }
    if t.value > 0 && maxfee > t.value / 20 { w.push("high_fee_pct") }
    if let Some(tc) = evm::token_call(&t.data) {
        if tc.method == "approve" { w.push(if tc.amount.iter().all(|&x| x == 0xff) { "unlimited_approve" } else { "token_approve" }) }
        if tc.method == "transferFrom" { w.push("token_transfer_from") }
    } else if !t.data.is_empty() { w.push("unknown_calldata") }
    let from = t.from().map(|a| addr(&a));
    if t.sig.is_some() && from.is_none() { w.push("bad_signature") }
    let inputs = from.map(|a| vec![Io { txid: None, vout: None, address: Some(a), kind: "eth", amount: None }]).unwrap_or_default();
    let outputs = vec![Io { txid: None, vout: None, address: t.to.map(|a| addr(&a)), kind: "eth", amount: u64::try_from(t.value).ok() }];
    Ok(Decoded { chain: "eth".into(), ty: if t.kind == evm::Kind::Legacy { "evm-legacy" } else { "evm-1559" }, signed: t.sig.is_some(),
        txid: t.txhash().map(|h| format!("0x{}", hex_enc(h))), inputs, outputs, fee: None, vsize: None, locktime: None, rbf: None, evm: Some(t), warnings: w, unproven_inputs: 0 })
}

/// tx-decode's EVM path: every envelope `evm_decode` reads (legacy, 2930, 1559, 4844 canonical and
/// network form, 7702). The summary keeps the legacy/1559 keys and warnings of `evm_decoded`; the
/// View carries the additive keys (`View::extra`). Signing paths keep using `evm::Tx::parse`.
pub fn decode_evm_view(b: &[u8]) -> Result<(Decoded, evm_decode::View), &'static str> {
    let v = evm_decode::parse(b)?;
    let t = v.as_tx();
    let mut w = Vec::new();
    if t.chain_id.is_none() { w.push("no_chain_id") }
    if t.to.is_none() { w.push("contract_creation") }
    if t.sig.is_none() { w.push("unsigned") }
    let maxfee = t.max_fee_per_gas.saturating_mul(t.gas as u128);
    if t.max_fee_per_gas > 1_000_000_000_000 { w.push("high_gas_price") }
    if t.value > 0 && maxfee > t.value / 20 { w.push("high_fee_pct") }
    if let Some(tc) = evm::token_call(&t.data) {
        if tc.method == "approve" { w.push(if tc.amount.iter().all(|&x| x == 0xff) { "unlimited_approve" } else { "token_approve" }) }
        if tc.method == "transferFrom" { w.push("token_transfer_from") }
    } else if !t.data.is_empty() { w.push("unknown_calldata") }
    if v.tx_type == 4 { w.push("eip7702_delegation") }
    let from = v.from.map(|a| addr(&a));
    if t.sig.is_some() && from.is_none() { w.push("bad_signature") }
    let inputs = from.map(|a| vec![Io { txid: None, vout: None, address: Some(a), kind: "eth", amount: None }]).unwrap_or_default();
    let outputs = vec![Io { txid: None, vout: None, address: t.to.map(|a| addr(&a)), kind: "eth", amount: u64::try_from(t.value).ok() }];
    let d = Decoded { chain: "eth".into(), ty: v.type_name(), signed: t.sig.is_some(), txid: v.hash.map(|h| format!("0x{}", hex_enc(h))),
        inputs, outputs, fee: None, vsize: None, locktime: None, rbf: None, evm: Some(t), warnings: w, unproven_inputs: 0 };
    Ok((d, v))
}

fn btc_amt(s: u64) -> String { format!("{}.{:08}", s / 100_000_000, s % 100_000_000) }
/// Exact gwei with up to 9 decimals (finding 3: integer division showed "0 gwei" below 1 gwei).
fn gwei_amt(w: u128) -> String {
    let (i, f) = (w / 1_000_000_000, w % 1_000_000_000);
    let f = format!("{f:09}"); let f = f.trim_end_matches('0');
    if f.is_empty() { i.to_string() } else { format!("{i}.{f}") }
}

fn wei_amt(w: u128) -> String {
    let (i, f) = (w / 1_000_000_000_000_000_000, w % 1_000_000_000_000_000_000);
    let f = format!("{f:018}"); let f = f.trim_end_matches('0');
    format!("{i}.{}", if f.is_empty() { "0" } else { f })
}

impl Decoded {
    /// Public JSON lines (no keys exist in a transaction): a summary line, then one per input/output.
    pub fn json_lines(&self) -> Vec<Value> {
        let mut s = json!({"tool":"tx-decode","status":"ok","role":"summary","chain":self.chain,"type":self.ty,"signed":self.signed,
            "inputs":self.inputs.len(),"outputs":self.outputs.len(),"warnings":self.warnings});
        let o = s.as_object_mut().unwrap();
        if chains::chain_spec_banner(&self.chain).is_some() { o.insert("chain_spec".into(), json!("unverified chain spec")); }
        if let Some(t) = &self.txid { o.insert("txid".into(), json!(t)); }
        if let Some(f) = self.fee { o.insert("fee".into(), json!(f)); }
        if let Some(v) = self.vsize { o.insert("vsize".into(), json!(v)); if let Some(f) = self.fee { o.insert("fee_rate".into(), json!(f / v.max(1))); } }
        if let Some(l) = self.locktime { o.insert("locktime".into(), json!(l)); }
        if let Some(r) = self.rbf { o.insert("rbf".into(), json!(r)); }
        if let Some(t) = &self.evm {
            o.insert("chain_id".into(), json!(t.chain_id)); o.insert("nonce".into(), json!(t.nonce)); o.insert("gas".into(), json!(t.gas));
            o.insert("max_fee_per_gas".into(), json!(t.max_fee_per_gas.to_string()));
            if let Some(p) = t.max_priority_fee_per_gas { o.insert("max_priority_fee_per_gas".into(), json!(p.to_string())); }
            o.insert("max_fee".into(), json!(t.max_fee_per_gas.saturating_mul(t.gas as u128).to_string()));
            o.insert("value".into(), json!(t.value.to_string()));
            if let Some(a) = t.to { o.insert("to".into(), json!(addr(&a))); }
            if let Some(a) = self.inputs.first().and_then(|i| i.address.clone()) { o.insert("from".into(), json!(a)); }
            o.insert("data_len".into(), json!(t.data.len()));
            if let Some(tc) = evm::token_call(&t.data) {
                o.insert("selector".into(), json!(tc.method)); o.insert("token".into(), json!(t.to.map(|a| addr(&a))));
                o.insert("token_to".into(), json!(addr(&tc.to))); o.insert("token_amount".into(), json!(evm::dec(&tc.amount)));
            }
        }
        let mut v = vec![s];
        if self.evm.is_none() {
            for (role, list) in [("input", &self.inputs), ("output", &self.outputs)] {
                for (i, io) in list.iter().enumerate() {
                    let mut l = json!({"tool":"tx-decode","status":"ok","role":role,"index":i,"chain":self.chain,"kind":io.kind});
                    let m = l.as_object_mut().unwrap();
                    if let Some(t) = &io.txid { m.insert("txid".into(), json!(t)); }
                    if let Some(n) = io.vout { m.insert("vout".into(), json!(n)); }
                    if let Some(a) = &io.address { m.insert("address".into(), json!(a)); }
                    if let Some(a) = io.amount { m.insert("amount".into(), json!(a)); }
                    v.push(l);
                }
            }
        }
        v
    }
    /// Plain-language summary a human reads before typing the confirmation code.
    pub fn text(&self) -> String {
        let mut s = String::new();
        use std::fmt::Write;
        let _ = writeln!(s, "=== TRANSACTION ({} {}, {}) ===", self.chain, self.ty, if self.signed { "SIGNED" } else { "unsigned" });
        // Chain spec (docs/CHAIN-SPEC.md): second line of every plain summary, so tx-decode,
        // tx-verify --text and the tx-sign confirmation all carry it.
        if let Some(b) = chains::chain_spec_banner(&self.chain) { let _ = writeln!(s, "{b}"); }
        if let Some(t) = &self.evm {
            // Critical lines first, boxed and upper-case, so they cannot be missed.
            let sym = evm::native_symbol(t.chain_id);
            let tc = evm::token_call(&t.data);
            let mf = t.max_fee_per_gas.saturating_mul(t.gas as u128);
            let _ = writeln!(s, "################ CHECK THESE ################");
            let _ = writeln!(s, "## CHAIN ID  : {}", t.chain_id.map_or("NONE - REPLAYABLE ON ANY CHAIN".into(), |c| format!("{c} = {}", evm::chain_name(c).to_uppercase())));
            match &tc {
                Some(c) => { let _ = writeln!(s, "## KIND      : TOKEN {} (contract {})", c.method.to_uppercase(), t.to.map_or(String::new(), |a| addr(&a)));
                    let _ = writeln!(s, "## RECIPIENT : {}", addr(&c.to));
                    let _ = writeln!(s, "## AMOUNT    : {} token raw units", evm::dec(&c.amount)); }
                None => { let _ = writeln!(s, "## KIND      : {}", if t.data.is_empty() { format!("NATIVE {sym}") } else { "CONTRACT CALL (UNRECOGNISED)".into() });
                    let _ = writeln!(s, "## RECIPIENT : {}", t.to.map_or("(contract creation)".into(), |a| addr(&a))); }
            }
            let _ = writeln!(s, "## VALUE     : {} {sym}{}", wei_amt(t.value), if tc.is_some() && t.value > 0 { "  <-- NATIVE COIN SENT TO A TOKEN CONTRACT" } else { "" });
            let _ = writeln!(s, "## MAX FEE   : {} {sym}", wei_amt(mf));
            let _ = writeln!(s, "#############################################");
            let cid = t.chain_id.map_or("NONE (replayable on any chain!)".to_string(), |c| format!("{c} ({})", evm::chain_name(c)));
            let _ = writeln!(s, "network chain id : {cid}");
            if let Some(a) = self.inputs.first().and_then(|i| i.address.as_ref()) { let _ = writeln!(s, "from             : {a}"); }
            let _ = writeln!(s, "to               : {}", t.to.map_or("(contract creation)".into(), |a| addr(&a)));
            let _ = writeln!(s, "value            : {} (native coin, {} wei)", wei_amt(t.value), t.value);
            let _ = writeln!(s, "nonce            : {}", t.nonce);
            let mf = t.max_fee_per_gas.saturating_mul(t.gas as u128);
            let _ = writeln!(s, "max network fee  : {} (gas {} x {} gwei)", wei_amt(mf), t.gas, gwei_amt(t.max_fee_per_gas));
            if let Some(tc) = evm::token_call(&t.data) {
                let _ = writeln!(s, "TOKEN {:<11}: token contract {} -> {} amount {} (raw units)", tc.method, t.to.map_or(String::new(), |a| addr(&a)), addr(&tc.to), evm::dec(&tc.amount));
            } else if !t.data.is_empty() { let _ = writeln!(s, "contract data    : {} bytes (NOT a recognised token transfer)", t.data.len()); }
        } else {
            for (n, i) in self.inputs.iter().enumerate() {
                let _ = writeln!(s, "in  #{n}: {} {}", i.address.as_deref().unwrap_or("(unknown address)"), i.amount.map_or("(amount unknown)".into(), btc_amt));
            }
            for (n, o) in self.outputs.iter().enumerate() {
                let _ = writeln!(s, "OUT #{n}: {} {} [{}]", o.address.as_deref().unwrap_or("(no address)"), o.amount.map_or(String::new(), btc_amt), o.kind);
            }
            match (self.fee, self.vsize) {
                (Some(f), Some(v)) => { let _ = writeln!(s, "fee    : {} {} (~{} sat/vB)", btc_amt(f), self.chain, f / v.max(1)); }
                _ => { let _ = writeln!(s, "fee    : UNKNOWN (input amounts not in this data)"); }
            }
            let _ = writeln!(s, "rbf {} locktime {}", self.rbf.unwrap_or(false), self.locktime.unwrap_or(0));
        }
        if !self.warnings.is_empty() { let _ = writeln!(s, "WARNINGS: {}", self.warnings.join(", ")); }
        s
    }
}
