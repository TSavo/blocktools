//! Offline transaction building from files (never the network).
//! UTXO file: JSON lines {"txid","vout","amount"(sats),"address"[, "prev_tx" hex]}.
use bitcoin::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use blocktools_core::chains::{self, Chain};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Utxo { pub txid: Txid, pub vout: u32, pub amount: u64, pub script: Vec<u8>, pub kind: &'static str, pub prev_tx: Option<Transaction> }

pub fn parse_utxos(c: &Chain, text: &str) -> Result<Vec<Utxo>, String> {
    let mut v = Vec::new();
    for (n, l) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        if v.len() >= 2000 { return Err("too_many_utxos".into()) }
        let e = |m: &str| format!("utxo line {}: {m}", n + 1);
        let j: serde_json::Value = serde_json::from_str(l).map_err(|_| e("bad_json"))?;
        let txid = Txid::from_str(j["txid"].as_str().ok_or_else(|| e("txid"))?).map_err(|_| e("txid"))?;
        let vout = j["vout"].as_u64().filter(|&x| x <= u32::MAX as u64).ok_or_else(|| e("vout"))? as u32;
        let amount = j["amount"].as_u64().filter(|&x| x > 0 && x <= 21_000_000 * 100_000_000).ok_or_else(|| e("amount"))?;
        let addr = j["address"].as_str().ok_or_else(|| e("address"))?;
        let script = chains::address_to_script(c, addr).ok_or_else(|| e("address not valid for chain"))?;
        let kind = chains::script_to_address(c, &script).map(|x| x.0).unwrap_or("unknown");
        let prev_tx = match j["prev_tx"].as_str() {
            Some(h) => { let t: Transaction = bitcoin::consensus::deserialize(&blocktools_core::hex_dec(h).ok_or_else(|| e("prev_tx hex"))?).map_err(|_| e("prev_tx"))?;
                if crate::digest::txid(&t, crate::digest::Digest::for_chain(c)) != txid { return Err(e("prev_tx does not match txid")) }
                if t.output.get(vout as usize).map(|o| (o.value.to_sat(), o.script_pubkey.as_bytes().to_vec())) != Some((amount, script.clone())) { return Err(e("prev_tx output differs from amount/address")) }
                Some(t) }
            None => None,
        };
        v.push(Utxo { txid, vout, amount, script, kind, prev_tx });
    }
    if v.is_empty() { return Err("no_utxos".into()) }
    Ok(v)
}
/// Signed input vbytes by kind (estimates used for fee calculation).
pub fn in_vb(kind: &str) -> u64 { match kind { "p2wpkh" => 68, "p2sh" => 91, "p2tr" => 58, _ => 148 } }
pub fn out_vb(script: &[u8]) -> u64 { 9 + script.len() as u64 }

pub struct BtcPlan { pub to: String, pub send: Option<u64>, pub change: Option<String>, pub fee_rate: u64, pub rbf: bool, pub dust: u64, pub locktime: u32 }

pub fn build_btc(c: &Chain, mut utxos: Vec<Utxo>, p: &BtcPlan) -> Result<Psbt, String> {
    if p.fee_rate == 0 || p.fee_rate > 2000 { return Err("fee_rate must be 1..2000 sat/vB".into()) }
    let to = chains::address_to_script(c, &p.to).ok_or("bad --to address")?;
    let vsize = |ins: &[Utxo], outs: &[&[u8]]| 11 + ins.iter().map(|u| in_vb(u.kind)).sum::<u64>() + outs.iter().map(|s| out_vb(s)).sum::<u64>();
    let mut outs: Vec<(Vec<u8>, u64)> = Vec::new();
    let chosen: Vec<Utxo> = match p.send {
        None => { // sweep / consolidate: everything, one output
            let total: u64 = utxos.iter().map(|u| u.amount).sum();
            let fee = vsize(&utxos, &[&to]) * p.fee_rate;
            let v = total.checked_sub(fee).filter(|&v| v >= p.dust).ok_or("balance does not cover the fee (or leaves dust)")?;
            outs.push((to, v)); utxos
        }
        Some(amount) => {
            if amount < p.dust { return Err("amount below dust limit".into()) }
            let ch = chains::address_to_script(c, p.change.as_deref().ok_or("--send needs --change ADDR")?).ok_or("bad --change address")?;
            utxos.sort_by(|a, b| b.amount.cmp(&a.amount));
            let mut sel = Vec::new(); let mut total = 0;
            let mut done = false;
            for u in utxos { total += u.amount; sel.push(u);
                if total >= amount + vsize(&sel, &[&to, &ch]) * p.fee_rate { done = true; break } }
            if !done {
                // maybe enough without a change output
                if total < amount + vsize(&sel, &[&to]) * p.fee_rate { return Err("insufficient funds".into()) }
            }
            let fee2 = vsize(&sel, &[&to, &ch]) * p.fee_rate;
            outs.push((to, amount));
            if let Some(change) = total.checked_sub(amount + fee2).filter(|&x| x >= p.dust) { outs.push((ch, change)) } // else the remainder goes to fee
            sel
        }
    };
    let seq = if p.rbf { Sequence::ENABLE_RBF_NO_LOCKTIME } else if p.locktime != 0 { Sequence::ENABLE_LOCKTIME_NO_RBF } else { Sequence::MAX };
    let tx = Transaction { version: Version::TWO, lock_time: LockTime::from_consensus(p.locktime),
        input: chosen.iter().map(|u| TxIn { previous_output: OutPoint { txid: u.txid, vout: u.vout }, script_sig: ScriptBuf::new(), sequence: seq, witness: Witness::new() }).collect(),
        output: outs.iter().map(|(s, v)| TxOut { value: Amount::from_sat(*v), script_pubkey: ScriptBuf::from_bytes(s.clone()) }).collect() };
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|_| "psbt")?;
    for (i, u) in chosen.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(TxOut { value: Amount::from_sat(u.amount), script_pubkey: ScriptBuf::from_bytes(u.script.clone()) });
        psbt.inputs[i].non_witness_utxo = u.prev_tx.clone();
    }
    Ok(psbt)
}

/// What an EVM transaction moves.
#[derive(Debug, Clone, PartialEq)]
pub enum EvmAmount {
    /// Native value in wei.
    Send(u128),
    /// Whole balance minus max gas cost (balance in wei).
    Sweep { balance: u128 },
    /// `units` × max_fee_per_gas wei: gas money for a later token move.
    Topup(u128),
    /// ERC-20 `transfer(to, amount)` on the token contract.
    Token { token: [u8; 20], amount: u128 },
}
/// Parameters of an unsigned EVM transaction. `priority_fee` None = legacy (type 0).
#[derive(Debug, Clone, PartialEq)]
pub struct EvmPlan { pub chain_id: u64, pub nonce: u64, pub max_fee: u128, pub priority_fee: Option<u128>, pub gas: Option<u64>, pub to: [u8; 20], pub amount: EvmAmount }

/// Build the unsigned EVM transaction. Default gas: 21000, or 100000 for a token transfer.
pub fn build_evm(p: &EvmPlan) -> Result<crate::evm::Tx, &'static str> {
    use crate::evm::{transfer_calldata, Kind, Tx};
    let gas = p.gas.unwrap_or(if matches!(p.amount, EvmAmount::Token { .. }) { 100_000 } else { 21_000 });
    let fee = p.max_fee.checked_mul(gas as u128).ok_or("fee overflow")?;
    let (dest, value, data) = match p.amount {
        EvmAmount::Token { token, amount } => (token, 0, transfer_calldata(&p.to, amount)),
        EvmAmount::Topup(units) => (p.to, units.checked_mul(p.max_fee).ok_or("overflow")?, vec![]),
        EvmAmount::Sweep { balance } => (p.to, balance.checked_sub(fee).filter(|&v| v > 0).ok_or("balance does not cover gas")?, vec![]),
        EvmAmount::Send(v) => (p.to, v, vec![]),
    };
    Ok(Tx { kind: if p.priority_fee.is_none() { Kind::Legacy } else { Kind::Eip1559 }, chain_id: Some(p.chain_id), nonce: p.nonce,
        max_fee_per_gas: p.max_fee, max_priority_fee_per_gas: p.priority_fee.map(|x| x.min(p.max_fee)), gas, to: Some(dest), value, data,
        access_list: crate::rlp::Rlp::L(vec![]), sig: None })
}

/// Unsigned sweep of every P2PKH `utxos` entry to `to` on an nTime chain (PPC/NVC/CLAM/RDD), with
/// tx timestamp `time` (unix seconds). Fee = fee_rate (base units per byte) x signed size.
pub fn build_pos_sweep(c: &Chain, utxos: &[Utxo], to: &str, fee_rate: u64, time: u32, dust: u64) -> Result<(crate::pos::PosTx, crate::pos::Prevouts), String> {
    use crate::pos::{layout, PIn, PosTx};
    use bitcoin::hashes::Hash;
    let l = layout(c.name).ok_or("not an nTime chain with a verified layout")?;
    if fee_rate == 0 || fee_rate > 100_000 { return Err("fee_rate must be 1..100000 per byte".into()) }
    if let Some(u) = utxos.iter().find(|u| u.kind != "p2pkh") { return Err(format!("pos-ntime sweep supports p2pkh inputs only (got {})", u.kind)) }
    if utxos.iter().any(|u| u.prev_tx.is_some()) { return Err("prev_tx is not used for pos-ntime chains".into()) }
    let to_s = chains::address_to_script(c, to).ok_or("bad --to address")?;
    let inputs = utxos.iter().map(|u| PIn { txid: u.txid.to_byte_array(), vout: u.vout, script_sig: vec![], sequence: 0xffff_ffff }).collect();
    let mut tx = PosTx { layout: l, time, inputs, outputs: vec![(0, to_s)], locktime: 0, speech: vec![] };
    let total: u64 = utxos.iter().map(|u| u.amount).sum();
    let fee = crate::pos::signed_size(&tx) * fee_rate;
    tx.outputs[0].0 = total.checked_sub(fee).filter(|&v| v >= dust).ok_or("balance does not cover the fee (or leaves dust)")?;
    Ok((tx, utxos.iter().map(|u| (u.amount, u.script.clone())).collect()))
}
