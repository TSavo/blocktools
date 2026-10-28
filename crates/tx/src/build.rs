//! Offline transaction building from files (never the network).
//! UTXO file: JSON lines {"txid","vout","amount"(sats),"address"[, "prev_tx" hex][, "redeem_script" hex][, "script" hex]}.
//! A bare-pubkey (P2PK) output is spent when "script" or the prev_tx output is `<key> OP_CHECKSIG`
//! for the key behind the P2PKH "address"; prev_tx is then required (legacy sighash).
use bitcoin::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use blocktools_core::chains::{self, Chain};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct Utxo { pub txid: Txid, pub vout: u32, pub amount: u64, pub script: Vec<u8>, pub kind: &'static str, pub prev_tx: Option<Transaction>, pub redeem: Option<ScriptBuf>,
    /// Raw previous tx bytes for nTime chains (PoS layout, not a bitcoin Transaction).
    pub prev_raw: Option<Vec<u8>> }

/// The pubkey of a bare P2PK script (`<33|65-byte key> OP_CHECKSIG`).
pub fn p2pk_key(spk: &[u8]) -> Option<&[u8]> {
    match spk { [0x21, k @ .., 0xac] if k.len() == 33 => Some(k), [0x41, k @ .., 0xac] if k.len() == 65 => Some(k), _ => None }
}
pub fn parse_utxos(c: &Chain, text: &str) -> Result<Vec<Utxo>, String> {
    let mut v = Vec::new();
    for (n, l) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        if v.len() >= 2000 { return Err("too_many_utxos".into()) }
        let e = |m: &str| format!("utxo line {}: {m}", n + 1);
        let j: serde_json::Value = serde_json::from_str(l).map_err(|_| e("bad_json"))?;
        let txid = Txid::from_str(j["txid"].as_str().ok_or_else(|| e("txid"))?).map_err(|_| e("txid"))?;
        let vout = j["vout"].as_u64().filter(|&x| x <= u32::MAX as u64).ok_or_else(|| e("vout"))? as u32;
        let amount = crate::json_amount(&j["amount"], crate::MAX_AMOUNT).ok_or_else(|| e("amount"))?;
        let addr = j["address"].as_str().ok_or_else(|| e("address"))?;
        let mut script = chains::address_to_script(c, addr).ok_or_else(|| e("address not valid for chain"))?;
        let mut kind = chains::script_to_address(c, &script).map(|x| x.0).unwrap_or("unknown");
        // Bare-pubkey (P2PK) output, e.g. PoS coinstake: owned by the P2PKH address of its key. Taken
        // from an explicit "script" or from the prev_tx output; either way prev_tx must prove it below.
        let pos = crate::pos::layout(c.name).is_some();
        let addr_h: Option<[u8; 20]> = (kind == "p2pkh").then(|| script[3..23].try_into().unwrap());
        let p2pk_ok = |spk: &[u8]| p2pk_key(spk).is_some_and(|k| { use bitcoin::hashes::Hash; addr_h == Some(bitcoin::hashes::hash160::Hash::hash(k).to_byte_array()) });
        let out_at = |b: &[u8]| -> Option<Vec<u8>> { if pos { crate::pos::PosTx::parse(c.name, b).ok()?.outputs.get(vout as usize).map(|o| o.1.clone()) }
            else { bitcoin::consensus::deserialize::<Transaction>(b).ok()?.output.get(vout as usize).map(|o| o.script_pubkey.to_bytes()) } };
        let explicit = match j["script"].as_str() { Some(h) => Some(blocktools_core::hex_dec(h).ok_or_else(|| e("script hex"))?), None => None };
        let from_prev = j["prev_tx"].as_str().and_then(blocktools_core::hex_dec).and_then(|b| out_at(&b));
        match (explicit, from_prev) {
            (Some(x), _) if x == script => {}
            (Some(x), _) if p2pk_ok(&x) => { script = x; kind = "p2pk" }
            (Some(_), _) => return Err(e("script is neither the address script nor a P2PK of its key")),
            (None, Some(x)) if p2pk_ok(&x) => { script = x; kind = "p2pk" }
            _ => {}
        }
        if kind == "p2pk" && j["prev_tx"].as_str().is_none() { return Err(e("p2pk input needs prev_tx (legacy sighash, amount unproven)")) }
        let mut prev_raw = None;
        let prev_tx = match j["prev_tx"].as_str() {
            Some(h) if pos => { let b = blocktools_core::hex_dec(h).ok_or_else(|| e("prev_tx hex"))?;
                let t = crate::pos::PosTx::parse(c.name, &b).map_err(|_| e("prev_tx"))?;
                if t.txid_hex() != txid.to_string() { return Err(e("prev_tx does not match txid")) }
                if t.outputs.get(vout as usize) != Some(&(amount, script.clone())) { return Err(e("prev_tx output differs from amount/address")) }
                prev_raw = Some(b); None }
            Some(h) => { let t: Transaction = bitcoin::consensus::deserialize(&blocktools_core::hex_dec(h).ok_or_else(|| e("prev_tx hex"))?).map_err(|_| e("prev_tx"))?;
                if crate::digest::txid(&t, crate::digest::Digest::for_chain(c)) != txid { return Err(e("prev_tx does not match txid")) }
                if t.output.get(vout as usize).map(|o| (o.value.to_sat(), o.script_pubkey.as_bytes().to_vec())) != Some((amount, script.clone())) { return Err(e("prev_tx output differs from amount/address")) }
                Some(t) }
            None => None,
        };
        let redeem = match j["redeem_script"].as_str() {
            Some(h) => { let r = ScriptBuf::from_bytes(blocktools_core::hex_dec(h).ok_or_else(|| e("redeem_script hex"))?);
                if !crate::digest::p2sh_proven_segwit(bitcoin::Script::from_bytes(&script), Some(&r)) { return Err(e("redeem_script is not a witness program hashing to this p2sh address")) }
                Some(r) }
            None => None,
        };
        v.push(Utxo { txid, vout, amount, script, kind, prev_tx, redeem, prev_raw });
    }
    if v.is_empty() { return Err("no_utxos".into()) }
    Ok(v)
}
/// Signed input vbytes by kind (estimates used for fee calculation).
pub fn in_vb(kind: &str) -> u64 { match kind { "p2wpkh" => 68, "p2sh" => 91, "p2tr" => 58, "p2pk" => 114, _ => 148 } }
pub fn out_vb(script: &[u8]) -> u64 { 9 + script.len() as u64 }

/// `op_return`: optional zero-value trailing output script (e.g. a THORChain memo). Its vbytes are
/// counted during coin selection, so the memo is funded like any other output.
pub struct BtcPlan { pub to: String, pub send: Option<u64>, pub change: Option<String>, pub fee_rate: u64, pub rbf: bool, pub dust: u64, pub op_return: Option<Vec<u8>>, pub locktime: u32 }

/// Largest OP_RETURN data push the chain's reference node relays (bytes). Mirrors
/// `blocktools::psbtmemo::op_return_limit`, measured by memo-regtest.sh on regtest: BCHN 28.0.1 accepts 220,
/// Litecoin and Dogecoin accept 80. Bitcoin's 80 is not measured: memo-regtest.sh runs ltc, doge and bch only. Used by tx-build's `--op-return`/`--memo` (THORChain memo).
pub fn op_return_limit(chain: &str) -> usize { match chain { "bch" => 220, _ => 80 } }

/// OP_RETURN output script for `memo`, refused above the chain's relay limit (`op_return_limit`).
/// `6a <pushdata> <memo>`: a direct push for <=75 bytes, OP_PUSHDATA1 (0x4c) above it.
pub fn op_return_script(chain: &str, memo: &[u8]) -> Result<Vec<u8>, String> {
    let max = op_return_limit(chain).min(255);
    if memo.len() > max { return Err(format!("memo is {} bytes, over the {max}-byte OP_RETURN limit for {chain}", memo.len())) }
    let mut s = vec![0x6a];
    if memo.len() <= 75 { s.push(memo.len() as u8) } else { s.extend([0x4c, memo.len() as u8]) }
    s.extend_from_slice(memo);
    Ok(s)
}

pub fn build_btc(c: &Chain, mut utxos: Vec<Utxo>, p: &BtcPlan) -> Result<Psbt, String> {
    let cap = chains::fee_warn(c.name).rate_cap();
    if p.fee_rate == 0 || p.fee_rate > cap { return Err(format!("fee_rate must be 1..{cap} sat/vB for {}", c.name)) }
    let to = chains::address_to_script(c, &p.to).ok_or("bad --to address")?;
    let opr_vb = p.op_return.as_deref().map(out_vb).unwrap_or(0);
    let vsize = |ins: &[Utxo], outs: &[&[u8]]| 11 + opr_vb + ins.iter().map(|u| in_vb(u.kind)).sum::<u64>() + outs.iter().map(|s| out_vb(s)).sum::<u64>();
    let mut outs: Vec<(Vec<u8>, u64)> = Vec::new();
    let chosen: Vec<Utxo> = match p.send {
        None => { // sweep / consolidate: everything, one output
            let total = crate::sum_amounts(utxos.iter().map(|u| u.amount)).ok_or("amount_overflow")?;
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
            for u in utxos { total = crate::sum_amounts([total, u.amount]).ok_or("amount_overflow")?; sel.push(u);
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
    if let Some(o) = &p.op_return { outs.push((o.clone(), 0)) }
    let seq = if p.rbf { Sequence::ENABLE_RBF_NO_LOCKTIME } else if p.locktime != 0 { Sequence::ENABLE_LOCKTIME_NO_RBF } else { Sequence::MAX };
    let tx = Transaction { version: Version::TWO, lock_time: LockTime::from_consensus(p.locktime),
        input: chosen.iter().map(|u| TxIn { previous_output: OutPoint { txid: u.txid, vout: u.vout }, script_sig: ScriptBuf::new(), sequence: seq, witness: Witness::new() }).collect(),
        output: outs.iter().map(|(s, v)| TxOut { value: Amount::from_sat(*v), script_pubkey: ScriptBuf::from_bytes(s.clone()) }).collect() };
    if chosen.iter().any(|u| crate::digest::input_amount_uncommitted(bitcoin::Script::from_bytes(&u.script), u.redeem.as_deref()) && u.prev_tx.is_none()) {
        return Err("legacy_input_needs_prev_tx: a non-segwit input (incl. P2SH without a witness-program redeem_script) needs its previous transaction (utxo-fetch adds prev_tx unless --no-prev-tx)".into())
    }
    let mut psbt = Psbt::from_unsigned_tx(tx).map_err(|_| "psbt")?;
    for (i, u) in chosen.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(TxOut { value: Amount::from_sat(u.amount), script_pubkey: ScriptBuf::from_bytes(u.script.clone()) });
        psbt.inputs[i].non_witness_utxo = u.prev_tx.clone();
        psbt.inputs[i].redeem_script = u.redeem.clone();
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
    let cap = crate::chains::fee_warn(c.name).rate_cap();
    if fee_rate == 0 || fee_rate > cap { return Err(format!("fee_rate must be 1..{cap} per byte for {}", c.name)) }
    if let Some(u) = utxos.iter().find(|u| u.kind != "p2pkh" && u.kind != "p2pk") { return Err(format!("pos-ntime sweep supports p2pkh/p2pk inputs only (got {})", u.kind)) }
    if utxos.iter().any(|u| u.prev_raw.is_none()) { return Err("legacy_input_needs_prev_tx: nTime inputs need prev_tx (utxo-fetch adds it)".into()) }
    let to_s = chains::address_to_script(c, to).ok_or("bad --to address")?;
    let inputs = utxos.iter().map(|u| PIn { txid: u.txid.to_byte_array(), vout: u.vout, script_sig: vec![], sequence: 0xffff_ffff }).collect();
    let mut tx = PosTx { layout: l, time, inputs, outputs: vec![(0, to_s)], locktime: 0, speech: vec![] };
    let total = crate::sum_amounts(utxos.iter().map(|u| u.amount)).ok_or("amount_overflow")?;
    let fee = crate::pos::signed_size(&tx) * fee_rate;
    tx.outputs[0].0 = total.checked_sub(fee).filter(|&v| v >= dust).ok_or("balance does not cover the fee (or leaves dust)")?;
    Ok((tx, utxos.iter().map(|u| (u.amount, u.script.clone())).collect()))
}
