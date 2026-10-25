//! Signing. Callers MUST show the tx-decode summary and get a human confirmation first
//! (tx-sign does). Sighash computation is rust-bitcoin's; signatures are libsecp256k1's.
use bitcoin::hashes::Hash;
use bitcoin::key::{Keypair, TapTweak};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType};
use bitcoin::{ScriptBuf, TapNodeHash, Transaction, TxOut, Witness};

fn h160(b: &[u8]) -> [u8; 20] { bitcoin::hashes::hash160::Hash::hash(b).to_byte_array() }
fn p2wpkh(pk: &[u8]) -> Vec<u8> { let mut s = vec![0, 20]; s.extend(h160(pk)); s }
fn p2pkh(pk: &[u8]) -> Vec<u8> { let mut s = vec![0x76, 0xa9, 20]; s.extend(h160(pk)); s.extend([0x88, 0xac]); s }
fn push(b: &[u8]) -> Vec<u8> { let mut s = vec![b.len() as u8]; s.extend(b); s } // all pushes here are < 76 bytes

pub fn taproot_sig(tx: &Transaction, i: usize, prevouts: &[TxOut], sk: &SecretKey, merkle: Option<TapNodeHash>, ty: TapSighashType, secp: &Secp256k1<All>) -> Result<Vec<u8>, &'static str> {
    let h = SighashCache::new(tx).taproot_key_spend_signature_hash(i, &Prevouts::All(prevouts), ty).map_err(|_| "sighash")?;
    let kp = Keypair::from_secret_key(secp, sk).tap_tweak(secp, merkle).to_keypair();
    let sig = secp.sign_schnorr_with_aux_rand(&Message::from_digest(h.to_byte_array()), &kp, &[0u8; 32]);
    let mut v = sig.as_ref().to_vec();
    if ty != TapSighashType::Default { v.push(ty as u8) }
    Ok(v)
}

pub use crate::digest::*;

/// Sign every input whose script matches one of `keys`; finalize it. Returns the number signed.
/// Supports p2pkh (compressed and uncompressed), p2wpkh, p2sh-p2wpkh, p2tr key-path (no script tree).
pub fn sign_psbt(p: &mut Psbt, keys: &[SecretKey]) -> Result<usize, &'static str> { sign_psbt_digest(p, keys, Digest::Sha256d) }
/// As `sign_psbt`, under digest `d`. Taproot is refused for anything but sha256d.
pub fn sign_psbt_digest(p: &mut Psbt, keys: &[SecretKey], dg: Digest) -> Result<usize, &'static str> {
    let secp = Secp256k1::new();
    let tx = p.unsigned_tx.clone();
    let prev: Vec<TxOut> = p.inputs.iter().zip(&tx.input).map(|(i, ti)| i.witness_utxo.clone()
        .or_else(|| i.non_witness_utxo.as_ref()?.output.get(ti.previous_output.vout as usize).cloned()))
        .collect::<Option<_>>().ok_or("input_missing_utxo")?;
    let mut n = 0;
    for i in 0..tx.input.len() {
        let spk = prev[i].script_pubkey.as_bytes().to_vec();
        let amt = prev[i].value;
        for sk in keys {
            let pk = PublicKey::from_secret_key(&secp, sk);
            let (c, u) = (pk.serialize(), pk.serialize_uncompressed());
            let ecdsa = |script_code: &[u8], segwit: bool| -> Result<Vec<u8>, &'static str> {
                let h: [u8; 32] = if segwit && dg == Digest::Sha256d {
                    SighashCache::new(&tx).p2wpkh_signature_hash(i, &ScriptBuf::from_bytes(script_code.to_vec()), amt, EcdsaSighashType::All).map_err(|_| "sighash")?.to_byte_array()
                } else if segwit {
                    let mut sc = vec![0x76, 0xa9, 20]; sc.extend(&script_code[2..]); sc.extend([0x88, 0xac]);
                    bip143_all(&tx, i, &sc, amt.to_sat(), dg)?
                } else { legacy_sighash(&tx, i, script_code, 1, dg)? };
                let mut s = secp.sign_ecdsa(&Message::from_digest(h), sk).serialize_der().to_vec(); s.push(1); Ok(s)
            };
            let inp = &mut p.inputs[i];
            let redeem = p2wpkh(&c);
            let mut sh = vec![0xa9, 20]; sh.extend(h160(&redeem)); sh.push(0x87);
            let xonly = pk.x_only_public_key().0;
            let tr = ScriptBuf::new_p2tr(&secp, xonly, None);
            if spk == p2wpkh(&c) {
                let s = ecdsa(&redeem, true)?; inp.final_script_witness = Some(Witness::from_slice(&[s, c.to_vec()]));
            } else if spk == sh {
                let s = ecdsa(&redeem, true)?; inp.final_script_witness = Some(Witness::from_slice(&[s, c.to_vec()]));
                inp.final_script_sig = Some(ScriptBuf::from_bytes(push(&redeem)));
            } else if spk == p2pkh(&c) || spk == p2pkh(&u) {
                let k: &[u8] = if spk == p2pkh(&c) { &c } else { &u };
                let s = ecdsa(&spk, false)?; let mut ss = push(&s); ss.extend(push(k));
                inp.final_script_sig = Some(ScriptBuf::from_bytes(ss));
            } else if spk == tr.as_bytes() && dg == Digest::Sha256d {
                let s = taproot_sig(&tx, i, &prev, sk, None, TapSighashType::Default, &secp)?;
                inp.final_script_witness = Some(Witness::from_slice(&[s]));
            } else { continue }
            n += 1; break;
        }
    }
    Ok(n)
}
/// Extract the network tx once every input is finalized.
pub fn extract(p: &Psbt) -> Result<Transaction, &'static str> {
    if p.inputs.iter().any(|i| i.final_script_sig.is_none() && i.final_script_witness.is_none()) { return Err("input_without_key") }
    let mut tx = p.unsigned_tx.clone();
    for (ti, i) in tx.input.iter_mut().zip(&p.inputs) {
        if let Some(s) = &i.final_script_sig { ti.script_sig = s.clone() }
        if let Some(w) = &i.final_script_witness { ti.witness = w.clone() }
    }
    Ok(tx)
}
