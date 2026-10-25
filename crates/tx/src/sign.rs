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
    let mut prev: Vec<TxOut> = Vec::new();
    // P2SH is amount-committed only as wrapped segwit: proven by the PSBT redeem_script, or by a
    // signing key whose P2SH-P2WPKH redeem script hashes to the spk (the only P2SH signed here).
    let own_redeems: Vec<ScriptBuf> = keys.iter().map(|k| ScriptBuf::from_bytes(p2wpkh(&PublicKey::from_secret_key(&secp, k).serialize()))).collect();
    for (i, ti) in p.inputs.iter().zip(&tx.input) {
        let o = i.witness_utxo.clone().or_else(|| i.non_witness_utxo.as_ref()?.output.get(ti.previous_output.vout as usize).cloned()).ok_or("input_missing_utxo")?;
        // Fail closed: a legacy-sighash input is only signed against a previous tx that proves its amount.
        let seg = crate::digest::p2sh_proven_segwit(&o.script_pubkey, i.redeem_script.as_deref()) || own_redeems.iter().any(|r| crate::digest::p2sh_proven_segwit(&o.script_pubkey, Some(r)));
        let o = if amount_uncommitted(&o.script_pubkey) && !seg { proven_prevout(i, &ti.previous_output, dg).ok_or("legacy_input_amount_unproven")? } else { o };
        prev.push(o);
    }
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
            } else if crate::build::p2pk_key(&spk).is_some_and(|k| k == c || k == u) {
                inp.final_script_sig = Some(ScriptBuf::from_bytes(push(&ecdsa(&spk, false)?)));
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

/// Sign every P2PKH or P2PK input of an nTime tx whose prevout script matches one of `keys`
/// (compressed or uncompressed), SIGHASH_ALL, low-S. Returns the number signed.
pub fn sign_pos(tx: &mut crate::pos::PosTx, prev: &[(u64, Vec<u8>)], keys: &[SecretKey]) -> Result<usize, &'static str> {
    if prev.len() != tx.inputs.len() { return Err("pos_prevouts_count_mismatch") }
    let secp = Secp256k1::new();
    let unsigned = tx.clone();
    let mut n = 0;
    for (i, (_, spk)) in prev.iter().enumerate() {
        for sk in keys {
            let pk = PublicKey::from_secret_key(&secp, sk);
            let (c, u) = (pk.serialize(), pk.serialize_uncompressed());
            // P2PK: script code = the pubkey script, scriptSig = <sig> only.
            let bare = crate::build::p2pk_key(spk).filter(|k| *k == c || *k == u).is_some();
            let k: &[u8] = if *spk == p2pkh(&c) { &c } else if *spk == p2pkh(&u) { &u } else if bare { &[] } else { continue };
            let h = unsigned.sighash_all(i, spk)?;
            let mut s = secp.sign_ecdsa(&Message::from_digest(h), sk).serialize_der().to_vec(); s.push(1);
            let mut ss = push(&s); if !bare { ss.extend(push(k)) }
            tx.inputs[i].script_sig = ss; n += 1; break;
        }
    }
    Ok(n)
}

/// Sign every P2PKH input of a Zcash v4/v5 tx whose prevout matches one of `keys` (compressed
/// or uncompressed), SIGHASH_ALL (ZIP-243 / ZIP-244), low-S. Returns the number signed.
pub fn sign_zcash(tx: &mut crate::zcash::ZTx, prev: &[(u64, Vec<u8>)], keys: &[SecretKey]) -> Result<usize, &'static str> {
    if prev.len() != tx.inputs.len() { return Err("zec_prevouts_count_mismatch") }
    let secp = Secp256k1::new();
    let unsigned = tx.clone();
    let amounts: Vec<u64> = prev.iter().map(|p| p.0).collect();
    let spks: Vec<Vec<u8>> = prev.iter().map(|p| p.1.clone()).collect();
    let mut n = 0;
    for (i, spk) in spks.iter().enumerate() {
        for sk in keys {
            let pk = PublicKey::from_secret_key(&secp, sk);
            let (c, u) = (pk.serialize(), pk.serialize_uncompressed());
            let k: &[u8] = if *spk == p2pkh(&c) { &c } else if *spk == p2pkh(&u) { &u } else { continue };
            let h = unsigned.sighash(Some((i, &amounts, &spks)), 1)?;
            let mut s = secp.sign_ecdsa(&Message::from_digest(h), sk).serialize_der().to_vec(); s.push(1);
            let mut ss = push(&s); ss.extend(push(k));
            tx.inputs[i].script_sig = ss; n += 1; break;
        }
    }
    Ok(n)
}
