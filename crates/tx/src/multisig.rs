//! m-of-n multisig over P2WSH (witness-v0 script hash). Three library pieces the CLI composes:
//!   - `multisig_script` / `p2wsh_address`: build the `OP_m <pk>… OP_n OP_CHECKMULTISIG` witness
//!     script and its P2WSH address (the `multisig` tool). Pure, no keys.
//!   - `partial_sign`: for each input carrying that witness script, ECDSA-sign the BIP143 sighash
//!     (script_code = witness script) with each held key whose pubkey is in the script, and record it
//!     in the PSBT's `partial_sigs` — NEVER finalizing (tx-sign --partial).
//!   - `combine_finalize`: once ≥ threshold partial sigs are present, assemble the final witness
//!     `<OP_0> <sig>… <witnessScript>` with sigs ordered to the pubkey order in the script (tx-combine).
//! Signatures are libsecp256k1's; the sighash is rust-bitcoin's. Compressed pubkeys only (segwit).
#[cfg(feature = "secrets")]
use crate::digest::Digest;
use bitcoin::blockdata::opcodes::all::OP_CHECKMULTISIG;
use bitcoin::blockdata::script::{Builder, Instruction};
#[cfg(feature = "secrets")]
use bitcoin::ecdsa;
#[cfg(feature = "secrets")]
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
#[cfg(feature = "secrets")]
use bitcoin::secp256k1::{Message, PublicKey as SecpPub, Secp256k1, SecretKey};
#[cfg(feature = "secrets")]
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::{Network, PublicKey, ScriptBuf, Witness};

/// Build an m-of-n P2WSH witness script: `OP_m <pk>… OP_n OP_CHECKMULTISIG` (compressed keys only,
/// 1 ≤ m ≤ n ≤ 20). Pubkeys are kept in the given order — that order is consensus-significant for
/// CHECKMULTISIG, so signatures must later be supplied in the same order.
pub fn multisig_script(threshold: usize, pubkeys: &[PublicKey]) -> Result<ScriptBuf, &'static str> {
    if threshold == 0 || threshold > pubkeys.len() || pubkeys.len() > 20 {
        return Err("bad m-of-n (need 1 <= m <= n <= 20)");
    }
    if pubkeys.iter().any(|k| !k.compressed) {
        return Err("multisig requires compressed pubkeys");
    }
    let mut b = Builder::new().push_int(threshold as i64);
    for pk in pubkeys {
        b = b.push_key(pk);
    }
    Ok(b.push_int(pubkeys.len() as i64).push_opcode(OP_CHECKMULTISIG).into_script())
}

/// The P2WSH address for a witness script on `net`.
pub fn p2wsh_address(witness_script: &ScriptBuf, net: Network) -> String {
    bitcoin::Address::p2wsh(witness_script, net).to_string()
}

/// CLI convenience: build an m-of-n P2WSH from hex-encoded compressed pubkeys on `net`
/// ("bitcoin"/"mainnet", "testnet", "signet", "regtest"). Returns
/// (witness_script hex, P2WSH address, `wsh(multi(m,…))` descriptor). Pure, no keys.
pub fn multisig_from_hex(
    threshold: usize,
    pubkey_hex: &[String],
    net: &str,
) -> Result<(String, String, String), String> {
    let network = match net {
        "bitcoin" | "mainnet" | "btc" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => return Err(format!("unknown network: {net}")),
    };
    let mut pubs = Vec::new();
    for h in pubkey_hex {
        let b = blocktools_core::hex_dec(h).ok_or_else(|| format!("bad pubkey hex: {h}"))?;
        pubs.push(PublicKey::from_slice(&b).map_err(|_| format!("not a valid pubkey: {h}"))?);
    }
    let ws = multisig_script(threshold, &pubs).map_err(|e| e.to_string())?;
    let descriptor = format!("wsh(multi({threshold},{}))", pubkey_hex.join(","));
    Ok((blocktools_core::hex_enc(ws.as_bytes()), p2wsh_address(&ws, network), descriptor))
}

fn op_small_int(v: u8) -> Option<usize> {
    // OP_1..OP_16 encode the integers 1..16 as opcodes 0x51..0x60.
    (0x51..=0x60).contains(&v).then(|| (v - 0x50) as usize)
}

/// Parse a standard m-of-n multisig script into `(threshold, ordered pubkeys)`, else `None`.
pub fn parse_multisig(s: &bitcoin::Script) -> Option<(usize, Vec<PublicKey>)> {
    let mut it = s.instructions();
    let m = match it.next()?.ok()? {
        Instruction::Op(op) => op_small_int(op.to_u8())?,
        _ => return None,
    };
    let mut keys = Vec::new();
    let n = loop {
        match it.next()?.ok()? {
            Instruction::PushBytes(b) => keys.push(PublicKey::from_slice(b.as_bytes()).ok()?),
            Instruction::Op(op) => break op_small_int(op.to_u8())?,
        }
    };
    if n != keys.len() || m == 0 || m > n {
        return None;
    }
    match it.next()?.ok()? {
        Instruction::Op(op) if op == OP_CHECKMULTISIG => {}
        _ => return None,
    }
    if it.next().is_some() {
        return None;
    }
    Some((m, keys))
}

/// Takes private keys: compiled only with the `secrets` feature (never into the wasm).
/// ECDSA-partial-sign every P2WSH multisig input of `p` with each key in `keys` that appears in the
/// input's witness script. Inserts `(pubkey -> sig)` into `partial_sigs` and leaves the input
/// UNFINALIZED. Returns the number of partial signatures added. P2WSH is BIP143 (sha256d) only.
#[cfg(feature = "secrets")]
pub fn partial_sign(p: &mut Psbt, keys: &[SecretKey], dg: Digest) -> Result<usize, &'static str> {
    if dg != Digest::Sha256d {
        return Err("multisig partial-sign is segwit (sha256d) only");
    }
    let secp = Secp256k1::new();
    let tx = p.unsigned_tx.clone();
    let mut added = 0;
    for i in 0..tx.input.len() {
        let ws = match &p.inputs[i].witness_script {
            Some(w) => w.clone(),
            None => continue,
        };
        let (_m, pubs) = parse_multisig(&ws).ok_or("witness_script is not a standard m-of-n multisig")?;
        let o = p.inputs[i]
            .witness_utxo
            .clone()
            .ok_or("multisig input needs witness_utxo (P2WSH amount is committed)")?;
        let h = SighashCache::new(&tx)
            .p2wsh_signature_hash(i, &ws, o.value, EcdsaSighashType::All)
            .map_err(|_| "sighash")?;
        for sk in keys {
            let bpk = PublicKey::new(SecpPub::from_secret_key(&secp, sk));
            if !pubs.contains(&bpk) {
                continue;
            }
            let signature = secp.sign_ecdsa(&Message::from_digest(h.to_byte_array()), sk);
            p.inputs[i]
                .partial_sigs
                .insert(bpk, ecdsa::Signature { signature, sighash_type: EcdsaSighashType::All });
            added += 1;
        }
    }
    Ok(added)
}

/// For every still-unfinalized P2WSH multisig input with ≥ threshold partial sigs, build the final
/// witness `<OP_0> <sig>… <witnessScript>` with signatures ordered to the pubkey order in the script,
/// and set `final_script_witness`. Fails closed (`not_enough_signatures`) if any such input is below
/// threshold. Returns the number of inputs finalized here. (Inputs already finalized are left as-is.)
pub fn combine_finalize(p: &mut Psbt) -> Result<usize, &'static str> {
    let mut fin = 0;
    for inp in p.inputs.iter_mut() {
        if inp.final_script_witness.is_some() {
            continue;
        }
        let ws = match &inp.witness_script {
            Some(w) => w.clone(),
            None => continue,
        };
        let (m, pubs) = parse_multisig(&ws).ok_or("witness_script is not a standard m-of-n multisig")?;
        // The empty element is the well-known CHECKMULTISIG off-by-one dummy.
        let mut wit: Vec<Vec<u8>> = vec![Vec::new()];
        let mut have = 0;
        for pk in &pubs {
            if let Some(s) = inp.partial_sigs.get(pk) {
                wit.push(s.to_vec());
                have += 1;
                if have == m {
                    break;
                }
            }
        }
        if have < m {
            return Err("not_enough_signatures");
        }
        wit.push(ws.to_bytes());
        inp.final_script_witness = Some(Witness::from_slice(&wit));
        fin += 1;
    }
    Ok(fin)
}

/// Build the network transaction from a PSBT whose every input is finalized (final_script_sig or
/// final_script_witness set). Un-gated (no signing/secrets): a combiner needs only PSBT assembly.
/// Errors `input_without_signature` if any input is still unfinalized.
pub fn extract(p: &Psbt) -> Result<bitcoin::Transaction, &'static str> {
    if p.inputs.iter().any(|i| i.final_script_sig.is_none() && i.final_script_witness.is_none()) {
        return Err("input_without_signature");
    }
    let mut tx = p.unsigned_tx.clone();
    for (ti, i) in tx.input.iter_mut().zip(&p.inputs) {
        if let Some(s) = &i.final_script_sig {
            ti.script_sig = s.clone();
        }
        if let Some(w) = &i.final_script_witness {
            ti.witness = w.clone();
        }
    }
    Ok(tx)
}

/// Merge the partial-signature PSBTs of one m-of-n spend (P2WSH and/or Taproot script-path inputs),
/// finalize every multisig input that meets its threshold, and extract the signed tx. Keyless: reads only
/// public PSBTs. Returns `(signed tx bytes, finalized PSBT bytes)`. The one path `tx-combine` and the wasm
/// `combinePsbts` export share. Errors: `no_psbts`, `not_a_psbt`, `psbts_do_not_combine`, then the
/// finalizers' own refusals (`not_enough_signatures`, ...).
pub fn combine_psbts(psbts: &[Vec<u8>]) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let (first, rest) = psbts.split_first().ok_or("no_psbts")?;
    let mut acc = Psbt::deserialize(first).map_err(|_| "not_a_psbt")?;
    for raw in rest {
        acc.combine(Psbt::deserialize(raw).map_err(|_| "not_a_psbt")?).map_err(|_| "psbts_do_not_combine")?;
    }
    combine_finalize(&mut acc)?;
    crate::taproot_multisig::combine_finalize(&mut acc)?;
    let tx = extract(&acc)?;
    Ok((bitcoin::consensus::serialize(&tx), acc.serialize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey as SecpPub, Secp256k1, SecretKey};

    fn key(b: u8) -> SecretKey {
        let mut k = [0u8; 32];
        k[31] = b;
        SecretKey::from_slice(&k).unwrap()
    }

    #[test]
    fn script_round_trips_and_address_is_p2wsh() {
        let secp = Secp256k1::new();
        let pubs: Vec<PublicKey> =
            (1u8..=5).map(|b| PublicKey::new(SecpPub::from_secret_key(&secp, &key(b)))).collect();
        let ws = multisig_script(3, &pubs).unwrap();
        let (m, parsed) = parse_multisig(&ws).unwrap();
        assert_eq!(m, 3);
        assert_eq!(parsed, pubs);
        assert!(p2wsh_address(&ws, Network::Bitcoin).starts_with("bc1q"));
    }

    #[test]
    fn rejects_bad_thresholds() {
        let secp = Secp256k1::new();
        let pubs: Vec<PublicKey> =
            (1u8..=3).map(|b| PublicKey::new(SecpPub::from_secret_key(&secp, &key(b)))).collect();
        assert!(multisig_script(0, &pubs).is_err());
        assert!(multisig_script(4, &pubs).is_err());
    }

    #[cfg(feature = "secrets")]
    #[test]
    fn partial_sign_then_combine_produces_verifying_sigs() {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid};
        let secp = Secp256k1::new();
        let sks: Vec<SecretKey> = (1u8..=3).map(key).collect();
        let pubs: Vec<PublicKey> =
            sks.iter().map(|sk| PublicKey::new(SecpPub::from_secret_key(&secp, sk))).collect();
        let ws = multisig_script(2, &pubs).unwrap(); // 2-of-3
        let spk = ScriptBuf::new_p2wsh(&ws.wscript_hash());
        let amount = Amount::from_sat(100_000);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: Txid::all_zeros(), vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(90_000), script_pubkey: spk.clone() }],
        };
        let mut base = Psbt::from_unsigned_tx(tx).unwrap();
        base.inputs[0].witness_utxo = Some(TxOut { value: amount, script_pubkey: spk });
        base.inputs[0].witness_script = Some(ws.clone());

        // Two cosigners sign separate PSBTs; combine the partial PSBTs, then finalize.
        let mut p1 = base.clone();
        assert_eq!(partial_sign(&mut p1, &[sks[0]], Digest::Sha256d).unwrap(), 1);
        let mut p2 = base.clone();
        assert_eq!(partial_sign(&mut p2, &[sks[1]], Digest::Sha256d).unwrap(), 1);
        // Below threshold: finalizing p1 alone must refuse.
        assert_eq!(combine_finalize(&mut p1.clone()).unwrap_err(), "not_enough_signatures");

        p1.combine(p2).unwrap();
        assert_eq!(combine_finalize(&mut p1).unwrap(), 1);
        let w = p1.inputs[0].final_script_witness.clone().unwrap();
        assert_eq!(w.len(), 4); // [empty, sig, sig, witnessScript]
        assert!(w.nth(0).unwrap().is_empty());
        assert_eq!(w.nth(3).unwrap(), ws.as_bytes());

        // Each signature must cryptographically verify against the P2WSH sighash under a script pubkey.
        let h = SighashCache::new(&p1.unsigned_tx)
            .p2wsh_signature_hash(0, &ws, amount, EcdsaSighashType::All)
            .unwrap();
        let msg = Message::from_digest(h.to_byte_array());
        for k in 1..=2usize {
            let sb = w.nth(k).unwrap();
            let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&sb[..sb.len() - 1]).unwrap();
            assert!(pubs.iter().any(|pk| secp.verify_ecdsa(&msg, &sig, &pk.inner).is_ok()));
        }
    }
}
