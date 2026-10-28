//! m-of-n multisig over a Taproot **script path** (BIP341/342 tapscript), the Schnorr sibling of the
//! P2WSH path in `multisig.rs`. One tapleaf holds an `OP_CHECKSIGADD` k-of-n script
//!   `<pk1> OP_CHECKSIG <pk2> OP_CHECKSIGADD … <pkN> OP_CHECKSIGADD <m> OP_NUMEQUAL`
//! committed under an UNSPENDABLE NUMS internal key (BIP341 "H"), so there is no key-path spend — the
//! only way to spend is to reveal the script and satisfy m of the n Schnorr checks.
//!   - `tapscript_multisig` / `taproot_multisig_from_hex`: build the leaf script, the P2TR address, the
//!     control block and the merkle root (the `taproot-multisig` tool). Pure, no keys.
//!   - `partial_sign`: for each input carrying that tapleaf, BIP341 script-spend sighash → Schnorr-sign
//!     with each held key whose x-only pubkey is in the leaf, recorded in `tap_script_sigs`. No finalize.
//!   - `combine_finalize`: once ≥ threshold script sigs are present, assemble the witness
//!     `[sigN … sig1, leaf_script, control_block]` (sigs in REVERSE pubkey order, empty for a
//!     non-signer, per CHECKSIGADD stack order) and set `final_script_witness` (tx-combine).
//! x-only pubkeys only (32-byte). Sighash + Schnorr are rust-bitcoin/libsecp256k1's.
use bitcoin::blockdata::opcodes::all::{OP_CHECKSIG, OP_CHECKSIGADD, OP_NUMEQUAL};
use bitcoin::blockdata::script::{Builder, Instruction};
use bitcoin::hashes::Hash;
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootBuilder};
use bitcoin::{Network, ScriptBuf, TxOut, Witness};

/// BIP341 unspendable NUMS internal key H (x-only): nothing-up-my-sleeve, so no one holds a key-path
/// spending key and the output is script-path only. This is the constant from BIP341.
pub const NUMS_XONLY_HEX: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

fn nums() -> XOnlyPublicKey {
    XOnlyPublicKey::from_slice(&blocktools_core::hex_dec(NUMS_XONLY_HEX).expect("const hex"))
        .expect("const NUMS key")
}

/// Build the k-of-n tapscript: `<pk1> CHECKSIG <pk2> CHECKSIGADD … <pkN> CHECKSIGADD <m> NUMEQUAL`
/// (x-only keys, 1 ≤ m ≤ n ≤ 20). Key order is consensus-significant: the witness supplies one stack
/// element per key (a signature or an empty push) in the reverse of this order.
pub fn tapscript_multisig(threshold: usize, keys: &[XOnlyPublicKey]) -> Result<ScriptBuf, &'static str> {
    if threshold == 0 || threshold > keys.len() || keys.len() > 20 {
        return Err("bad m-of-n (need 1 <= m <= n <= 20)");
    }
    let mut b = Builder::new();
    for (i, k) in keys.iter().enumerate() {
        b = b.push_x_only_key(k);
        b = b.push_opcode(if i == 0 { OP_CHECKSIG } else { OP_CHECKSIGADD });
    }
    Ok(b.push_int(threshold as i64).push_opcode(OP_NUMEQUAL).into_script())
}

/// The committed taproot output for a single-leaf tapscript multisig under the NUMS internal key.
/// Returns the spend info (output key, merkle root, control block source).
pub fn spend_info(
    leaf: &ScriptBuf,
) -> Result<bitcoin::taproot::TaprootSpendInfo, &'static str> {
    let secp = Secp256k1::verification_only();
    TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .map_err(|_| "taproot add_leaf")?
        .finalize(&secp, nums())
        .map_err(|_| "taproot finalize")
}

/// The control block for the single leaf (the script-path reveal: NUMS internal key + empty merkle path).
pub fn control_block(info: &bitcoin::taproot::TaprootSpendInfo, leaf: &ScriptBuf) -> Result<ControlBlock, &'static str> {
    info.control_block(&(leaf.clone(), LeafVersion::TapScript)).ok_or("no control block for the leaf")
}

/// The P2TR address committing to this spend info on `net`.
pub fn p2tr_address(info: &bitcoin::taproot::TaprootSpendInfo, net: Network) -> String {
    bitcoin::Address::p2tr_tweaked(info.output_key(), net).to_string()
}

/// CLI convenience: build a script-path m-of-n from hex-encoded x-only (32-byte) pubkeys on `net`.
/// Returns (leaf_script hex, P2TR address, control_block hex, merkle_root hex, descriptor).
pub fn taproot_multisig_from_hex(
    threshold: usize,
    pubkey_hex: &[String],
    net: &str,
) -> Result<(String, String, String, String, String), String> {
    let network = match net {
        "bitcoin" | "mainnet" | "btc" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        _ => return Err(format!("unknown network: {net}")),
    };
    let mut keys = Vec::new();
    for h in pubkey_hex {
        let b = blocktools_core::hex_dec(h).ok_or_else(|| format!("bad pubkey hex: {h}"))?;
        // Accept a 32-byte x-only key, or a 33-byte compressed key (drop the parity byte).
        let x = match b.len() {
            32 => XOnlyPublicKey::from_slice(&b),
            33 => XOnlyPublicKey::from_slice(&b[1..]),
            _ => return Err(format!("pubkey must be 32-byte x-only or 33-byte compressed: {h}")),
        }
        .map_err(|_| format!("not a valid x-only pubkey: {h}"))?;
        keys.push(x);
    }
    let leaf = tapscript_multisig(threshold, &keys).map_err(|e| e.to_string())?;
    let info = spend_info(&leaf).map_err(|e| e.to_string())?;
    let cb = control_block(&info, &leaf).map_err(|e| e.to_string())?;
    let merkle = info.merkle_root().ok_or("single leaf has a merkle root")?;
    let descriptor = format!("tr({NUMS_XONLY_HEX},multi_a({threshold},{}))", pubkey_hex.join(","));
    Ok((
        blocktools_core::hex_enc(leaf.as_bytes()),
        p2tr_address(&info, network),
        blocktools_core::hex_enc(&cb.serialize()),
        blocktools_core::hex_enc(&merkle.to_byte_array()),
        descriptor,
    ))
}

/// Parse a tapscript multisig leaf into `(threshold, ordered x-only pubkeys)`, else `None`. Mirrors
/// the exact shape `tapscript_multisig` emits: `<pk> CHECKSIG (<pk> CHECKSIGADD)* <m> NUMEQUAL`.
pub fn parse_tapscript_multisig(s: &bitcoin::Script) -> Option<(usize, Vec<XOnlyPublicKey>)> {
    let mut it = s.instructions();
    let mut keys = Vec::new();
    // First key + OP_CHECKSIG.
    match it.next()?.ok()? {
        Instruction::PushBytes(b) => keys.push(XOnlyPublicKey::from_slice(b.as_bytes()).ok()?),
        _ => return None,
    }
    match it.next()?.ok()? {
        Instruction::Op(op) if op == OP_CHECKSIG => {}
        _ => return None,
    }
    // Zero or more (key, OP_CHECKSIGADD), then (<m>, OP_NUMEQUAL).
    let m = loop {
        match it.next()?.ok()? {
            Instruction::PushBytes(b) => {
                // Either another pubkey (33? no, 32 x-only) followed by CHECKSIGADD, or the threshold
                // push <m> followed by NUMEQUAL. Disambiguate by what follows.
                if b.len() == 32 {
                    let k = XOnlyPublicKey::from_slice(b.as_bytes()).ok()?;
                    match it.next()?.ok()? {
                        Instruction::Op(op) if op == OP_CHECKSIGADD => keys.push(k),
                        _ => return None,
                    }
                } else {
                    return None; // a non-32 push here is not our shape
                }
            }
            Instruction::Op(op) => break small_int(op.to_u8())?,
        }
    };
    match it.next()?.ok()? {
        Instruction::Op(op) if op == OP_NUMEQUAL => {}
        _ => return None,
    }
    if it.next().is_some() || m == 0 || m > keys.len() {
        return None;
    }
    Some((m, keys))
}

fn small_int(v: u8) -> Option<usize> {
    // OP_1..OP_16 encode 1..16 as 0x51..0x60; a bare m in a tapscript multisig is in this range.
    (0x51..=0x60).contains(&v).then(|| (v - 0x50) as usize)
}

/// Collect every input's committed prevout (`witness_utxo`), required for the BIP341 all-prevouts
/// sighash. Errors if any input lacks one.
fn all_prevouts(p: &Psbt) -> Result<Vec<TxOut>, &'static str> {
    p.inputs
        .iter()
        .map(|i| i.witness_utxo.clone().ok_or("taproot input needs witness_utxo (all-prevouts sighash)"))
        .collect()
}

/// Schnorr-partial-sign every tapscript-multisig input of `p` with each key in `keys` whose x-only
/// pubkey appears in the input's revealed leaf. Inserts `((xonly, leaf_hash) -> sig)` into
/// `tap_script_sigs` and leaves the input UNFINALIZED. Returns the number of signatures added.
pub fn partial_sign(p: &mut Psbt, keys: &[SecretKey]) -> Result<usize, &'static str> {
    let secp = Secp256k1::new();
    let tx = p.unsigned_tx.clone();
    let prevouts = all_prevouts(p)?;
    let mut added = 0;
    for i in 0..tx.input.len() {
        // A tapscript-multisig input carries exactly one revealed leaf in tap_scripts.
        let Some((cb, (leaf, ver))) = p.inputs[i].tap_scripts.iter().next().map(|(c, v)| (c.clone(), v.clone()))
        else {
            continue;
        };
        let _ = cb;
        if ver != LeafVersion::TapScript {
            continue;
        }
        let (_m, leaf_keys) = parse_tapscript_multisig(&leaf).ok_or("tap leaf is not a standard tapscript multisig")?;
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let sighash = SighashCache::new(&tx)
            .taproot_script_spend_signature_hash(i, &Prevouts::All(&prevouts), leaf_hash, TapSighashType::Default)
            .map_err(|_| "sighash")?;
        let msg = Message::from_digest(sighash.to_byte_array());
        for sk in keys {
            let kp = Keypair::from_secret_key(&secp, sk);
            let (xonly, _) = kp.x_only_public_key();
            if !leaf_keys.contains(&xonly) {
                continue;
            }
            let sig = secp.sign_schnorr_with_aux_rand(&msg, &kp, &[0u8; 32]);
            p.inputs[i].tap_script_sigs.insert(
                (xonly, leaf_hash),
                bitcoin::taproot::Signature { signature: sig, sighash_type: TapSighashType::Default },
            );
            added += 1;
        }
    }
    Ok(added)
}

/// For every still-unfinalized tapscript-multisig input with ≥ threshold script sigs, assemble the
/// witness `[sigN … sig1, leaf_script, control_block]` — one stack element per key in REVERSE order
/// (its Schnorr sig, or an empty push for a non-signer, as CHECKSIGADD consumes them) — and set
/// `final_script_witness`. Fails closed (`not_enough_signatures`) below threshold. Returns the count.
pub fn combine_finalize(p: &mut Psbt) -> Result<usize, &'static str> {
    let mut fin = 0;
    for inp in p.inputs.iter_mut() {
        if inp.final_script_witness.is_some() {
            continue;
        }
        let Some((cb, (leaf, ver))) = inp.tap_scripts.iter().next().map(|(c, v)| (c.clone(), v.clone())) else {
            continue;
        };
        if ver != LeafVersion::TapScript {
            continue;
        }
        let (m, leaf_keys) = parse_tapscript_multisig(&leaf).ok_or("tap leaf is not a standard tapscript multisig")?;
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let have = leaf_keys.iter().filter(|k| inp.tap_script_sigs.contains_key(&(**k, leaf_hash))).count();
        if have < m {
            return Err("not_enough_signatures");
        }
        // One element per key, REVERSE order (pkN first): its sig, or empty for a non-signer. Keep only
        // m signatures so the CHECKSIGADD count equals exactly m (extra sigs would overshoot NUMEQUAL).
        let mut wit: Vec<Vec<u8>> = Vec::new();
        let mut kept = 0;
        for k in leaf_keys.iter().rev() {
            match inp.tap_script_sigs.get(&(*k, leaf_hash)) {
                Some(sig) if kept < m => {
                    wit.push(sig.to_vec());
                    kept += 1;
                }
                _ => wit.push(Vec::new()),
            }
        }
        wit.push(leaf.to_bytes());
        wit.push(cb.serialize());
        inp.final_script_witness = Some(Witness::from_slice(&wit));
        fin += 1;
    }
    Ok(fin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::secp256k1::{PublicKey as SecpPub, Secp256k1};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid};

    fn key(b: u8) -> SecretKey {
        let mut k = [0u8; 32];
        k[31] = b;
        SecretKey::from_slice(&k).unwrap()
    }

    #[test]
    fn script_round_trips_and_address_is_p2tr() {
        let secp = Secp256k1::new();
        let xs: Vec<XOnlyPublicKey> =
            (1u8..=5).map(|b| SecpPub::from_secret_key(&secp, &key(b)).x_only_public_key().0).collect();
        let leaf = tapscript_multisig(3, &xs).unwrap();
        let (m, parsed) = parse_tapscript_multisig(&leaf).unwrap();
        assert_eq!(m, 3);
        assert_eq!(parsed, xs);
        let info = spend_info(&leaf).unwrap();
        assert!(p2tr_address(&info, Network::Bitcoin).starts_with("bc1p"));
        assert!(control_block(&info, &leaf).is_ok());
    }

    #[test]
    fn rejects_bad_thresholds() {
        let secp = Secp256k1::new();
        let xs: Vec<XOnlyPublicKey> =
            (1u8..=3).map(|b| SecpPub::from_secret_key(&secp, &key(b)).x_only_public_key().0).collect();
        assert!(tapscript_multisig(0, &xs).is_err());
        assert!(tapscript_multisig(4, &xs).is_err());
    }

    #[test]
    fn partial_sign_then_combine_produces_verifying_schnorr_sigs() {
        let secp = Secp256k1::new();
        let sks: Vec<SecretKey> = (1u8..=3).map(key).collect();
        let xs: Vec<XOnlyPublicKey> =
            sks.iter().map(|sk| SecpPub::from_secret_key(&secp, sk).x_only_public_key().0).collect();
        let leaf = tapscript_multisig(2, &xs).unwrap(); // 2-of-3
        let info = spend_info(&leaf).unwrap();
        let cb = control_block(&info, &leaf).unwrap();
        let spk = ScriptBuf::new_p2tr_tweaked(info.output_key());
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
        base.inputs[0].tap_internal_key = Some(nums());
        base.inputs[0].tap_merkle_root = info.merkle_root();
        base.inputs[0].tap_scripts.insert(cb.clone(), (leaf.clone(), LeafVersion::TapScript));

        let mut p1 = base.clone();
        assert_eq!(partial_sign(&mut p1, &[sks[0]]).unwrap(), 1);
        let mut p2 = base.clone();
        assert_eq!(partial_sign(&mut p2, &[sks[2]]).unwrap(), 1); // keys 1 and 3 sign (2-of-3)
        // Below threshold: one sig alone must refuse.
        assert_eq!(combine_finalize(&mut p1.clone()).unwrap_err(), "not_enough_signatures");

        p1.combine(p2).unwrap();
        assert_eq!(combine_finalize(&mut p1).unwrap(), 1);
        let w = p1.inputs[0].final_script_witness.clone().unwrap();
        // 3 keys -> 3 stack elements + leaf + control block.
        assert_eq!(w.len(), 5);
        assert_eq!(w.nth(3).unwrap(), leaf.as_bytes());
        assert_eq!(w.nth(4).unwrap(), cb.serialize());

        // Each present signature must verify as a BIP340 Schnorr sig over the leaf sighash.
        let leaf_hash = TapLeafHash::from_script(&leaf, LeafVersion::TapScript);
        let prevouts = all_prevouts(&p1).unwrap();
        let sighash = SighashCache::new(&p1.unsigned_tx)
            .taproot_script_spend_signature_hash(0, &Prevouts::All(&prevouts), leaf_hash, TapSighashType::Default)
            .unwrap();
        let msg = Message::from_digest(sighash.to_byte_array());
        let mut verified = 0;
        for el in 0..3 {
            let b = w.nth(el).unwrap();
            if b.is_empty() {
                continue;
            }
            let sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&b[..64]).unwrap();
            assert!(xs.iter().any(|x| secp.verify_schnorr(&sig, &msg, x).is_ok()));
            verified += 1;
        }
        assert_eq!(verified, 2, "exactly m=2 signatures present");
    }
}
