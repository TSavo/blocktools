//! Bare-pubkey (P2PK) spends, as left by PoS coinstakes. Mainnet vector: NVC coinstake c053a3fd
//! spends output 1 of cdced5fa (`21 <02..> ac`, owned by 4FTwax..); both rebuilt from the
//! api.novaco.in JSON fixtures, fail-closed on txid. Its sig-only scriptSig verifies under the
//! legacy sighash with script code = the P2PK script, and not with the key's P2PKH script.
mod common;
use blocktools_tx::{build::{p2pk_key, parse_utxos}, nvc_json::serialize_nvc_tx_from_json, pos::PosTx};
fn hx(s: &str) -> Vec<u8> { blocktools_core::hex_dec(s).unwrap() }
const PREV: &str = "cdced5fa03d9651443deea305e09290b925794ed3836de21ef30e13f42f83bd7";
const SPEND: &str = "c053a3fddd508df8cadd90bf8c987c35802c2779a8a19b4efc8c83124d11df20";
fn raw(json: &str, id: &str) -> Vec<u8> { hx(&serialize_nvc_tx_from_json(json, id).unwrap()) }
fn prev() -> Vec<u8> { raw(include_str!("data/nvc_cdced5fa.json"), PREV) }
fn nvc() -> &'static blocktools_core::chains::Chain { blocktools_core::chains::supported("nvc").unwrap() }

#[test] fn mainnet_coinstake_p2pk_signature() {
    let p = PosTx::parse("nvc", &prev()).unwrap();
    let s = PosTx::parse("nvc", &raw(include_str!("data/nvc_c053a3fd.json"), SPEND)).unwrap();
    let mut id = p.txid_hex().into_bytes(); id.clear(); let mut t = hx(PREV); t.reverse(); id.extend(t);
    assert_eq!((s.inputs[0].txid.to_vec(), s.inputs[0].vout), (id, 1));
    let (amt, spk) = p.outputs[1].clone();
    assert_eq!(amt, 155721245);
    let key = p2pk_key(&spk).expect("prevout is P2PK");
    let ss = &s.inputs[0].script_sig; assert_eq!(ss[0] as usize + 1, ss.len(), "sig-only scriptSig");
    let secp = secp256k1::Secp256k1::verification_only();
    let mut sig = secp256k1::ecdsa::Signature::from_der(&ss[1..ss.len() - 1]).unwrap(); sig.normalize_s();
    let pk = secp256k1::PublicKey::from_slice(key).unwrap();
    let m = |sc: &[u8]| secp256k1::Message::from_digest(s.sighash_all(0, sc).unwrap());
    assert!(secp.verify_ecdsa(&m(&spk), &sig, &pk).is_ok());
    let h = { use bitcoin::hashes::Hash; bitcoin::hashes::hash160::Hash::hash(key).to_byte_array() };
    let p2pkh = [&[0x76, 0xa9, 20][..], &h, &[0x88, 0xac]].concat();
    assert!(secp.verify_ecdsa(&m(&p2pkh), &sig, &pk).is_err());
    assert_eq!(blocktools_tx::pos::unproven("nvc", &s, &[(amt, spk.clone())], &[Some(prev())]), 0);
    assert_eq!(blocktools_tx::pos::unproven("nvc", &s, &[(amt + 1, spk)], &[Some(prev())]), 1);
}

#[test] fn utxo_p2pk_detected_from_prev_tx_and_proven() {
    let pv = blocktools_core::hex_enc(prev());
    let l = |amt: u64, addr: &str, extra: &str| format!("{{\"txid\":\"{PREV}\",\"vout\":1,\"amount\":{amt},\"address\":\"{addr}\"{extra}}}");
    let u = parse_utxos(nvc(), &l(155721245, "4FTwax8Daz5RFUV7yFTtxjY4aFsoyeSxE3", &format!(",\"prev_tx\":\"{pv}\""))).unwrap();
    assert_eq!(u[0].kind, "p2pk"); assert!(p2pk_key(&u[0].script).is_some());
    // amount must match the proven output
    assert!(parse_utxos(nvc(), &l(155721246, "4FTwax8Daz5RFUV7yFTtxjY4aFsoyeSxE3", &format!(",\"prev_tx\":\"{pv}\""))).unwrap_err().contains("differs"));
    // another key's address does not adopt this P2PK output
    assert!(parse_utxos(nvc(), &l(155721245, "4QP6S2Gv3WZmgnJgR8mshrbHA9W6hQiTxR", &format!(",\"prev_tx\":\"{pv}\""))).unwrap_err().contains("differs"));
    // explicit P2PK script without prev_tx: refused (legacy sighash, amount unproven)
    let spk = blocktools_core::hex_enc(&u[0].script);
    assert!(parse_utxos(nvc(), &l(155721245, "4FTwax8Daz5RFUV7yFTtxjY4aFsoyeSxE3", &format!(",\"script\":\"{spk}\""))).unwrap_err().contains("needs prev_tx"));
    // explicit script for a different key: refused
    let k1 = "21".to_owned() + "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" + "ac";
    assert!(parse_utxos(nvc(), &l(155721245, "4FTwax8Daz5RFUV7yFTtxjY4aFsoyeSxE3", &format!(",\"script\":\"{k1}\",\"prev_tx\":\"{pv}\""))).unwrap_err().contains("neither"));
    // builder accepts it
    let (tx, pr) = blocktools_tx::build::build_pos_sweep(nvc(), &u, "4QP6S2Gv3WZmgnJgR8mshrbHA9W6hQiTxR", 5, 1792953300, 546).unwrap();
    assert_eq!(pr[0].1, u[0].script); assert_eq!(tx.inputs.len(), 1);
}

#[cfg(feature = "secrets")]
#[test] fn sign_p2pk_pos_and_bitcoin() {
    use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    let k = secp256k1::SecretKey::from_slice(&[[0u8; 31].as_slice(), &[1]].concat()).unwrap(); // throwaway
    let secp = secp256k1::Secp256k1::new();
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &k);
    for compressed in [true, false] {
        let key = if compressed { pk.serialize().to_vec() } else { pk.serialize_uncompressed().to_vec() };
        let spk = [vec![key.len() as u8], key.clone(), vec![0xac]].concat();
        let h = { use bitcoin::hashes::Hash; bitcoin::hashes::hash160::Hash::hash(&key).to_byte_array() };
        let verify = |digest: [u8; 32], ss: &[u8]| { assert_eq!(ss[0] as usize + 1, ss.len());
            let s = secp256k1::ecdsa::Signature::from_der(&ss[1..ss.len() - 1]).unwrap();
            assert!(secp.verify_ecdsa(&secp256k1::Message::from_digest(digest), &s, &pk).is_ok()) };
        // nTime (nvc)
        let c = nvc();
        let addr = blocktools_core::chains::script_to_address(c, &[&[0x76, 0xa9, 20][..], &h, &[0x88, 0xac]].concat()).unwrap().1;
        let p = PosTx { layout: blocktools_tx::pos::layout("nvc").unwrap(), time: 1_700_000_000, inputs: vec![blocktools_tx::pos::PIn { txid: [7; 32], vout: 0, script_sig: vec![0x51], sequence: u32::MAX }],
            outputs: vec![(0, vec![]), (40_000, spk.clone())], locktime: 0, speech: vec![] };
        let line = format!("{{\"txid\":\"{}\",\"vout\":1,\"amount\":40000,\"address\":\"{addr}\",\"prev_tx\":\"{}\"}}", p.txid_hex(), blocktools_core::hex_enc(p.serialize()));
        let u = parse_utxos(c, &line).unwrap(); assert_eq!(u[0].kind, "p2pk");
        let (mut tx, prev) = blocktools_tx::build::build_pos_sweep(c, &u, "4SzCSxnMzRjvTqMeXQofeEELknbFfka5SC", 5, 1792800000, 546).unwrap();
        let unsigned = tx.clone();
        assert_eq!(blocktools_tx::sign::sign_pos(&mut tx, &prev, &[k]).unwrap(), 1);
        verify(unsigned.sighash_all(0, &spk).unwrap(), &tx.inputs[0].script_sig);
        let env = blocktools_tx::pos::envelope("nvc", &tx, &prev, &[u[0].prev_raw.clone()]).to_string();
        assert_eq!(blocktools_tx::decode(&env, "nvc").unwrap().unproven_inputs, 0);
        // bitcoin PSBT path (legacy sighash, non_witness_utxo proof)
        let c = blocktools_core::chains::supported("btc").unwrap();
        let addr = blocktools_core::chains::script_to_address(c, &[&[0x76, 0xa9, 20][..], &h, &[0x88, 0xac]].concat()).unwrap().1;
        let t = Transaction { version: Version::ONE, lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::from_bytes(vec![1, 1]), sequence: Sequence::MAX, witness: Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(50_000), script_pubkey: ScriptBuf::from_bytes(spk.clone()) }] };
        let line = format!("{{\"txid\":\"{}\",\"vout\":0,\"amount\":50000,\"address\":\"{addr}\",\"prev_tx\":\"{}\"}}", t.compute_txid(), blocktools_core::hex_enc(bitcoin::consensus::serialize(&t)));
        let u = parse_utxos(c, &line).unwrap(); assert_eq!(u[0].kind, "p2pk");
        let mut ps = blocktools_tx::build::build_btc(c, u, &blocktools_tx::build::BtcPlan { to: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH".into(), send: None, change: None, fee_rate: 2, rbf: true, dust: 546, op_return: None, locktime: 0 }).unwrap();
        let ut = ps.unsigned_tx.clone();
        assert_eq!(ut.output[0].value.to_sat(), 50_000 - 2 * (11 + 114 + 34), "p2pk input sized at 114 vB");
        assert_eq!(blocktools_tx::sign::sign_psbt(&mut ps, &[k]).unwrap(), 1);
        let st = blocktools_tx::sign::extract(&ps).unwrap();
        verify(blocktools_tx::digest::legacy_sighash(&ut, 0, &spk, 1, blocktools_tx::digest::Digest::Sha256d).unwrap(), st.input[0].script_sig.as_bytes());
        let _ = common::line;
    }
}
