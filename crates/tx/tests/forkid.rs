//! Fork-id sighash (BCH/BSV/BTG) known-answer tests on PUBLIC data only:
//! vectors/abc-sighash.json is a verbatim copy of Bitcoin ABC src/test/data/sighash.json
//! (MIT), column 4 = SignatureHash(script, tx, in, type, amount 0) with SIGHASH_FORKID enabled.
use blocktools_tx::digest::forkid_sighash;

#[test] fn abc_sighash_json_forkid_rows() {
    let v: serde_json::Value = serde_json::from_str(include_str!("vectors/abc-sighash.json")).unwrap();
    let (mut ok, mut skipped) = (0, 0);
    for r in v.as_array().unwrap().iter().skip(1) {
        let r = r.as_array().unwrap();
        let ty = r[3].as_i64().unwrap() as u32;
        if ty & 0x40 == 0 { continue }
        let raw = blocktools_core::hex_dec(r[0].as_str().unwrap()).unwrap();
        let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw) else { skipped += 1; continue };
        let sc = blocktools_core::hex_dec(r[1].as_str().unwrap()).unwrap();
        let mut h = forkid_sighash(&tx, r[2].as_u64().unwrap() as usize, &sc, 0, ty).unwrap();
        h.reverse(); // uint256::GetHex prints reversed
        assert_eq!(blocktools_core::hex_enc(h), r[4].as_str().unwrap(), "row {r:?}");
        ok += 1;
    }
    eprintln!("forkid rows matched: {ok}, unparseable: {skipped}");
    assert!(ok >= 400 && skipped == 0, "{ok} {skipped}");
}
#[test] fn no_forkid_bit_refused() {
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&blocktools_core::hex_dec("01000000000100000000000000000000000000").unwrap_or_default()).unwrap_or(bitcoin::Transaction { version: bitcoin::transaction::Version(1), lock_time: bitcoin::absolute::LockTime::ZERO, input: vec![bitcoin::TxIn::default()], output: vec![] });
    assert_eq!(forkid_sighash(&tx, 0, &[], 0, 1), Err("sighash_without_forkid"));
}
/// vectors/forkid-signed.json: one signed public tx per fork-id chain. The signature in the tx
/// must verify under `forkid_sighash` with the chain's type (BCH/BSV 0x41, BTG 0x41|79<<8), and
/// must NOT verify under the plain BTC sighash (replay protection).
#[test] fn signed_mainnet_and_wallet_core_vectors_verify() {
    use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
    let v: serde_json::Value = serde_json::from_str(include_str!("vectors/forkid-signed.json")).unwrap();
    let secp = Secp256k1::verification_only();
    let h = |s: &str| blocktools_core::hex_dec(s).unwrap();
    let mut n = 0;
    for x in v.as_array().unwrap() {
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&h(x["tx"].as_str().unwrap())).unwrap();
        let i = x["input"].as_u64().unwrap() as usize;
        let (spk, amt) = match x.get("prev_tx") {
            Some(p) => { let p: bitcoin::Transaction = bitcoin::consensus::deserialize(&h(p.as_str().unwrap())).unwrap();
                assert_eq!(p.compute_txid(), tx.input[i].previous_output.txid);
                let o = &p.output[tx.input[i].previous_output.vout as usize]; (o.script_pubkey.to_bytes(), o.value.to_sat()) }
            None => (h(x["spk"].as_str().unwrap()), x["amount"].as_u64().unwrap()),
        };
        let ty = x["type"].as_u64().unwrap() as u32;
        let (sig, pk) = if spk.len() == 22 && spk[0] == 0 { let w = &tx.input[i].witness; (w.nth(0).unwrap().to_vec(), w.nth(1).unwrap().to_vec()) } else {
            let ins = tx.input[i].script_sig.instructions().map(|i| i.unwrap().push_bytes().unwrap().as_bytes().to_vec()).collect::<Vec<_>>(); (ins[0].clone(), ins[1].clone()) };
        assert_eq!(*sig.last().unwrap() as u32, ty & 0xff, "{}", x["chain"]);
        let code = if spk.len() == 22 { let mut c = vec![0x76, 0xa9, 20]; c.extend(&spk[2..]); c.extend([0x88, 0xac]); c } else { spk.clone() };
        let d = forkid_sighash(&tx, i, &code, amt, ty).unwrap();
        let (s, k) = (Signature::from_der(&sig[..sig.len() - 1]).unwrap(), PublicKey::from_slice(&pk).unwrap());
        assert!(secp.verify_ecdsa(&Message::from_digest(d), &s, &k).is_ok(), "{} forkid sighash", x["chain"]);
        let legacy = blocktools_tx::digest::legacy_sighash(&tx, i, &code, ty, blocktools_tx::digest::Digest::Sha256d).unwrap();
        assert!(secp.verify_ecdsa(&Message::from_digest(legacy), &s, &k).is_err());
        if ty != 0x41 { assert!(secp.verify_ecdsa(&Message::from_digest(forkid_sighash(&tx, i, &code, amt, 0x41).unwrap()), &s, &k).is_err(), "fork id 0 must not verify a BTG sig") }
        n += 1;
    }
    assert_eq!(n, 3);
}
