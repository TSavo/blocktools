//! PoS-nTime chains: real mainnet txs. The on-chain txid must equal sha256d of our
//! serialisation, and every consensus-accepted P2PKH signature must verify against our legacy
//! sighash (and fail with the opposite timestamp-in-preimage choice: PPC/NVC/CLAM include it, RDD omits it).
mod common;
use blocktools_tx::pos::PosTx;
fn hx(s: &str) -> Vec<u8> { blocktools_core::hex_dec(s).unwrap() }

pub fn check(chain: &str, txid: &str, spks: &str, raw: &str) {
    let secp = secp256k1::Secp256k1::verification_only();
    let tx = PosTx::parse(chain, &hx(raw)).unwrap_or_else(|e| panic!("{chain} {txid}: {e}"));
    assert_eq!(tx.serialize(), hx(raw), "{chain} round-trip");
    if txid != "-" { assert_eq!(tx.txid_hex(), txid, "{chain} txid") }
    let spks: Vec<Vec<u8>> = spks.split(',').map(hx).collect();
    assert_eq!(spks.len(), tx.inputs.len());
    let mut flipped = tx.clone(); flipped.layout.sighash_time = !tx.layout.sighash_time;
    for (i, spk) in spks.iter().enumerate() {
        let ss = &tx.inputs[i].script_sig; let n = ss[0] as usize;
        let (sig, pk) = (&ss[1..1 + n], &ss[2 + n..]);
        assert_eq!(*sig.last().unwrap(), 1, "SIGHASH_ALL");
        let pkk = secp256k1::PublicKey::from_slice(pk).unwrap();
        let mut es = secp256k1::ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap(); es.normalize_s();
        let m = |h: [u8; 32]| secp256k1::Message::from_digest(h);
        assert!(secp.verify_ecdsa(&m(tx.sighash_all(i, spk).unwrap()), &es, &pkk).is_ok(), "{chain} {txid} input {i}");
        // The opposite choice (time in / out of the preimage) must NOT verify.
        assert!(secp.verify_ecdsa(&m(flipped.sighash_all(i, spk).unwrap()), &es, &pkk).is_err(), "{chain} sighash_time choice");
    }
}
#[test] fn mainnet_txids_and_signatures() {
    let mut per = std::collections::BTreeMap::new();
    for l in include_str!("data/pos_mainnet.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let f: Vec<&str> = l.split(' ').collect();
        if f[0] == "blk" { continue }
        check(f[0], f[1], f[3], f[4]); *per.entry(f[0]).or_insert(0) += 1;
    }
    for c in ["ppc", "nvc", "clam", "rdd"] { assert!(per.get(c).copied().unwrap_or(0) >= 1, "{c} has a vector") }
}
/// Blackcoin dropped the tx timestamp (v2 txs, Bitcoin layout): its mainnet txs parse and
/// verify with plain rust-bitcoin + sha256d legacy sighash.
#[test] fn blackcoin_is_bitcoin_layout() {
    use blocktools_tx::digest::{legacy_sighash, Digest};
    let secp = secp256k1::Secp256k1::verification_only();
    let mut n = 0;
    for l in include_str!("data/pos_mainnet.txt").lines().filter(|l| l.starts_with("blk ")) {
        let f: Vec<&str> = l.split(' ').collect();
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&hx(f[4])).unwrap();
        assert_eq!(tx.compute_txid().to_string(), f[1]);
        for (i, spk) in f[3].split(',').map(hx).enumerate() {
            let ss = tx.input[i].script_sig.as_bytes(); let k = ss[0] as usize;
            let mut es = secp256k1::ecdsa::Signature::from_der(&ss[1..k]).unwrap(); es.normalize_s();
            let pk = secp256k1::PublicKey::from_slice(&ss[2 + k..]).unwrap();
            assert!(secp.verify_ecdsa(&secp256k1::Message::from_digest(legacy_sighash(&tx, i, &spk, 1, Digest::Sha256d).unwrap()), &es, &pk).is_ok());
        }
        n += 1;
    }
    assert!(n >= 1);
}
/// Sign a built sweep with throwaway key 1 (all four layouts); the result verifies under the
/// same checks as the mainnet vectors.
#[cfg(feature = "secrets")]
#[test] fn sign_built_sweep_roundtrip() {
    let k = secp256k1::SecretKey::from_slice(&[[0u8; 31].as_slice(), &[1]].concat()).unwrap(); // throwaway
    for (c, from, to) in [("ppc", "PKGSi8HTQzLx89rkZrRrVkPFjrcSC55NP9", "PMsYj4nuMuX6uCuig8TeS82KLVhb6hBZqt"), ("nvc", "4QP6S2Gv3WZmgnJgR8mshrbHA9W6hQiTxR", "4SzCSxnMzRjvTqMeXQofeEELknbFfka5SC"),
                          ("clam", "xJyuT2j5dnLoBhHraFjzG2hmMDjnS3fefx", "xMb1TyEXahWwxkLpgXmnCQLpwrpwLRRhrb"), ("rdd", "RjJ4cn5Bg58D2khGiNRmQW1yWtA6Py9kWa", "RmuAdiadczJMookEpeTZLsf37XFFKpkCxW")] {
        let ch = blocktools_core::chains::supported(c).unwrap();
        let line = common::line(ch, 1, 30000, from);
        let u = blocktools_tx::build::parse_utxos(ch, &line).unwrap();
        let env = blocktools_tx::pos::envelope(c, &blocktools_tx::build::build_pos_sweep(ch, &u, to, 5, 1792800000, 546).unwrap().0, &blocktools_tx::build::build_pos_sweep(ch, &u, to, 5, 1792800000, 546).unwrap().1, &[u[0].prev_raw.clone()]).to_string();
        assert_eq!(blocktools_tx::decode(&env, c).unwrap().unproven_inputs, 0);
        let mut lie: serde_json::Value = serde_json::from_str(&env).unwrap(); lie["pos_prevouts"][0]["amount"] = 3_000_000.into(); lie["pos_prevouts"][0]["amount_str"] = "3000000".into();
        assert_eq!(blocktools_tx::decode(&lie.to_string(), c).unwrap().unproven_inputs, 1);
        let mut none: serde_json::Value = serde_json::from_str(&env).unwrap(); none["pos_prevouts"][0].as_object_mut().unwrap().remove("prev_tx");
        assert!(blocktools_tx::policy::check(&blocktools_tx::decode(&none.to_string(), c).unwrap(), &Default::default()).contains(&"legacy_input_amount_unproven"));
        let (mut tx, prev) = blocktools_tx::build::build_pos_sweep(ch, &u, to, 5, 1792800000, 546).unwrap();
        assert_eq!(blocktools_tx::sign::sign_pos(&mut tx, &prev, &[k]).unwrap(), 1);
        let spks: Vec<String> = prev.iter().map(|p| blocktools_core::hex_enc(&p.1)).collect();
        check(c, "-", &spks.join(","), &blocktools_core::hex_enc(tx.serialize()));
    }
}
