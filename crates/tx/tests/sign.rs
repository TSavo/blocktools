use bitcoin::consensus::{deserialize, serialize};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::sighash::TapSighashType;
use bitcoin::{Amount, ScriptBuf, TapNodeHash, Transaction, TxOut};
use blocktools_core::hex_dec as h;
use blocktools_tx::{build, sign};
use std::str::FromStr;
mod common;

fn sk(x: &str) -> SecretKey { SecretKey::from_slice(&h(x).unwrap()).unwrap() }

#[test]
fn bip143_p2sh_p2wpkh_byte_exact() {
    let tx: Transaction = deserialize(&h("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap()).unwrap();
    let mut p = Psbt::from_unsigned_tx(tx).unwrap();
    p.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(1_000_000_000), script_pubkey: ScriptBuf::from_bytes(h("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387").unwrap()) });
    let other = sk("0000000000000000000000000000000000000000000000000000000000000001");
    assert_eq!(sign::sign_psbt(&mut p, &[other, sk("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")]).unwrap(), 1);
    let out = blocktools_core::hex_enc(&serialize(&sign::extract(&p).unwrap()));
    assert_eq!(out, "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000");
}

#[test]
fn bip341_keypath_vectors() {
    let d: serde_json::Value = serde_json::from_str(include_str!("vectors/bip341-wallet.json")).unwrap();
    let k = &d["keyPathSpending"][0];
    let tx: Transaction = deserialize(&h(k["given"]["rawUnsignedTx"].as_str().unwrap()).unwrap()).unwrap();
    let prev: Vec<TxOut> = k["given"]["utxosSpent"].as_array().unwrap().iter().map(|u| TxOut { value: Amount::from_sat(u["amountSats"].as_u64().unwrap()), script_pubkey: ScriptBuf::from_bytes(h(u["scriptPubKey"].as_str().unwrap()).unwrap()) }).collect();
    let secp = Secp256k1::new();
    let mut n = 0;
    for v in k["inputSpending"].as_array().unwrap() {
        let g = &v["given"];
        let mr = g["merkleRoot"].as_str().map(|m| TapNodeHash::from_str(m).unwrap());
        let ty = TapSighashType::from_consensus_u8(g["hashType"].as_u64().unwrap() as u8).unwrap();
        let s = sign::taproot_sig(&tx, g["txinIndex"].as_u64().unwrap() as usize, &prev, &sk(g["internalPrivkey"].as_str().unwrap()), mr, ty, &secp).unwrap();
        assert_eq!(blocktools_core::hex_enc(&s), v["expected"]["witness"][0].as_str().unwrap()); n += 1;
    }
    assert_eq!(n, 7);
}

const K: &str = "0000000000000000000000000000000000000000000000000000000000000001";
// Addresses of private key 1 (public, well known).
#[test]
fn build_then_sign_every_kind() {
    let c = blocktools_core::chains::chain("btc").unwrap();
    let addrs = ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN"];
    let tid = "a".repeat(64);
    let utxos: String = addrs.iter().enumerate().map(|(i, a)| common::line(c, i as u32, 10000 * (i as u64 + 1), a)).collect();
    let u = build::parse_utxos(c, &utxos).unwrap();
    let mut p = build::build_btc(c, u.clone(), &build::BtcPlan { to: addrs[0].into(), send: None, change: None, fee_rate: 2, rbf: true, dust: 546, op_return: None, locktime: 0 }).unwrap();
    assert_eq!(p.unsigned_tx.output.len(), 1);
    let fee = 100000 - p.unsigned_tx.output[0].value.to_sat();
    assert_eq!(fee, (11 + 68 + 148 + 148 + 91 + 31) * 2);
    assert_eq!(sign::sign_psbt(&mut p, &[sk(K)]).unwrap(), 4);
    let tx = sign::extract(&p).unwrap();
    // decode the signed result with tx-decode's library: all inputs priced, signed
    let d = blocktools_tx::decode(&blocktools_core::hex_enc(&serialize(&tx)), "btc");
    assert!(d.is_ok());
    // send with change; insufficient funds; wrong key leaves inputs unsigned
    let p2 = build::build_btc(c, u.clone(), &build::BtcPlan { to: addrs[1].into(), send: Some(30000), change: Some(addrs[0].into()), fee_rate: 1, rbf: false, dust: 546, op_return: None, locktime: 0 }).unwrap();
    assert_eq!(p2.unsigned_tx.output.len(), 2);
    assert!(build::build_btc(c, u.clone(), &build::BtcPlan { to: addrs[1].into(), send: Some(200000), change: Some(addrs[0].into()), fee_rate: 1, rbf: false, dust: 546, op_return: None, locktime: 0 }).is_err());
    let mut p3 = p2.clone();
    assert_eq!(sign::sign_psbt(&mut p3, &[sk("0000000000000000000000000000000000000000000000000000000000000002")]).unwrap(), 0);
    assert!(sign::extract(&p3).is_err());
    // hostile utxo lines
    assert!(build::parse_utxos(c, "{\"txid\":\"zz\"}").is_err());
    assert!(build::parse_utxos(c, &format!("{{\"txid\":\"{tid}\",\"vout\":0,\"amount\":5,\"address\":\"LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1\"}}")).is_err());
}

/// Each produced signature verifies (libsecp256k1) against rust-bitcoin's sighash for that input,
/// and the witness/scriptSig has the standard shape. (Bitcoin Core's interpreter is not linked:
/// no C++ toolchain in the build; BIP-143/BIP-341 byte-exact vectors above cover the segwit paths.)
#[test]
fn every_signature_verifies() {
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{ecdsa, schnorr, Message, XOnlyPublicKey};
    use bitcoin::sighash::{EcdsaSighashType, Prevouts, SighashCache};
    let c = blocktools_core::chains::chain("btc").unwrap();
    let addrs = ["bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN", "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9"];
    let _tid = "b".repeat(64);
    let utxos: String = addrs.iter().enumerate().map(|(i, a)| common::line(c, i as u32, 10000 * (i as u64 + 1), a)).collect();
    let u = build::parse_utxos(c, &utxos).unwrap();
    let mut p = build::build_btc(c, u, &build::BtcPlan { to: addrs[4].into(), send: None, change: None, fee_rate: 3, rbf: false, dust: 546, op_return: None, locktime: 0 }).unwrap();
    assert_eq!(sign::sign_psbt(&mut p, &[sk(K)]).unwrap(), 5);
    let tx = sign::extract(&p).unwrap();
    let prev: Vec<TxOut> = p.inputs.iter().map(|i| i.witness_utxo.clone().unwrap()).collect();
    let secp = Secp256k1::verification_only();
    let pushes = |s: &[u8]| { let mut v = Vec::new(); let mut i = 0; while i < s.len() { let n = s[i] as usize; v.push(s[i + 1..i + 1 + n].to_vec()); i += 1 + n } v };
    for (i, o) in prev.iter().enumerate() {
        let spk = o.script_pubkey.as_bytes();
        let mut cache = SighashCache::new(&tx);
        let (sig, pk, h) = if spk[0] == 0x51 { // p2tr
            let w = tx.input[i].witness.to_vec(); assert_eq!(w.len(), 1);
            let h = cache.taproot_key_spend_signature_hash(i, &Prevouts::All(&prev), TapSighashType::Default).unwrap();
            let pk = XOnlyPublicKey::from_slice(&spk[2..]).unwrap();
            secp.verify_schnorr(&schnorr::Signature::from_slice(&w[0]).unwrap(), &Message::from_digest(h.to_byte_array()), &pk).unwrap();
            continue;
        } else if spk[0] == 0x76 { let v = pushes(tx.input[i].script_sig.as_bytes()); let h = cache.legacy_signature_hash(i, &o.script_pubkey, 1).unwrap().to_byte_array(); (v[0].clone(), v[1].clone(), h)
        } else { let w = tx.input[i].witness.to_vec();
            let code = { let mut s = vec![0u8, 20]; s.extend(bitcoin::hashes::hash160::Hash::hash(&w[1]).to_byte_array()); s };
            if spk[0] == 0xa9 { assert_eq!(pushes(tx.input[i].script_sig.as_bytes())[0], code) }
            let h = cache.p2wpkh_signature_hash(i, &ScriptBuf::from_bytes(code), o.value, EcdsaSighashType::All).unwrap().to_byte_array(); (w[0].clone(), w[1].clone(), h) };
        assert_eq!(*sig.last().unwrap(), 1);
        let pk = bitcoin::secp256k1::PublicKey::from_slice(&pk).unwrap();
        secp.verify_ecdsa(&Message::from_digest(h), &ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap(), &pk).unwrap_or_else(|_| panic!("input {i}"));
    }
}

/// Security review finding 1: a legacy P2PKH input whose claimed amount is not proven by the
/// previous tx must never be signed or pass tx-verify (its sighash does not commit to the amount,
/// so a 0.0003 claim on a 3 BTC input would sign bytes paying 2.9997 BTC to miners).
#[test]
fn legacy_lying_amount_refused() {
    use blocktools_tx::policy::{check, Policy};
    let c = blocktools_core::chains::chain("btc").unwrap();
    let a = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
    let (txid, real) = common::prev_tx(c, 0, 300_000_000, a); // real prevout: 3 BTC
    let claim = |extra: &str| format!("{{\"txid\":\"{txid}\",\"vout\":0,\"amount\":30000,\"address\":\"{a}\"{extra}}}");
    // tx-build: no prev tx -> refused; prev tx that disagrees with the claim -> refused
    let plan = build::BtcPlan { to: a.into(), send: None, change: None, fee_rate: 1, rbf: false, dust: 546, op_return: None, locktime: 0 };
    let u = build::parse_utxos(c, &claim("")).unwrap();
    assert!(build::build_btc(c, u.clone(), &plan).unwrap_err().contains("legacy_input_needs_prev_tx"));
    assert!(build::parse_utxos(c, &claim(&format!(",\"prev_tx\":\"{real}\""))).unwrap_err().contains("differs"));
    // A hand-made PSBT with only the lying witness_utxo (what the old tx-build produced)
    let tx = Transaction { version: bitcoin::transaction::Version::TWO, lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn { previous_output: bitcoin::OutPoint { txid: bitcoin::Txid::from_str(&txid).unwrap(), vout: 0 }, ..Default::default() }],
        output: vec![TxOut { value: Amount::from_sat(29_000), script_pubkey: u[0].script.clone().into() }] };
    let mut p = Psbt::from_unsigned_tx(tx).unwrap();
    p.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(30_000), script_pubkey: u[0].script.clone().into() });
    let pol = Policy { expect_to: vec![a.into()], max_fee: Some(100_000), ..Default::default() };
    let d = blocktools_tx::decode_bytes(&p.serialize(), "btc").unwrap();
    assert_eq!(d.fee, Some(1000)); // the lie the human would have seen
    assert!(check(&d, &pol).contains(&"legacy_input_amount_unproven"));
    assert!(check(&d, &Policy { allow_warnings: true, ..pol.clone() }).contains(&"legacy_input_amount_unproven"));
    assert_eq!(sign::sign_psbt(&mut p.clone(), &[sk(K)]).unwrap_err(), "legacy_input_amount_unproven");
    // Attaching the real prev tx: mismatch with witness_utxo -> still refused
    p.inputs[0].non_witness_utxo = Some(deserialize(&h(&real).unwrap()).unwrap());
    assert!(check(&blocktools_tx::decode_bytes(&p.serialize(), "btc").unwrap(), &pol).contains(&"legacy_input_amount_unproven"));
    assert_eq!(sign::sign_psbt(&mut p.clone(), &[sk(K)]).unwrap_err(), "legacy_input_amount_unproven");
    // Honest: witness_utxo agrees with the prev tx -> the true 2.9997 BTC fee shows and the cap refuses it
    p.inputs[0].witness_utxo = None;
    let d = blocktools_tx::decode_bytes(&p.serialize(), "btc").unwrap();
    assert_eq!((d.unproven_inputs, d.fee), (0, Some(300_000_000 - 29_000)));
    assert!(check(&d, &pol).contains(&"fee_above_cap"));
    assert_eq!(sign::sign_psbt(&mut p, &[sk(K)]).unwrap(), 1);
}
/// Same for GRS (legacy sighash under single SHA-256): the prev tx must hash with GRS's digest.
#[test]
fn grs_legacy_needs_prev_tx() {
    let c = blocktools_core::chains::chain("grs").unwrap();
    let a = blocktools_core::chains::pub_rows(c, "", &bitcoin::secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &sk(K)), true).into_iter().find(|r| r.kind == "p2pkh").unwrap().address;
    let plan = build::BtcPlan { to: a.clone(), send: None, change: None, fee_rate: 1, rbf: false, dust: 546, op_return: None, locktime: 0 };
    let u = build::parse_utxos(c, &common::line(c, 1, 50_000, &a)).unwrap();
    let mut p = build::build_btc(c, u, &plan).unwrap();
    assert_eq!(blocktools_tx::decode_bytes(&p.serialize(), "grs").unwrap().unproven_inputs, 0);
    assert_eq!(sign::sign_psbt_digest(&mut p.clone(), &[sk(K)], sign::Digest::Sha256).unwrap(), 1);
    p.inputs[0].non_witness_utxo = None;
    assert_eq!(sign::sign_psbt_digest(&mut p, &[sk(K)], sign::Digest::Sha256).unwrap_err(), "legacy_input_amount_unproven");
}

/// Review A: a bare P2SH input is legacy-sighash (no amount commitment) unless its redeem script
/// is proven to be a witness program. Key 1's P2SH-P2WPKH (public) is the wrapped-segwit case.
#[test]
fn bare_p2sh_is_not_amount_committed() {
    use blocktools_tx::digest::{self, Digest};
    let c = blocktools_core::chains::chain("btc").unwrap();
    // The sighash KAT: legacy sighash never sees the amount; BIP143 changes with it.
    let tx: Transaction = deserialize(&h("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap()).unwrap();
    let legacy_redeem = h("51").unwrap(); // OP_TRUE wrapped in bare P2SH
    let code = h("76a91479091972186c449eb1ded22b78e40d009bdf008988ac").unwrap();
    assert_ne!(digest::bip143_all(&tx, 0, &code, 1, Digest::Sha256d).unwrap(), digest::bip143_all(&tx, 0, &code, 2, Digest::Sha256d).unwrap());
    let l = digest::legacy_sighash(&tx, 0, &legacy_redeem, 1, Digest::Sha256d).unwrap(); // takes no amount at all
    assert_eq!(l, digest::legacy_sighash(&tx, 0, &legacy_redeem, 1, Digest::Sha256d).unwrap());
    let p2sh = "3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN";
    let spk = ScriptBuf::from_bytes(blocktools_core::chains::address_to_script(c, p2sh).unwrap());
    let good = h("0014751e76e8199196d454941c45d1b3a323f1433bd6").unwrap();
    assert!(digest::amount_uncommitted(&spk));
    assert!(digest::p2sh_proven_segwit(&spk, Some(bitcoin::Script::from_bytes(&good))));
    assert!(!digest::p2sh_proven_segwit(&spk, Some(bitcoin::Script::from_bytes(&legacy_redeem))));
    // tx-build: bare P2SH without prev_tx is refused; a proving redeem_script is accepted and carried.
    let tid = "c".repeat(64);
    let plan = build::BtcPlan { to: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(), send: None, change: None, fee_rate: 1, rbf: false, dust: 546, op_return: None, locktime: 0 };
    let bare = format!("{{\"txid\":\"{tid}\",\"vout\":0,\"amount\":50000,\"address\":\"{p2sh}\"}}");
    assert!(build::build_btc(c, build::parse_utxos(c, &bare).unwrap(), &plan).unwrap_err().contains("legacy_input_needs_prev_tx"));
    let bad = format!("{{\"txid\":\"{tid}\",\"vout\":0,\"amount\":50000,\"address\":\"{p2sh}\",\"redeem_script\":\"51\"}}");
    assert!(build::parse_utxos(c, &bad).unwrap_err().contains("redeem_script"));
    let ok = format!("{{\"txid\":\"{tid}\",\"vout\":0,\"amount\":50000,\"address\":\"{p2sh}\",\"redeem_script\":\"{}\"}}", blocktools_core::hex_enc(&good));
    let p = build::build_btc(c, build::parse_utxos(c, &ok).unwrap(), &plan).unwrap();
    assert_eq!(p.inputs[0].redeem_script.as_ref().unwrap().as_bytes(), &good[..]);
    assert_eq!(blocktools_tx::decode_bytes(&p.serialize(), "btc").unwrap().unproven_inputs, 0);
    // tx-decode/verify: the same PSBT with no redeem_script and no prev tx counts as unproven.
    let mut q = p.clone(); q.inputs[0].redeem_script = None;
    assert_eq!(blocktools_tx::decode_bytes(&q.serialize(), "btc").unwrap().unproven_inputs, 1);
    // tx-sign: its own key proves the wrapped-segwit redeem (signs BIP143); a stranger key refuses.
    assert_eq!(sign::sign_psbt(&mut q.clone(), &[sk(K)]).unwrap(), 1);
    assert_eq!(sign::sign_psbt(&mut q.clone(), &[sk("0000000000000000000000000000000000000000000000000000000000000002")]).unwrap_err(), "legacy_input_amount_unproven");
}

/// Fork-id signing, byte-exact against Trust Wallet Core's published signed txs (public test keys
/// from tests/chains/BitcoinCash/TWBitcoinCashTests.cpp and BitcoinGold/TWBitcoinGoldTests.cpp;
/// the BCH one is mainnet tx 96ee2000…bbb4). RFC 6979 nonces make the bytes reproducible.
#[test]
fn forkid_bch_btg_byte_exact() {
    let cases = [ // (prev spk, prev amount, key, fork id, segwit, expected signed tx; the unsigned tx is it with scriptSig/witness cleared)
        ("76a914aff1e0789e5fe316b729577665aa0a04d5b0f8c788ac", 5151, "7fdafb9db5bc501f2096e7d13d331dc7a75d9594af3d251313ba8b6200f4e384", 0, false, // public test vector (Trust Wallet Core)
         "0100000001e28c2b955293159898e34c6840d99bf4d390e2ee1c6f606939f18ee1e2000d05020000006b483045022100b70d158b43cbcded60e6977e93f9a84966bc0cec6f2dfd1463d1223a90563f0d02207548d081069de570a494d0967ba388ff02641d91cadb060587ead95a98d4e3534121038eab72ec78e639d02758e7860cdec018b49498c307791f785aa3019622f4ea5bffffffff0258020000000000001976a914769bdff96a02f9135a1d19b749db6a78fe07dc9088ace5100000000000001976a9149e089b6889e032d46e3b915a3392edfd616fb1c488ac00000000"),
        ("0014d53cae7c6fb6c8efe4fd8bfecea36534105b1674", 10000, "cbe13a79b82ec7f8871b336a64fd8d531f598e7c9022e29c67e824cfd54af57f", 79, true, // public test vector (Trust Wallet Core)
         "010000000001015727794fa2b94aa22a226e206130524201ede9b50e032526e713c848493a890f0000000000fdffffff028813000000000000160014db746a75d9aae8995d135b1e19a04d7765242a8ffb12000000000000160014ebae10950c8a35a506e0e265b928305233e802ab0247304402202b371b7cae885463c06357d1fc6ca95ab155613f212711bc7fb115500654946d0220430af77cbbb30afe7d7dcaccb72a55da802ee0a2bfea790dfe7c4e1a4c53fd7d412103e00b5dec8078d526fba090247bd92db6b67a4dd1953b788cea9b52de9471b8cf71890900"),
    ];
    for (spk, amt, k, fid, sw, want) in cases {
        let want = want.replace(' ', "");
        let mut u: Transaction = deserialize(&h(&want).unwrap()).unwrap();
        for i in &mut u.input { i.script_sig = ScriptBuf::new(); i.witness = bitcoin::Witness::new() }
        let mut p = Psbt::from_unsigned_tx(u).unwrap();
        let prev = [TxOut { value: Amount::from_sat(amt), script_pubkey: ScriptBuf::from_bytes(h(spk).unwrap()) }];
        assert_eq!(sign::sign_forkid_prevouts(&mut p, &prev, &[sk(k)], fid, sw).unwrap(), 1);
        assert_eq!(blocktools_core::hex_enc(&serialize(&sign::extract(&p).unwrap())), want, "fork id {fid}");
    }
}
/// Refusals kept on the fork-id signer: no proving prev tx, a script it does not sign, P2WPKH on
/// a chain without segwit (BCH/BSV).
#[test]
fn forkid_signer_refusals() {
    let tx: Transaction = { let mut t: Transaction = deserialize(&h("0100000001e28c2b955293159898e34c6840d99bf4d390e2ee1c6f606939f18ee1e2000d05020000006b483045022100b70d158b43cbcded60e6977e93f9a84966bc0cec6f2dfd1463d1223a90563f0d02207548d081069de570a494d0967ba388ff02641d91cadb060587ead95a98d4e3534121038eab72ec78e639d02758e7860cdec018b49498c307791f785aa3019622f4ea5bffffffff0258020000000000001976a914769bdff96a02f9135a1d19b749db6a78fe07dc9088ace5100000000000001976a9149e089b6889e032d46e3b915a3392edfd616fb1c488ac00000000").unwrap()).unwrap(); t.input[0].script_sig = ScriptBuf::new(); t };
    let key = sk("0000000000000000000000000000000000000000000000000000000000000001");
    let mut p = Psbt::from_unsigned_tx(tx.clone()).unwrap();
    p.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(5151), script_pubkey: ScriptBuf::from_bytes(h("76a914aff1e0789e5fe316b729577665aa0a04d5b0f8c788ac").unwrap()) });
    assert_eq!(sign::sign_psbt_forkid(&mut p, &[key], 0, false), Err("legacy_input_amount_unproven"));
    for (spk, sw) in [("a9144733f37cf4db86fbc2efed2500b4f4e49f31202387", true), ("0014d53cae7c6fb6c8efe4fd8bfecea36534105b1674", false)] {
        let prev = Transaction { version: bitcoin::transaction::Version(1), lock_time: bitcoin::absolute::LockTime::ZERO, input: vec![bitcoin::TxIn::default()],
            output: vec![TxOut { value: Amount::from_sat(5151), script_pubkey: ScriptBuf::from_bytes(h(spk).unwrap()) }] };
        let mut t = tx.clone(); t.input[0].previous_output = bitcoin::OutPoint { txid: prev.compute_txid(), vout: 0 };
        let mut p = Psbt::from_unsigned_tx(t).unwrap(); p.inputs[0].non_witness_utxo = Some(prev);
        assert_eq!(sign::sign_psbt_forkid(&mut p, &[key], 0, sw), Err("forkid_script_unsupported"), "{spk}");
    }
}
