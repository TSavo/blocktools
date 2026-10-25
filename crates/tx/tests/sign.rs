use bitcoin::consensus::{deserialize, serialize};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::sighash::TapSighashType;
use bitcoin::{Amount, ScriptBuf, TapNodeHash, Transaction, TxOut};
use blocktools_core::hex_dec as h;
use blocktools_tx::{build, sign};
use std::str::FromStr;

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
    let utxos: String = addrs.iter().enumerate().map(|(i, a)| format!("{{\"txid\":\"{tid}\",\"vout\":{i},\"amount\":{},\"address\":\"{a}\"}}\n", 10000 * (i + 1))).collect();
    let u = build::parse_utxos(c, &utxos).unwrap();
    let mut p = build::build_btc(c, u.clone(), &build::BtcPlan { to: addrs[0].into(), send: None, change: None, fee_rate: 2, rbf: true, dust: 546, locktime: 0 }).unwrap();
    assert_eq!(p.unsigned_tx.output.len(), 1);
    let fee = 100000 - p.unsigned_tx.output[0].value.to_sat();
    assert_eq!(fee, (11 + 68 + 148 + 148 + 91 + 31) * 2);
    assert_eq!(sign::sign_psbt(&mut p, &[sk(K)]).unwrap(), 4);
    let tx = sign::extract(&p).unwrap();
    // decode the signed result with tx-decode's library: all inputs priced, signed
    let d = blocktools_tx::decode(&blocktools_core::hex_enc(&serialize(&tx)), "btc");
    assert!(d.is_ok());
    // send with change; insufficient funds; wrong key leaves inputs unsigned
    let p2 = build::build_btc(c, u.clone(), &build::BtcPlan { to: addrs[1].into(), send: Some(30000), change: Some(addrs[0].into()), fee_rate: 1, rbf: false, dust: 546, locktime: 0 }).unwrap();
    assert_eq!(p2.unsigned_tx.output.len(), 2);
    assert!(build::build_btc(c, u.clone(), &build::BtcPlan { to: addrs[1].into(), send: Some(200000), change: Some(addrs[0].into()), fee_rate: 1, rbf: false, dust: 546, locktime: 0 }).is_err());
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
    let tid = "b".repeat(64);
    let utxos: String = addrs.iter().enumerate().map(|(i, a)| format!("{{\"txid\":\"{tid}\",\"vout\":{i},\"amount\":{},\"address\":\"{a}\"}}\n", 10000 * (i + 1))).collect();
    let u = build::parse_utxos(c, &utxos).unwrap();
    let mut p = build::build_btc(c, u, &build::BtcPlan { to: addrs[4].into(), send: None, change: None, fee_rate: 3, rbf: false, dust: 546, locktime: 0 }).unwrap();
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
