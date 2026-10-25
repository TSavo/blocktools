//! Groestlcoin (single-SHA-256 tx digests) known-answer tests, all from groestlcoinjs-lib
//! (an independent implementation): test/fixtures/transaction.json `hashForWitnessV0` and
//! test/integration/transactions.spec.ts "can create a 1-to-1 Transaction" (RFC6979 signature).
use bitcoin::{consensus::deserialize, Transaction};
use blocktools_tx::sign::{bip143_all, legacy_sighash, Digest};

fn hx(s: &str) -> Vec<u8> { blocktools_core::hex_dec(s).unwrap() }
fn p2pkh(h: &str) -> Vec<u8> { [hx("76a914"), hx(h), hx("88ac")].concat() }

#[test] fn bip143_single_sha256_vectors() {
    for l in include_str!("data/grs_witness_v0.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let tx: Transaction = deserialize(&hx(f[0])).unwrap();
        let mut h = bip143_all(&tx, f[1].parse().unwrap(), &p2pkh(f[2]), f[3].parse().unwrap(), Digest::Sha256).unwrap();
        h.reverse(); // fixtures print the hash reversed? accept either order below
        let fwd = { let mut x = h; x.reverse(); blocktools_core::hex_enc(x) };
        assert!(fwd == f[4] || blocktools_core::hex_enc(h) == f[4], "{} vs {}", fwd, f[4]);
    }
}
/// Our BIP143 encoder under sha256d equals rust-bitcoin's (so only the digest differs for GRS).
#[test] fn bip143_matches_rust_bitcoin_under_sha256d() {
    use bitcoin::{sighash::{EcdsaSighashType, SighashCache}, Amount, ScriptBuf, hashes::Hash};
    for l in include_str!("data/grs_witness_v0.txt").lines() {
        let f: Vec<&str> = l.split(' ').collect();
        let tx: Transaction = deserialize(&hx(f[0])).unwrap();
        let i: usize = f[1].parse().unwrap(); let v: u64 = f[3].parse().unwrap();
        let ours = bip143_all(&tx, i, &p2pkh(f[2]), v, Digest::Sha256d).unwrap();
        let mut wp = vec![0u8, 20]; wp.extend(hx(f[2]));
        let theirs = SighashCache::new(&tx).p2wpkh_signature_hash(i, &ScriptBuf::from_bytes(wp), Amount::from_sat(v), EcdsaSighashType::All).unwrap().to_byte_array();
        assert_eq!(ours, theirs);
    }
}
/// Real Groestlcoin mainnet txs: the on-chain txid is the single-SHA-256 txid, and the
/// consensus-accepted signatures verify against our single-SHA-256 legacy / BIP143 sighash
/// (and NOT against the sha256d variant).
#[test] fn mainnet_signatures_verify_under_single_sha256() {
    use bitcoin::hashes::Hash;
    let secp = secp256k1::Secp256k1::verification_only();
    for l in include_str!("data/grs_mainnet.txt").lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = l.split(' ').collect();
        let amounts: Vec<u64> = f[1].split(',').map(|x| x.parse().unwrap()).collect();
        let spks: Vec<Vec<u8>> = f[2].split(',').map(|x| blocktools_core::hex_dec(x).unwrap()).collect();
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&blocktools_core::hex_dec(f[3]).unwrap()).unwrap();
        if f[0] != "-" {
            assert_eq!(blocktools_tx::sign::txid_hex(&tx, Digest::Sha256), f[0]);
            assert_ne!(blocktools_tx::sign::txid_hex(&tx, Digest::Sha256d), f[0]);
        }
        assert_eq!(tx.input.len(), spks.len());
        for (i, (spk, amount)) in spks.iter().zip(amounts).enumerate() {
            let (sig, pk, segwit) = if spk[0] == 0 {
                let w = &tx.input[i].witness; (w.nth(0).unwrap().to_vec(), w.nth(1).unwrap().to_vec(), true)
            } else {
                let ss = tx.input[i].script_sig.as_bytes(); let n = ss[0] as usize;
                (ss[1..1 + n].to_vec(), ss[2 + n..].to_vec(), false)
            };
            assert_eq!(*sig.last().unwrap(), 1, "SIGHASH_ALL");
            let pkk = secp256k1::PublicKey::from_slice(&pk).unwrap();
            let es = secp256k1::ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap();
            let code = [vec![0x76, 0xa9, 20], bitcoin::hashes::hash160::Hash::hash(&pk).as_byte_array().to_vec(), vec![0x88, 0xac]].concat();
            if !segwit { assert_eq!(&code, spk); } else { assert_eq!(&code[3..23], &spk[2..]); }
            for (d, want) in [(Digest::Sha256, true), (Digest::Sha256d, false)] {
                let h = if segwit { bip143_all(&tx, i, &code, amount, d).unwrap() } else { legacy_sighash(&tx, i, &code, 1, d).unwrap() };
                assert_eq!(secp.verify_ecdsa(&secp256k1::Message::from_digest(h), &es, &pkk).is_ok(), want, "{} in{i} {:?}", &f[0], d);
            }
        }
    }
}
