//! Quarkcoin (qrk) tx format: 2 mainnet txs (8 and 170 inputs). txid = sha256d of Bitcoin-legacy bytes, every
//! P2PKH input signature verifies under the legacy sighash, and hash160(pubkey) under the qrk
//! p2pkh byte (58) gives the address the explorer shows.
use bitcoin::{consensus::deserialize, hashes::Hash, sighash::SighashCache, PubkeyHash, ScriptBuf, Transaction};
use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};

#[test]
fn qrk_mainnet_txs_are_bitcoin_legacy() {
    let secp = Secp256k1::verification_only();
    let c = blocktools_core::chains::chain("qrk").unwrap();
    let (mut txs, mut sigs, mut p2pk) = (0, 0, 0);
    for l in include_str!("data/qrk_mainnet.txt").lines().filter(|l| !l.starts_with('#')) {
        let mut it = l.split(' ');
        let (txid, addrs, hex) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap());
        let tx: Transaction = deserialize(&blocktools_core::hex_dec(hex).unwrap()).unwrap();
        assert_eq!(tx.compute_txid().to_string(), txid);
        let addrs: Vec<&str> = addrs.split(',').collect();
        let cache = SighashCache::new(&tx);
        for (n, i) in tx.input.iter().enumerate() {
            let p: Vec<_> = i.script_sig.instructions().map(|x| x.unwrap().push_bytes().unwrap().as_bytes().to_vec()).collect();
            if p.len() == 1 { p2pk += 1; continue } // P2PK spend: pubkey is in the prevout, not checked here
            let (sig, pk) = (&p[0], PublicKey::from_slice(&p[1]).unwrap());
            let h = PubkeyHash::hash(&pk.serialize_uncompressed()[..]);
            let h = if p[1].len() == 33 { PubkeyHash::hash(&p[1]) } else { h };
            let spk = ScriptBuf::new_p2pkh(&h);
            assert_eq!(blocktools_core::chains::script_to_address(c, spk.as_bytes()).unwrap().1, addrs[n]);
            let sh = cache.legacy_signature_hash(n, &spk, sig[sig.len() - 1] as u32).unwrap();
            let s = Signature::from_der_lax(&sig[..sig.len() - 1]).unwrap();
            let mut s2 = s; s2.normalize_s();
            secp.verify_ecdsa(&Message::from_digest(sh.to_byte_array()), &s2, &pk).unwrap();
            sigs += 1;
        }
        txs += 1;
    }
    assert_eq!(txs, 2); assert_eq!(sigs + p2pk, 178); assert!(sigs >= 8);
    eprintln!("qrk: {txs} txs, {sigs} P2PKH signatures, {p2pk} P2PK inputs skipped");
}
