//! Zcash v4/v5: BLAKE2b against Python hashlib, the upstream ZIP-243/244 test vectors
//! (zcash-test-vectors), and real mainnet txs (txid + every P2PKH signature verifies).
use blocktools_tx::{blake2b::blake2b, zcash::ZTx};
fn hx(s: &str) -> Vec<u8> { blocktools_core::hex_dec(s).unwrap() }
fn h(b: &[u8]) -> String { blocktools_core::hex_enc(b) }
fn rows(t: &str) -> impl Iterator<Item = Vec<&str>> { t.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).map(|l| l.split(' ').collect()) }

#[test] fn blake2b_matches_hashlib() {
    // python3: hashlib.blake2b(bytes(i%251 for i in range(n)), digest_size=32, person=p)
    for (n, p, want) in [
        (0, &b"ZTxIdHeadersHash"[..], "e6f9967555b66ebd3bd806f976a6d2b559dbd87a587e0ab738d1c4d90332e695"),
        (127, b"ZcashSigHash\x5b\x16\xa5\x37", "f81748c1eb67140e9027dc1249043aba4da34bf0e2b4283a6fd862ac236173b1"),
        (128, b"0123456789abcdef", "68f5bac43bc706250ecbf60870c6e7c556f62ab2e572d17d6da79e07667a91fa"),
        (129, b"ZTxTrAmountsHash", "2bd53576dd636c2d7a303a3b6b0c28dac134846677f2427bd097cd78978f64b9"),
        (1000, b"Zcash___TxInHash", "b8a0d70aaf2866b38792a0422cc4ff900cf23484d1db2175cdfec2044dcf104a"),
    ] {
        let d: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
        assert_eq!(h(&blake2b(32, p.try_into().unwrap(), &d)), want, "n={n}");
    }
    // RFC 7693 Appendix A: BLAKE2b-512("abc"), no personalization.
    assert_eq!(h(&blake2b(64, &[0; 16], b"abc")), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
}

#[test] fn zip244_vectors() {
    let (mut n_sig, mut n_sh) = (0, 0);
    for f in rows(include_str!("data/zec_zip244.txt")) {
        let tx = ZTx::parse(&hx(f[0]), 0).unwrap();
        assert_eq!(tx.serialize(), hx(f[0]), "round-trip");
        assert_eq!(h(&tx.txid()), f[1], "txid");
        let amounts: Vec<u64> = if f[3] == "-" { vec![] } else { f[3].split(',').map(|a| a.parse().unwrap()).collect() };
        let spks: Vec<Vec<u8>> = if f[4] == "-" { vec![] } else { f[4].split(',').map(hx).collect() };
        if amounts.len() == tx.inputs.len() { assert_eq!(h(&tx.shielded_sighash_v5(&amounts, &spks).unwrap()), f[6], "sighash_shielded"); n_sh += 1 }
        if f[5] == "-" { continue }
        let i: usize = f[5].parse().unwrap();
        for (k, ht) in [(7, 1u8), (8, 2), (9, 3), (10, 0x81), (11, 0x82), (12, 0x83)] {
            if f[k] == "-" { continue }
            assert_eq!(h(&tx.sighash(Some((i, &amounts, &spks)), ht).unwrap()), f[k], "sighash {ht:#x}"); n_sig += 1;
        }
    }
    assert!(n_sig >= 30 && n_sh >= 8, "{n_sig} {n_sh}");
}

#[test] fn zip243_vectors() {
    let mut n = 0;
    for f in rows(include_str!("data/zec_zip243.txt")) {
        let branch: u32 = f[5].parse().unwrap();
        let tx = ZTx::parse(&hx(f[0]), branch).unwrap();
        assert_eq!(tx.serialize(), hx(f[0]), "round-trip");
        let ht = f[3].parse::<u32>().unwrap() as u8;
        let input: i64 = f[2].parse().unwrap();
        let got = if input < 0 { tx.sighash(None, ht) } else {
            let i = input as usize; let k = tx.inputs.len();
            let mut amounts = vec![0u64; k]; amounts[i] = f[4].parse().unwrap();
            let mut spks = vec![vec![]; k]; spks[i] = if f[1] == "-" { vec![] } else { hx(f[1]) };
            tx.sighash(Some((i, &amounts, &spks)), ht)
        };
        match got { Ok(g) => { assert_eq!(h(&g), f[6], "zip243 #{n}"); n += 1 } Err(e) => panic!("{e} ht={ht:#x}") }
    }
    assert_eq!(n, 10);
}

pub fn check_mainnet(txid: &str, amounts: &str, spks: &str, raw: &str, branch: u32) {
    let secp = secp256k1::Secp256k1::verification_only();
    let tx = ZTx::parse(&hx(raw), branch).unwrap();
    assert_eq!(tx.serialize(), hx(raw));
    assert_eq!(tx.txid_hex(), txid, "txid");
    let amounts: Vec<u64> = amounts.split(',').map(|a| a.parse().unwrap()).collect();
    let spks: Vec<Vec<u8>> = spks.split(',').map(hx).collect();
    for i in 0..tx.inputs.len() {
        let ss = &tx.inputs[i].script_sig; let n = ss[0] as usize;
        let (sig, pk) = (&ss[1..1 + n], &ss[2 + n..]);
        let ht = *sig.last().unwrap();
        let pkk = secp256k1::PublicKey::from_slice(pk).unwrap();
        let mut es = secp256k1::ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap(); es.normalize_s();
        let d = tx.sighash(Some((i, &amounts, &spks)), ht).unwrap();
        assert!(secp.verify_ecdsa(&secp256k1::Message::from_digest(d), &es, &pkk).is_ok(), "{txid} input {i}");
        // A different consensus branch id must not verify (v4: branch only enters the sighash).
        let mut wrong = tx.clone(); wrong.branch_id ^= 1;
        let d = wrong.sighash(Some((i, &amounts, &spks)), ht).unwrap();
        assert!(secp.verify_ecdsa(&secp256k1::Message::from_digest(d), &es, &pkk).is_err(), "{txid} branch");
    }
}
#[test] fn mainnet_txs() {
    let (mut v4, mut v5) = (0, 0);
    for f in rows(include_str!("data/zec_mainnet.txt")) {
        check_mainnet(f[1], f[3], f[4], f[5], blocktools_tx::zcash::MAINNET_BRANCH_ID);
        if f[2] == "4" { v4 += 1 } else { v5 += 1 }
    }
    assert!(v4 >= 3 && v5 >= 3, "{v4} {v5}");
}

/// Independent address vectors: blockchair's decoded recipient for every input/output script
/// of the mainnet txs (20 P2PKH + 1 P2SH scripts).
#[test]
fn mainnet_scripts_match_explorer_addresses() {
    let mut n = 0;
    for l in include_str!("data/zec_addresses.txt").lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
        let (s, a) = l.split_once(' ').unwrap();
        let script = blocktools_core::hex_dec(s).unwrap();
        assert_eq!(blocktools_tx::zcash::script_to_address(&script).map(|(_, x)| x).as_deref(), Some(a), "{s}");
        n += 1;
    }
    assert_eq!(n, 21);
}
