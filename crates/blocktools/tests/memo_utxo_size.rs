//! THORChain memo sends on LTC/DOGE/BCH: the builder's vsize estimate vs the TRUE size of the
//! tx signed with the public throwaway key 1 (tests only), plus shape (vault VOUT0, change VOUT1,
//! OP_RETURN last, non-RBF) and BCH forkid signing.
use bitcoin::hashes::{hash160, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::SecretKey;
use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use blocktools_core::chains;
use blocktools_tx::{digest, sign};

fn key(n: u8) -> (SecretKey, [u8; 20]) {
    let mut b = [0u8; 32]; b[31] = n;
    let sk = SecretKey::from_slice(&b).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&bitcoin::secp256k1::Secp256k1::new(), &sk).serialize();
    (sk, hash160::Hash::hash(&pk).to_byte_array())
}
fn p2pkh(h: &[u8; 20]) -> Vec<u8> { let mut s = vec![0x76, 0xa9, 20]; s.extend(h); s.extend([0x88, 0xac]); s }
fn p2wpkh(h: &[u8; 20]) -> Vec<u8> { let mut s = vec![0, 20]; s.extend(h); s }
fn p2sh_p2wpkh(h: &[u8; 20]) -> (Vec<u8>, Vec<u8>) { let r = p2wpkh(h); let mut s = vec![0xa9, 20]; s.extend(hash160::Hash::hash(&r).to_byte_array()); s.push(0x87); (s, r) }

/// UTXO lines with prev_tx paying `spk` (public synthetic data).
fn lines(c: &chains::Chain, spk: &[u8], amts: &[u64], redeem: Option<&[u8]>) -> String {
    let addr = chains::script_to_address(c, spk).unwrap().1;
    amts.iter().enumerate().map(|(i, &a)| {
        let t = Transaction { version: Version::ONE, lock_time: LockTime::ZERO,
            input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::from_bytes(vec![1, i as u8 + 1]), sequence: Sequence::MAX, witness: Witness::new() }],
            output: vec![TxOut { value: Amount::from_sat(a), script_pubkey: ScriptBuf::from_bytes(spk.to_vec()) }] };
        let r = redeem.map(|r| format!(",\"redeem_script\":\"{}\"", blocktools_core::hex_enc(r))).unwrap_or_default();
        format!("{{\"txid\":\"{}\",\"vout\":0,\"amount\":{a},\"address\":\"{addr}\",\"prev_tx\":\"{}\"{r}}}\n", digest::txid_hex(&t, digest::Digest::for_chain(c)), blocktools_core::hex_enc(bitcoin::consensus::serialize(&t)))
    }).collect()
}

/// Build, sign, return (estimated vsize, true vsize, fee, psbt).
fn run(chain: &str, spk: &[u8], redeem: Option<&[u8]>, to: &str, change: &str, rate: u64, n_in: usize) -> (u64, u64, u64, Psbt, Transaction) {
    let c = chains::chain(chain).unwrap();
    let amts: Vec<u64> = (0..n_in).map(|i| 3_000_000 + i as u64).collect();
    let send = 3_000_000 * n_in as u64 - 2_000_000;
    let v = blocktools::psbtmemo::build(chain, &lines(c, spk, &amts, redeem), to, Some(send), Some(change), rate, b"=:THOR.RUNE:thor1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq").unwrap();
    let mut p = Psbt::deserialize(&blocktools_core::b64::decode(v["psbt"].as_str().unwrap()).unwrap()).unwrap();
    let (sk, _) = key(1);
    let n = match c.sign { chains::Sign::ForkId(f) => sign::sign_psbt_forkid(&mut p, &[sk], f, false).unwrap(), _ => sign::sign_psbt_digest(&mut p, &[sk], digest::Digest::for_chain(c)).unwrap() };
    assert_eq!(n, n_in);
    let tx = sign::extract(&p).unwrap();
    (v["vsize"].as_u64().unwrap(), tx.vsize() as u64, v["fee"].as_str().unwrap().parse().unwrap(), p, tx)
}

#[test]
fn measure() {
    let (_, h1) = key(1); let (_, h2) = key(2);
    let mut rows = vec![];
    for chain in ["ltc", "doge", "bch"] {
        let c = chains::chain(chain).unwrap();
        let vault = if chain == "bch" { blocktools_core::cashaddr::encode("bitcoincash", 0, &h2).unwrap() } else { chains::script_to_address(c, &p2pkh(&h2)).unwrap().1 };
        let change = chains::script_to_address(c, &p2pkh(&h1)).unwrap().1;
        let mut kinds: Vec<(&str, Vec<u8>, Option<Vec<u8>>)> = vec![("p2pkh", p2pkh(&h1), None)];
        if chain == "ltc" { kinds.push(("p2wpkh", p2wpkh(&h1), None)); let (s, r) = p2sh_p2wpkh(&h1); kinds.push(("p2sh-p2wpkh", s, Some(r))); }
        for (k, spk, r) in &kinds { for n in [1usize, 3] {
            let (est, real, fee, p, tx) = run(chain, spk, r.as_deref(), &vault, &change, 10, n);
            let t = &p.unsigned_tx;
            assert!(t.input.iter().all(|i| i.sequence.0 == 0xffff_ffff), "non-RBF");
            assert_eq!(t.output[0].script_pubkey.as_bytes(), chains::address_to_script(c, &vault).unwrap().as_slice());
            assert_eq!(t.output[1].script_pubkey.as_bytes(), p2pkh(&h1).as_slice());
            assert_eq!(t.output.last().unwrap().script_pubkey.as_bytes()[0], 0x6a);
            assert!(est >= real && est - real <= 2 * n as u64, "{chain} {k} in={n}: estimate {est} vs signed {real}");
            rows.push(format!("{chain} {k} in={n} est_vb={est} real_vb={real} real_bytes={} fee={fee}", bitcoin::consensus::serialize(&tx).len()));
        } }
    }
    for r in &rows { eprintln!("MEASURE {r}") }
}

/// Per-chain policy measured on the pinned regtest nodes (scripts/e2e.d/memo-regtest.sh):
/// P2PKH dust LTC 5460, DOGE 1_000_000 (wallet floor; node hard floor 100_000), BCH 546;
/// OP_RETURN data max LTC/DOGE 80 bytes, BCH 220. The builder never emits sub-dust change and
/// refuses memos the chain would not relay.
#[test]
fn chain_dust_and_memo_limits() {
    let (_, h1) = key(1); let (_, h2) = key(2);
    for (chain, dust, max) in [("ltc", 5460u64, 80usize), ("doge", 1_000_000, 80), ("bch", 546, 220), ("btc", 546, 80)] {
        let c = chains::chain(chain).unwrap();
        let to = chains::script_to_address(c, &p2pkh(&h2)).unwrap().1; let ch = chains::script_to_address(c, &p2pkh(&h1)).unwrap().1;
        let u = lines(c, &p2pkh(&h1), &[10_000_000], None);
        assert!(blocktools::psbtmemo::build(chain, &u, &to, Some(5_000_000), Some(&ch), 1, &vec![b'm'; max]).is_ok(), "{chain} {max}-byte memo");
        assert_eq!(blocktools::psbtmemo::build(chain, &u, &to, Some(5_000_000), Some(&ch), 1, &vec![b'm'; max + 1]).unwrap_err(), "memo_length", "{chain}");
        // change just under the chain's dust folds into the fee instead of a non-relayable output
        assert!(blocktools::psbtmemo::build(chain, &u, &to, Some(dust - 1), Some(&ch), 1, b"m").unwrap_err().contains("dust"), "{chain}: send below dust");
        assert!(blocktools::psbtmemo::build(chain, &u, &to, Some(dust), Some(&ch), 1, b"m").is_ok(), "{chain}: send at dust");
        let probe = 10_000_000 - dust + 1 - 300; // leaves change ~dust-1 after a ~300 vB fee at 1/vB
        let v = blocktools::psbtmemo::build(chain, &u, &to, Some(probe), Some(&ch), 1, b"m").unwrap();
        for o in v["outputs"].as_array().unwrap() { let x: u64 = o["value"].as_str().unwrap().parse().unwrap(); assert!(x == 0 || x >= dust, "{chain}: output {x} below dust {dust}") }
    }
}

/// THORChain BCH vault as served by /thorchain/inbound_addresses (prefixless CashAddr, read live 2026-10-27).
#[test]
fn bch_vault_cashaddr_forms() {
    use blocktools::cashaddr::{address_to_script, to_legacy};
    let v = "qrs928gzftvvlm0ukyuu3hwx90jadhz66y3f968clg";
    let legacy = to_legacy(v).unwrap();
    let a = address_to_script("bch", v).unwrap();
    assert_eq!(a, address_to_script("bch", &format!("bitcoincash:{v}")).unwrap());
    assert_eq!(a, address_to_script("bch", &legacy).unwrap());
    assert_eq!(&a[..3], &[0x76, 0xa9, 0x14]);
    println!("legacy {legacy}");
}
