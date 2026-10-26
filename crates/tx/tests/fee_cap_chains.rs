//! Per-chain default UTXO fee cap (policy::default_fee_cap). SwapChan's corpus (35 legitimate
//! sweeps from its test suite, 2026-10-25): 9 were refused by the old flat 100,000-sat cap.
use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use blocktools_tx::policy::{check, verify, Policy};

fn waived() -> Policy { Policy { allow_warnings: true, ..Default::default() } }
fn capped(f: &[&str]) -> bool { f.contains(&"fee_above_cap") }

#[test] fn corpus_all_35_pass_the_default_cap() {
    let (mut n, mut old_refused) = (0, 0);
    for l in include_str!("data/feeprobe-corpus.jsonl").lines() {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        let chain = v["chain"].as_str().unwrap();
        let d = blocktools_tx::decode(v["input"].as_str().unwrap(), chain).unwrap();
        assert_eq!(d.fee.unwrap().to_string(), v["fee"].as_str().unwrap());
        let vd = verify(&d, &Policy::default());
        assert!(!capped(&vd.findings), "{chain} fee {:?} refused, cap {:?}", d.fee, vd.fee_cap);
        assert_eq!(vd.fee_cap.chain, chain);
        if d.fee.unwrap() as u128 > blocktools_tx::policy::DEFAULT_MAX_FEE_SATS { old_refused += 1 }
        n += 1;
    }
    assert_eq!((n, old_refused), (35, 9), "corpus size / sweeps the flat cap refused");
}

fn psbt_n(n: usize, fee: u64) -> Vec<u8> {
    let spk = ScriptBuf::from_hex("76a914000102030405060708090a0b0c0d0e0f1011121388ac").unwrap();
    let ins = (0..n).map(|i| TxIn { previous_output: OutPoint { txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), vout: i as u32 }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }).collect();
    let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: ins,
        output: vec![TxOut { value: Amount::from_sat(n as u64 * 1_000_000_000_000 - fee), script_pubkey: spk.clone() }] };
    let mut p = bitcoin::psbt::Psbt::from_unsigned_tx(tx).unwrap();
    for i in &mut p.inputs { i.witness_utxo = Some(TxOut { value: Amount::from_sat(1_000_000_000_000), script_pubkey: spk.clone() }) }
    p.serialize()
}

/// Every chain whose txs blocktools decodes as PSBT (chain table: UTXO, tx_format buildable, not
/// PoS-nTime/zec layouts): a fee 1 base unit over the cap is refused even with warnings waived,
/// the cap itself passes, explicit max_fee overrides, and the verdict names the chain.
#[test] fn every_buildable_chain_refuses_excessive_fee() {
    let mut tested = Vec::new();
    for c in blocktools_core::chains::CHAINS {
        let (fmt, buildable) = c.tx_format();
        if !buildable || fmt == "pos-ntime" || c.name == "zec" { continue }
        for n in [1usize, 147] {
            let d = blocktools_tx::decode_bytes(&psbt_n(n, 1000), c.name).unwrap_or_else(|e| panic!("{}: {e}", c.name));
            let cap = blocktools_tx::policy::default_fee_cap(&d);
            assert_eq!(cap.chain, c.name);
            assert!(cap.cap >= blocktools_tx::policy::DEFAULT_MAX_FEE_SATS);
            let at = blocktools_tx::decode_bytes(&psbt_n(n, cap.cap as u64), c.name).unwrap();
            assert_eq!(at.vsize, d.vsize);
            assert!(!capped(&check(&at, &waived())), "{} n={n}: fee == cap refused", c.name);
            let over = blocktools_tx::decode_bytes(&psbt_n(n, cap.cap as u64 + 1), c.name).unwrap();
            assert!(capped(&check(&over, &waived())), "{} n={n}: fee cap+1 accepted", c.name);
            // 10x the cap: clearly excessive, refused; an explicit human max_fee lets it through.
            let x10 = blocktools_tx::decode_bytes(&psbt_n(n, cap.cap as u64 * 10), c.name).unwrap();
            assert!(capped(&check(&x10, &waived())), "{}", c.name);
            assert!(!capped(&check(&x10, &Policy { max_fee: Some(cap.cap * 10), ..waived() })), "{}", c.name);
        }
        tested.push(c.name);
    }
    assert!(tested.len() >= 20, "{tested:?}");
    println!("chains tested: {} {:?}", tested.len(), tested);
}

/// BTC behavior kept: 0.0024 BTC on an ordinary 1-input tx is refused with warnings waived.
#[test] fn btc_small_tx_cap_unchanged() {
    let d = blocktools_tx::decode_bytes(&psbt_n(1, 240_000), "btc").unwrap();
    let v = verify(&d, &waived());
    assert!(capped(&v.findings));
    assert_eq!((v.fee_cap.chain.as_str(), v.fee_cap.cap, v.fee_cap.source), ("btc", 100_000, "floor"));
    assert!(!capped(&check(&blocktools_tx::decode_bytes(&psbt_n(1, 2_000), "btc").unwrap(), &waived())));
}

/// The buildable chains the PSBT loop skips (PoS nTime layouts, zec v5): same cap rule, checked on
/// the decoded view the verifier sees (corpus covers their real decode: ppc, rdd, nvc, zec).
#[test] fn pos_and_zec_chains_refuse_excessive_fee() {
    let mut tested = Vec::new();
    // zec is not a CHAINS row (own crate), but its transparent v5 sweep is buildable.
    let pos = blocktools_core::chains::CHAINS.iter().filter(|c| c.tx_format() == ("pos-ntime", true)).map(|c| c.name);
    for name in pos.chain(["zec"]) {
        struct C { name: &'static str } let c = C { name };
        for vsize in [196u64, 21_800] {
            let mk = |fee: u64| blocktools_tx::Decoded { chain: c.name.into(), ty: "pos-ntime", signed: false, txid: None, inputs: vec![], outputs: vec![],
                fee: Some(fee), vsize: Some(vsize), locktime: None, rbf: None, evm: None, warnings: vec![], unproven_inputs: 0 };
            let cap = blocktools_tx::policy::default_fee_cap(&mk(0));
            assert_eq!(cap.chain, c.name);
            assert!(!capped(&check(&mk(cap.cap as u64), &waived())), "{}", c.name);
            assert!(capped(&check(&mk(cap.cap as u64 + 1), &waived())), "{}", c.name);
        }
        tested.push(c.name);
    }
    assert_eq!(tested, ["ppc", "nvc", "clam", "rdd", "zec"]);
    println!("pos/zec chains tested: {} {:?}", tested.len(), tested);
}
