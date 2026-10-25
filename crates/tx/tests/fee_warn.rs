//! Per-coin fee-warning limits: the same 0.05-coin fee warns on BTC but not on DGB/RVN/QTUM.
mod common;
use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::psbt::Psbt;

fn psbt_bytes(fee: u64) -> Vec<u8> {
    let spk = ScriptBuf::from_hex("76a914000102030405060708090a0b0c0d0e0f1011121388ac").unwrap();
    let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }],
        output: vec![TxOut { value: Amount::from_sat(100_000_000_000 - fee), script_pubkey: spk.clone() }] };
    let mut p = Psbt::from_unsigned_tx(tx).unwrap();
    p.inputs[0].witness_utxo = Some(TxOut { value: Amount::from_sat(100_000_000_000), script_pubkey: spk });
    p.serialize()
}
fn warns(chain: &str, fee: u64) -> Vec<&'static str> { blocktools_tx::decode_bytes(&psbt_bytes(fee), chain).unwrap().warnings }

#[test]
fn per_coin_fee_limits() {
    assert!(warns("btc", 5_000_000).contains(&"high_fee"));
    for c in ["dgb", "rvn", "qtum"] { assert!(!warns(c, 5_000_000).contains(&"high_fee"), "{c}") }
    assert!(warns("dgb", 50_000_000).contains(&"high_fee"));
    // XPM: a typical 0.448 XPM fee (measured median) must not warn; 30 XPM must.
    assert!(!warns("xpm", 44_800_000).contains(&"high_fee"));
    assert!(warns("xpm", 3_000_000_000).contains(&"high_fee"));
    // Rate limit: 2,000,000 on a ~170 vB tx is > 500 sat/vB (btc) but < 20,000 (rvn).
    assert!(warns("btc", 2_000_000).contains(&"high_fee_rate"));
    assert!(!warns("rvn", 2_000_000).contains(&"high_fee_rate"));
}
#[test]
fn fee_table_rows_are_chains() {
    for (n, f) in blocktools_core::chains::FEE_WARN { assert!(blocktools_core::chains::chain(n).is_some(), "{n}"); assert!(f.fee >= 1_000_000 && f.rate >= 500) }
    assert_eq!(blocktools_core::chains::fee_warn("ltc"), blocktools_core::chains::FEE_WARN_DEFAULT);
}

fn psbt_n(n: usize, fee: u64) -> Vec<u8> {
    let spk = ScriptBuf::from_hex("76a914000102030405060708090a0b0c0d0e0f1011121388ac").unwrap();
    let ins = (0..n).map(|i| TxIn { previous_output: OutPoint { txid: bitcoin::Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros()), vout: i as u32 }, script_sig: ScriptBuf::new(), sequence: Sequence::MAX, witness: Witness::new() }).collect();
    let tx = Transaction { version: Version::TWO, lock_time: LockTime::ZERO, input: ins,
        output: vec![TxOut { value: Amount::from_sat(n as u64 * 100_000_000_000 - fee), script_pubkey: spk.clone() }] };
    let mut p = Psbt::from_unsigned_tx(tx).unwrap();
    for i in &mut p.inputs { i.witness_utxo = Some(TxOut { value: Amount::from_sat(100_000_000_000), script_pubkey: spk.clone() }) }
    p.serialize()
}

/// SwapChan: a 147-input VTC sweep at the measured rate paid 2.6M (limit was a flat 2M).
#[test]
fn absolute_limit_scales_with_size() {
    let d = blocktools_tx::decode_bytes(&psbt_n(147, 2_600_000), "vtc").unwrap();
    assert!(d.vsize.unwrap() > 21_000, "{:?}", d.vsize);
    assert!(!d.warnings.contains(&"high_fee"), "{:?}", d.warnings);
    assert!(blocktools_tx::decode_bytes(&psbt_n(1, 2_600_000), "vtc").unwrap().warnings.contains(&"high_fee"));
    let fw = blocktools_core::chains::fee_warn("vtc");
    assert_eq!((fw.fee_for(1), fw.fee_for(1000), fw.fee_for(1001)), (fw.fee, fw.fee, 2 * fw.fee));
}

/// SwapChan: XPM's measured median is 100312 sat/B, but build_btc capped at 2000.
#[test]
fn rate_cap_is_per_coin() {
    use blocktools_core::chains::{self, fee_warn};
    use blocktools_tx::build;
    assert_eq!(fee_warn("btc").rate_cap(), 2000);
    assert!(fee_warn("xpm").rate_cap() >= 4 * 100_312);
    let c = chains::chain("xpm").unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_slice(&<Vec<u8> as bitcoin::hex::FromHex>::from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()).unwrap();
    let a = chains::pub_rows(c, "", &pk, false).into_iter().find(|r| r.kind == "p2pkh").unwrap().address;
    let u = build::parse_utxos(c, &common::line(c, 0, 5_000_000_000, &a)).unwrap();
    let plan = |r| build::BtcPlan { to: a.clone(), send: None, change: None, fee_rate: r, rbf: false, dust: 546, op_return: None, locktime: 0 };
    assert!(build::build_btc(c, u.clone(), &plan(100_312)).is_ok());
    assert!(build::build_btc(c, u.clone(), &plan(fee_warn("xpm").rate_cap() + 1)).is_err());
    assert!(build::build_btc(chains::chain("btc").unwrap(), vec![], &plan(2001)).unwrap_err().contains("1..2000"));
}

/// SwapChan item 4: a tx paying the measured median rate (and MONA's 100 sat/vB wallet mode,
/// and SwapChan's 220) raises no fee warning; 30 x the median does.
#[test]
fn measured_rows_doge_ftc_mona() {
    let vs = blocktools_tx::decode_bytes(&psbt_n(1, 1000), "doge").unwrap().vsize.unwrap();
    let w = |c: &str, rate: u64| blocktools_tx::decode_bytes(&psbt_n(1, rate * vs), c).unwrap().warnings;
    for (c, r) in [("doge", 60_463), ("doge", 1000), ("ftc", 2000), ("mona", 3), ("mona", 100), ("mona", 220)] {
        let x = w(c, r); assert!(!x.contains(&"high_fee") && !x.contains(&"high_fee_rate"), "{c} {r} {x:?}");
    }
    for (c, r) in [("doge", 30 * 60_463), ("ftc", 30 * 2000), ("mona", 3000)] { assert!(w(c, r).contains(&"high_fee_rate"), "{c}") }
}
