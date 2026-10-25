//! Per-coin fee-warning limits: the same 0.05-coin fee warns on BTC but not on DGB/RVN/QTUM.
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
