//! decode_with_prevtxs: input values and fee from hash-checked previous transactions (mock-bitcoind vectors).
use blocktools_tx::decode_with_prevtxs;
const SPEND: &str = "020000000182828e1ac3748b6ee0093af877a9cc135836e0b5d3295aaf354167392f285dc30000000000fdffffff0168bf000000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000";
const PREV: &str = "0200000001356519a1005d3d7d0e493977e362d17d6655ac57a3acd2ab5c2ec528206786e00000000000fdffffff0150c3000000000000160014751e76e8199196d454941c45d1b3a323f1433bd600000000";
fn h(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
#[test]
fn known_fee_1000_sat() {
    let d = decode_with_prevtxs(&h(SPEND), "btc", &[h(PREV)]).unwrap();
    assert_eq!(d.fee, Some(1000));
    assert_eq!(d.inputs[0].amount, Some(50000));
    assert!(!d.warnings.contains(&"input_amounts_unknown"), "{:?}", d.warnings);
}
#[test]
fn missing_unused_and_bad_prevtx() {
    let d = decode_with_prevtxs(&h(SPEND), "btc", &[]).unwrap();
    assert!(d.warnings.contains(&"prevout_missing") && d.fee.is_none(), "{:?}", d.warnings);
    // a prev tx that is not an input's outpoint (here the spend itself) is refused, not ignored
    assert_eq!(decode_with_prevtxs(&h(SPEND), "btc", &[h(SPEND)]).err(), Some("prevtx_unused"));
    // a forged prev tx with a larger value hashes differently, so it cannot inflate the fee
    let forged = PREV.replace("50c3000000000000", "a086010000000000");
    assert_eq!(decode_with_prevtxs(&h(SPEND), "btc", &[h(&forged)]).err(), Some("prevtx_unused"));
    assert_eq!(decode_with_prevtxs(&h(SPEND), "btc", &[vec![1, 2, 3]]).err(), Some("bad_prevtx"));
}
