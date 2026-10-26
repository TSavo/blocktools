//! finding 3: the EVM summary printed "0 gwei" for gas prices under 1 gwei (integer division by 1e9).
#[test]
fn sub_gwei_gas_price_is_shown_exactly() {
    // unsigned legacy EIP-155 transfer on Base (8453), gasPrice 5_000_000 wei = 0.005 gwei, gas 21000
    let d = blocktools_tx::decode("0xe480834c4b4082520894000000000000000000000000000000000000dead01808221058080", "btc").unwrap();
    let t = d.text();
    assert!(t.contains("x 0.005 gwei)"), "{t}");
    assert!(!t.contains("x 0 gwei)"), "{t}");
}
