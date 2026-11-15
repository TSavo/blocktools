//! Display names for known EVM chain ids (evm::chain_name / native_symbol).
use blocktools_tx::evm::{self, Kind, Tx};
use blocktools_tx::rlp::Rlp;

#[test]
fn known_evm_chain_names() {
    assert_eq!(evm::chain_name(1), "Ethereum mainnet");
    assert_eq!(evm::chain_name(10), "Optimism");
    assert_eq!(evm::chain_name(56), "BNB Smart Chain");
    assert_eq!(evm::chain_name(137), "Polygon");
    assert_eq!(evm::chain_name(8453), "Base");
    assert_eq!(evm::chain_name(42161), "Arbitrum One");
    assert_eq!(evm::chain_name(43114), "Avalanche C-Chain");
    assert_eq!(evm::chain_name(11155111), "Sepolia testnet");
    assert_eq!(evm::chain_name(17000), "Holesky testnet");
    assert_eq!(evm::chain_name(7777777), "Zora Network");
    assert_eq!(evm::chain_name(999999999), "Zora Sepolia testnet");
    assert_eq!(evm::chain_name(2), "unknown chain");
    assert_eq!(evm::native_symbol(Some(1)), "ETH");
    assert_eq!(evm::native_symbol(Some(7777777)), "ETH");
    assert_eq!(evm::native_symbol(Some(999999999)), "ETH");
    assert_eq!(evm::native_symbol(Some(56)), "BNB");
    assert_eq!(evm::native_symbol(Some(2)), "native");
}

fn unsigned_legacy(chain_id: u64) -> String {
    let tx = Tx {
        kind: Kind::Legacy,
        chain_id: Some(chain_id),
        nonce: 0,
        max_fee_per_gas: 1_000_000_000,
        max_priority_fee_per_gas: None,
        gas: 21_000,
        to: Some([
            0xde, 0xad, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]),
        value: 1,
        data: vec![],
        access_list: Rlp::L(vec![]),
        sig: None,
    };
    tx.encode_unsigned()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn zora_name_appears_in_tx_summary() {
    let d = blocktools_tx::decode(&unsigned_legacy(7777777), "eth").unwrap();
    let t = d.text();
    assert!(t.contains("7777777 = ZORA NETWORK"), "{t}");
    assert!(t.contains("7777777 (Zora Network)"), "{t}");
    assert!(t.contains("NATIVE ETH"), "{t}");
    assert!(!t.to_ascii_lowercase().contains("unknown chain"), "{t}");
}

#[test]
fn zora_sepolia_name_appears_in_tx_summary() {
    let d = blocktools_tx::decode(&unsigned_legacy(999999999), "eth").unwrap();
    let t = d.text();
    assert!(t.contains("999999999 = ZORA SEPOLIA TESTNET"), "{t}");
    assert!(t.contains("999999999 (Zora Sepolia testnet)"), "{t}");
    assert!(t.contains("NATIVE ETH"), "{t}");
}
