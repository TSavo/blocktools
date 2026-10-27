//! tx-decode's EVM view (evm_decode): every envelope type, the 4844 network form, pre-EIP-155 legacy,
//! and the guarantee that the legacy/1559 summary keys are unchanged (additive only).
use blocktools_tx::{decode, decode_evm_view, evm_decode};
use sha3::{Digest, Keccak256};

fn fixture(name: &str) -> Vec<u8> {
    let p = format!("{}/../../fixtures/evm-mainnet/{name}.raw.json", env!("CARGO_MANIFEST_DIR"));
    let j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    blocktools_core::hex_dec(j["result"].as_str().unwrap()).unwrap()
}

#[test]
fn every_type_hashes_to_keccak_of_its_bytes_and_recovers_a_sender() {
    for (n, t) in [("legacy", 0), ("eip2930", 1), ("eip1559", 2), ("eip4844", 3), ("eip7702", 4)] {
        let b = fixture(n);
        let v = evm_decode::parse(&b).unwrap();
        assert_eq!(v.tx_type, t, "{n}");
        assert_eq!(v.hash.unwrap(), <[u8; 32]>::from(Keccak256::digest(&b)), "{n}");
        assert!(v.from.is_some(), "{n}");
    }
}

#[test]
fn legacy_and_1559_summary_keys_are_a_superset_of_the_old_shape() {
    for n in ["legacy", "eip1559"] {
        let b = fixture(n);
        let old = decode(&blocktools_core::hex_enc(&b), "btc").unwrap().json_lines();
        let (d, _) = decode_evm_view(&b).unwrap();
        let new = d.json_lines();
        assert_eq!(old, new, "{n}: the shared summary must not change; extras are merged by tx-decode only");
    }
}

#[test]
fn eip4844_network_form_unwraps_to_the_canonical_hash() {
    let b = fixture("eip4844");
    let body = blocktools_tx::rlp::decode(&b[1..]).unwrap();
    let e = blocktools_tx::rlp::Rlp::L(vec![]);
    let mut w = vec![3u8];
    w.extend(blocktools_tx::rlp::encode(&blocktools_tx::rlp::Rlp::L(vec![body, e.clone(), e.clone(), e])));
    let (a, n) = (evm_decode::parse(&b).unwrap(), evm_decode::parse(&w).unwrap());
    assert_eq!(a.hash, n.hash); assert_eq!(a.from, n.from); assert_eq!(n.blobs, Some(0)); assert_eq!(a.blobs, None);
}

#[test]
fn pre_eip155_legacy_recovers_the_known_signer() {
    // The public "Nick's method" CREATE2 factory deployment (mainnet tx 0xeddf9e61…3d26), v = 27, no chain id.
    let r = "f8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222";
    let (d, v) = decode_evm_view(&blocktools_core::hex_dec(r).unwrap()).unwrap();
    assert_eq!(d.inputs[0].address.as_deref(), Some("0x3fAB184622Dc19b6109349B94811493BF2a45362"));
    assert_eq!(d.txid.as_deref(), Some("0xeddf9e61fb9d8f5111840daef55e5fde0041f5702856532cdbb5a02998033d26"));
    assert_eq!(v.chain_id, None); assert!(d.warnings.contains(&"no_chain_id"));
}

#[test]
fn unsigned_typed_txs_decode_without_sender_or_hash() {
    // unsigned type 1: [chainId=1, nonce=0, gasPrice=1, gas=21000, to, value=1, data, accessList]
    let mut f = vec![blocktools_tx::rlp::uint(1), blocktools_tx::rlp::uint(0), blocktools_tx::rlp::uint(1), blocktools_tx::rlp::uint(21000),
        blocktools_tx::rlp::Rlp::B(vec![0x35; 20]), blocktools_tx::rlp::uint(1), blocktools_tx::rlp::Rlp::B(vec![]), blocktools_tx::rlp::Rlp::L(vec![])];
    let mut b = vec![1u8]; b.extend(blocktools_tx::rlp::encode(&blocktools_tx::rlp::Rlp::L(f.clone())));
    let (d, v) = decode_evm_view(&b).unwrap();
    assert_eq!((d.ty, d.signed, v.hash, v.from), ("evm-2930", false, None, None));
    assert!(d.warnings.contains(&"unsigned"));
    f.pop(); let mut b = vec![1u8]; b.extend(blocktools_tx::rlp::encode(&blocktools_tx::rlp::Rlp::L(f)));
    assert_eq!(evm_decode::parse(&b).err(), Some("bad_field_count"));
}

#[test]
fn signing_paths_still_refuse_the_types_only_decode_reads() {
    for (n, e) in [("eip2930", "eip2930_unsupported"), ("eip4844", "eip4844_unsupported"), ("eip7702", "eip7702_unsupported")] {
        assert_eq!(blocktools_tx::evm::Tx::parse(&fixture(n)).err(), Some(e), "{n}");
    }
}

#[test]
fn utxo_bytes_are_not_evm() {
    assert!(!evm_decode::is_evm(&[0x01, 0, 0, 0, 0x01])); assert!(!evm_decode::is_evm(&[0x02, 0, 0, 0]));
    assert!(evm_decode::is_evm(&[0x02, 0xc0])); assert!(evm_decode::is_evm(&[0xc0]));
}
