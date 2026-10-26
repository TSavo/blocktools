//! Trust Wallet Core EVM signer vectors (rust/tw_evm/tests/signer.rs, Apache-2.0, public test keys),
//! vendored as vectors/twc-evm.json: legacy EIP-155 and EIP-1559 txs for native, ERC-20 transfer /
//! approve, ERC-721 / ERC-1155 transfer, contract creation and an access list. Each signed tx must
//! parse, recover to its key's address, and re-sign byte for byte (RFC 6979, low-s) from its
//! unsigned form. EIP-2930 (type 1) and EIP-7702 (type 4) have no vector here and stay refused.
use blocktools_tx::evm::{Kind, Tx};
use secp256k1::{Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
fn h(s: &str) -> Vec<u8> { blocktools_core::hex_dec(s).unwrap() }

#[test]
fn twc_evm_vectors_resign_byte_exact() {
    let v: serde_json::Value = serde_json::from_str(include_str!("vectors/twc-evm.json")).unwrap();
    let (mut legacy, mut typed) = (0, 0);
    for x in v["vectors"].as_array().unwrap() {
        let name = x["test"].as_str().unwrap();
        let signed = x["signed"].as_str().unwrap();
        let sk = SecretKey::from_slice(&h(x["key"].as_str().unwrap())).unwrap();
        let pk = sk.public_key(&Secp256k1::new()).serialize_uncompressed();
        let addr: [u8; 20] = Keccak256::digest(&pk[1..])[12..].try_into().unwrap();
        let t = Tx::parse(&h(signed)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(t.from(), Some(addr), "{name}: sender");
        assert_eq!(blocktools_core::hex_enc(t.encode_signed().unwrap()), signed, "{name}: round trip");
        let mut u = t.clone(); u.sig = None;
        let mut u = Tx::parse(&u.encode_unsigned()).unwrap();
        assert!(u.sig.is_none(), "{name}: unsigned form parses as unsigned");
        u.sign(&sk).unwrap();
        assert_eq!(blocktools_core::hex_enc(u.encode_signed().unwrap()), signed, "{name}: re-sign");
        let mut bad = t.clone(); bad.nonce += 1;
        assert_ne!(bad.from(), Some(addr), "{name}: tampered nonce must not recover the signer");
        if t.kind == Kind::Legacy { legacy += 1 } else { typed += 1 }
    }
    eprintln!("twc evm vectors: {legacy} legacy, {typed} eip-1559");
    assert_eq!((legacy, typed), (7, 6));
}

#[test]
fn untyped_envelopes_without_vectors_refused() {
    assert_eq!(Tx::parse(&h("01c0")), Err("eip2930_unsupported"));
    assert_eq!(Tx::parse(&h("04c0")), Err("eip7702_unsupported"));
    assert_eq!(Tx::parse(&h("03c0")), Err("eip4844_unsupported"));
}
