//! Known-answer tests on PUBLIC transactions only: Bitcoin block 170, the BIP-174 test
//! vectors, the EIP-155 example (public test key 0x46..46), and EIP-1559 txs produced by the
//! independent eth-account Python library with that same public key.
use blocktools_tx::evm::{self, Tx};
use blocktools_tx::{decode, decode_bytes};

const EIP155_SIGNED: &str = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
const E1559_ETH: &str = "02f873010984773594008506fc23ac00825208943535353535353535353535353535353535353535880de0b6b3a764000080c080a02b03b67e070f45175ce9d07c4512720168bd468a24edb6997977a53d48c87a12a0733d775fdd689d306e08ac8ab399f34b5a0253b47ed81b8bf2d2a6ea607fcac7";
const E1559_ERC20: &str = "02f8b28189808506fc23ac0085174876e80082fde8942791bca1f2de4661ed88a30c99a7a9449aa8417480b844a9059cbb000000000000000000000000353535353535353535353535353535353535353500000000000000000000000000000000000000000000000000000000000f4240c001a00b680ddc04089de962005498e7315b5c0417988270f426d7e766432f3b8c92f1a04870483a2ce3a985cde71917cb97811deb5e6e53ac9d907d3901f21cf298cc0e";
const SENDER: &str = "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F";
#[cfg(feature = "secrets")]
fn test_key() -> secp256k1::SecretKey { secp256k1::SecretKey::from_slice(&[0x46; 32]).unwrap() }
fn h(s: &str) -> Vec<u8> { blocktools_core::hex_dec(s).unwrap() }

#[test] fn eip155_example() {
    let t = Tx::parse(&h(EIP155_SIGNED)).unwrap();
    assert_eq!((t.chain_id, t.nonce, t.gas, t.max_fee_per_gas, t.value), (Some(1), 9, 21000, 20_000_000_000, 1_000_000_000_000_000_000));
    // signing hash from the EIP-155 text
    assert_eq!(blocktools_core::hex_enc(t.sighash()), "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53");
    let d = decode(EIP155_SIGNED, "btc").unwrap();
    assert_eq!(d.inputs[0].address.as_deref(), Some(SENDER));
    assert!(d.signed && d.warnings.is_empty(), "{:?}", d.warnings);
    // re-signing the unsigned form reproduces the exact signed bytes (RFC6979)
    #[allow(unused_mut)]
    let mut u = Tx::parse(&t.encode_unsigned()).unwrap();
    assert!(u.sig.is_none());
    #[cfg(feature = "secrets")] {
        u.sign(&test_key()).unwrap();
        assert_eq!(blocktools_core::hex_enc(u.encode_signed().unwrap()), EIP155_SIGNED);
    }
}
#[test] fn eip1559_cross_checked_with_eth_account() {
    for (raw, cid) in [(E1559_ETH, 1), (E1559_ERC20, 137)] {
        let t = Tx::parse(&h(raw)).unwrap();
        assert_eq!(t.chain_id, Some(cid));
        assert_eq!(decode(raw, "btc").unwrap().inputs[0].address.as_deref(), Some(SENDER));
        #[cfg(feature = "secrets")] {
            let mut u = Tx::parse(&t.encode_unsigned()).unwrap();
            u.sign(&test_key()).unwrap();
            assert_eq!(blocktools_core::hex_enc(u.encode_signed().unwrap()), raw);
        }
    }
    let d = decode(E1559_ERC20, "btc").unwrap();
    let j = &d.json_lines()[0];
    assert_eq!(j["selector"], "transfer");
    assert_eq!(j["token_to"], "0x3535353535353535353535353535353535353535");
    assert_eq!(j["token_amount"], "1000000");
    assert_eq!(j["token"], "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174");
    assert!(d.text().contains("Polygon"));
}
#[test] fn evm_warnings_and_rejects() {
    let mut t = Tx::parse(&h(EIP155_SIGNED)).unwrap();
    t.sig = None; t.chain_id = None;
    let d = decode_bytes(&t.encode_unsigned(), "btc").unwrap();
    assert!(d.warnings.contains(&"no_chain_id") && d.warnings.contains(&"unsigned"));
    #[cfg(feature = "secrets")]
    assert_eq!(t.sign(&test_key()), Err("refuse_no_chain_id"));
    t.chain_id = Some(1); t.data = evm::transfer_calldata(&[0x35; 20], 5);
    t.data[..4].copy_from_slice(&evm::APPROVE); t.data[36..].fill(0xff);
    assert!(decode_bytes(&t.encode_unsigned(), "btc").unwrap().warnings.contains(&"unlimited_approve"));
    for bad in ["01c0", "02c0", "f8", "c3010203ff", ""] { assert!(decode(bad, "btc").is_err(), "{bad}") }
    assert_eq!(evm::dec(&[0xff; 32]), "115792089237316195423570985008687907853269984665640564039457584007913129639935");
}
#[test] fn block_170() {
    let d = decode(include_str!("vectors/block170.hex"), "btc").unwrap();
    assert_eq!(d.txid.as_deref(), Some("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16"));
    let o: Vec<_> = d.outputs.iter().map(|o| (o.address.clone().unwrap(), o.amount.unwrap())).collect();
    assert_eq!(o, [("1Q2TWHE3GMdB6BZKafqwxXtWAWgFt5Jvm3".into(), 1_000_000_000), ("12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S".into(), 4_000_000_000)]);
    assert!(d.signed && d.fee.is_none() && d.warnings.contains(&"input_amounts_unknown"));
}
#[test] fn bip174_vectors() {
    for l in include_str!("vectors/bip174-invalid.b64").lines() { assert!(decode(l, "btc").is_err(), "{l}") }
    let v: Vec<_> = include_str!("vectors/bip174-valid.b64").lines().map(|l| decode(l, "btc").unwrap()).collect();
    assert_eq!(v.len(), 10);
    // "one P2PKH input and one P2SH-P2WPKH input both with non-final scriptSigs ... Outputs filled"
    let d = &v[3];
    assert_eq!(d.ty, "psbt");
    assert_eq!(d.fee, Some(90341));
    assert_eq!(d.outputs.len(), 2);
    assert!(!d.signed);
    for d in &v[8..] { assert!(d.warnings.contains(&"no_inputs_or_outputs") && !d.signed) }
}
#[test] fn base64_hex_json_equivalent() {
    let b64 = include_str!("vectors/bip174-valid.b64").lines().nth(3).unwrap();
    let raw = blocktools_core::b64::decode(b64).unwrap();
    let a = decode(b64, "btc").unwrap().json_lines();
    assert_eq!(a, decode(&blocktools_core::hex_enc(&raw), "btc").unwrap().json_lines());
    assert_eq!(a, decode(&format!("{{\"psbt\":\"{b64}\"}}"), "btc").unwrap().json_lines());
}
