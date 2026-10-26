//! Trust Wallet Core message-signer vectors (rust/tw_evm/tests/message_signer.rs,
//! tests/chains/Bitcoin/MessageSignerTests.cpp @ adf80f8b). Sign byte-exact, recover, refuse.
use blocktools_tx::message::*;
fn h(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
fn sk(s: &str) -> secp256k1::SecretKey { secp256k1::SecretKey::from_slice(&h(s)).unwrap() }
const IMX: &str = "Only sign this request if you\u{2019}ve initiated an action with Immutable X.\n\nFor internal use:\nbd717ba31dca6e0f3f136f7c4197babce5f09a9f25176044c0b3112b1b6017a3";

#[test]
fn twc_eth_personal_sign_vectors() {
    let cases: [(&str, Vec<u8>, EthV, &str); 4] = [
        ("03a9ca895dca1623c7dfd69693f7b4111f5d819d2e145536e0b03c136025a25d", b"Foo".to_vec(), EthV::Legacy, "21a779d499957e7fd39392d49a079679009e60e492d9654a148829be43d2490736ec72bc4a5644047d979c3cf4ebe2c1c514044cf436b063cb89fc6676be71101b"),
        ("9066aa168c379a403becb235c15e7129c133c244e56a757ab07bc369288bcab0", h("c0a96273d5c3fbe4d4000491f08daef9c17f88df846c1d6f57eb5f33c1fbd035"), EthV::Legacy, "b18a666ad08bf9bfcd39920b26b5a5d1486b67b45119810b3c7bda22e41e5c4c1bfbe0c932f6c14df4947a18ba310831a37b7307d724a3ac2a4935b99d7075141b"),
        ("03a9ca895dca1623c7dfd69693f7b4111f5d819d2e145536e0b03c136025a25d", b"Foo".to_vec(), EthV::Eip155(0), "21a779d499957e7fd39392d49a079679009e60e492d9654a148829be43d2490736ec72bc4a5644047d979c3cf4ebe2c1c514044cf436b063cb89fc6676be711023"),
        ("3b0a61f46fdae924007146eacb6db6642de7a5603ad843ec58e10331d89d4b84", IMX.as_bytes().to_vec(), EthV::Raw, "32cd5a58f3419fc5db672e3d57f76199b853eda0856d491b38f557b629b0a0814ace689412bf354a1af81126d2749207dffae8ae8845160f33948a6b787e17ee01"),
    ];
    let secp = secp256k1::Secp256k1::new();
    for (k, m, v, sig) in cases {
        let k = sk(k);
        assert_eq!(hex(&eth_sign(&m, &k, v)), sig);
        let (addr, kind) = eth_recover(&m, &h(sig)).unwrap();
        assert_eq!(addr, blocktools_core::eth_address(&k, &secp)); assert_eq!(kind, v);
        let mut bad = m.clone(); bad.push(b'!');
        assert_ne!(eth_recover(&bad, &h(sig)).map(|x| x.0).ok(), Some(addr));
    }
    // legacy_hex: the hex form of a 32-byte value is signed as bytes by TWC; we verify it but refuse to sign it blind
    assert_eq!(sign_refusal(&h("c0a96273d5c3fbe4d4000491f08daef9c17f88df846c1d6f57eb5f33c1fbd035"), true), Some("blind_hash_message"));
    assert_eq!(sign_refusal(b"0xc0a96273d5c3fbe4d4000491f08daef9c17f88df846c1d6f57eb5f33c1fbd035", false), Some("blind_hash_message"));
    assert_eq!(sign_refusal(b"Foo", false), None);
    assert_eq!(eth_recover(b"Foo", &h("21a779d4")).unwrap_err(), "signature_not_65_bytes");
}
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }

#[test]
fn twc_btc_signmessage_vectors() {
    assert_eq!(hex(&btc_hash(b"Hello, world!")), "02d6c0643e40b0db549cbbd7eb47dcab71a59d7017199ebde6b272f28fbbf95f");
    assert_eq!(hex(&btc_hash(b"test signature")), "8e81cc5bca9862d8b7f22be1f7cb762b49121cf4e1611c27906a041f9a9eb21f");
    let k = sk("afeefca74d9a325cf1d6b6911d61a65c32afa8e02bd5e78e2e4ac2910bab45f5");
    for (m, c, sig) in [
        ("test signature", true, "ILH5K7JQLaRGaKGXXH5mYM6FIIy9IWyY4JUPI+PHYY4WaupxUbg+zy0bhBCrDuehy9x4WidwjkRR1GSLnWvOXBo="),
        ("another text", true, "H7vrF2C+TlFiHyegAw3QLv6SK0myuEEXUOgfx0+Qio1YVDuSa6p/OHpoQVlUt3F8QJdbdZN9M1h/fYEAnEz16V0="),
        ("test signature", false, "HLH5K7JQLaRGaKGXXH5mYM6FIIy9IWyY4JUPI+PHYY4WaupxUbg+zy0bhBCrDuehy9x4WidwjkRR1GSLnWvOXBo="),
    ] { assert_eq!(btc_sign(m.as_bytes(), &k, c), sig, "{m}"); }
    for (a, m, sig) in [
        ("1B8Qea79tsxmn4dTiKKRVvsJpHwL2fMQnr", "test signature", "H+3L5IbSVcejp4S2VwLXCxLEMQAWDvKbE8lQyq0ocdvyM1aoEudkzN/S/qLI3vnNOFY6V13BXWSFrPr3OjGa5Dk="),
        ("1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN", "This is an example of a signed message.", "G39Qf0XrZHICWbz3r5gOkcgTRw3vM4leGjiR3refr/K1OezcKmmXaLn4zc8ji2rjbBUIMrIhH/jc5Z2qEEz7qVk="),
        ("1H8X4u6CVZRTLLNbUQTKAnc5vCkqWMpwfF", "compressed key", "IKUI9v2xbHogJe8HKXI2M5KEhMKaW6fjNxtyEy27Mf+3/e1ht4jZoc85e4F8stPsxt4Xcg8Yr42S28O6L/Qx9fE="),
        ("19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X", "test signature", "ILH5K7JQLaRGaKGXXH5mYM6FIIy9IWyY4JUPI+PHYY4WaupxUbg+zy0bhBCrDuehy9x4WidwjkRR1GSLnWvOXBo="),
        ("19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X", "another text", "H7vrF2C+TlFiHyegAw3QLv6SK0myuEEXUOgfx0+Qio1YVDuSa6p/OHpoQVlUt3F8QJdbdZN9M1h/fYEAnEz16V0="),
        ("1E4T9JZ3mq6cdgiRJEWzHqDXb9t322fE6d", "test signature", "HLH5K7JQLaRGaKGXXH5mYM6FIIy9IWyY4JUPI+PHYY4WaupxUbg+zy0bhBCrDuehy9x4WidwjkRR1GSLnWvOXBo="),
    ] { assert_eq!(btc_recover(m.as_bytes(), sig).unwrap(), a, "{m}"); }
    // TWC negatives: wrong address does not match; short sig; non-legacy address refused
    assert_ne!(btc_recover(b"test signature", "H+3L5IbSVcejp4S2VwLXCxLEMQAWDvKbE8lQyq0ocdvyM1aoEudkzN/S/qLI3vnNOFY6V13BXWSFrPr3OjGa5Dk=").unwrap(), "1HZwkjkeaoZfTSaJxDw6aKkxp45agDiEzN");
    let short = blocktools_core::b64::encode(&h("1fedcbe486d255c7a3a784b65702d70b12c43100160ef29b13c950caad2871dbf23356a812e764ccdfd2fea2c8def9cd38563a575dc15d6485acfaf73a319ae4"));
    assert_eq!(btc_recover(b"test signature", &short).unwrap_err(), "signature_not_65_bytes");
    assert_eq!(detect_chain("bc1qpjult34k9spjfym8hss2jrwjgf0xjf40ze0pp8").unwrap_err(), "address_not_p2pkh");
    assert_eq!(detect_chain("__THIS_IS_NOT_A_VALID_ADDRESS__").unwrap_err(), "unrecognised_address");
    assert_eq!(detect_chain("19cAJn4Ms8jodBBGtroBNNpCZiHAWGAq7X").unwrap(), "btc");
    let a = blocktools_core::eth_address(&sk("9066aa168c379a403becb235c15e7129c133c244e56a757ab07bc369288bcab0"), &secp256k1::Secp256k1::new());
    assert_eq!(detect_chain(&a).unwrap(), "eth"); assert_eq!(detect_chain(&a.to_lowercase()).unwrap(), "eth");
}
