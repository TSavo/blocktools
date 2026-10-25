//! Stellar SEP-0005 KATs (public test vectors from stellar-protocol ecosystem/sep-0005.md).
//! Secrets are compared in-test only, never printed.
#![cfg(feature = "ed25519")]
use blocktools_core::chains::{self, strkey_decode, xlm_row};

fn seed(m: &str) -> [u8; 64] { bip39::Mnemonic::parse(m).unwrap().to_seed("") }

#[test] fn sep5_vector1() {
    let s = seed("illness spike retreat truth genius clock brain pass fit cave bargain toe");
    for (i, a) in [(0, "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6"), (1, "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX")] {
        let r = xlm_row("", &chains::slip10_ed25519(&s, &[44, 148, i]));
        assert_eq!(r.address, a);
        let (v, p) = strkey_decode(&r.secret).unwrap();
        assert_eq!((v, p.len()), (18 << 3, 32));
        assert!(r.secret.starts_with('S'));
    }
}
#[test] fn strkey_rejects_bad_crc() {
    assert!(strkey_decode("GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6").is_ok());
    assert!(strkey_decode("GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ7").is_err());
    assert!(blocktools_core::validate::validate("xlm", "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX").is_ok());
    assert!(blocktools_core::validate::validate("xlm", "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQA").is_err());
}
