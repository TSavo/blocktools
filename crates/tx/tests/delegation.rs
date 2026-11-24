#[cfg(feature = "secrets")]
#[test]
fn base_sepolia_authorization_matches_eth_account() {
    use blocktools_tx::delegation::Authorization;
    let mut auth = Authorization {
        chain_id: 84532.try_into().unwrap(),
        delegate: [0x11; 20],
        nonce: 0,
    };
    // Public test vector from Python eth_account.Account.sign_authorization.
    let key = secp256k1::SecretKey::from_slice(&[1; 32]).unwrap();
    assert_eq!(
        blocktools_core::hex_enc(&auth.digest().unwrap()),
        "c1e4cc56bf023d91c05c44418f300a5702bd393ca41b9776af0395bc8be82096"
    );
    let (parity, sig) = auth.sign(&key).unwrap();
    assert_eq!(parity, 0);
    assert_eq!(blocktools_core::hex_enc(&sig), "7b6483ad067c60fba7133569b62f8862c01c384f6d9a73aa9941851a979d05ad1f93ac1677caf0023c36569d8ab828cdfb43821f3e49dc662ee834ee15672112");
    auth.nonce = u64::MAX;
    assert!(auth.sign(&key).is_err());
}
