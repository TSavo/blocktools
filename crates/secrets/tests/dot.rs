//! Polkadot KAT: substrate `subkey` documentation vector (public mnemonic "caution juice ...",
//! public key d6a3105d...8746, generic SS58 5Gv8YY...), re-derived with py-sr25519-bindings +
//! py-bip39-bindings; Polkadot (prefix 0) address from the same key. Secrets stay in-test.
#![cfg(feature = "sr25519")]
use blocktools_core::chains;
const M: &str = "caution juice atom organ advance problem want pledge someone senior holiday very";

#[test] fn subkey_vector() {
    let k = chains::substrate_mini_secret(M, "").unwrap();
    let dot = chains::chain("dot").unwrap();
    let r = chains::ss58_row(dot, "", &k);
    let pk = chains::ss58_decode(0, &r.address).unwrap();
    assert_eq!(blocktools_core::hex_enc(&pk), "d6a3105d6768e956e9e5d41050ac29843f98561410d3a47f9dd5b3b227ab8746");
    assert_eq!(chains::ss58_address(42, &pk), "5Gv8YYFu8H1btvmrJy9FjjAWfb99wrhV3uhPFoNEr918utyR");
    assert_eq!(r.address, "15rRgsWxz4H5LTnNGcCFsszfXD8oeAFd8QRsR6MbQE2f6XFF");
    assert!(blocktools_core::validate::validate("dot", &r.address).is_ok());
    assert!(blocktools_core::validate::validate("dot", "5Gv8YYFu8H1btvmrJy9FjjAWfb99wrhV3uhPFoNEr918utyR").is_err());
    assert!(blocktools_core::validate::validate("dot", "15rRgsWxz4H5LTnNGcCFsszfXD8oeAFd8QRsR6MbQE2f6XFG").is_err());
}
