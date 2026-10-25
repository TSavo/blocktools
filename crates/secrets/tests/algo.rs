//! Algorand KAT: py-algorand-sdk tests/unit_tests/test_transaction.py (public test mnemonic
//! "advice pudding ..."; its account 47YPQ... appears in the same suite and was re-derived with
//! py-algorand-sdk 2.12.0). Secrets stay in-test.
#![cfg(all(feature = "algo", feature = "ed25519"))]
use blocktools_core::chains;
const M: &str = "advice pudding treat near rule blouse same whisper inner electric quit surface sunny dismiss leader blood seat clown cost exist hospital century reform able sponsor";
const A: &str = "47YPQTIGQEO7T4Y4RWDYWEKV6RTR2UNBQXBABEEGM72ESWDQNCQ52OPASU";

#[test] fn sdk_mnemonic_address() {
    let k = chains::algo_mnemonic_key(M).unwrap();
    let r = chains::algo_row("", &k);
    assert_eq!(r.address, A);
    assert_eq!(blocktools_core::b64::decode(&r.secret).unwrap().len(), 64);
    let rows = blocktools_secrets::keys::rows_for(chains::chain("algo").unwrap(), &k, None);
    assert_eq!(rows[0].address, A);
}
#[test] fn checksum_and_validate() {
    let bad = M.replace("sponsor", "abandon");
    assert!(chains::algo_mnemonic_key(&bad).is_err());
    assert!(chains::algo_mnemonic_key(&M.replace("advice", "adviec")).is_err());
    assert!(blocktools_core::validate::validate("algo", A).is_ok());
    assert!(blocktools_core::validate::validate("algo", &A.replace("ASU", "ASV")).is_err());
    assert!(blocktools_core::validate::validate("algo", "PNWOET7LLOWMBMLE4KOCELCX6X3D3Q4H2Q4QJASYIEOF7YIPPQBG3YQ5YI").is_ok());
}
