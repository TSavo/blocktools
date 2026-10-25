//! Known-answer tests through the facade with default features (public data only).
use blocktools::{chains, validate, xpub};

// BIP84 test vector account 0 xpub (zpub converted to xpub form is not needed: from_xpub takes
// the account-level xpub used in crates/core/src/xpub.rs tests).
#[test]
fn facade_xpub_and_validate() {
    let btc = chains::chain("btc").unwrap();
    let x = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
    let rows = xpub::from_xpub(x, btc, &["p2wpkh"], &[0], &[0, 1]).unwrap();
    assert_eq!(rows[0].address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert_eq!(rows[1].address, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
    for r in &rows { assert!(validate::validate("btc", &r.address).is_ok()) }
}
