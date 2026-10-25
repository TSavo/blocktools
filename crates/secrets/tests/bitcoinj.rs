//! bitcoinj / MultiBit HD on the btcrecover public test wallets (scripts/fetch-fixtures.sh;
//! public test password "btcr-test-password"). Skipped when the fixtures are absent.
//! Independent expectations: the .txt WIF btcrecover ships for the encrypted MultiBit wallet;
//! for the others, the stored public key / HD root key that the module checks against.
#![cfg(feature = "multibit")]
use blocktools_secrets::bitcoinj::{open, Secret};
const PW: &str = "btcr-test-password"; // public test password
fn fx(n: &str) -> Option<Vec<u8>> {
    let p = format!("{}/../../fixtures/external/{n}", env!("CARGO_MANIFEST_DIR"));
    let r = std::fs::read(&p).ok();
    if r.is_none() { assert!(std::env::var("BLOCKTOOLS_REQUIRE_FIXTURES").is_err(), "missing {n}"); eprintln!("skip {n}") }
    r
}
fn wifs(v: &[Secret]) -> Vec<String> { v.iter().filter_map(|s| match s { Secret::Wif(w) => Some(w.to_string()), _ => None }).collect() }
#[test] fn multibit_classic_wallet_matches_txt() {
    let (Some(w), Some(t)) = (fx("multibit.wallet.bitcoinj.encrypted"), fx("multibit.wallet.bitcoinj.encrypted.txt")) else { return };
    let want = String::from_utf8(t).unwrap().split_whitespace().next().unwrap().to_string();
    let got = wifs(&open(&w, PW).unwrap());
    assert!(got.len() == 1 && got[0] == want, "decrypted key differs from the published one");
    assert_eq!(open(&w, "wrong").err(), Some("wrong_password"));
}
#[test] fn bitcoinj_wallets() {
    if let Some(w) = fx("bitcoinj-wallet.wallet") { assert_eq!(wifs(&open(&w, PW).unwrap()).len(), 1); assert_eq!(open(&w, "x").err(), Some("wrong_password")) }
    if let Some(w) = fx("multibit.wallet.bitcoinj.clear") { assert_eq!(wifs(&open(&w, "").unwrap()).len(), 1) }
}
#[test] fn multibit_hd() {
    let Some(w) = fx("mbhd.wallet.aes") else { return };
    let r = open(&w, PW).unwrap();
    assert!(r.len() == 1 && matches!(&r[0], Secret::Master(x) if x.starts_with("xprv")));
    assert_eq!(open(&w, "btcr-test-passwore").err(), Some("wrong_password"));
    assert_eq!(open(&[0u8; 64], PW).err(), Some("wrong_password"));
}
