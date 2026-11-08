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

/// Kusama / Polymesh: Trust Wallet Core tests/chains/{Kusama,Polymesh} public-key -> address vectors
/// (SS58 encoding only; TWC's own keys are ed25519, ours are sr25519 from the substrate key, as dot).
#[test] fn twc_ss58_prefixes() {
    let pk = |h: &str| -> [u8; 32] { let v = blocktools_core::hex_dec(h).unwrap(); v.try_into().unwrap() };
    let k = pk("032eb287017c5cde2940b5dd062d413f9d09f8aa44723fc80bf46b96c81ac23d");
    assert_eq!(chains::ss58_address(2, &k), "CeVXtoU4py9e7F6upfM2ZarVave299TjcdaTSxhDDZrYgnM");
    assert!(blocktools_core::validate::validate("ksm", "CeVXtoU4py9e7F6upfM2ZarVave299TjcdaTSxhDDZrYgnM").is_ok());
    assert!(blocktools_core::validate::validate("ksm", "15rRgsWxz4H5LTnNGcCFsszfXD8oeAFd8QRsR6MbQE2f6XFF").is_err());
    let p = pk("beff0e5d6f6e6e6d573d3044f3e2bfb353400375dc281da3337468d4aa527908");
    assert_eq!(chains::ss58_address(12, &p), "2GmLy7KywpsV5fDpZfJMcgGgzoJWyrEA3Wc3fDmsoq5iqtBT");
    let p2 = pk("849e2f6b165d4b28b39ef3d98f86c0520d82bc349536324365c10af08f323f83");
    assert_eq!(chains::ss58_address(12, &p2), "2FSoQykVV3uWe5ChZuazMDHBoaZmCPPuoYx5KHL5VqXooDQW");
    assert!(blocktools_core::validate::validate("polyx", "2E5u4xA1TqswQ3jMJH96zekxwr2itvKu79fDC1mmnVZRh6Uv").is_ok());
    // Same substrate key as the dot row, other prefixes.
    let mk = chains::substrate_mini_secret(M, "").unwrap();
    let r = chains::ss58_row(chains::chain("ksm").unwrap(), "", &mk);
    assert_eq!(chains::ss58_decode(2, &r.address).unwrap(), chains::ss58_decode(0, "15rRgsWxz4H5LTnNGcCFsszfXD8oeAFd8QRsR6MbQE2f6XFF").unwrap());
}

/// Trust Wallet Core ed25519 rows for ksm/polyx (dummy key 0x46×32 and FromPrivateKey hexes)
/// alongside the existing sr25519 row. `derive --explain` uses the TWC registry paths.
#[cfg(feature = "ed25519")]
#[test] fn twc_ss58_ed25519() {
    let dummy = [0x46u8; 32];
    let ksm = chains::chain("ksm").unwrap();
    let polyx = chains::chain("polyx").unwrap();
    let dot = chains::chain("dot").unwrap();
    let r = chains::ss58_ed25519_row(ksm, "", &dummy);
    assert_eq!(r.kind, "ed25519");
    assert_eq!(r.address, "Hy8mqcexg5FMwMYnQvzrUvD723qMxDjMRU9HdNCnTsMAypY");
    assert!(blocktools_core::validate::validate("ksm", &r.address).is_ok());
    let r = chains::ss58_ed25519_row(polyx, "", &dummy);
    assert_eq!(r.address, "2HqjMm2goapWvXQBqjjEdVaTZsUmunWwEq1TSToDR1pDzQ1F");
    assert!(blocktools_core::validate::validate("polyx", &r.address).is_ok());
    let hx = |h: &str| { let v = blocktools_core::hex_dec(h).unwrap(); let mut k = [0u8; 32]; k.copy_from_slice(&v); k };
    // public test vector: TWC tests/chains/Kusama FromPrivateKey
    assert_eq!(chains::ss58_ed25519_row(ksm, "", &hx("a21981f3bb990c40837df44df639541ff57c5e600f9eb4ac00ed8d1f718364e5")).address, "CeVXtoU4py9e7F6upfM2ZarVave299TjcdaTSxhDDZrYgnM");
    // public test vector: TWC tests/chains/Polymesh FromPrivateKey
    assert_eq!(chains::ss58_ed25519_row(polyx, "", &hx("612d82bc053d1b4729057688ecb1ebf62745d817ddd9b595bc822f5f2ba0e41a")).address, "2GmLy7KywpsV5fDpZfJMcgGgzoJWyrEA3Wc3fDmsoq5iqtBT");
    let rows = blocktools_secrets::keys::rows_for(ksm, &dummy, None);
    assert!(rows.iter().any(|r| r.kind == "sr25519"));
    assert!(rows.iter().any(|r| r.kind == "ed25519" && r.address == "Hy8mqcexg5FMwMYnQvzrUvD723qMxDjMRU9HdNCnTsMAypY"));
    let rows = blocktools_secrets::keys::rows_for(dot, &dummy, None);
    assert!(rows.iter().any(|r| r.kind == "sr25519"));
    assert!(!rows.iter().any(|r| r.kind == "ed25519"));
    let plan = blocktools_core::plan::from_args(&["--chain".into(), "ksm".into(), "--explain".into()]).unwrap();
    let s = plan.specs.iter().find(|s| s.kind == "ed25519").unwrap();
    assert_eq!(s.template, "m/44'/{coin}'/{account}'/0'/{i}'");
    assert_eq!(blocktools_core::plan::expand(&s.template, s, 0, 0, 0).unwrap(), "m/44'/434'/0'/0'/0'");
    let plan = blocktools_core::plan::from_args(&["--chain".into(), "polyx".into()]).unwrap();
    let s = plan.specs.iter().find(|s| s.kind == "ed25519").unwrap();
    assert_eq!(blocktools_core::plan::expand(&s.template, s, 0, 0, 0).unwrap(), "m/44'/595'/0'/0'/0'");
    assert!(blocktools_core::plan::from_args(&["--chain".into(), "dot".into()]).is_err());
}
