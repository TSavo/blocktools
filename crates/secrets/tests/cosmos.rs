//! Cosmos Hub KAT: cosmjs packages/amino/src/secp256k1hdwallet.spec.ts (public test mnemonic,
//! default path m/44'/118'/0'/0/0). Secrets stay inside the test.
#![cfg(feature = "keys")]
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use blocktools_core::chains;
use std::str::FromStr;

#[test] fn cosmjs_default_address() {
    let seed = bip39::Mnemonic::parse("special sign fit simple patrol salute grocery chicken wheat radar tonight ceiling").unwrap().to_seed("");
    let secp = Secp256k1::new();
    let k = Xpriv::new_master(bitcoin::Network::Bitcoin, &seed).unwrap().derive_priv(&secp, &DerivationPath::from_str("m/44'/118'/0'/0/0").unwrap()).unwrap();
    let c = chains::chain("atom").unwrap();
    let r = chains::secp_rows(c, "", &k.private_key, false, &secp);
    assert_eq!(r.len(), 1);
    assert_eq!(r[0].address, "cosmos1jhg0e7s6gn44tfc5k37kr04sznyhedtc9rzys5");
    assert!(blocktools_core::validate::validate("atom", &r[0].address).is_ok());
    assert!(blocktools_core::validate::validate("atom", "cosmos1jhg0e7s6gn44tfc5k37kr04sznyhedtc9rzys4").is_err());
    assert!(blocktools_core::validate::validate("atom", "osmo1jhg0e7s6gn44tfc5k37kr04sznyhedtcvnnv3c").is_err());
}
