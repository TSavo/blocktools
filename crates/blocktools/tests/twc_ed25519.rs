//! ed25519 account chains (aptos, sui, near) against Trust Wallet Core's public vectors (wallet-core adf80f8):
//! DERIVE = tests/common/CoinAddressDerivationTests.cpp `Coin.DeriveAddress` (public dummy key 0x46 x 32);
//! HD = tests/common/HDWallet/HDWalletTests.cpp AptosKey / NearKey (public test mnemonics);
//! Aptos AddressTests.cpp, Sui rust/tw_tests/tests/chains/sui/sui_address.rs (validation).
//! Registry paths: registry.json (aptos m/44'/637'/0'/0'/0', sui m/44'/784'/0'/0'/0', near m/44'/397'/0').
use blocktools::chains::{self, EdAddr};
use blocktools::secrets::seed::{readings, Reading};
fn hx(s: &str) -> [u8; 32] { let v: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&s[2*i..2*i+2], 16).unwrap()).collect(); v.try_into().unwrap() }
fn row(n: &str, path: &str, k: &[u8; 32]) -> chains::Row { chains::ed_row(chains::chain(n).unwrap(), path, k) }
fn detect(a: &str) -> Vec<&'static str> { blocktools::address::detect(a).into_iter().map(|x| x.0).collect() }

#[test] fn derive_dummy_key() {
    let k = [0x46u8; 32];
    for (n, want) in [("aptos", "0xce2fd04ac9efa74f17595e5785e847a2399d7e637f5e8179244f76191f653276"),
                      ("sui", "0x870deb25d5c0a4d7250d52d5cd58dacca2d51eb2a120a979b13384cd52e21e1b"),
                      ("near", "ee93a4f66f8d16b819bb9beb9ffccdfcdc1412e87fee6a324c2a99a1e0e67148")] {
        let r = row(n, "", &k);
        assert_eq!(r.address, want, "{n}");
        assert_eq!(r.kind, n);
        assert!(detect(want).contains(&n), "{n}: detect");
    }
}
#[test] fn aptos_from_public_key() {
    assert_eq!(chains::ed_address(EdAddr::Aptos, &hx("ad0e293a56c9fc648d1872a00521d97e6b65724519a2676c2c47cb95d131cf5a")),
        "0xe9c4d0b6fe32a5cc8ebd1e9ad5b54a0276a57f2d081dcb5e30342319963626c3");
    assert_eq!(row("aptos", "", &hx("088baa019f081d6eab8dff5c447f9ce2f83c1babf3d03686299eaf6a1e89156e")).address,
        "0xe9c4d0b6fe32a5cc8ebd1e9ad5b54a0276a57f2d081dcb5e30342319963626c3");
}
fn seed(m: &str) -> [u8; 64] { match &readings(m, "")[0] { Reading::Master { seed, .. } => **seed, _ => panic!("no master") } }
#[test] fn hd_paths() {
    // HDWalletTests mnemonic1 (public test phrase), AptosKey.
    let s = seed("ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal");
    let k = chains::slip10_ed25519(&s, &[44, 637, 0, 0, 0]);
    assert_eq!(blocktools_hex(&k), "7f2634c0e2414a621e96e39c41d09021700cee12ee43328ed094c5580cd0bd6f");
    // NearKey (public test phrase).
    let s = seed("owner erupt swamp room swift final allow unaware hint identify figure cotton");
    let k = chains::slip10_ed25519(&s, &[44, 397, 0]);
    assert_eq!(blocktools_hex(&k), "35e0d9631bd538d5569266abf6be7a9a403ebfda92ddd49b3268e35360a6c2dd");
    assert_eq!(row("near", "m/44'/397'/0'", &k).address, "b8d5df25047841365008f30fb6b30dd820e9a84d869f05623d114e96831f2fbf");
    // Standard templates match the registry paths at i = 0.
    for (n, t) in [("aptos", "m/44'/{coin}'/{i}'/0'/0'"), ("sui", "m/44'/{coin}'/{i}'/0'/0'"), ("near", "m/44'/{coin}'/{i}'")] {
        assert_eq!(blocktools::plan::std_template(chains::chain(n).unwrap()), t, "{n}");
    }
}
fn blocktools_hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
#[test] fn validation() {
    let ok = |n: &str, a: &str| chains::chain(n).map(|c| blocktools_core_validate(c, a)).unwrap();
    for a in ["0x1", "0x0", "0xeeff357ea5c1a4e7bc11b2b17ff2dc2dcca69750bfef1e1ebcaccf8c8018175b", "0x0000777821c78442e17d82c3d7a371f42de7189e4248e529fe6eee6bca40ddbb"] { assert!(ok("aptos", a), "aptos {a}") }
    for a in ["", "0x01", "Seff357ea5c1a4e7bc11b2b17ff2dc2dcca69750bfef1e1ebcaccf8c8018175b", "eeff357ea5c1a4e7bc11b2b17ff2dc2dcca69750bfef1e1ebcaccf8c8018175bb",
              "0xSeff357ea5c1a4e7bc11b2b17ff2dc2dcca69750bfef1e1ebcaccf8c8018175b", "eeff357ea5c1a4e7bc11b2b17ff2dc2dcca69750bfef1e1ebcaccf8c8018175b",
              "0x777821c78442e17d82c3d7a371f42de7189e4248e529fe6eee6bca40ddbb", "0xeeff357ea5c1a4e7bc11b2b17ff2dc2dcca69750bfef1e1ebcaccf8c8018175"] { assert!(!ok("aptos", a), "aptos {a}") }
    for a in ["0x259ff8074ab425cbb489f236e18e08f03f1a7856bdf7c7a2877bd64f738b5015", "259ff8074ab425cbb489f236e18e08f03f1a7856bdf7c7a2877bd64f738b5015"] { assert!(ok("sui", a), "sui {a}") }
    for a in ["0xb1dc06bd64d4e179a482b97bb68243f6c02c1b92", "b1dc06bd64d4e179a482b97bb68243f6c02c1b92", "d575ad7f18e948462a5cf698f564ef394a752a71fec62493af8a055c012c0d502",
              "b1dc06bd64d4e179a482b97bb68243f6c02c1b9", "0x11", "0xS59ff8074ab425cbb489f236e18e08f03f1a7856bdf7c7a2877bd64f738b5015"] { assert!(!ok("sui", a), "sui {a}") }
    assert!(ok("near", "b8d5df25047841365008f30fb6b30dd820e9a84d869f05623d114e96831f2fbf"));
    assert!(!ok("near", "0xb8d5df25047841365008f30fb6b30dd820e9a84d869f05623d114e96831f2fbf"));
    assert!(!ok("near", "alice.near"), "named accounts not supported");
}
fn blocktools_core_validate(c: &chains::Chain, a: &str) -> bool { blocktools::validate::validate(c.name, a).is_ok() }
