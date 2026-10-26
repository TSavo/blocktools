//! ed25519 account chains (aptos, sui, near) against Trust Wallet Core's public vectors (wallet-core adf80f8):
//! DERIVE = tests/common/CoinAddressDerivationTests.cpp `Coin.DeriveAddress` (public dummy key 0x46 x 32);
//! HD = tests/common/HDWallet/HDWalletTests.cpp AptosKey / NearKey (public test mnemonics);
//! Aptos AddressTests.cpp, Sui rust/tw_tests/tests/chains/sui/sui_address.rs (validation).
//! Tezos AddressTests.cpp, MultiversX AddressTests.cpp + TestAccounts.h, interface/TWHDWalletTests.cpp DeriveTezos /
//! DeriveMultiversX (public seedHex of the TWC test phrase with passphrase TREZOR).
//! Registry paths: xtz m/44'/1729'/0'/0', egld m/44'/508'/0'/0'/0', registry.json (aptos m/44'/637'/0'/0'/0', sui m/44'/784'/0'/0'/0', near m/44'/397'/0').
use blocktools::chains::{self, EdAddr};
use blocktools::secrets::seed::{readings, Reading};
fn hx(s: &str) -> [u8; 32] { let v: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&s[2*i..2*i+2], 16).unwrap()).collect(); v.try_into().unwrap() }
fn row(n: &str, path: &str, k: &[u8; 32]) -> chains::Row { chains::ed_row(chains::chain(n).unwrap(), path, k) }
fn detect(a: &str) -> Vec<&'static str> { blocktools::address::detect(a).into_iter().map(|x| x.0).collect() }

#[test] fn derive_dummy_key() {
    let k = [0x46u8; 32];
    for (n, want) in [("aptos", "0xce2fd04ac9efa74f17595e5785e847a2399d7e637f5e8179244f76191f653276"),
                      ("sui", "0x870deb25d5c0a4d7250d52d5cd58dacca2d51eb2a120a979b13384cd52e21e1b"),
                      ("near", "ee93a4f66f8d16b819bb9beb9ffccdfcdc1412e87fee6a324c2a99a1e0e67148"),
                      ("xtz", "tz1gcEWswVU6dxfNQWbhTgaZrUrNUFwrsT4z"),
                      ("egld", "erd1a6f6fan035ttsxdmn04ellxdlnwpgyhg0lhx5vjv92v6rc8xw9yq83344f")] {
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
#[test] fn tezos_multiversx() {
    // Tezos PublicKeyInit (TWC passes the key with a 01 tag byte; the 32-byte key follows it).
    assert_eq!(chains::ed_address(EdAddr::Tezos, &hx("fe157cc8011727936c592f856c9071d39cf4acdadfa6d76435e4619c9dc56f63")), "tz1cG2jx3W4bZFeVGBjsTxUAG8tdpTXtE8PT");
    // MultiversX TestAccounts.h alice / bob.
    assert_eq!(chains::ed_address(EdAddr::Mvx, &hx("0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1")), "erd1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssycr6th");
    assert_eq!(chains::ed_address(EdAddr::Mvx, &hx("8049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f8")), "erd1spyavw0956vq68xj8y4tenjpq2wd5a9p2c6j8gsz7ztyrnpxrruqzu66jx");
    assert_eq!(row("egld", "", &hx("413f42575f7f26fad3317a778771212fdb80245850981e48b58a4f25e344e8f9")).address, "erd1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssycr6th");
    // TWHDWalletTests seedHex (public): DeriveTezos public key, DeriveMultiversX key + address.
    let sh = "7ae6f661157bda6492f6162701e570097fc726b6235011ea5ad09bf04986731ed4d92bc43cbdee047b60ea0dd1b1fa4274377c9bf5bd14ab1982c272d8076f29";
    let s: Vec<u8> = (0..64).map(|i| u8::from_str_radix(&sh[2*i..2*i+2], 16).unwrap()).collect();
    let k = chains::slip10_ed25519(&s, &[44, 1729, 0, 0]);
    let want_tz = chains::ed_address(EdAddr::Tezos, &hx("c834147f97bcf95bf01f234455646a197f70b25e93089591ffde8122370ad371"));
    assert_eq!(row("xtz", "m/44'/1729'/0'/0'", &k).address, want_tz);
    let k = chains::slip10_ed25519(&s, &[44, 508, 0, 0, 0]);
    assert_eq!(blocktools_hex(&k), "0eb593141de897d60a0883320793eb49e63d556ccdf783a87ec014f150d50453");
    assert_eq!(row("egld", "m/44'/508'/0'/0'/0'", &k).address, "erd1a6l7q9cfvrgr80xuzm37tapdr4zm3mwrtl6vt8f45df45x7eadfs8ds5vv");
    let ok = |n: &str, a: &str| blocktools::validate::validate(n, a).is_ok();
    for a in ["tz1Yju7jmmsaUiG9qQLoYv35v5pHgnWoLWbt", "tz2PdGc7U5tiyqPgTSgqCDct94qd6ovQwP6u", "tz3VEZ4k6a4Wx42iyev6i2aVAptTRLEAivNN", "KT1XnTn74bUtxHfDtBmm2bGZAQfhPbvKWR8o", "tz1d1qQL3mYVuiH4JPFvuikEpFwaDm85oabM"] { assert!(ok("xtz", a), "xtz {a}") }
    for a in ["NmH7tmeJUmHcncBDvpr7aJNEBk7rp5zYsB1qt", "tz1eZwq8b5cvE2bPKokatLkVMzkxz24z3AAAA", "1tzeZwq8b5cvE2bPKokatLkVMzkxz24zAAAAA", "tz1Yju7jmmsaUiG9qQLoYv35v5pHgnWoLWbt\0"] { assert!(!ok("xtz", a), "xtz {a}") }
    for a in ["", "foo", "10z9xdugayn528ksaesdwlhf006fw5sg2qmmm0h52fvxczwgesyvq5pwemr", "xerd10z9xdugayn528ksaesdwlhf006fw5sg2qmmm0h52fvxczwgesyvq5pwemr",
              "foo10z9xdugayn528ksaesdwlhf006fw5sg2qmmm0h52fvxczwgesyvq5pwemr", "0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1"] { assert!(!ok("egld", a), "egld {a}") }
    assert_eq!(detect("tz1gcEWswVU6dxfNQWbhTgaZrUrNUFwrsT4z"), vec!["xtz"]);
    assert_eq!(detect("erd1qyu5wthldzr8wx5c9ucg8kjagg0jfs53s8nr3zpz3hypefsdd8ssycr6th"), vec!["egld"]);
}
