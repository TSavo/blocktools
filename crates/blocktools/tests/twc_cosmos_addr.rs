//! Cosmos SDK chain-table rows against Trust Wallet Core's public address vectors (wallet-core adf80f8):
//! DERIVE = tests/common/CoinAddressDerivationTests.cpp `Coin.DeriveAddress` (public dummy key 0x46 x 32);
//! ANY = tests/chains/Cosmos/<Chain>/TWAnyAddressTests.cpp (public key -> address).
//! Each row: the chain table's encoder must produce TWC's address, the address must be detected as that
//! chain only, and the path coin type must equal TWC registry.json's derivation path.
use blocktools::chains;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
fn hx(s: &str) -> Vec<u8> { (0..s.len()/2).map(|i| u8::from_str_radix(&s[2*i..2*i+2], 16).unwrap()).collect() }
fn addr(name: &str, pk: &PublicKey) -> String {
    let c = chains::chain(name).unwrap_or_else(|| panic!("{name} not in table"));
    let r = chains::pub_rows(c, "m", pk, false); assert_eq!(r.len(), 1, "{name}"); r[0].address.clone()
}
/// (table name, TWC coin, coin type from TWC derivation path, DERIVE address)
const DERIVE: &[(&str, &str, u32, &str)] = &[
    ("band", "BandChain", 494, "band1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0q5lp5f"),
    ("blz", "Bluzelle", 483, "bluzelle1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0vrup2s"),
    ("cro", "CryptoOrg", 394, "cro1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0pqh6ss"),
    ("kava", "Kava", 459, "kava1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z09wt76x"),
    ("rune", "THORChain", 931, "thor1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0luxce7"),
    ("bld", "Agoric", 564, "agoric1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0txauuh"),
    ("strd", "Stride", 118, "stride1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z06sllcd"),
    ("axl", "Axelar", 118, "axelar1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0a4ft8q"),
    ("cre", "Crescent", 118, "cre1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0anvxev"),
    ("kuji", "Kujira", 118, "kujira1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0gnampt"),
    ("cmdx", "Comdex", 118, "comdex1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z075ap4k"),
    ("ntrn", "Neutron", 118, "neutron1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0aykpkx"),
    ("somm", "Sommelier", 118, "somm1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z048s0at"),
    ("fet", "FetchAI", 118, "fetch1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z02xk8wk"),
    ("mars", "Mars", 118, "mars1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0yxx6e6"),
    ("umee", "Umee", 118, "umee1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0tdzugn"),
    ("coreum", "Coreum", 990, "core1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0248ct6"),
    ("qsr", "Quasar", 118, "quasar1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0hc97py"),
    ("xprt", "Persistence", 118, "persistence1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0hhesz9"),
    ("akt", "Akash", 118, "akash1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z05qjy4m"),
    ("noble", "Noble", 118, "noble1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z03c2t50"),
    ("sei", "Sei", 118, "sei1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z05hw42q"),
    ("tia", "Tia", 118, "celestia1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0g3wnkv"),
    ("dydx", "Dydx", 118, "dydx1hkfq3zahaqkkzx5mjnamwjsfpq2jk7z0sz38vk"),
];
/// (table name, TWC test file, public key, address)
const ANY: &[(&str, &str, &str, &str)] = &[
    ("bld", "Cosmos/Agoric/TWAnyAddressTests.cpp", "03602731bc2f787eec358c1ba8ddb8e7c7720f56a0406b8d16e20c93b822953960", "agoric1wu32wujsvz290sasq308fswznx77nk9k0cxqwg"),
    ("akt", "Cosmos/Akash/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "akash1mry47pkga5tdswtluy0m8teslpalkdq0n6af90"),
    ("axl", "Cosmos/Axelar/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "axelar1mry47pkga5tdswtluy0m8teslpalkdq060xxh5"),
    ("cmdx", "Cosmos/Comdex/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "comdex1mry47pkga5tdswtluy0m8teslpalkdq0ewjv9z"),
    ("coreum", "Cosmos/Coreum/TWAnyAddressTests.cpp", "0345d8d927b955c3cd468d12b5bc634c7919ee4777e578439af6314cf04b2ff114", "core1a5nvz6smgsph9gephguyhn30fmzrpaxrvvdjun"),
    ("cre", "Cosmos/Crescent/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "cre1mry47pkga5tdswtluy0m8teslpalkdq06frtfc"),
    ("cro", "Cosmos/CryptoOrg/TWAnyAddressTests.cpp", "025824f188c340235910b15e5e35aea11cfc28eabfa7756da5585c08f74db437ef", "cro1tcfsr7m7d6jk6fpyety373m8c39ea2f8dmp830"),
    ("fet", "Cosmos/FetchAI/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "fetch1mry47pkga5tdswtluy0m8teslpalkdq0due27z"),
    ("kuji", "Cosmos/Kujira/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "kujira1mry47pkga5tdswtluy0m8teslpalkdq00fjk3l"),
    ("mars", "Cosmos/Mars/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "mars1mry47pkga5tdswtluy0m8teslpalkdq0rufhfw"),
    ("ntrn", "Cosmos/Neutron/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "neutron1mry47pkga5tdswtluy0m8teslpalkdq067evxj"),
    ("noble", "Cosmos/Noble/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "noble1mry47pkga5tdswtluy0m8teslpalkdq0kz9xym"),
    ("xprt", "Cosmos/Persistence/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "persistence1mry47pkga5tdswtluy0m8teslpalkdq0sdkaj3"),
    ("qsr", "Cosmos/Quasar/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "quasar1mry47pkga5tdswtluy0m8teslpalkdq0sz2n3s"),
    ("sei", "Cosmos/Sei/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "sei1mry47pkga5tdswtluy0m8teslpalkdq0ndpc65"),
    ("somm", "Cosmos/Sommelier/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "somm1mry47pkga5tdswtluy0m8teslpalkdq0jalzdl"),
    ("strd", "Cosmos/Stride/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "stride1mry47pkga5tdswtluy0m8teslpalkdq0a2sjge"),
    ("tia", "Cosmos/Tia/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "celestia1mry47pkga5tdswtluy0m8teslpalkdq00tp7xc"),
    ("umee", "Cosmos/Umee/TWAnyAddressTests.cpp", "02cbfdb5e472893322294e60cf0883d43df431e1089d29ecb447a9e6d55045aae5", "umee1mry47pkga5tdswtluy0m8teslpalkdq0vhd3c8"),
];
#[test] fn twc_derive_address() {
    let sk = SecretKey::from_slice(&[0x46; 32]).unwrap(); let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    for (n, twc, coin, want) in DERIVE {
        assert_eq!(addr(n, &pk), *want, "{n} ({twc})");
        let d: Vec<&str> = blocktools::address::detect(want).into_iter().map(|x| x.0).collect();
        assert_eq!(d, vec![*n], "{n}: auto-detect from address");
        assert_eq!(chains::chain(n).unwrap().coin, *coin, "{n} coin type");
        // registry.json "decimals": 8 for cro and rune, 18 for dydx, 6 for the rest
        let dec = match *n { "cro" | "rune" => 8, "dydx" => 18, _ => 6 };
        assert_eq!(blocktools::address::decimals(n), Some(dec), "{n} decimals");
    }
    assert_eq!(DERIVE.len(), 24);
}
#[test] fn twc_any_address() {
    for (n, f, pk, want) in ANY { assert_eq!(addr(n, &PublicKey::from_slice(&hx(pk)).unwrap()), *want, "{n} ({f})") }
    assert_eq!(ANY.len(), 19);
}
#[test] fn hrps_unique() {
    let mut h: Vec<&str> = chains::CHAINS.iter().filter_map(|c| match c.enc { chains::Enc::Cosmos { hrp, .. } => Some(hrp), _ => None }).collect();
    let n = h.len(); h.sort(); h.dedup(); assert_eq!(h.len(), n, "duplicate cosmos hrp in table");
}
/// Ethermint (ethsecp256k1) rows: (table name, TWC coin, DERIVE address for 0x46 x 32, TWAnyAddress file, ANY address).
/// ANY public key (all four files): 04868e7e…0ab8 (Secp256k1Extended), from
/// tests/chains/Cosmos/Native{Injective,Evmos,Canto}/TWAnyAddressTests.cpp and
/// rust/tw_tests/tests/chains/zetachain/zetachain_address.rs.
const ETH_PK: &str = "04868e7e1634417db2adfd9fe38205bfa0fea01898a7fd30565d13f7056a37c065211845f6e553524c2c1611af9712ac02b7a3b439c9f0cfcadfd81a2c86cc0ab8";
const ETHERMINT: &[(&str, &str, &str, &str, &str)] = &[
    ("inj", "NativeInjective", "inj1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj0knl55v", "Cosmos/NativeInjective/TWAnyAddressTests.cpp", "inj14py36sx57ud82t9yrks9z6hdsrpn5x6k8tf7m3"),
    ("evmos", "NativeEvmos", "evmos1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj07me7uu", "Cosmos/NativeEvmos/TWAnyAddressTests.cpp", "evmos14py36sx57ud82t9yrks9z6hdsrpn5x6k0r05np"),
    ("canto", "NativeCanto", "canto1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj0wvfqju", "Cosmos/NativeCanto/TWAnyAddressTests.cpp", "canto14py36sx57ud82t9yrks9z6hdsrpn5x6kl5l2ap"),
    ("zeta", "NativeZetaChain", "zeta1nk9x9ajk4rgkzhqjjn7hr6w0k0jg2kj027x9uy", "rust/tw_tests/tests/chains/zetachain/zetachain_address.rs", "zeta14py36sx57ud82t9yrks9z6hdsrpn5x6kmxs0ne"),
];
#[test] fn twc_ethermint_address() {
    let sk = SecretKey::from_slice(&[0x46; 32]).unwrap(); let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let apk = PublicKey::from_slice(&hx(ETH_PK)).unwrap();
    for (n, twc, want, f, any) in ETHERMINT {
        assert_eq!(addr(n, &pk), *want, "{n} ({twc}) derive");
        assert_eq!(addr(n, &apk), *any, "{n} ({f})");
        for a in [*want, *any] {
            let d: Vec<&str> = blocktools::address::detect(a).into_iter().map(|x| x.0).collect();
            assert_eq!(d, vec![*n], "{n}: auto-detect from address");
        }
        let c = chains::chain(n).unwrap(); assert_eq!(c.coin, 60, "{n} coin type (TWC m/44'/60'/0'/0/0)");
        assert_eq!(blocktools::address::decimals(n), Some(18), "{n} decimals");
    }
    assert_eq!(ETHERMINT.len(), 4);
}
