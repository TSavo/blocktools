#![cfg(feature = "keys")]
// External vector: monero-ecosystem/monero-python tests/test_seed.py::test_keys (public test seed).
use blocktools_monero::*;
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
const SEED: &str = "adjust mugged vaults atlas nasty mews damp toenail suddenly toxic possible framed succeed fuzzy return demonstrate nucleus album noises peculiar virtual rowboat inorganic jester fuzzy";
const ADDR: &str = "44cWztNFdAqNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH4YtKdH";
#[test] fn wordlist_is_1626() { assert_eq!(wordlist().len(), 1626); }
#[test] fn seed_to_keys_and_address() {
    assert!(is_seed_shape(SEED));
    let k = keys_from_spend(&seed_to_spend(SEED).unwrap());
    assert_eq!(hex(&k.spend_secret[..]), "482700617ba810f94035d7f4d7ccc1a29878e165b4867872b705204c85406906");
    assert_eq!(hex(&k.view_secret[..]), "09ed72c713d3e9e19bef2f5204cf85f6cb25de7842aa0722abeb12697f171903");
    assert_eq!(hex(&k.spend_public), "4ee576f52b9c6a824a3d5c2832d117177d2bb9992507c2c78788bb8dbaf4b640");
    assert_eq!(hex(&k.view_public), "e1ef99d66312ec0b16b17c66c591ab59594e21621588b63b62fa69fe615a768e");
    assert_eq!(address(Net::Main, &k.spend_public, &k.view_public), ADDR);
    assert_eq!(address(Net::Stage, &k.spend_public, &k.view_public), "54pZ5jHDGmwNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH6cuARW");
}
#[test] fn validate_roundtrip_and_refusals() {
    let (n, s, v) = validate(ADDR).unwrap();
    assert_eq!(n, Net::Main); assert_eq!(address(n, &s, &v), ADDR);
    let mut bad = ADDR.to_string(); bad.replace_range(90..91, if &ADDR[90..91] == "Y" { "Z" } else { "Y" });
    assert!(validate(&bad).is_err());
    let swapped = SEED.replace("fuzzy return", "return fuzzy");
    assert!(seed_to_spend(&swapped).is_err());
}
