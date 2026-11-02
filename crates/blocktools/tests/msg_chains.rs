//! Published vectors only (docs/PROVENANCE-msg.md). Tron + Solana raw: Trust Wallet Core 2a8aa020
//! (tests/chains/Tron/TronMessageSignerTests.cpp, tests/chains/Solana/SolanaMessageSigner.cpp). Solana
//! offchain-v0 bytes: anza-xyz/solana-sdk offchain-message/src/lib.rs tests. Cosmos: cosmos-sdk
//! docs/architecture/adr-036-arbitrary-signature.md "Signed MsgSignData json example".
use blocktools::msgchain::{self, Opts};
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
fn hx(s: &str) -> Vec<u8> { blocktools::hex_dec(s).unwrap() }
const N: Opts = Opts { format: None, pubkey: None };
fn tron_addr() -> String {
    // TWC's public test key (not a user secret); only its public key is used.
    let sk = SecretKey::from_slice(&hx("75065f100e38d3f3b4c5c4235834ba8216de62272a4f03532c44b31a5734360a")).unwrap();
    msgchain::tron_address(&PublicKey::from_secret_key(&Secp256k1::new(), &sk).serialize_uncompressed())
}
#[test] fn tron_twc_vectors() {
    let a = tron_addr(); assert_eq!(a, "TWWb9EjUWai17YEVB7FR8hreupYJKG9sMR");
    for (m, s) in [("Hello World", "bc0753c070cc55693097df11bc11e1a7c4bd5e1a40b9dc94c75568e59bcc9d6b50a7873ef25b469e494490a54de37327b4bc7fc825c81a377b555e34fb7261ba1c"),
        ("A much longer message to test the signing and verification process", "93aee5f753cf889e0749c74dd0c5996cce889883ae079e09ede462e16d65d06a4f43d1ed2745e9f3c1690695628269bd58f057a4a93953cc50e66b4a05bc0f451b")] {
        assert_eq!(msgchain::verify(&a, m.as_bytes(), s, &N).unwrap()["status"], "ok");
        assert_eq!(msgchain::verify(&a, b"Hello world", s, &N).unwrap()["status"], "signer_mismatch");
    }
    assert_eq!(msgchain::verify(&a, b"x", "00", &N), Err("signature_not_65_bytes"));
    assert_eq!(msgchain::verify(&a, b"x", &"00".repeat(65), &Opts { format: Some("raw"), pubkey: None }), Err("format_only_for_solana"));
}
const SOL_SIG: &str = "2iBZ6zrQRKHcbD8NWmm552gU5vGvh1dk3XV4jxnyEdRKm8up8AeQk1GFr9pJokSmchw7i9gMtNyFBdDt8tBxM1cG";
#[test] fn solana_raw_twc_vector() {
    let a = blocktools::sol::b58enc(&hx("ee6d61a89fc8f9909585a996bb0d2b2ac69ae23b5acf39a19f32631239ba06f9"));
    assert_eq!(msgchain::detect_chain(&a), Ok("sol"));
    let raw = Opts { format: Some("raw"), pubkey: None };
    assert_eq!(msgchain::verify(&a, b"Hello world", SOL_SIG, &raw).unwrap()["status"], "ok");
    assert_eq!(msgchain::verify(&a, b"Hello World", SOL_SIG, &raw).unwrap()["status"], "signer_mismatch");
    assert_eq!(msgchain::verify(&a, b"Hello world", SOL_SIG, &Opts { format: Some("offchain-v0"), pubkey: None }).unwrap()["status"], "signer_mismatch");
    assert_eq!(msgchain::verify(&a, b"Hello world", SOL_SIG, &N), Err("solana_format_required"));
    assert_eq!(msgchain::verify(&a, b"Hello world", SOL_SIG, &Opts { format: Some("offchain"), pubkey: None }), Err("unknown_solana_format"));
}
#[test] fn solana_offchain_v0_bytes_solana_sdk() {
    let ascii: Vec<u8> = [255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110, 0, 0, 12, 0, 84, 101, 115, 116, 32, 77, 101, 115, 115, 97, 103, 101].to_vec();
    assert_eq!(msgchain::sol_offchain_v0(b"Test Message").unwrap(), ascii);
    let utf: Vec<u8> = [255, 115, 111, 108, 97, 110, 97, 32, 111, 102, 102, 99, 104, 97, 105, 110, 0, 1, 35, 0,
        208, 162, 208, 181, 209, 129, 209, 130, 208, 190, 208, 178, 208, 190, 208, 181, 32, 209, 129, 208, 190, 208, 190, 208, 177, 209, 137, 208, 181, 208, 189, 208, 184, 208, 181].to_vec();
    assert_eq!(msgchain::sol_offchain_v0("Тестовое сообщение".as_bytes()).unwrap(), utf);
    // solana-sdk's published sha256 of each serialization
    use bitcoin::hashes::{sha256, Hash};
    assert_eq!(blocktools::sol::b58enc(&sha256::Hash::hash(&ascii).to_byte_array()), "HG5JydBGjtjTfD3sSn21ys5NTWPpXzmqifiGC2BVUjkD");
    assert_eq!(blocktools::sol::b58enc(&sha256::Hash::hash(&utf).to_byte_array()), "6GXTveatZQLexkX4WeTpJ3E7uk1UojRXpKp43c4ArSun");
    assert_eq!(msgchain::sol_offchain_v0(b""), Err("empty_message"));
}
/// UNTESTED against a published signature: the ADR-036 spec's JSON example does not verify (its signer
/// has an invalid bech32 checksum, and the signature fails for both that string and the pubkey's address),
/// and Keplr's amino.spec.ts signs with a random key. This is a self round-trip only (bytes-level interop unproven).
#[test] fn cosmos_adr036_roundtrip_and_refusals() {
    use bitcoin::hashes::{sha256, Hash};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x46; 32]).unwrap(); // TWC's public dummy key (twc_cosmos_addr.rs)
    let pk = PublicKey::from_secret_key(&secp, &sk).serialize();
    let a = msgchain::cosmos_addr("osmo", &pk); assert_eq!(msgchain::detect_chain(&a), Ok("cosmos"));
    assert_eq!(msgchain::adr036_doc(&a, &[1, 2, 3]), format!(r#"{{"account_number":"0","chain_id":"","fee":{{"amount":[],"gas":"0"}},"memo":"","msgs":[{{"type":"sign/MsgSignData","value":{{"data":"AQID","signer":"{a}"}}}}],"sequence":"0"}}"#));
    let d = sha256::Hash::hash(msgchain::adr036_doc(&a, b"random").as_bytes()).to_byte_array();
    let sig = blocktools::b64::encode(&secp.sign_ecdsa(&bitcoin::secp256k1::Message::from_digest(d), &sk).serialize_compact());
    let pkb = blocktools::b64::encode(&pk);
    let o = Opts { format: None, pubkey: Some(&pkb) };
    assert_eq!(msgchain::verify(&a, b"random", &sig, &o).unwrap()["status"], "ok");
    assert_eq!(msgchain::verify(&a, b"randon", &sig, &o).unwrap()["status"], "signer_mismatch");
    let other = blocktools::b64::encode(&PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x47; 32]).unwrap()).serialize());
    assert_eq!(msgchain::verify(&a, b"random", &sig, &Opts { format: None, pubkey: Some(&other) }).unwrap()["error"], "pubkey_does_not_match_address");
    assert_eq!(msgchain::verify(&a, b"random", &sig, &N), Err("cosmos_pubkey_required"));
    // the spec example's signer fails bech32 checksum: refused, not guessed
    assert_eq!(msgchain::detect_chain("cosmos1hftz5ugqmpg9243xeegsqqav62f8hnywsjr4xr"), Err("unrecognised_address"));
}
#[test] fn eth_btc_unchanged_and_options_refused() {
    let a = "0x" .to_string() + &"11".repeat(20);
    assert_eq!(msgchain::detect_chain(&a), Ok("eth"));
    assert_eq!(msgchain::verify(&a, b"x", "00", &Opts { format: None, pubkey: Some("AA==") }), Err("pubkey_only_for_cosmos"));
}
