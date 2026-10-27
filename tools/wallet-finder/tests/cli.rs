//! wallet-finder CLI: finds a phrase hidden in text for all five shapes, emits no key, exit codes.
use blocktools_utxo::{write_dump, Coin};
use std::io::Write;
use std::process::{Command, Stdio};
fn run(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_wallet-finder")).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
}
// Public test vector: the five addresses of sha256("correct horse battery staple"), per key-to-addresses.
const SHAPES: [(&str, &str); 5] = [("p2pkh", "1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8"), ("p2pkh-uncompressed", "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T"),
    ("p2sh-p2wpkh", "3KToBU4ykTWfjnu4kAUV1q8QosnxT61sbf"), ("p2wpkh", "bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4"),
    ("p2tr", "bc1p3833qjvky7c2w3r7earqqwc377qeztadmfwjpwyy5srsch868lgs2v8tnw")];
fn dump(tag: &str) -> String {
    let btc = blocktools_core::chains::chain("btc").unwrap();
    let coins: Vec<Coin> = SHAPES.iter().enumerate().map(|(i, (_, a))| Coin { txid: [i as u8; 32], vout: 0, height: 1, coinbase: false, value: 1000 + i as u64, script: blocktools_core::chains::address_to_script(btc, a).unwrap() }).collect();
    let p = std::env::temp_dir().join(format!("wallet-finder-cli-{}-{tag}.dat", std::process::id()));
    std::fs::write(&p, write_dump(25, [0; 4], [0; 32], &coins)).unwrap();
    p.to_string_lossy().into()
}
#[test]
fn finds_all_five_shapes_in_free_text_and_no_key() {
    let d = dump("a");
    let (c, out, err) = run(&["--dump", &d], "Groceries: eggs.\nreminder - Correct horse battery staple!\n");
    assert_eq!(c, 1, "case differs: not found without --rules case; {err}");
    assert!(out.is_empty());
    let (c, out, err) = run(&["--dump", &d, "--rules", "case"], "Groceries: eggs.\nreminder - Correct horse battery staple!\n");
    assert_eq!(c, 0, "{err}");
    let l: Vec<serde_json::Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(l.len(), 5);
    for (i, (k, a)) in SHAPES.iter().enumerate() {
        let h = l.iter().find(|h| h["kind"] == *k).unwrap_or_else(|| panic!("{k} missing"));
        assert_eq!((h["address"].as_str(), h["value_sat"].as_u64(), h["passphrase"].as_str(), h["scheme"].as_str()), (Some(*a), Some(1000 + i as u64), Some("correct horse battery staple"), Some("sha256")));
        let keys: Vec<&String> = h.as_object().unwrap().keys().collect();
        assert_eq!(keys.len(), 8, "{keys:?}");
        for f in ["wif", "private_key", "xprv", "secret", "seed"] { assert!(h.get(f).is_none()) }
    }
    std::fs::remove_file(d).ok();
}
#[test]
fn limits_and_refusals() {
    let d = dump("b");
    let (c, _, err) = run(&["--dump", &d, "--limit", "1"], "correct horse battery staple\n");
    assert_eq!(c, 0, "the whole line is the first candidate; {err}");
    let (c, _, err) = run(&["--dump", &d, "--window", "0"], "correct horse battery staple. Then more words\n");
    assert_eq!(c, 0, "sentence split alone finds it; {err}");
    assert!(err.contains("\"candidates_per_sec\""));
    assert_eq!(run(&["--dump", &d, "--rules", "bogus"], "x").0, 2);
    assert_eq!(run(&["--dump", &d, "--scheme", "md5"], "x").0, 2);
    assert_eq!(run(&[], "x").0, 2);
    std::fs::remove_file(d).ok();
}
/// fixtures/utxo/brainwallet-5.utxo-hex.txt (hex, 60-char lines so no line looks like a 32-byte key; decoded by the man page examples and recipe check) is exactly this test's dump:
/// the five public test-vector scripts, 1000..1004 sat. Regenerate: BLESS=1 cargo test -p wallet-finder.
#[test]
fn committed_fixture_is_reproducible() {
    let d = dump("f");
    let want = std::fs::read(&d).unwrap();
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/utxo/brainwallet-5.utxo-hex.txt");
    let hex: String = want.iter().map(|b| format!("{b:02x}")).collect();
    let text: String = hex.as_bytes().chunks(60).map(|c| format!("{}\n", std::str::from_utf8(c).unwrap())).collect();
    if std::env::var("BLESS").as_deref() == Ok("1") { std::fs::write(p, &text).unwrap() }
    assert_eq!(std::fs::read_to_string(p).unwrap(), text);
    std::fs::remove_file(d).ok();
}
