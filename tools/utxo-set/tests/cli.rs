//! utxo-set CLI: funded/empty answers, both formats, refusals, exit codes.
use blocktools_utxo::{write_dump, Coin};
use std::io::Write;
use std::process::{Command, Stdio};
fn run(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_utxo-set")).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
}
const FUNDED: &str = "1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T"; // public test vector (sha256 brainwallet "correct horse battery staple")
const EMPTY: &str = "bc1q08alc0e5ua69scxhvyma568nvguqccrv4cc9n4";
fn dump(fmt: u16, tag: &str) -> String {
    let btc = blocktools_core::chains::chain("btc").unwrap();
    let s = blocktools_core::chains::address_to_script(btc, FUNDED).unwrap();
    let coins = [Coin { txid: [1; 32], vout: 0, height: 1, coinbase: false, value: 1500, script: s.clone() },
                 Coin { txid: [2; 32], vout: 3, height: 1, coinbase: true, value: 25, script: s }];
    let p = std::env::temp_dir().join(format!("utxo-set-cli-{}-{tag}-{fmt}.dat", std::process::id()));
    std::fs::write(&p, write_dump(fmt, [0xf9, 0xbe, 0xb4, 0xd9], [0; 32], &coins)).unwrap();
    p.to_string_lossy().into()
}
#[test]
fn funded_empty_and_script_queries() {
    for fmt in [25, 28] {
        let d = dump(fmt, "q");
        let (c, out, err) = run(&["--dump", &d], &format!("{FUNDED}\n# comment\n\n{EMPTY}\n"));
        assert_eq!(c, 0, "{err}");
        let l: Vec<serde_json::Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert_eq!((l[0]["status"].as_str(), l[0]["value_sat"].as_u64(), l[0]["outputs"].as_u64(), l[0]["chain"].as_str()), (Some("funded"), Some(1525), Some(2), Some("btc")));
        assert_eq!((l[1]["status"].as_str(), l[1]["value_sat"].as_u64()), (Some("empty"), Some(0)));
        let i: serde_json::Value = serde_json::from_str(err.lines().next().unwrap()).unwrap();
        assert_eq!(i["coins"], 2); assert_eq!(i["scripts"], 1);
        assert_eq!(i["network"].as_str(), if fmt == 28 { Some("btc") } else { None });
        let (c, out, _) = run(&["--dump", &d], &format!("{}\n", l[0]["script"].as_str().unwrap()));
        assert_eq!(c, 0); assert!(out.contains("\"funded\""));
        let (c, out, _) = run(&["--dump", &d, "--bits", "0"], &format!("{FUNDED}\n"));
        assert_eq!(c, 0); assert!(out.contains("\"funded\""), "exact set alone");
        let (c, out, _) = run(&["--dump", &d, "--stats"], "");
        assert_eq!(c, 0); assert!(out.contains("\"coins\":2"));
        std::fs::remove_file(d).ok();
    }
}
#[test]
fn refusals() {
    let d = dump(25, "r");
    let (c, out, _) = run(&["--dump", &d], "not-an-address\n");
    assert_eq!(c, 1); assert!(out.contains("bad_input"));
    let (c, _, _) = run(&["--dump", &d, "--chain", "ltc"], &format!("{FUNDED}\n"));
    assert_eq!(c, 1, "a btc address is not an ltc address");
    assert_eq!(run(&[], "").0, 2);
    assert_eq!(run(&["--dump", "/nonexistent"], "").0, 2);
    let t = std::fs::read(&d).unwrap();
    std::fs::write(&d, &t[..t.len() - 3]).unwrap();
    let (c, _, err) = run(&["--dump", &d], "");
    assert_eq!(c, 2); assert!(err.contains("bad_dump"));
    std::fs::remove_file(d).ok();
}
