//! log-decode CLI: getLogs envelope, receipts, JSON lines, filters, refusals.
use std::io::Write;
use std::process::{Command, Stdio};
fn run(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_log-decode")).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
}
const T: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
const SIG: &str = "Transfer(address indexed from,address indexed to,uint256 value)";
fn log(addr: &str, t0: &str) -> String {
    format!(r#"{{"address":"{addr}","topics":["{t0}","0x{:064x}","0x{:064x}"],"data":"0x{:064x}","blockNumber":"0x10","logIndex":"0x2"}}"#, 0xb1, 0xb2, 7)
}
const A: &str = "0x00000000000000000000000000000000000000aa";
const C: &str = "0x00000000000000000000000000000000000000cc";
#[test]
fn getlogs_envelope_decodes_with_metadata() {
    let inp = format!(r#"{{"jsonrpc":"2.0","id":1,"result":[{},{}]}}"#, log(A, T), log(C, &format!("0x{:064x}", 9)));
    let (c, out, err) = run(&["--sig", SIG], &inp);
    assert_eq!(c, 0, "{err}");
    let l: Vec<serde_json::Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(l.len(), 2);
    assert_eq!(l[0]["event"], "Transfer"); assert_eq!(l[0]["args"][2]["value"], "7");
    assert_eq!(l[0]["block_number"], 16); assert_eq!(l[0]["log_index"], 2);
    assert_eq!(l[1]["status"], "no_match");
    let (_, out, _) = run(&["--sig", SIG, "--only-matched"], &inp);
    assert_eq!(out.lines().count(), 1);
    let (_, out, _) = run(&["--sig", SIG, "--address", C], &inp);
    assert_eq!(out.lines().count(), 1); assert!(out.contains("no_match"));
}
#[test]
fn receipt_and_json_lines() {
    let rc = format!(r#"{{"result":{{"status":"0x1","logs":[{}]}}}}"#, log(A, T));
    let (c, out, _) = run(&["--sig", SIG], &rc);
    assert_eq!(c, 0); assert!(out.contains("Transfer"));
    let jl = format!("{}\n{}\n", log(A, T), log(A, T));
    let (c, out, _) = run(&["--sig", SIG], &jl);
    assert_eq!(c, 0); assert_eq!(out.lines().count(), 2);
}
#[test]
fn refusals() {
    assert_eq!(run(&[], &log(A, T)).0, 2);
    assert_eq!(run(&["--sig", SIG], "not json").0, 2);
    let bad = log(A, T).replace(T, "0x1234");
    let (c, err, _) = run(&["--sig", SIG], &bad);
    assert_eq!(c, 2); assert!(err.contains("topic"), "{err}");
    // indexed/data mismatch: same topic0, data too short
    let short = log(A, T).replace(&format!("0x{:064x}\",\"blockNumber", 7), "0x\",\"blockNumber");
    let (c, out, err) = run(&["--sig", SIG], &short);
    assert!(c != 0 || out.contains("no_match"), "{out}{err}");
}
