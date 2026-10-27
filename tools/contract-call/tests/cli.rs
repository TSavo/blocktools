//! End-to-end CLI tests against an in-process mock HTTP server that records the raw request bytes.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

type Log = Arc<Mutex<Vec<Vec<u8>>>>;
/// Serve `replies` (status, body) in order; one request per connection. Returns base URL and the request log.
/// The URL carries a per-mock random path token. A connection whose request line lacks it is a stray
/// (any other process on the host's loopback that hit this ephemeral port: on the shared Battleaxe runners a
/// stray once took the 302 reply and rpc got the fallback 500, failing redirect_not_followed_and_size_capped).
/// Strays get 404, are reported on stderr, and neither consume a reply nor enter the log.
fn mock(replies: Vec<(u16, String)>) -> (String, Log) {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
    let token = format!("/m{:x}{:x}{:x}", std::process::id(), nanos, N.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let url = format!("http://127.0.0.1:{}{token}", l.local_addr().unwrap().port());
    let log: Log = Arc::default();
    let lg = log.clone();
    std::thread::spawn(move || {
        let mut replies = replies.into_iter();
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };  // a failed accept (e.g. ECONNABORTED) must not kill the server
            let mut buf = vec![]; let mut tmp = [0u8; 65536];
            loop {
                let n = match s.read(&mut tmp) { Ok(n) => n, Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue, Err(_) => 0 };
                if n == 0 { break }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(h) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..h]).to_ascii_lowercase();
                    let cl = head.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                    if buf.len() >= h + 4 + cl { break }
                }
            }
            let line = String::from_utf8_lossy(&buf[..buf.iter().position(|&b| b == b'\n').unwrap_or(buf.len())]).into_owned();
            if !line.split(' ').nth(1).is_some_and(|t| t == token || t.starts_with(&format!("{token}/")) || t.starts_with(&format!("{token}?"))) {
                eprintln!("mock {token}: stray connection ignored (request line {line:?})");
                let _ = write!(s, "HTTP/1.1 404 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                continue;
            }
            lg.lock().unwrap().push(buf);
            let (code, body) = replies.next().unwrap_or((500, "{}".into()));
            let extra = if code == 302 { "Location: https://elsewhere.example/\r\n" } else { "" };
            let _ = write!(s, "HTTP/1.1 {code} X\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    (url, log)
}
fn run(args: &[&str], stdin: &str) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_contract-call")).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
}
fn body(req: &[u8]) -> String { let h = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap(); String::from_utf8_lossy(&req[h + 4..]).into() }
fn res(v: serde_json::Value) -> (u16, String) { (200, serde_json::json!({"jsonrpc":"2.0","id":1,"result":v}).to_string()) }
const TOKEN: &str = "0x00000000000000000000000000000000000000aa";
const HOLDER: &str = "0x00000000000000000000000000000000000000bb";
fn word(n: u64) -> String { format!("{:064x}", n) }

#[test]
fn balance_of_encodes_calldata_and_decodes_uint() {
    let (url, log) = mock(vec![res("0x89".into()), res(format!("0x{}", word(1000)).into())]);
    let (c, out, err) = run(&[&url, TOKEN, "balanceOf(address) returns (uint256)", HOLDER], "");
    assert_eq!(c, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["chain_id"], 137); assert_eq!(v["selector"], "0x70a08231");
    assert_eq!(v["outputs"][0]["value"], "1000"); assert_eq!(v["returns"], "(uint256)");
    let l = log.lock().unwrap();
    assert!(body(&l[0]).contains("eth_chainId"));
    let b = body(&l[1]);
    assert!(b.contains("eth_call") && b.contains(&format!("0x70a08231{}", "0".repeat(24) + "00000000000000000000000000000000000000bb")) && b.contains("latest"), "{b}");
}
#[test]
fn chain_id_mismatch_refused_before_eth_call() {
    let (url, log) = mock(vec![res("0x1".into())]);
    let (c, _, err) = run(&["--chain-id", "56", &url, TOKEN, "totalSupply() returns (uint256)"], "");
    assert_eq!(c, 1); assert!(err.contains("chain_id_mismatch"));
    assert_eq!(log.lock().unwrap().len(), 1);
}
#[test]
fn revert_is_decoded_error_string_and_custom_error() {
    // Error("nope")
    let rev = format!("0x08c379a0{}{}{}", word(32), word(4), format!("{:0<64}", "6e6f7065"));
    let (url, _) = mock(vec![res("0x1".into()), (200, serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":rev}}).to_string())]);
    let (c, out, err) = run(&[&url, TOKEN, "f()"], "");
    assert_eq!(c, 1); assert!(out.is_empty());
    assert!(err.contains(r#""status":"reverted""#) && err.contains(r#""value":"nope""#), "{err}");
    // custom error Unauthorized(address) via --error
    let sel = "0x8e4a23d6"; // keccak("Unauthorized(address)")[..4]
    let (url, _) = mock(vec![res("0x1".into()), (200, serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":format!("{sel}{}", word(0xbb))}}).to_string())]);
    let (c, _, err) = run(&["--error", "Unauthorized(address who)", &url, TOKEN, "f()"], "");
    assert_eq!(c, 1); assert!(err.contains("Unauthorized(address)") && err.contains(r#""name":"who""#), "{err}");
}
#[test]
fn empty_return_is_not_success() {
    let (url, _) = mock(vec![res("0x1".into()), res("0x".into())]);
    let (c, out, err) = run(&[&url, TOKEN, "decimals() returns (uint8)"], "");
    assert_eq!(c, 1); assert!(out.is_empty()); assert!(err.contains("empty_return"));
}
#[test]
fn dirty_return_refused() {
    let (url, _) = mock(vec![res("0x1".into()), res(format!("0x{}", word(300)).into())]);
    let (c, _, err) = run(&[&url, TOKEN, "decimals() returns (uint8)"], "");
    assert_eq!(c, 1); assert!(err.contains("bad_return") && err.contains("dirty_uint8"));
}
#[test]
fn read_calls_every_view_getter_only() {
    let abi = std::env::temp_dir().join(format!("cc-abi-{}.json", std::process::id()));
    std::fs::write(&abi, r#"[{"type":"function","name":"decimals","inputs":[],"outputs":[{"type":"uint8"}],"stateMutability":"view"},
      {"type":"function","name":"mint","inputs":[],"outputs":[{"type":"bool"}],"stateMutability":"nonpayable"},
      {"type":"function","name":"balanceOf","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}],"stateMutability":"view"},
      {"type":"function","name":"name","inputs":[],"outputs":[{"type":"string"}],"stateMutability":"view"}]"#).unwrap();
    let s = format!("0x{}{}{}", word(32), word(3), format!("{:0<64}", "616263"));
    let (url, log) = mock(vec![res("0x1".into()), res(format!("0x{}", word(18)).into()), res(s.into())]);
    let (c, out, err) = run(&[&url, TOKEN, "--abi", abi.to_str().unwrap(), "--read"], "");
    assert_eq!(c, 0, "{err}");
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains(r#""value":"18""#) && lines[1].contains(r#""value":"abc""#));
    assert_eq!(log.lock().unwrap().len(), 3);
}
#[test]
fn stdin_json_lines_and_block_number() {
    let (url, log) = mock(vec![res("0x1".into()), res(format!("0x{}", word(5)).into())]);
    let (c, out, _) = run(&[&url], &format!(r#"{{"to":"{TOKEN}","sig":"balanceOf(address) returns (uint256)","args":["{HOLDER}"],"block":"100"}}"#));
    assert_eq!(c, 0); assert!(out.contains(r#""block":"0x64""#));
    assert!(body(&log.lock().unwrap()[1]).contains(r#""0x64""#));
}
#[test]
fn bad_args_decided_locally_nothing_sent() {
    let (url, log) = mock(vec![]);
    let (c, _, err) = run(&[&url, TOKEN, "balanceOf(address) returns (uint256)", "0x12"], "");
    assert_eq!(c, 2, "{err}");
    let (c, _, _) = run(&[&url, TOKEN, "balanceOf(address)"], "");
    assert_eq!(c, 2);
    assert!(log.lock().unwrap().is_empty());
}
#[test]
fn policy_deny_eth_call_sends_nothing_and_auth_redacted() {
    let p = std::env::temp_dir().join(format!("cc-pol-{}.json", std::process::id()));
    std::fs::write(&p, r#"{"version":1,"rpc":{"deny":["eth_call"]}}"#).unwrap();
    let (url, log) = mock(vec![res("0x1".into())]);
    let (c, _, err) = run(&["--policy", p.to_str().unwrap(), &url, TOKEN, "f()"], "");
    assert_eq!(c, 1); assert!(err.contains("method_denied_by_policy"));
    assert!(log.lock().unwrap().iter().all(|r| !body(r).contains("eth_call")));
    let a = std::env::temp_dir().join(format!("cc-auth-{}", std::process::id()));
    std::fs::write(&a, "Bearer sekrit-token-123").unwrap();
    let (url, log) = mock(vec![(200, r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"bad sekrit-token-123"}}"#.into())]);
    let (c, out, err) = run(&["--auth-file", a.to_str().unwrap(), &url, TOKEN, "f()"], "");
    assert_eq!(c, 1); assert!(!out.contains("sekrit") && !err.contains("sekrit"), "{err}");
    assert!(String::from_utf8_lossy(&log.lock().unwrap()[0]).contains("sekrit-token-123"));
}
