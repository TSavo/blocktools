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
    let mut c = Command::new(env!("CARGO_BIN_EXE_contract-trace")).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
}
fn body(req: &[u8]) -> String { let h = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap(); String::from_utf8_lossy(&req[h + 4..]).into() }
fn res(v: serde_json::Value) -> (u16, String) { (200, serde_json::json!({"jsonrpc":"2.0","id":1,"result":v}).to_string()) }
const TO: &str = "0x00000000000000000000000000000000000000aa";
const CID: (u16, &str) = (200, r#"{"jsonrpc":"2.0","id":1,"result":"0x1"}"#);
fn tmp(name: &str, body: &str) -> String { let p = std::env::temp_dir().join(format!("ct-{}-{name}", std::process::id())); std::fs::write(&p, body).unwrap(); p.to_string_lossy().into() }
fn trace() -> serde_json::Value { serde_json::json!({"type":"CALL","from":"0x01","to":TO,"input":"0x313ce567","output":"0x","gas":"0x1","gasUsed":"0x1",
    "calls":[{"type":"STATICCALL","input":"0x70a08231","calls":[{"type":"CALL","input":"0x"}]},{"type":"DELEGATECALL","input":"0x"}]}) }

#[test]
fn trace_refused_without_allow_unlisted_nothing_sent() {
    let (u, log) = mock(vec![]);
    let (c, out, err) = run(&[&u, TO, "decimals()"], "");
    assert_eq!(c, 1, "{err}"); assert!(out.is_empty());
    assert!(err.contains("\"refused\"") && err.contains("--allow-unlisted"), "{err}");
    assert!(log.lock().unwrap().is_empty());
}

#[test]
fn call_tracer_frames_with_state_overrides() {
    let st = tmp("st.json", &format!(r#"{{"{TO}": {{"balance":"1000","stateDiff":{{"0x{}":"0x{}"}}}}}}"#, "0".repeat(64), "1".repeat(64)));
    let abi = tmp("abi.txt", "decimals() returns (uint8)\nbalanceOf(address) returns (uint256)\n");
    let (u, log) = mock(vec![(CID.0, CID.1.into()), res(trace())]);
    let (c, out, err) = run(&[&u, TO, "decimals()", "--allow-unlisted", "--state", &st, "--abi", &abi, "--from", "0x00000000000000000000000000000000000000bb"], "");
    assert_eq!(c, 0, "{err}");
    let lines: Vec<serde_json::Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines.iter().map(|l| (l["depth"].as_u64().unwrap(), l["type"].as_str().unwrap().to_string())).collect::<Vec<_>>(),
        vec![(0, "CALL".into()), (1, "STATICCALL".into()), (2, "CALL".into()), (1, "DELEGATECALL".into())]);
    assert_eq!(lines[0]["function"], "decimals()"); assert_eq!(lines[0]["chain_id"], 1);
    assert!(lines[0]["call"].to_string().contains("decimals"), "{}", lines[0]);
    assert!(lines.iter().all(|l| l.get("calls").is_none()));
    let req = body(&log.lock().unwrap()[1]);
    let v: serde_json::Value = serde_json::from_str(&req).unwrap();
    assert_eq!(v["method"], "debug_traceCall");
    assert_eq!(v["params"][0]["data"], "0x313ce567");
    assert_eq!(v["params"][2]["tracer"], "callTracer");
    let so = v["params"][2]["stateOverrides"].as_object().unwrap();
    assert_eq!(so.values().next().unwrap()["balance"], "0x3e8");
}

#[test]
fn call_only_sends_eth_call_with_overrides() {
    let st = tmp("st2.json", &format!(r#"{{"{TO}": {{"code":"0x6000"}}}}"#));
    let (u, log) = mock(vec![(CID.0, CID.1.into()), res(serde_json::json!(format!("0x{}", "0".repeat(63) + "6")))]);
    let (c, out, err) = run(&[&u, TO, "--data", "0x313ce567", "--call-only", "--state", &st], "");
    assert_eq!(c, 0, "{err}");
    let o: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(o["state_overrides"], 1); assert!(o["returndata"].as_str().unwrap().ends_with('6'));
    let v: serde_json::Value = serde_json::from_str(&body(&log.lock().unwrap()[1])).unwrap();
    assert_eq!(v["method"], "eth_call"); assert_eq!(v["params"].as_array().unwrap().len(), 3);
}

#[test]
fn reverted_top_frame_prints_frames_and_exits_1() {
    let mut t = trace(); t["error"] = serde_json::json!("execution reverted"); t["revertReason"] = serde_json::json!("nope");
    let (u, _) = mock(vec![(CID.0, CID.1.into()), res(t)]);
    let (c, out, err) = run(&[&u, TO, "--data", "0x00", "--allow-unlisted"], "");
    assert_eq!(c, 1); assert_eq!(out.lines().count(), 4);
    assert!(err.contains("\"reverted\"") && err.contains("nope"), "{err}");
}

#[test]
fn bad_state_and_chain_mismatch() {
    let st = tmp("st3.json", &format!(r#"{{"{TO}": {{"storage":{{}}}}}}"#));
    let (u, log) = mock(vec![]);
    let (c, _, err) = run(&[&u, TO, "--data", "0x00", "--state", &st], "");
    assert_eq!(c, 2, "{err}"); assert!(log.lock().unwrap().is_empty());
    let (u, log) = mock(vec![(CID.0, CID.1.into())]);
    let (c, _, err) = run(&[&u, TO, "--data", "0x00", "--call-only", "--chain-id", "137"], "");
    assert_eq!(c, 1); assert!(err.contains("chain_id_mismatch"), "{err}");
    assert_eq!(log.lock().unwrap().len(), 1);
}
