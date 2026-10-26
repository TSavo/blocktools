//! End-to-end CLI tests against an in-process mock HTTP server that records the raw request bytes.
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

type Log = Arc<Mutex<Vec<Vec<u8>>>>;
/// Serve `replies` (status, body) in order; one request per connection. Returns base URL and the request log.
fn mock(replies: Vec<(u16, String)>) -> (String, Log) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", l.local_addr().unwrap().port());
    let log: Log = Arc::default();
    let lg = log.clone();
    std::thread::spawn(move || {
        let mut replies = replies.into_iter();
        for s in l.incoming() {
            let mut s = s.unwrap();
            let mut buf = vec![]; let mut tmp = [0u8; 65536];
            loop {
                let n = s.read(&mut tmp).unwrap_or(0); if n == 0 { break }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(h) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&buf[..h]).to_ascii_lowercase();
                    let cl = head.lines().find_map(|l| l.strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().unwrap())).unwrap_or(0);
                    if buf.len() >= h + 4 + cl { break }
                }
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
    let mut c = Command::new(env!("CARGO_BIN_EXE_rpc")).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    c.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into(), String::from_utf8_lossy(&o.stderr).into())
}
fn body(req: &[u8]) -> &[u8] { let h = req.windows(4).position(|w| w == b"\r\n\r\n").unwrap(); &req[h + 4..] }

#[test]
fn passthrough_sends_exact_bytes_and_prints_raw_response() {
    let (url, log) = mock(vec![(200, r#"{"jsonrpc":"2.0","id":7,"result":"0x10"}"#.into())]);
    let req = r#"{"jsonrpc":"2.0", "id":7,"method":"eth_blockNumber","params":[]}"#;
    let (c, out, _) = run(&[&url], req);
    assert_eq!(c, 0);
    assert_eq!(out.trim(), r#"{"jsonrpc":"2.0","id":7,"result":"0x10"}"#);
    assert_eq!(body(&log.lock().unwrap()[0]), req.as_bytes());
}
#[test]
fn batch_with_one_error_exits_nonzero() {
    let (url, _) = mock(vec![(200, r#"[{"id":1,"result":"0x1"},{"id":2,"error":{"code":-32601,"message":"nope"}}]"#.into())]);
    let (c, out, err) = run(&[&url], r#"[{"jsonrpc":"2.0","id":1,"method":"eth_chainId"},{"jsonrpc":"2.0","id":2,"method":"eth_x"}]"#);
    assert_eq!(c, 1); assert!(out.contains("0x1")); assert!(err.contains("rpc_error") && err.contains("nope"));
}
#[test]
fn rpc_error_goes_to_stderr() {
    let (url, _) = mock(vec![(200, r#"{"id":1,"error":{"code":-32000,"message":"bad"}}"#.into())]);
    let (c, out, err) = run(&[&url, "eth_call", "[]"], "");
    assert_eq!(c, 1); assert!(out.is_empty()); assert!(err.contains(r#""status":"rpc_error""#));
}
#[test]
fn planted_denied_methods_are_refused_and_nothing_is_sent() {
    for (m, p, code) in [("dumpprivkey", "[\"1abc\"]", "method_exports_secrets"), ("walletpassphrase", "[\"x\",60]", "method_unlocks_wallet"),
        ("personal_unlockAccount", "[]", "method_unlocks_wallet"), ("eth_sign", "[]", "method_wallet_signs"),
        ("listdescriptors", "[true]", "method_exports_secrets"), ("signrawtransactionwithwallet", "[\"00\"]", "method_wallet_signs"),
        ("eth_sendRawTransaction", "[\"0x00\"]", "broadcast_needs_sendraw")] {
        let (url, log) = mock(vec![]);
        let (c, out, err) = run(&[&url, m, p], "");
        assert_eq!(c, 1, "{m}"); assert!(out.is_empty()); assert!(err.contains(code), "{m}: {err}");
        assert!(log.lock().unwrap().is_empty(), "{m} reached the server");
        // and the same inside a batch on stdin
        let (url, log) = mock(vec![]);
        let (c, _, _) = run(&[&url], &format!(r#"[{{"id":1,"method":"eth_chainId"}},{{"id":2,"method":"{m}","params":{p}}}]"#));
        assert_eq!(c, 1); assert!(log.lock().unwrap().is_empty());
    }
}
#[test]
fn policy_adds_refusals() {
    let d = std::env::temp_dir().join(format!("rpc-pol-{}", std::process::id()));
    std::fs::write(&d, r#"{"version":1,"rpc":{"deny":["eth_call"]}}"#).unwrap();
    let (url, log) = mock(vec![]);
    let (c, _, err) = run(&["--policy", d.to_str().unwrap(), &url, "eth_call", "[]"], "");
    assert_eq!(c, 1); assert!(err.contains("method_denied_by_policy")); assert!(log.lock().unwrap().is_empty());
    std::fs::write(&d, r#"{"version":1,"rpc":{"allow":["eth_sign"]}}"#).unwrap();
    let (c, _, err) = run(&["--policy", d.to_str().unwrap(), &url, "eth_call", "[]"], "");
    assert_eq!(c, 2); assert!(err.contains("policy_unknown_key"));
}
const TX: &str = r#"{"from":"0x1111111111111111111111111111111111111111","to":"0x2222222222222222222222222222222222222222","value":"0xde0b6b3a7640000","data":"0xa9059cbb0000","chainId":"0x1"}"#;
#[test]
fn wallet_sign_methods_refused_by_default() {
    for m in ["eth_sendTransaction", "eth_signTypedData_v4"] {
        let (url, log) = mock(vec![]);
        let (c, _, err) = run(&[&url, m, &format!("[{TX}]")], "");
        assert_eq!(c, 1); assert!(err.contains("wallet_sign_needs_flag"), "{err}"); assert!(log.lock().unwrap().is_empty());
    }
}
#[test]
fn flagged_send_transaction_prints_summary_and_sends_exact_bytes() {
    let (url, log) = mock(vec![(200, r#"{"id":1,"result":"0x1"}"#.into()), (200, r#"{"id":5,"result":"0xabc"}"#.into())]);
    let req = format!(r#"{{"jsonrpc":"2.0","id":5,"method":"eth_sendTransaction","params":[{TX}]}}"#);
    let (c, out, err) = run(&["--allow-wallet-sign", &url], &req);
    assert_eq!(c, 0, "{err}"); assert!(out.contains("0xabc"));
    for s in ["0x2222222222222222222222222222222222222222", "1000000000000000000", "0xa9059cbb", "chain id"] { assert!(err.contains(s), "summary lacks {s}: {err}") }
    let l = log.lock().unwrap();
    assert_eq!(l.len(), 2); assert_eq!(body(&l[1]), req.as_bytes());
}
#[test]
fn flagged_send_transaction_chain_mismatch_refused() {
    let (url, log) = mock(vec![(200, r#"{"id":1,"result":"0x89"}"#.into())]);
    let (c, _, err) = run(&["--allow-wallet-sign", &url, "eth_sendTransaction", &format!("[{TX}]")], "");
    assert_eq!(c, 1); assert!(err.contains("wallet_sign_chain_mismatch")); assert_eq!(log.lock().unwrap().len(), 1);
}
#[test]
fn flagged_typed_data_summary_and_undecodable_refused() {
    let td = r#"{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"}],"Permit":[{"name":"spender","type":"address"},{"name":"value","type":"uint256"}]},"primaryType":"Permit","domain":{"name":"USD Coin","chainId":1},"message":{"spender":"0x3333333333333333333333333333333333333333","value":"115792089237316195423570985008687907853269984665640564039457584007913129639935"}}"#;
    let params = serde_json::json!(["0x1111111111111111111111111111111111111111", td]).to_string();
    let (url, log) = mock(vec![(200, r#"{"id":1,"result":"0x1"}"#.into()), (200, r#"{"id":1,"result":"0xsig"}"#.into())]);
    let (c, _, err) = run(&["--allow-wallet-sign", &url, "eth_signTypedData_v4", &params], "");
    assert_eq!(c, 0, "{err}");
    for s in ["Permit", "USD Coin", "spender", "0x3333333333333333333333333333333333333333"] { assert!(err.contains(s), "{s}: {err}") }
    assert_eq!(log.lock().unwrap().len(), 2);
    for bad in [r#""not json""#, r#"{"primaryType":"Permit"}"#, r#"{"types":{"Permit":[{"name":"a","type":"uint256"}]},"primaryType":"Permit","domain":{},"message":{"a":1,"hidden":2}}"#] {
        let (url, log) = mock(vec![(200, r#"{"id":1,"result":"0x1"}"#.into())]);
        let p = format!(r#"["0x1111111111111111111111111111111111111111",{bad}]"#);
        let (c, _, err) = run(&["--allow-wallet-sign", &url, "eth_signTypedData_v4", &p], "");
        assert_eq!(c, 1, "{bad}"); assert!(err.contains("wallet_sign_undecodable"), "{err}"); assert!(log.lock().unwrap().is_empty());
    }
}
#[test]
fn eth_sign_family_refused_even_with_flag() {
    for m in ["eth_sign", "personal_sign", "eth_signTransaction", "personal_sendTransaction", "eth_signTypedData", "eth_signTypedData_v3"] {
        let (url, log) = mock(vec![]);
        let (c, _, err) = run(&["--allow-wallet-sign", &url, m, "[]"], "");
        assert_eq!(c, 1, "{m}"); assert!(!err.contains("wallet_sign_needs_flag")); assert!(err.contains("refused")); assert!(log.lock().unwrap().is_empty());
    }
}
#[test]
fn auth_file_secret_never_on_stdout_or_stderr() {
    let secret = "S3cr3tPassw0rd-zz";
    let f = std::env::temp_dir().join(format!("rpc-auth-{}", std::process::id()));
    std::fs::write(&f, format!("rpcuser:{secret}\n")).unwrap();
    let b64 = { use std::process::Command as C; let o = C::new("sh").arg("-c").arg(format!("printf %s 'rpcuser:{secret}' | base64")).output().unwrap(); String::from_utf8(o.stdout).unwrap().trim().to_string() };
    // server echoes the credential in both a success and an error body
    let (url, log) = mock(vec![(200, format!(r#"{{"id":1,"result":"seen {secret} {b64}"}}"#)), (401, format!(r#"{{"id":1,"error":{{"code":-1,"message":"bad {secret} {b64}"}}}}"#)), (500, format!("oops {secret}"))]);
    for _ in 0..3 {
        let (_, out, err) = run(&["--auth-file", f.to_str().unwrap(), &url, "getblockcount"], "");
        for s in [secret, b64.as_str()] { assert!(!out.contains(s) && !err.contains(s), "leak: {out} {err}") }
    }
    let l = log.lock().unwrap();
    assert!(String::from_utf8_lossy(&l[0]).contains(&format!("Basic {b64}")), "header not sent");
    // env var form
    let (url, log2) = mock(vec![(200, r#"{"id":1,"result":1}"#.into())]);
    let o = Command::new(env!("CARGO_BIN_EXE_rpc")).args(["--auth-env", "RPC_T", &url, "getblockcount"]).env("RPC_T", format!("Bearer {secret}")).output().unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&log2.lock().unwrap()[0]).contains(&format!("Bearer {secret}")));
}
#[test]
fn credentials_on_command_line_refused() {
    let (c, _, err) = run(&["--user", "a:b", "http://127.0.0.1:1", "getblockcount"], ""); assert_eq!(c, 1); assert!(err.contains("credential_on_command_line"));
    let (c, _, err) = run(&["http://u:p@127.0.0.1:1", "getblockcount"], ""); assert_eq!(c, 1); assert!(err.contains("credential_on_command_line")); assert!(!err.contains(":p@"));
}
#[test]
fn redirect_not_followed_and_size_capped() {
    let (url, log) = mock(vec![(302, "{}".into())]);
    let (c, _, err) = run(&[&url, "eth_blockNumber"], ""); assert_eq!(c, 1); assert!(err.contains("redirect"), "{err}"); assert_eq!(log.lock().unwrap().len(), 1);
    let big = format!(r#"{{"id":1,"result":"{}"}}"#, "a".repeat(9 << 20));
    let (url, _) = mock(vec![(200, big)]);
    let (c, out, err) = run(&[&url, "eth_blockNumber"], ""); assert_eq!(c, 1); assert!(out.is_empty()); assert!(err.contains("http_error"), "{err}");
}
#[test]
fn response_with_private_key_withheld() {
    // public test vector: WIF of private key 1 (throwaway)
    let (url, _) = mock(vec![(200, r#"{"id":1,"result":{"privkey":"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"}}"#.into())]);
    let (c, out, err) = run(&["--protocol", "btc", &url, "getwalletinfo"], ""); assert_eq!(c, 1); assert!(out.is_empty()); assert!(err.contains("response_contains_secret"));
    assert!(!err.contains("KwDiBf89"));
}
#[test]
fn shortcuts_emit_tool_shapes() {
    let (url, log) = mock(vec![(200, r#"{"id":1,"result":"0x1"}"#.into()), (200, r#"{"id":1,"result":"0x5"}"#.into()), (200, r#"{"id":1,"result":"0xde0b6b3a7640000"}"#.into()), (200, r#"{"id":1,"result":"0x3b9aca00"}"#.into()), (200, r#"{"id":1,"result":"0x5f5e100"}"#.into())]);
    let (c, out, err) = run(&["--protocol", "evm", &url, "account", "0x1111111111111111111111111111111111111111"], "");
    assert_eq!(c, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v, serde_json::json!({"chain_id":1,"nonce":5,"balance":"1000000000000000000","max_fee_per_gas":"2100000000","max_priority_fee_per_gas":"100000000"}));
    assert_eq!(log.lock().unwrap().len(), 5);
    // esplora utxos: utxo-fetch line shape; dummy txid below is a throwaway, not a key
    let (url, _) = mock(vec![(200, r#"[{"txid":"aa00000000000000000000000000000000000000000000000000000000000000","vout":1,"value":5000}]"#.into())]);
    let (c, out, err) = run(&["--protocol", "esplora", &url, "utxos", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"], "");
    assert_eq!(c, 0, "{err}");
    assert_eq!(out.trim(), r#"{"address":"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq","amount":5000,"txid":"aa00000000000000000000000000000000000000000000000000000000000000","vout":1}"#);
    // bitcoind scantxoutset: exact sats
    let (url, _) = mock(vec![(200, r#"{"id":1,"result":{"success":true,"height":10,"unspents":[{"txid":"bb00000000000000000000000000000000000000000000000000000000000000","vout":0,"amount":0.29,"height":5}],"total_amount":0.29}}"#.into())]);
    let (c, out, _) = run(&["--protocol", "btc", &url, "utxos", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"], "");
    assert_eq!(c, 0); assert!(out.contains(r#""amount":29000000"#), "{out}");
}
#[test]
fn detection_and_chain_id_pin() {
    let (url, log) = mock(vec![(200, r#"{"id":1,"result":"0x89"}"#.into())]);
    let (c, _, err) = run(&["--chain-id", "1", &url, "eth_blockNumber"], "");
    assert_eq!(c, 1); assert!(err.contains("chain_id_mismatch")); assert_eq!(log.lock().unwrap().len(), 1);
    // shortcut probe: eth_chainId answers -> evm
    let (url, _) = mock(vec![(200, r#"{"id":1,"result":"0x1"}"#.into()), (200, r#"{"id":1,"result":"0x10"}"#.into())]);
    let (c, out, err) = run(&[&url, "height"], ""); assert_eq!(c, 0, "{err}"); assert!(out.contains(r#""height":16"#) && out.contains("evm"));
}
