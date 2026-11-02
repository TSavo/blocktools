//! siwe: EIP-4361 Sign-In with Ethereum messages, as a stdin/stdout filter. No keys, no signatures.
//!   siwe build [--raw] < fields.json     JSON fields (siwe camelCase names) -> the message text
//!   siwe parse [--domain D] [--nonce N] [--now RFC3339 | --check-time] < message
//! build: stdout one JSON line {tool,status:"ok",message} (or, with --raw, only the message bytes, no
//! newline, for msg-sign/msg-verify --message-file). Unknown keys, missing fields and invalid values are
//! bad_input (exit 2).
//! parse: the text must be valid EIP-4361 AND canonical (exactly what build prints for its fields: no CR,
//! no trailing newline or spaces). stdout {tool,status:"ok",fields,checked,unchecked}; a bad message is
//! {status:"refused",failures:[code]} (exit 1). Checks run only when asked: --domain (exact match of the
//! domain line's authority), --nonce (exact), --now/--check-time (expired at or after expirationTime,
//! not_yet_valid before notBefore). The signature is never checked here: use msg-verify on the same text.
use blocktools_io::outln;
use serde_json::json;
use siwe::{rfc3339_ms, Siwe};
use std::io::Read;

fn out(status: &str, mut v: serde_json::Value) -> ! {
    v["tool"] = json!("siwe"); v["status"] = json!(status);
    outln!("{v}");
    std::process::exit(blocktools_io::exit_code(status))
}
fn bad(e: &str) -> ! { out("bad_input", json!({"error": e})) }

fn main() {
    blocktools_io::help("siwe build [--raw] < fields.json  |  siwe parse [--domain D] [--nonce N] [--now RFC3339 | --check-time] < message");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let flag = |f: &str| a.iter().any(|x| x == f);
    let one = |f: &str| -> Option<String> {
        let mut it = a.iter().enumerate().filter(|(_, x)| *x == f);
        let r = it.next().map(|(i, _)| a.get(i + 1).cloned().unwrap_or_else(|| bad(&format!("{f} needs a value"))));
        if it.next().is_some() { bad(&format!("{f} given twice")) }
        r
    };
    let known = ["build", "parse", "--raw", "--domain", "--nonce", "--now", "--check-time"];
    let mut skip = false;
    for x in &a {
        if skip { skip = false; continue }
        if !known.contains(&x.as_str()) { bad(&format!("unknown argument {x}")) }
        skip = ["--domain", "--nonce", "--now"].contains(&x.as_str());
    }
    let mut buf = Vec::new();
    std::io::stdin().take((64 << 10) + 1).read_to_end(&mut buf).unwrap_or_else(|_| bad("cannot read stdin"));
    if buf.len() > 64 << 10 { bad("input over 64 KiB") }
    let text = String::from_utf8(buf).unwrap_or_else(|_| bad("input is not UTF-8"));
    match a.first().map(String::as_str) {
        Some("build") => {
            if one("--domain").is_some() || one("--nonce").is_some() || one("--now").is_some() || flag("--check-time") { bad("checks are for parse") }
            let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_else(|_| bad("fields must be one JSON object"));
            let m = Siwe::from_json(&v).unwrap_or_else(|e| bad(&e));
            m.validate().unwrap_or_else(|e| bad(e));
            let msg = m.render();
            if Siwe::parse(&msg).as_ref() != Ok(&m) { out("error", json!({"error":"render_parse_mismatch"})) }
            if flag("--raw") {
                use std::io::Write;
                let mut o = std::io::stdout().lock();
                if o.write_all(msg.as_bytes()).and_then(|_| o.flush()).is_err() { std::process::exit(0) }
                std::process::exit(0)
            }
            out("ok", json!({"message": msg}))
        }
        Some("parse") => {
            if flag("--raw") { bad("--raw is for build") }
            let now = match (one("--now"), flag("--check-time")) {
                (Some(_), true) => bad("--now or --check-time, not both"),
                (Some(t), false) => Some(rfc3339_ms(&t).unwrap_or_else(|| bad("--now must be an RFC 3339 date-time"))),
                (None, true) => Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or_else(|_| bad("clock before 1970"))),
                (None, false) => None,
            };
            let m = Siwe::parse(&text).unwrap_or_else(|e| out("refused", json!({"failures": [e]})));
            let (mut checked, mut unchecked, mut fail) = (vec![], vec!["signature"], vec![]);
            match one("--domain") { Some(d) => { checked.push("domain"); if d != m.domain { fail.push("domain_mismatch") } } None => unchecked.push("domain") }
            match one("--nonce") { Some(n) => { checked.push("nonce"); if n != m.nonce { fail.push("nonce_mismatch") } } None => unchecked.push("nonce") }
            match now {
                Some(t) => {
                    checked.push("time");
                    if m.expiration_time.as_deref().and_then(rfc3339_ms).is_some_and(|e| t >= e) { fail.push("expired") }
                    if m.not_before.as_deref().and_then(rfc3339_ms).is_some_and(|nb| t < nb) { fail.push("not_yet_valid") }
                }
                None => unchecked.push("time"),
            }
            if !fail.is_empty() { out("refused", json!({"failures": fail, "fields": m.to_json()})) }
            out("ok", json!({"fields": m.to_json(), "checked": checked, "unchecked": unchecked}))
        }
        _ => bad("first argument: build or parse"),
    }
}
