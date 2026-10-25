//! classify: unknown wallet material -> public JSON lines, one per item:
//!   {"tool":"classify","status":"ok","class":"mnemonic","line":1,"fp":"ab12..9f0e"}
//! Reads FILE (one argument) or stdin, at most 16 MiB. Never echoes secrets: secret items get a
//! SHA-256 fingerprint (first/last 4 hex); only addresses ("address") and xpubs ("xpub") are echoed.
//! Classes: see blocktools_core::classify::CLASSES. Use it to pick the reader (recipes/recover.sh).
use blocktools_core::classify::classify;
use serde_json::json;
use std::io::Read;

fn main() {
    blocktools_io::help("classify [FILE] (or stdin) -> {\"class\",\"line\",\"fp\"} per item; no secret is ever echoed");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut buf = Vec::new();
    let r = match a.as_slice() {
        [] => std::io::stdin().take(16 << 20).read_to_end(&mut buf),
        [f] if !f.starts_with('-') => std::fs::File::open(f).and_then(|f| f.take(16 << 20).read_to_end(&mut buf)),
        _ => { blocktools_io::outln!(r#"{{"tool":"classify","status":"bad_input"}}"#); std::process::exit(2) }
    };
    if r.is_err() { blocktools_io::outln!(r#"{{"tool":"classify","status":"bad_input","error":"cannot read input"}}"#); std::process::exit(2) }
    for row in classify(&buf) {
        let mut v = json!({"tool":"classify","status":"ok","class":row.class,"line":row.line,"fp":row.fp});
        if let Some(p) = row.public { v[if row.class == "xpub" { "xpub" } else { "address" }] = json!(p) }
        if let Some(c) = row.chain { v["chain"] = json!(c) }
        blocktools_io::outln!("{v}");
    }
}
