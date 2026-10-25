//! multibit-read: MultiBit Classic .key export -> {"wif"} per key. Output CONTAINS SECRETS.
//! Pipe to key-to-addresses (addresses) or tx-sign (keys). stdin: line 1 = password, rest = .key file.
//! Thin wrapper around blocktools_secrets::multibit.
use blocktools_secrets::multibit::{open, MAX_FILE};
use std::io::Read;
use zeroize::Zeroizing;

fn main() {
    blocktools_io::help("multibit-read < (password line, then MultiBit .key file) -> {\"wif\"} per key");
    let mut all = Zeroizing::new(String::new());
    if std::io::stdin().take(MAX_FILE as u64).read_to_string(&mut all).is_err() { blocktools_io::outln!(r#"{{"tool":"multibit-read","status":"bad_input"}}"#); std::process::exit(2) }
    let (pw, body) = all.split_once('\n').unwrap_or(("", &all));
    match open(body, pw.trim_end_matches('\r')) {
        Ok(k) => for w in k { blocktools_io::outln!(r#"{{"tool":"multibit-read","status":"ok","wif":"{}"}}"#, w.as_str()) },
        Err(e) => { blocktools_io::outln!(r#"{{"tool":"multibit-read","status":"{e}"}}"#); std::process::exit(1) }
    }
}
