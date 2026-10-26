//! keystore-open: Ethereum Web3 Secret Storage v3 JSON + password -> address
//! and private key. Thin wrapper around blocktools_secrets::keystore. Output CONTAINS SECRETS ("private_key").
//! stdin: first line = password, rest = keystore JSON.
//! With --password-tty the password is asked from the human on /dev/tty and
//! all of stdin is the keystore JSON.
use blocktools_secrets::keystore;
use std::io::Read;
use zeroize::Zeroizing;

fn st(s: &str) -> ! { blocktools_io::outln!(r#"{{"tool":"keystore-open","status":"{s}"}}"#); std::process::exit(blocktools_io::exit_code(s)) }

fn read_tty_password() -> Zeroizing<String> {
    blocktools_tty::read_secret("keystore password (not echoed): ").unwrap_or_else(|| st("bad_input"))
}

fn main() {
    blocktools_io::help("keystore-open [--password-tty] < password line + Ethereum V3 keystore JSON -> address + private key");
    let a: Vec<String> = std::env::args().collect();
    let tty = match a.get(1).map(|s| s.as_str()) { None => false, Some("--password-tty") if a.len() == 2 => true, _ => st("bad_input") };
    let mut raw = Zeroizing::new(Vec::new());
    std::io::stdin().take(keystore::MAX_FILE).read_to_end(&mut raw).unwrap_or_else(|_| st("bad_input"));
    let text = Zeroizing::new(String::from_utf8(raw.to_vec()).unwrap_or_else(|_| st("bad_input")));
    let (pw, json) = if tty {
        (read_tty_password(), text.as_str())
    } else {
        let (p, rest) = text.split_once('\n').unwrap_or_else(|| st("bad_input"));
        (Zeroizing::new(p.trim_end_matches('\r').to_string()), rest)
    };
    match keystore::open_v3(json, pw.as_bytes()) {
        Ok((addr, k)) => blocktools_io::outln!(r#"{{"tool":"keystore-open","status":"ok","kind":"eth","address":"{addr}","private_key":"{}"}}"#, k.as_str()),
        Err(e) => st(e),
    }
}

