//! seed-to-master: seed phrase (+ optional passphrase) -> BIP32 master key(s).
//! stdin JSON lines: optional {"passphrase":"..."} then {"mnemonic":"...","candidate":N}, or a bare phrase line.
//! A phrase is tried as BIP39 AND as an Electrum (2.x+) seed; every valid reading is
//! one output line with its "scheme". If the phrase has extra words (e.g. a note
//! line), the trailing 12/13/15/18/21/24 words are tried too (sliding window).
//! --passphrase-prompt asks the human on /dev/tty with echo off (never argv/env).
//! Output CONTAINS SECRETS ("xprv", "seed"). One job: phrase -> master key.
use std::io::{BufRead, Read};
use blocktools_secrets::seed::{readings, Reading};
use zeroize::Zeroizing;

fn main() {
    blocktools_io::help("seed-to-master [--passphrase-prompt] < {\"mnemonic\":...} lines -> master keys (BIP39 and Electrum standard/segwit; 2FA and old-Electrum: unsupported, planned)");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut passphrase = Zeroizing::new(String::new());
    match args.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice() {
        [] => {}
        ["--passphrase-prompt"] => match blocktools_tty::read_secret("BIP39/Electrum passphrase (not echoed, empty = none): ") {
            Some(p) => passphrase = p,
            None => { blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"bad_input"}}"#); std::process::exit(2) }
        },
        ["--help"] => { println!("seed-to-master [--passphrase-prompt]  < {{\"mnemonic\":...}} lines\n  tries BIP39 and Electrum (standard/segwit); 2FA and old-Electrum: unsupported (planned)"); return }
        _ => { blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"bad_input"}}"#); std::process::exit(2) }
    }
    let mut n = 0u64;
    let reader = std::io::stdin().lock().take(16 << 20);
    for line in reader.lines().map_while(Result::ok) {
        let line = Zeroizing::new(line);
        let t = line.trim();
        // A bare phrase line (e.g. an Electrum seed file) is read as {"mnemonic": line}.
        let bare = !t.is_empty() && t.split_whitespace().all(|w| w.chars().all(char::is_alphabetic));
        let Ok(v) = (if bare { Ok(serde_json::json!({"mnemonic": t})) } else { serde_json::from_str::<serde_json::Value>(t) }) else { continue };
        if let Some(p) = v.get("passphrase").and_then(|m| m.as_str()) {
            if p.len() <= 1024 { passphrase = Zeroizing::new(p.to_string()); }
        }
        let Some(m) = v.get("mnemonic").and_then(|m| m.as_str()) else { continue };
        if m.len() > 4096 { continue }
        let cand = v.get("candidate").and_then(|c| c.as_u64()).unwrap_or(0);
        let mut got = 0;
        for r in readings(m, &passphrase) { match r {
            Reading::Master { scheme, xprv, seed } => {
                let hex = Zeroizing::new(blocktools_core::hex_enc(&seed[..]));
                blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"ok","candidate":{cand},"scheme":"{scheme}","xprv":"{}","seed":"{}"}}"#, xprv.as_str(), hex.as_str());
                n += 1; got += 1;
            }
            Reading::Unsupported { scheme } => { blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"unsupported","candidate":{cand},"scheme":"{scheme}"}}"#) }
        } }
        if got == 0 {
            blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"checksum_fail","candidate":{cand}}}"#)
        }
    }
    blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"done","count":{n}}}"#);
}

