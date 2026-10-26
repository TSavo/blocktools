//! seed-to-master: seed phrase (+ optional passphrase) -> BIP32 master key(s).
//! stdin JSON lines: optional {"passphrase":"..."} then {"mnemonic":"...","candidate":N}, or a bare phrase line.
//! A phrase is tried as BIP39 AND as an Electrum (2.x+) seed; every valid reading is
//! one output line with its "scheme". If the phrase has extra words (e.g. a note
//! line), the trailing 12/13/15/18/21/24 words are tried too (sliding window).
//! --passphrase-prompt asks the human on /dev/tty with echo off (never argv/env).
//! --passphrase-file FILE: candidate passphrases, one per line (SwapChan SCAN_JS PASSPHRASES): each
//!   phrase is tried with the empty passphrase first, then every non-empty line in file order; each
//!   output carries "passphrase_index" (0 = empty, N = line N of the non-empty lines). The file's
//!   text is never printed. A stdin {"passphrase"} field is refused (bad_input) in this mode.
//! Output CONTAINS SECRETS ("xprv", "seed"). One job: phrase -> master key.
use std::io::{BufRead, Read};
use blocktools_secrets::seed::{readings, Reading};
use zeroize::Zeroizing;

fn main() {
    blocktools_io::help("seed-to-master [--passphrase-prompt | --passphrase-file FILE] < {\"mnemonic\":...} lines -> master keys (BIP39 and Electrum standard/segwit; 2FA and old-Electrum: unsupported, planned)\n  --passphrase-file FILE  one candidate passphrase per line; tried after the empty one; outputs carry passphrase_index");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut passphrase = Zeroizing::new(String::new());
    let bad = || -> ! { blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"bad_input"}}"#); std::process::exit(2) };
    // --passphrase-file: candidate list (index 0 = empty passphrase).
    let mut file_cands: Option<Vec<Zeroizing<String>>> = None;
    match args.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice() {
        [] => {}
        ["--passphrase-prompt"] => match blocktools_tty::read_secret("BIP39/Electrum passphrase (not echoed, empty = none): ") {
            Some(p) => passphrase = p,
            None => { blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"bad_input"}}"#); std::process::exit(2) }
        },
        ["--passphrase-file", f] => {
            let mut b = Zeroizing::new(String::new());
            // 1 MiB, 10 000 candidates, 1024 bytes each; CRLF line ends are accepted.
            if std::fs::File::open(f).and_then(|h| h.take((1 << 20) + 1).read_to_string(&mut b)).is_err() || b.len() > 1 << 20 { bad() }
            let mut v = vec![Zeroizing::new(String::new())];
            for l in b.split('\n') { let l = l.strip_suffix('\r').unwrap_or(l); if !l.is_empty() { v.push(Zeroizing::new(l.to_string())) } }
            if v.len() > 10_001 || v.iter().any(|p| p.len() > 1024) { bad() }
            file_cands = Some(v);
        }
        _ => bad(),
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
            if file_cands.is_some() { blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"bad_input","reason":"passphrase_file_and_stdin_passphrase"}}"#); continue }
            if p.len() <= 1024 { passphrase = Zeroizing::new(p.to_string()); }
        }
        let Some(m) = v.get("mnemonic").and_then(|m| m.as_str()) else { continue };
        if m.len() > 4096 { continue }
        let cand = v.get("candidate").and_then(|c| c.as_u64()).unwrap_or(0);
        let mut got = 0;
        let single = [passphrase.clone()];
        let cands: &[Zeroizing<String>] = file_cands.as_deref().unwrap_or(&single);
        for (pi, pass) in cands.iter().enumerate() {
        let pij = if file_cands.is_some() { format!(r#","passphrase_index":{pi}"#) } else { String::new() };
        for r in readings(m, pass) { match r {
            Reading::Master { scheme, xprv, seed } => {
                let hex = Zeroizing::new(blocktools_core::hex_enc(&seed[..]));
                blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"ok","candidate":{cand}{pij},"scheme":"{scheme}","xprv":"{}","seed":"{}"}}"#, xprv.as_str(), hex.as_str());
                n += 1; got += 1;
            }
            // Unsupported readings do not depend on the passphrase: report once.
            Reading::Unsupported { scheme } => if pi == 0 { blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"unsupported","candidate":{cand},"scheme":"{scheme}"}}"#) },
        } }
        }
        if got == 0 {
            blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"checksum_fail","candidate":{cand}}}"#)
        }
    }
    blocktools_io::outln!(r#"{{"tool":"seed-to-master","status":"done","count":{n}}}"#);
}

