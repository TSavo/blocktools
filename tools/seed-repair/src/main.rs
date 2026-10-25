//! seed-repair: read a (possibly mistyped) BIP39 phrase, print checksum-valid
//! candidates as JSON lines. Output CONTAINS SECRETS (field "mnemonic").
//! Thin wrapper around blocktools_secrets::repair::repair.
use std::io::Read;

const MAX_INPUT: u64 = 4096;

fn main() {
    blocktools_io::help(r#"seed-repair < damaged BIP39 phrase -> checksum-valid candidate phrases {"mnemonic","candidate"}; `?` = unknown word, one word short = missing at any position"#);
    let args: Vec<String> = std::env::args().collect();
    let mut max_out = 1000usize;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--max" => { max_out = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(1000); i += 1; }
            _ => { blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"bad_input"}}"#); std::process::exit(2); }
        }
        i += 1;
    }
    let mut raw = Vec::new();
    // Pipe principle: the phrase arrives on stdin only, never via argv/env/file name.
    let res = std::io::stdin().take(MAX_INPUT).read_to_end(&mut raw);
    if res.is_err() { blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"bad_input"}}"#); std::process::exit(2); }
    let text = String::from_utf8_lossy(&raw).to_lowercase();
    let tokens: Vec<String> = text.split(|c: char| !(c.is_ascii_lowercase() || c == '?')).filter(|t| !t.is_empty() && t.len() <= 16).map(String::from).collect();
    match blocktools_secrets::repair::repair_missing(&tokens, max_out) {
        Ok(v) => {
            for (n, (w, c)) in v.iter().enumerate() {
                // Words come from the BIP39 wordlist (a-z only), so no JSON escaping is needed.
                blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"checksum_ok","candidate":{n},"changed_words":{c},"mnemonic":"{}"}}"#, w.join(" "));
            }
            blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"{}","count":{}}}"#, if v.is_empty() {"no_candidates"} else {"done"}, v.len());
        }
        Err(s) => { blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"{s}","count":0}}"#); std::process::exit(1); }
    }
}

