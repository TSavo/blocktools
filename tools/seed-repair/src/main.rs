//! seed-repair: read a (possibly mistyped) BIP39 / Electrum 2.x phrase, print checksum-valid
//! candidates as JSON lines. Output CONTAINS SECRETS (field "mnemonic").
//! Thin wrapper around blocktools_secrets::repair.
use blocktools_secrets::repair::{self, Scheme};
use std::io::Read;

const MAX_INPUT: u64 = 4096;

fn bad(e: &str) -> ! { blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"bad_input","error":"{e}"}}"#); std::process::exit(2) }

fn main() {
    blocktools_io::help(r#"seed-repair [--max N] [--scheme bip39|electrum|any] < damaged phrase -> {"mnemonic","candidate"}; `?` = unknown word (two `?` budgeted); one word short = missing at any position; pairwise swaps"#);
    let args: Vec<String> = std::env::args().collect();
    let mut max_out = 1000usize;
    let mut scheme = Scheme::Bip39;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            // finding:R1-2: an unknown --scheme (or a non-number --max) is refused, never silently defaulted.
            "--max" => { max_out = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or_else(|| bad("bad_max")); i += 1; }
            "--scheme" => {
                scheme = args.get(i + 1).and_then(|s| Scheme::parse(s)).unwrap_or_else(|| bad("unknown_scheme"));
                i += 1;
            }
            _ => { blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"bad_input"}}"#); std::process::exit(2); }
        }
        i += 1;
    }
    let mut raw = Vec::new();
    let res = std::io::stdin().take(MAX_INPUT).read_to_end(&mut raw);
    if res.is_err() { blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"bad_input"}}"#); std::process::exit(2); }
    let text = String::from_utf8_lossy(&raw).to_lowercase();
    let tokens: Vec<String> = text.split(|c: char| !(c.is_ascii_lowercase() || c == '?')).filter(|t| !t.is_empty() && t.len() <= 16).map(String::from).collect();
    match repair::repair_missing_scheme(&tokens, max_out, scheme) {
        Ok(v) => {
            for (n, (w, c)) in v.iter().enumerate() {
                blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"checksum_ok","candidate":{n},"changed_words":{c},"mnemonic":"{}"}}"#, w.join(" "));
            }
            blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"{}","count":{}}}"#, if v.is_empty() {"no_candidates"} else {"done"}, v.len());
        }
        Err(s) => { blocktools_io::outln!(r#"{{"tool":"seed-repair","status":"{s}","count":0}}"#); std::process::exit(1); }
    }
}
