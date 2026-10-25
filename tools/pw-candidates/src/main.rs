//! pw-candidates: expand a token list into password candidates (btcrecover-style, from public
//! docs only: product of tokens, case variants, adjacent swaps, digit append/prepend,
//! keyboard-adjacent substitutions). Bounded by --max. Output CONTAINS SECRETS (one
//! candidate per line). Pipe into a wallet opener: `pw-candidates T | while read p; do
//! printf '%s\n' "$p"; cat FILE; done | opener`.
mod expand;
use expand::expand;
use std::io::{BufRead, Write};

fn main() {
    blocktools_io::help(r#"pw-candidates [--max N] [--rules case,swap,typo,digit] [FILE]: expand a token list (one token per line, or space-separated on stdin) into password candidates. Output CONTAINS SECRETS (one candidate per line). Default rules: case,swap,digit. Default --max 1000. Pipe into a wallet opener."#);
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut max = 1000usize;
    let mut rules: Vec<&str> = vec!["case", "swap", "digit"];
    let mut file: Option<String> = None;
    let mut i = 0;
    while i < a.len() {
        match a[i].as_str() {
            "--max" => { max = a.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(1000).min(100_000); i += 2; }
            "--rules" => {
                let s = a.get(i + 1).map(String::as_str).unwrap_or("");
                rules = s.split(',').filter(|r| matches!(*r, "case"|"swap"|"typo"|"digit")).collect();
                i += 2;
            }
            s if !s.starts_with('-') => { file = Some(s.into()); i += 1; }
            _ => { eprintln!("pw-candidates: bad flag"); std::process::exit(2); }
        }
    }
    let mut tokens: Vec<String> = Vec::new();
    if let Some(p) = file {
        let t = std::fs::read_to_string(&p).unwrap_or_else(|_| { eprintln!("pw-candidates: cannot read {p}"); std::process::exit(2); });
        for line in t.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            tokens.extend(line.split_whitespace().map(str::to_string));
        }
    } else {
        for line in std::io::stdin().lock().lines().flatten() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }
            tokens.extend(line.split_whitespace().map(str::to_string));
        }
    }
    if tokens.is_empty() { eprintln!("pw-candidates: no tokens"); std::process::exit(2); }
    let cands = expand(&tokens, &rules, max);
    let mut out = std::io::stdout().lock();
    for c in &cands {
        if writeln!(out, "{c}").is_err() { std::process::exit(0); }
    }
}

#[cfg(test)]
mod tests {
    use super::expand::expand;
    #[test]
    fn product_and_case() {
        let v = expand(&["btcr".into(), "test".into()], &["case"], 100);
        assert!(v.iter().any(|s| s == "btcrtest"));
        assert!(v.iter().any(|s| s == "btcr test"));
        assert!(v.iter().any(|s| s == "BTCRTEST") || v.iter().any(|s| s == "Btcrtest"));
    }
    #[test]
    fn swap_bound_and_fixture() {
        assert!(expand(&["ab".into()], &["swap"], 10).iter().any(|s| s == "ba"));
        assert_eq!(expand(&["password".into()], &["case", "swap", "digit", "typo"], 5).len(), 5);
        assert!(expand(&["btcr-test-password".into()], &["case"], 20).iter().any(|s| s == "btcr-test-password"));
    }
}
