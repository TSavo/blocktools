//! seed-repair: read a (possibly mistyped) BIP39 phrase, print checksum-valid
//! candidates as JSON lines. Output CONTAINS SECRETS (field "mnemonic").
//! Input is treated as hostile data: bounded size, only [a-z ] tokens used.
use bip39::{Language, Mnemonic};
use std::io::Read;

const MAX_INPUT: u64 = 4096;
const MAX_COMBOS: u64 = 200_000;

fn lev(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push((prev[j] + (ca != *cb) as usize).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Candidate words for one token, best first. Known words map to themselves.
pub fn word_candidates(tok: &str) -> Vec<&'static str> {
    let wl = Language::English.word_list();
    if let Some(i) = Language::English.find_word(tok) { return vec![wl[i as usize]]; }
    let mut c: Vec<(usize, &'static str)> = wl.iter()
        .filter_map(|w| {
            let d = lev(tok, w);
            let prefix = tok.len() >= 4 && w.starts_with(&tok[..4]);
            if d <= 2 || prefix { Some((if prefix { 0 } else { d }, *w)) } else { None }
        }).collect();
    c.sort();
    c.into_iter().map(|x| x.1).collect()
}

fn valid(words: &[&str]) -> bool {
    Mnemonic::parse_in_normalized(Language::English, &words.join(" ")).is_ok()
}

/// Returns checksum-valid phrases (as word vectors) and how many words changed.
pub fn repair(tokens: &[String], max_out: usize) -> Result<Vec<(Vec<&'static str>, usize)>, &'static str> {
    if ![12, 15, 18, 21, 24].contains(&tokens.len()) { return Err("bad_input"); }
    let cands: Vec<Vec<&'static str>> = tokens.iter().map(|t| word_candidates(t)).collect();
    if cands.iter().any(|c| c.is_empty()) { return Err("no_candidates"); }
    let combos = cands.iter().try_fold(1u64, |a, c| a.checked_mul(c.len() as u64)).unwrap_or(u64::MAX);
    if combos > MAX_COMBOS { return Err("too_many_candidates"); }
    let orig: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
    let changed = |w: &[&str]| w.iter().zip(&orig).filter(|(a, b)| a != b).count();
    let mut out = Vec::new();
    let mut idx = vec![0usize; cands.len()];
    'outer: loop {
        let w: Vec<&'static str> = idx.iter().enumerate().map(|(i, &j)| cands[i][j]).collect();
        if valid(&w) { let c = changed(&w); out.push((w, c)); if out.len() >= max_out { break; } }
        let mut p = 0;
        loop {
            if p == idx.len() { break 'outer; }
            idx[p] += 1;
            if idx[p] < cands[p].len() { break; }
            idx[p] = 0; p += 1;
        }
    }
    if out.is_empty() {
        // All words known but checksum fails: try adjacent swaps, then one wrong word.
        let base: Vec<&'static str> = cands.iter().map(|c| c[0]).collect();
        for i in 0..base.len() - 1 {
            let mut w = base.clone(); w.swap(i, i + 1);
            if w != base && valid(&w) { out.push((w, 2)); }
        }
        for i in 0..base.len() {
            for nw in Language::English.word_list() {
                if *nw == base[i] { continue; }
                let mut w = base.clone(); w[i] = nw;
                if valid(&w) { out.push((w, 1)); if out.len() >= max_out { return Ok(out); } }
            }
        }
    }
    Ok(out)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut max_out = 1000usize;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--max" => { max_out = args.get(i + 1).and_then(|s| s.parse().ok()).unwrap_or(1000); i += 1; }
            _ => { println!(r#"{{"tool":"seed-repair","status":"bad_input"}}"#); std::process::exit(2); }
        }
        i += 1;
    }
    let mut raw = Vec::new();
    // Pipe principle: the phrase arrives on stdin only, never via argv/env/file name.
    let res = std::io::stdin().take(MAX_INPUT).read_to_end(&mut raw);
    if res.is_err() { println!(r#"{{"tool":"seed-repair","status":"bad_input"}}"#); std::process::exit(2); }
    let text = String::from_utf8_lossy(&raw).to_lowercase();
    let tokens: Vec<String> = text.split(|c: char| !c.is_ascii_lowercase()).filter(|t| !t.is_empty() && t.len() <= 16).map(String::from).collect();
    match repair(&tokens, max_out) {
        Ok(v) => {
            for (n, (w, c)) in v.iter().enumerate() {
                println!("{}", serde_json::json!({"tool":"seed-repair","status":"checksum_ok","candidate":n,"changed_words":c,"mnemonic":w.join(" ")}));
            }
            println!(r#"{{"tool":"seed-repair","status":"{}","count":{}}}"#, if v.is_empty() {"no_candidates"} else {"done"}, v.len());
        }
        Err(s) => { println!(r#"{{"tool":"seed-repair","status":"{s}","count":0}}"#); std::process::exit(1); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn t(s: &str) -> Vec<String> { s.split(' ').map(String::from).collect() }
    const V: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    #[test] fn valid_passthrough() {
        let r = repair(&t(V), 10).unwrap();
        assert_eq!(r[0].0.join(" "), V); assert_eq!(r[0].1, 0);
    }
    #[test] fn typo_fixed() {
        let r = repair(&t("abandon abandon abandn abandon abandon abandon abandon abandon abandon abandon abandon abuot"), 100).unwrap();
        assert!(r.iter().any(|(w, c)| w.join(" ") == V && *c == 2));
    }
    #[test] fn wrong_known_word() {
        // last word replaced by a valid-but-wrong word -> checksum search must find "about"
        let r = repair(&t("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"), 5000).unwrap();
        assert!(r.iter().any(|(w, _)| w.join(" ") == V));
    }
    #[test] fn bad_len() { assert_eq!(repair(&t("abandon about"), 1).unwrap_err(), "bad_input"); }
}
