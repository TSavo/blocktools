//! wallet-finder: turn text you own (old notes, a diary, a password list) into brainwallet candidates,
//! derive each candidate's addresses, and test them against a UTXO set loaded from a Bitcoin Core
//! `dumptxoutset` file. Offline. On a hit it prints the phrase, scheme, address and balance; it never
//! prints a key and never signs. Turn a hit into a key yourself, sealed: phrase-to-key.
//!   wallet-finder --dump utxo.dat < notes.txt
use blocktools_core::chains;
use blocktools_io::outln;
use blocktools_utxo::{Answer, UtxoSet};
use serde_json::json;
use std::collections::HashSet;
use std::io::Read;
use std::time::Instant;
#[path = "../../pw-candidates/src/expand.rs"]
#[allow(dead_code)]
mod expand;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "wallet-finder", "status": "bad_input", "error": e}));
    std::process::exit(2)
}

/// Candidates from text, in first-seen order, deduplicated: every line (as written and trimmed),
/// every sentence (split at . ! ?), and every run of 1..=window consecutive words of a line joined
/// by one space, with the words as written and again with leading/trailing ASCII punctuation trimmed. Then each is expanded by the pw-candidates rules (case swap typo digit), up to
/// `max` per base candidate.
pub fn candidates(text: &str, window: usize, rules: &[&str], max: usize) -> Vec<String> {
    fn add(seen: &mut HashSet<String>, s: &str, out: &mut Vec<String>) { if !s.is_empty() && seen.insert(s.to_string()) { out.push(s.to_string()) } }
    let (mut bseen, mut seen) = (HashSet::new(), HashSet::new());
    let mut out = Vec::new();
    let mut base = Vec::new();
    let mut addb = |s: &str, base: &mut Vec<String>| add(&mut bseen, s, base);
    for line in text.lines() {
        addb(line, &mut base);
        addb(line.trim(), &mut base);
        for s in line.split(['.', '!', '?']) { addb(s.trim(), &mut base) }
        let raw: Vec<&str> = line.split_whitespace().collect();
        let bare: Vec<&str> = raw.iter().map(|w| w.trim_matches(|c: char| c.is_ascii_punctuation())).filter(|w| !w.is_empty()).collect();
        for w in [raw, bare] { for n in 1..=window.min(w.len()) { for win in w.windows(n) { addb(&win.join(" "), &mut base) } } }
    }
    for b in base {
        add(&mut seen, &b, &mut out);
        if !rules.is_empty() { for v in expand::expand(&[b.clone()], rules, max) { add(&mut seen, &v, &mut out) } }
    }
    out
}

fn main() {
    blocktools_io::help("wallet-finder --dump FILE [--window N] [--rules LIST] [--max N] [--scheme sha256|warpwallet]
              [--salt EMAIL] [--chain NAME] [--limit N]
  --dump FILE     a Bitcoin Core dumptxoutset file (Core 25-27, 0.21-24 / Litecoin 0.21.x, or 28+ with the \"utxo\" header)
  --window N      word windows of 1..N consecutive words per line, words as written and with edge
                  punctuation trimmed (default 6; 0 = lines and sentences only)
  --rules LIST    comma list of pw-candidates rules applied to every candidate: case,swap,typo,digit
                  (default none)
  --max N         variants per candidate from --rules (default 1000)
  --scheme S      sha256 (default: brainwallet.org / bitaddress.org) or warpwallet (scrypt, seconds each)
  --salt EMAIL    WarpWallet salt (default empty)
  --chain NAME    address encoding for hits (default: from the dump's network magic, else btc)
  --limit N       stop after N candidates
Each candidate key gives five addresses: p2pkh, p2pkh-uncompressed, p2sh-p2wpkh, p2wpkh, p2tr.
stdin: your text (UTF-8). Lines are used byte-for-byte as well as trimmed.
stdout: one JSON line per funded address {status: funded, scheme, passphrase, kind, address, value_sat,
  outputs}. Never a key; the passphrase is printed, treat the output like the input text.
stderr: the ingest line, then a summary {candidates, addresses_tested, hits, secs, candidates_per_sec,
  bloom_passes, bloom_false_positives}.
Exit 0 when at least one funded address was found, 1 when none (like grep), 2 on bad input.");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (mut dump, mut window, mut rules, mut max, mut scheme, mut salt, mut chain, mut limit) =
        (None, 6usize, String::new(), 1000usize, "sha256".to_string(), String::new(), None, usize::MAX);
    let mut i = 0;
    while i < a.len() {
        let next = |i: usize| a.get(i + 1).cloned().unwrap_or_else(|| die(&format!("{}_needs_a_value", a[i])));
        let num = |i: usize| next(i).parse::<usize>().unwrap_or_else(|_| die(&format!("{}_needs_a_number", a[i])));
        match a[i].as_str() {
            "--dump" => { dump = Some(next(i)); i += 1 }
            "--window" => { window = num(i); i += 1 }
            "--rules" => { rules = next(i); i += 1 }
            "--max" => { max = num(i); i += 1 }
            "--limit" => { limit = num(i); i += 1 }
            "--scheme" => { scheme = next(i); i += 1 }
            "--salt" => { salt = next(i); i += 1 }
            "--chain" => { let n = next(i); chain = Some(chains::supported(&n).unwrap_or_else(|| die("unknown_chain"))); i += 1 }
            o => die(&format!("unknown_argument:{o}")),
        }
        i += 1;
    }
    if !blocktools_secrets::brain::SCHEMES.contains(&scheme.as_str()) { die("unknown_scheme") }
    let rules: Vec<&str> = rules.split(',').filter(|r| !r.is_empty()).collect();
    if let Some(r) = rules.iter().find(|r| !["case", "swap", "typo", "digit"].contains(r)) { die(&format!("unknown_rule:{r}")) }
    let dump = dump.unwrap_or_else(|| die("missing_--dump"));
    let mut text = String::new();
    std::io::stdin().read_to_string(&mut text).unwrap_or_else(|_| die("stdin_not_utf8"));
    let f = std::fs::File::open(&dump).unwrap_or_else(|_| die("cannot_open_dump"));
    let t = Instant::now();
    let set = UtxoSet::ingest(std::io::BufReader::with_capacity(1 << 20, f), 12).unwrap_or_else(|e| die(&format!("bad_dump:{e}")));
    let h = &set.header;
    eprintln!("{}", json!({"tool": "wallet-finder", "status": "ok", "coins": set.coins, "scripts": set.scripts(), "base_blockhash": h.base_blockhash,
        "network": h.network(), "format": h.format, "layout": h.layout(), "nchaintx": h.nchaintx, "ingest_secs": t.elapsed().as_secs_f64()}));
    let chain = chain.unwrap_or_else(|| chains::chain("btc").expect("btc"));
    let cands = candidates(&text, window, &rules, max);
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (mut n, mut tested, mut hits, mut passes, mut fps) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let t = Instant::now();
    for c in cands.iter().take(limit) {
        n += 1;
        let k = match scheme.as_str() {
            "warpwallet" => blocktools_secrets::brain::warpwallet_key(c.as_bytes(), salt.as_bytes()).unwrap_or_else(|e| die(e)),
            _ => blocktools_secrets::brain::sha256_key(c.as_bytes()),
        };
        let Ok(sk) = bitcoin::secp256k1::SecretKey::from_slice(&k[..]) else { continue };
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
        for r in chains::pub_rows(chain, "", &pk, true) {
            let Some(s) = chains::address_to_script(chain, &r.address) else { continue };
            tested += 1;
            match set.query_script(&s) {
                Answer::Absent => {}
                Answer::BloomFalsePositive => { passes += 1; fps += 1 }
                Answer::Funded { value, outputs } => {
                    passes += 1; hits += 1;
                    outln!("{}", json!({"status": "funded", "scheme": scheme, "passphrase": c, "chain": chain.name, "kind": r.kind, "address": r.address, "value_sat": value, "outputs": outputs}));
                }
            }
        }
    }
    let secs = t.elapsed().as_secs_f64();
    eprintln!("{}", json!({"tool": "wallet-finder", "status": if hits > 0 { "ok" } else { "not_found" }, "candidates": n, "addresses_tested": tested, "hits": hits,
        "secs": secs, "candidates_per_sec": (n as f64 / secs.max(1e-9)).round(), "bloom_passes": passes, "bloom_false_positives": fps}));
    std::process::exit(if hits > 0 { 0 } else { 1 })
}
