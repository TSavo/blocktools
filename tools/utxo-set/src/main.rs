//! utxo-set: load a Bitcoin Core `dumptxoutset` file into RAM (exact set of funded output scripts,
//! bloom filter in front) and answer, for each address or scriptPubKey on stdin, whether it holds
//! unspent coins and how much. Offline; the dump is public data.
//!   bitcoin-cli dumptxoutset /data/utxo.dat      (on your node; Core 25+)
//!   echo 1JwSSubhmg6iPtRjtyqhUYYH7bZg3Lfy1T | utxo-set --dump utxo.dat
use blocktools_core::chains;
use blocktools_io::outln;
use blocktools_utxo::{Answer, UtxoSet};
use serde_json::json;
use std::io::BufRead;
use std::time::Instant;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "utxo-set", "status": "bad_input", "error": e}));
    std::process::exit(2)
}
/// Peak resident set (Linux /proc), bytes.
pub fn peak_rss() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    let l = s.lines().find(|l| l.starts_with("VmHWM:"))?;
    l.split_whitespace().nth(1)?.parse::<u64>().ok().map(|k| k * 1024)
}
fn script_of(q: &str, chain: Option<&'static chains::Chain>) -> Option<(Vec<u8>, Option<&'static str>)> {
    if let Some(h) = q.strip_prefix("script:") { return hex(h).map(|s| (s, None)) }
    let found = match chain {
        Some(c) => chains::address_to_script(c, q).map(|s| (s, Some(c.name))),
        None => chains::detectable().find_map(|c| chains::address_to_script(c, q).map(|s| (s, Some(c.name)))),
    };
    found.or_else(|| hex(q).map(|s| (s, None)))
}
fn hex(h: &str) -> Option<Vec<u8>> {
    if h.is_empty() || h.len() % 2 == 1 { return None }
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok()).collect()
}

fn main() {
    blocktools_io::help("utxo-set --dump FILE [--chain NAME] [--bits N] [--stats]
  --dump FILE   a Bitcoin Core dumptxoutset file (Core 25-27 format, or the Core 28+ format with its
                \"utxo\" magic header; detected from the first bytes)
  --chain NAME  decode addresses for this chain only (default: auto-detect each address from its
                prefix; scriptPubKeys are chain-free)
  --bits N      bloom filter bits per funded script (default 12; 0 = no bloom, exact set only)
  --stats       print only the ingest line on stdout and exit (no queries read)
stdin: one address or scriptPubKey per line (hex, or script:HEX). Blank lines and # comments are skipped.
stdout: one JSON line per query {query, chain, script, status: funded|empty|bad_input, value_sat, outputs, bloom}.
  value_sat is the sum of the unspent outputs paying exactly this script; bloom is pass or reject
  (a pass that the exact set then refuses is a bloom false positive, reported as empty).
stderr: one ingest line {coins, scripts, base_blockhash, network, format, ingest_secs, coins_per_sec,
  resident_bytes, peak_rss_bytes}. Exit 0 when every query was read (funded or empty), 2 on a bad dump
or argument, 1 when any query line could not be read as an address or script.");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (mut dump, mut chain, mut bits, mut stats) = (None, None, 12u32, false);
    let mut i = 0;
    while i < a.len() {
        let next = |i: usize| a.get(i + 1).cloned().unwrap_or_else(|| die(&format!("{}_needs_a_value", a[i])));
        match a[i].as_str() {
            "--dump" => { dump = Some(next(i)); i += 1 }
            "--chain" => { let n = next(i); chain = Some(chains::supported(&n).unwrap_or_else(|| die("unknown_chain"))); i += 1 }
            "--bits" => { bits = next(i).parse().ok().filter(|b| *b <= 64).unwrap_or_else(|| die("bits_must_be_0_to_64")); i += 1 }
            "--stats" => stats = true,
            o => die(&format!("unknown_argument:{o}")),
        }
        i += 1;
    }
    let dump = dump.unwrap_or_else(|| die("missing_--dump"));
    let f = std::fs::File::open(&dump).unwrap_or_else(|_| die("cannot_open_dump"));
    let t = Instant::now();
    let set = UtxoSet::ingest(std::io::BufReader::with_capacity(1 << 20, f), bits).unwrap_or_else(|e| die(&format!("bad_dump:{e}")));
    let secs = t.elapsed().as_secs_f64();
    let h = &set.header;
    let line = json!({"tool": "utxo-set", "status": "ok", "coins": set.coins, "scripts": set.scripts(), "base_blockhash": h.base_blockhash,
        "network": h.network(), "format": h.format, "bloom_bits": bits, "bloom_k": set.bloom().k(), "ingest_secs": secs,
        "coins_per_sec": (set.coins as f64 / secs.max(1e-9)).round(), "resident_bytes": set.resident_bytes(), "peak_rss_bytes": peak_rss()});
    if stats { outln!("{line}"); return }
    eprintln!("{line}");
    let mut rc = 0;
    for l in std::io::stdin().lock().lines() {
        let l = l.unwrap_or_else(|_| die("stdin_not_utf8"));
        let q = l.trim();
        if q.is_empty() || q.starts_with('#') { continue }
        let Some((s, cn)) = script_of(q, chain) else { outln!("{}", json!({"query": q, "status": "bad_input", "error": "not_an_address_or_script"})); rc = 1; continue };
        let (status, v, n, bloom) = match set.query_script(&s) {
            Answer::Funded { value, outputs } => ("funded", value, outputs, "pass"),
            Answer::BloomFalsePositive => ("empty", 0, 0, "pass"),
            Answer::Absent => ("empty", 0, 0, "reject"),
        };
        outln!("{}", json!({"query": q, "chain": cn, "script": s.iter().map(|b| format!("{b:02x}")).collect::<String>(), "status": status, "value_sat": v, "outputs": n, "bloom": bloom}));
    }
    std::process::exit(rc)
}
