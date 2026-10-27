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
    blocktools_io::help("utxo-set (--dump FILE | --chainstate DIR [--write-dump OUT]) [--chain NAME] [--bits N] [--stats]
  --dump FILE   a Bitcoin Core dumptxoutset file (Core 25-27 format, or the Core 28+ format with its
                \"utxo\" magic header; detected from the first bytes)
  --chainstate DIR  a Core-family node's chainstate/ LevelDB directory, read directly (forks with no
                dumptxoutset: Dogecoin 1.14, ...). Read-only; STOP the node first, or copy the
                directory while it is stopped. Both record layouts ('C' per output, 0.15+; 'c' per
                transaction, 0.8-0.14) and the obfuscation key are handled.
  --write-dump OUT  with --chainstate: also write the coins as a Core 25-format dumptxoutset file
                (base_blockhash = the chainstate's best block), so wallet-finder --dump OUT reads it
  --chain NAME  decode addresses for this chain only (default: auto-detect each address from its
                prefix; scriptPubKeys are chain-free)
  --bits N      bloom filter bits per funded script (default 12; 0 = no bloom, exact set only)
  --stats       print only the ingest line on stdout and exit (no queries read)
stdin: one address or scriptPubKey per line (hex, or script:HEX). Blank lines and # comments are skipped.
stdout: one JSON line per query {query, chain, script, status: funded|empty|bad_input, value_sat, outputs, bloom}.
  value_sat is the sum of the unspent outputs paying exactly this script; bloom is pass or reject
  (a pass that the exact set then refuses is a bloom false positive, reported as empty).
stderr: one ingest line {coins, scripts, base_blockhash, network, format (0 = chainstate), ingest_secs, coins_per_sec,
  resident_bytes, peak_rss_bytes}. Exit 0 when every query was read (funded or empty), 2 on a bad dump
or argument, 1 when any query line could not be read as an address or script.");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (mut dump, mut chain, mut bits, mut stats, mut cs, mut wd) = (None, None, 12u32, false, None::<String>, None::<String>);
    let mut i = 0;
    while i < a.len() {
        let next = |i: usize| a.get(i + 1).cloned().unwrap_or_else(|| die(&format!("{}_needs_a_value", a[i])));
        match a[i].as_str() {
            "--dump" => { dump = Some(next(i)); i += 1 }
            "--chain" => { let n = next(i); chain = Some(chains::supported(&n).unwrap_or_else(|| die("unknown_chain"))); i += 1 }
            "--bits" => { bits = next(i).parse().ok().filter(|b| *b <= 64).unwrap_or_else(|| die("bits_must_be_0_to_64")); i += 1 }
            "--stats" => stats = true,
            "--chainstate" => { cs = Some(next(i)); i += 1 }
            "--write-dump" => { wd = Some(next(i)); i += 1 }
            o => die(&format!("unknown_argument:{o}")),
        }
        i += 1;
    }
    if dump.is_some() == cs.is_some() { die("need_exactly_one_of_--dump_--chainstate") }
    if wd.is_some() && cs.is_none() { die("--write-dump_needs_--chainstate") }
    let t = Instant::now();
    let mut extra = json!({});
    let set = if let Some(dir) = &cs {
        let dir = std::path::Path::new(dir);
        if let Some(out) = &wd { extra["dump_written"] = json!(write_dump(dir, out)) }
        let (set, st) = UtxoSet::ingest_chainstate(dir, bits).unwrap_or_else(|e| die(&format!("bad_chainstate:{e}")));
        extra["per_output_keys"] = json!(st.per_output_keys); extra["per_tx_keys"] = json!(st.per_tx_keys); extra["obfuscated"] = json!(st.obfuscated); extra["total_sat"] = json!(st.total_value); extra["table_files"] = json!(st.table_files); extra["log_files"] = json!(st.log_files);
        set
    } else {
        let f = std::fs::File::open(dump.as_deref().unwrap()).unwrap_or_else(|_| die("cannot_open_dump"));
        UtxoSet::ingest(std::io::BufReader::with_capacity(1 << 20, f), bits).unwrap_or_else(|e| die(&format!("bad_dump:{e}")))
    };
    let secs = t.elapsed().as_secs_f64();
    let h = &set.header;
    let mut line = json!({"tool": "utxo-set", "status": "ok", "coins": set.coins, "scripts": set.scripts(), "base_blockhash": h.base_blockhash,
        "network": h.network(), "format": h.format, "bloom_bits": bits, "bloom_k": set.bloom().k(), "ingest_secs": secs,
        "coins_per_sec": (set.coins as f64 / secs.max(1e-9)).round(), "resident_bytes": set.resident_bytes(), "peak_rss_bytes": peak_rss()});
    for (k, v) in extra.as_object().unwrap() { line[k] = v.clone() }
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

/// Stream the chainstate's coins into a Core 25-format dump at `out` (count patched at the end).
fn write_dump(dir: &std::path::Path, out: &str) -> u64 {
    use std::io::{Seek, SeekFrom, Write};
    let mut cs = blocktools_utxo::chainstate::Chainstate::open(dir).unwrap_or_else(|e| die(&format!("bad_chainstate:{e}")));
    let f = std::fs::OpenOptions::new().write(true).create_new(true).open(out).unwrap_or_else(|_| die("cannot_create_--write-dump_(exists?)"));
    let mut w = std::io::BufWriter::with_capacity(1 << 20, f);
    let werr = |_| die("write_failed");
    w.write_all(&[0u8; 40]).unwrap_or_else(werr);
    let (mut n, mut b) = (0u64, Vec::new());
    while let Some(c) = cs.next_coin().unwrap_or_else(|e| die(&format!("bad_chainstate:{e}"))) {
        b.clear(); b.extend(c.txid); b.extend(c.vout.to_le_bytes()); blocktools_utxo::write_coin_body(&c, &mut b);
        w.write_all(&b).unwrap_or_else(werr); n += 1;
    }
    let mut base = [0u8; 32];
    if let Some(h) = &cs.stats.best_block { for i in 0..32 { base[31 - i] = u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap_or(0) } }
    let mut f = w.into_inner().unwrap_or_else(|_| die("write_failed"));
    f.seek(SeekFrom::Start(0)).unwrap_or_else(|_| die("write_failed"));
    f.write_all(&base).unwrap_or_else(werr); f.write_all(&n.to_le_bytes()).unwrap_or_else(werr);
    f.sync_all().unwrap_or_else(werr);
    n
}
