//! chainstate-dump: stream the UTXO set straight out of a Core-family node's `chainstate/` LevelDB
//! directory (a stopped node's, or a copy), with no node, RPC or dumptxoutset. Pure-Rust port of the
//! LevelDB read path (crates/utxo/src/leveldb.rs) and both coin layouts (crates/utxo/src/chainstate.rs).
//!   chainstate-dump --chain doge ~/.dogecoin/chainstate > coins.jsonl
use blocktools_core::chains;
use blocktools_io::outln;
use blocktools_utxo::chainstate::{Chainstate, Opts};
use serde_json::json;
use std::collections::BTreeMap;
use std::time::Instant;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "chainstate-dump", "status": "bad_input", "error": e}));
    std::process::exit(2)
}
fn hexs(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn peak_rss() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines().find(|l| l.starts_with("VmHWM:"))?.split_whitespace().nth(1)?.parse::<u64>().ok().map(|k| k * 1024)
}

fn main() {
    blocktools_io::help("chainstate-dump --chain NAME [--addresses-only | --census] [--era C|c] [--obfuscate-key HEX|none] [--hash-serialized] DIR
  DIR           a Core-family node's chainstate/ LevelDB directory. Read-only: nothing in DIR is opened
                for writing and no lock is taken. STOP the node first, or copy the directory while it is
                stopped; a directory whose LOCK a running process holds is refused (Linux, /proc/locks).
  --chain NAME  the coin whose base58 prefixes / bech32 HRP encode the address field (btc, ltc, doge, ...;
                mainnet encodings: on a testnet/regtest chainstate use scriptpubkey_hex)
  --addresses-only  one line per coin: the address, or script:HEX when the script has no address
                (feeds utxo-set / a membership set directly)
  --census      no per-coin lines: one JSON summary (coins, total, per script_type counts)
  --hash-serialized  also compute the pre-0.15 gettxoutsetinfo hash_serialized and bytes_serialized
                ('c' layout only: Dogecoin 1.14, Core 0.14 GetUTXOStats) into the summary; compare
                with the node's own gettxoutsetinfo at the same best block
  --era C|c     force the record layout ('C' per output, Core 0.15+; 'c' per transaction, 0.8-0.14).
                Default: detected. A record of the other layout is then an error, never reinterpreted.
  --obfuscate-key HEX|none  use this XOR key instead of the stored one (discrimination checks). A wrong
                key or era fails loudly (exit 2), it does not print garbage.
stdout: one JSON line per unspent output {txid, vout, height, coinbase, amount, script_type, scriptpubkey_hex,
  address}; amount in base units (satoshi), txid in the usual reversed display hex, address null when the
  script has none (script_type nonstandard), p2pk shown as its key's p2pkh address.
stderr: a start line {era_forced, obfuscate_key_forced} and a final line {status, coins, total, era ('C', 'c'
  or none), per_output_keys, per_tx_keys, obfuscated, best_block, table_files, log_files, snappy_blocks, secs,
  coins_per_sec, peak_rss_bytes}. Exit 0 when the whole directory was read, 2 on a bad, locked or
  undecodable directory or argument (no partial set is presented as complete).");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (mut chain, mut mode, mut dir, mut opts) = (None, "full", None::<String>, Opts::default());
    let mut i = 0;
    while i < a.len() {
        let v = || a.get(i + 1).cloned().unwrap_or_else(|| die("missing_value"));
        match a[i].as_str() {
            "--chain" => { chain = Some(chains::chain(&v()).filter(|c| matches!(c.enc, chains::Enc::Utxo { .. })).unwrap_or_else(|| die("chain_not_utxo"))); i += 1 }
            "--addresses-only" => mode = "addresses",
            "--hash-serialized" => opts.hash_serialized = true,
            "--census" => mode = "census",
            "--era" => { opts.era = Some(match v().as_str() { "C" => b'C', "c" => b'c', _ => die("era_unknown: C or c") }); i += 1 }
            "--obfuscate-key" => {
                let h = v(); i += 1;
                opts.xor = Some(if h == "none" { vec![0; 8] } else {
                    if h.is_empty() || h.len() % 2 == 1 { die("obfuscate_key_hex") }
                    (0..h.len()).step_by(2).map(|j| u8::from_str_radix(&h[j..j + 2], 16).unwrap_or_else(|_| die("obfuscate_key_hex"))).collect()
                });
            }
            s if s.starts_with("--") => die("unknown_flag"),
            s => { if dir.replace(s.to_string()).is_some() { die("one_directory") } }
        }
        i += 1;
    }
    let chain = chain.unwrap_or_else(|| die("chain_required: --chain NAME (address encoding)"));
    let dir = dir.unwrap_or_else(|| die("directory_required"));
    eprintln!("{}", json!({"tool": "chainstate-dump", "dir": dir, "chain": chain.name, "era_forced": opts.era.map(|e| (e as char).to_string()), "obfuscate_key_forced": opts.xor.is_some()}));
    let t0 = Instant::now();
    let mut cs = Chainstate::open_with(std::path::Path::new(&dir), opts.clone()).unwrap_or_else(|e| die(&e.to_string()));
    let (mut n, mut total, mut kinds) = (0u64, 0u128, BTreeMap::<&str, u64>::new());
    loop {
        let c = match cs.next_coin() { Ok(Some(c)) => c, Ok(None) => break, Err(e) => die(&format!("{e} (after {n} coins)")) };
        n += 1; total += u128::from(c.value);
        let addr = chains::script_to_address(chain, &c.script);
        let kind = match (&addr, c.script.first()) { (Some((k, _)), _) => *k, (None, Some(0xff)) => "p2pk-invalid-key", _ => "nonstandard" };
        *kinds.entry(kind).or_default() += 1;
        match mode {
            "census" => {}
            "addresses" => match &addr { Some((_, s)) => outln!("{s}"), None => outln!("script:{}", hexs(&c.script)) },
            _ => outln!("{}", json!({"txid": hexs(&c.txid.iter().rev().copied().collect::<Vec<u8>>()), "vout": c.vout, "height": c.height, "coinbase": c.coinbase,
                "amount": c.value, "script_type": kind, "scriptpubkey_hex": hexs(&c.script), "address": addr.map(|x| x.1)})),
        }
    }
    let secs = t0.elapsed().as_secs_f64();
    let st = &cs.stats;
    let era = if st.per_output_keys > 0 { Some("C") } else if st.per_tx_keys > 0 { Some("c") } else { None };
    let sum = json!({"tool": "chainstate-dump", "status": "ok", "coins": n, "total": total.to_string(), "era": era, "per_output_keys": st.per_output_keys,
        "per_tx_keys": st.per_tx_keys, "obfuscated": st.obfuscated, "best_block": st.best_block, "table_files": st.table_files, "log_files": st.log_files,
        "snappy_blocks": cs.db().snappy_blocks(), "hash_serialized": cs.serialized.hash, "bytes_serialized": opts.hash_serialized.then_some(cs.serialized.bytes), "transactions": opts.hash_serialized.then_some(cs.serialized.transactions), "script_types": kinds, "secs": secs, "coins_per_sec": (n as f64 / secs.max(1e-9)).round(), "peak_rss_bytes": peak_rss()});
    if mode == "census" { outln!("{sum}") }
    eprintln!("{sum}");
}
