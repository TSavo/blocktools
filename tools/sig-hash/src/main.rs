//! sig-hash: Solidity function/event/error selector and topic hash, plus reverse lookup against a file you supply.
//! Offline, no network, no built-in signature database. One JSON object per line.
//!   sig-hash 'transfer(address,uint256)'
//!   sig-hash 'event Transfer(address indexed from, address indexed to, uint256 value)'
//!   sig-hash --lookup 0x5bf6f916 --sigs my-errors.txt
//!   echo 0x68656c6c6f | sig-hash --keccak
use blocktools_evm::api;
use blocktools_io::outln;
use std::io::Read;

fn die(e: &str) -> ! {
    eprintln!("{}", serde_json::json!({"tool": "sig-hash", "status": "error", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help("sig-hash [SIGNATURE...] [--abi FILE] [--lookup HASH --sigs FILE] [--keccak [HEX]]
  --abi FILE      print selector/topic for every function, event and error in an ABI JSON file
  --lookup HASH   find a 4-byte selector or 32-byte topic among the signatures in --sigs (no built-in database)
  --sigs FILE     ABI JSON, or one signature per line (# comments), used by --lookup
  --keccak [HEX]  keccak256 of hex bytes (argument or stdin)
With no SIGNATURE arguments, signatures are read one per line from stdin.");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let val = |k: &str| a.iter().position(|x| x == k).map(|i| a.get(i + 1).cloned().unwrap_or_else(|| die(&format!("{k}_needs_a_value"))));
    let file = |p: String| std::fs::read_to_string(&p).unwrap_or_else(|_| die("cannot_read_file"));
    let stdin = || { let mut s = String::new(); std::io::stdin().take(16 << 20).read_to_string(&mut s).ok(); s };
    if a.iter().any(|x| x == "--keccak") {
        let h = a.iter().skip_while(|x| *x != "--keccak").nth(1).cloned().unwrap_or_else(stdin);
        match api::keccak256_hex(h.trim()) { Ok(k) => outln!("{}", serde_json::json!({"status": "ok", "keccak256": k})), Err(e) => die(&e) }
        return;
    }
    if let Some(h) = val("--lookup") {
        let sigs = api::load_sigs(&file(val("--sigs").unwrap_or_else(|| die("lookup_needs_--sigs_file")))).unwrap_or_else(|e| die(&e));
        match api::lookup(&h, &sigs) { Ok(v) => outln!("{v}"), Err(e) => die(&e) }
        return;
    }
    if let Some(p) = val("--abi") {
        for s in api::load_sigs(&file(p)).unwrap_or_else(|e| die(&e)) { outln!("{}", api::sig_info(&s)); }
        return;
    }
    let pos: Vec<String> = a.iter().filter(|x| !x.starts_with("--")).cloned().collect();
    let lines: Vec<String> = if pos.is_empty() {
        stdin().lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from).collect()
    } else { pos };
    if lines.is_empty() { die("no_signature"); }
    let mut bad = false;
    for l in lines {
        match api::sig_hash(&l) {
            Ok(v) => outln!("{v}"),
            Err(e) => { bad = true; outln!("{}", serde_json::json!({"status": "error", "input": l, "error": e})); }
        }
    }
    if bad { std::process::exit(2); }
}
