//! abi-inspect: list an ABI's functions, events and errors with selectors/topics, flag selector
//! collisions, and report which ERC-165 / ERC-20 interfaces it implements (ids recomputed), offline.
//!   abi-inspect token.abi.json
//!   abi-inspect < signatures.txt
use blocktools_evm::inspect;
use blocktools_io::outln;
use serde_json::json;
use std::io::Read;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "abi-inspect", "status": "bad_input", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help("abi-inspect [FILE]
FILE (or stdin): ABI JSON (array or {\"abi\": [...]}, e.g. a compiler artifact) or one signature per line.
Prints every item's canonical signature with selector/topic, selector_collisions, and interfaces:
ERC-165, ERC-20, ERC-721 (+Metadata, Enumerable), ERC-1155 with complete/missing and the interface_id.");
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.iter().any(|x| x.starts_with("--")) { die("unknown_option"); }
    if a.len() > 1 { die("one_file_only"); }
    let text = match a.first() {
        Some(p) => std::fs::read_to_string(p).unwrap_or_else(|_| die("cannot_read_abi_file")),
        None => { let mut s = String::new(); std::io::stdin().take(16 << 20).read_to_string(&mut s).ok(); s }
    };
    match inspect::inspect(&text) { Ok(v) => outln!("{v}"), Err(e) => die(&e) }
}
