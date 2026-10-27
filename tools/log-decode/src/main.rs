//! log-decode: decode EVM event logs (topics + data) against event signatures you bring, offline.
//! Input (stdin or FILE): one log, an array of logs, an eth_getLogs response, a receipt or a receipt
//! response, as the node sent it; JSON lines of any of these also work. One JSON line per log, in order,
//! carrying address, block_number, transaction_hash and log_index when the node gave them.
//! No signature database: a log whose topic0 matches none of yours is status no_match with its topic.
//! Indexed dynamic values (string, bytes, arrays, tuples) are stored on chain as a keccak256 hash only: value_hash.
//!   rpc URL eth_getLogs '[{"address":"0x...","fromBlock":"0x10","toBlock":"0x20"}]' | log-decode --sig 'event Transfer(address indexed from, address indexed to, uint256 value)'
//!   rpc URL receipt 0xTXHASH | log-decode --abi token.abi.json
//!   log-decode --abi token.abi.json --address 0xToken receipt.json
use blocktools_evm::{api, sig::{Kind, Sig}};
use blocktools_io::outln;
use serde_json::{json, Value};
use std::io::Read;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "log-decode", "status": "bad_input", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help("log-decode [--sig 'event SIGNATURE']... [--abi FILE] [--address ADDR] [--only-matched] [FILE]
  --sig SIGNATURE  an event signature, e.g. 'event Transfer(address indexed from, address indexed to, uint256 value)';
                   the event keyword is optional (repeatable)
  --abi FILE       ABI JSON file (array or {\"abi\": [...]}) or one signature per line; only its events are used
  --address ADDR   keep only logs emitted by this contract address
  --only-matched   print nothing for logs no signature matches (default: a no_match line each)
stdin (or FILE): a log, an array of logs, an eth_getLogs response, a receipt, or JSON lines of these.
stdout: one JSON line per log {status, event, signature, topic, args:[{name, type, indexed, value|value_hash}], address,
block_number, transaction_hash, log_index}. Exit 0 ok (no_match lines included), 2 bad input (the line says which log).");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (mut sigs, mut file, mut addr, mut only) = (Vec::<Sig>::new(), None, None, false);
    let mut i = 0;
    while i < a.len() {
        let next = |i: usize| a.get(i + 1).cloned().unwrap_or_else(|| die(&format!("{}_needs_a_value", a[i])));
        match a[i].as_str() {
            "--sig" => { sigs.push(Sig::parse_as(&next(i), Kind::Event).unwrap_or_else(|e| die(&e))); i += 1; }
            "--abi" => {
                let t = std::fs::read_to_string(next(i)).unwrap_or_else(|_| die("cannot_read_abi_file"));
                sigs.extend(api::load_sigs(&t).unwrap_or_else(|e| die(&e)));
                i += 1;
            }
            "--address" => { addr = Some(blocktools_evm::parse_address(&next(i)).unwrap_or_else(|e| die(&e))); i += 1; }
            "--only-matched" => only = true,
            x if x.starts_with("--") => die("unknown_option"),
            x if file.is_none() => file = Some(x.to_string()),
            _ => die("one_file_only"),
        }
        i += 1;
    }
    if !sigs.iter().any(|s| s.kind == Kind::Event) { die("no_event_signature_give_--sig_or_--abi"); }
    let text = match &file {
        Some(p) => std::fs::read_to_string(p).unwrap_or_else(|_| die("cannot_read_file")),
        None => { let mut s = String::new(); std::io::stdin().take(64 << 20).read_to_string(&mut s).ok(); s }
    };
    if text.trim().is_empty() { die("empty_input"); }
    let docs: Vec<Value> = match serde_json::from_str::<Value>(text.trim()) {
        Ok(v) => vec![v],
        Err(_) => text.lines().map(str::trim).filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|_| die("input_is_not_json_or_json_lines"))).collect(),
    };
    let mut rc = 0;
    for d in docs {
        let logs = api::collect_logs(&d).unwrap_or_else(|e| die(&e));
        for (n, l) in logs.iter().enumerate() {
            if let Some(want) = &addr {
                let got = l.get("address").and_then(Value::as_str).and_then(|s| blocktools_evm::parse_address(s).ok());
                if got.as_ref() != Some(want) { continue; }
            }
            match api::decode_log_object(l, &sigs) {
                Ok(v) if only && v["status"] != "ok" => {}
                Ok(v) => outln!("{v}"),
                Err(e) => { rc = 2; outln!("{}", json!({"status": "bad_input", "error": e, "log": n, "log_index": l.get("logIndex")})); }
            }
        }
    }
    std::process::exit(rc);
}
