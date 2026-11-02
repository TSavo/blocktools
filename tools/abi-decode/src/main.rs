//! abi-decode: decode Solidity ABI calldata, returndata, revert data or event logs, offline.
//! Input (stdin or last argument): hex, or a JSON-RPC response/tx/receipt/log/getLogs result as-is;
//! arrays of logs and receipts' `logs` give one JSON line per log. Error(string) and Panic(uint256) are built in.
//!   jq -r .result.input tx.json | abi-decode --sig 'transfer(address,uint256)'
//!   abi-decode --sig 'event Transfer(address indexed from, address indexed to, uint256 value)' < getLogs.json
//!   abi-decode --sig 'balanceOf(address) returns (uint256)' --output < eth_call.json
//!   abi-decode < revert.json
use blocktools_evm::api;
use blocktools_io::outln;
use serde_json::{json, Value};
use std::io::Read;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "abi-decode", "status": "bad_input", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help("abi-decode [--sig SIGNATURE] [--abi FILE] [--types '(T,..)'] [--output] [--allow-trailing] [--allow-gaps] [INPUT]
  --sig SIGNATURE  function, event or error signature, e.g. 'transfer(address,uint256)' (repeatable)
  --abi FILE       ABI JSON file (array or {\"abi\": [...]}) or one signature per line
  --types (T,..)   decode raw data as a type list, no selector (returndata, constructor args)
  --output         decode returndata with the first signature's returns (...) list
  --allow-trailing accept bytes after the last head/tail (e.g. an ERC-2771 suffix, extra returndata words) and
                   print them as trailing_hex (\"0x\" if none); all other strict checks still apply (docs/ABI-STRICT.md)
  --allow-gaps     accept a dynamic tail that starts after its canonical position, never before it (e.g. one
                   tuple decoded out of multi-param calldata); prints gap_bytes; trailing bytes still need --allow-trailing
Prints status no_match with the selector/topic when nothing matches; malformed data is bad_input (exit 2).");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut sigs: Vec<blocktools_evm::sig::Sig> = vec![];
    let (mut types, mut output, mut l, mut input) = (None, false, api::Lenient::default(), None);
    let mut i = 0;
    while i < a.len() {
        let next = |i: usize| a.get(i + 1).cloned().unwrap_or_else(|| die(&format!("{}_needs_a_value", a[i])));
        match a[i].as_str() {
            "--sig" => { sigs.push(blocktools_evm::sig::Sig::parse(&next(i)).unwrap_or_else(|e| die(&e))); i += 1; }
            "--abi" => {
                let t = std::fs::read_to_string(next(i)).unwrap_or_else(|_| die("cannot_read_abi_file"));
                sigs.extend(api::load_sigs(&t).unwrap_or_else(|e| die(&e)));
                i += 1;
            }
            "--types" => { types = Some(next(i)); i += 1; }
            "--output" => output = true,
            "--allow-trailing" => l.allow_trailing = true,
            "--allow-gaps" => l.allow_gaps = true,
            x if x.starts_with("--") => die("unknown_option"),
            x => input = Some(x.to_string()),
        }
        i += 1;
    }
    let input = input.unwrap_or_else(|| { let mut s = String::new(); std::io::stdin().take(64 << 20).read_to_string(&mut s).ok(); s });
    if input.trim().is_empty() { die("empty_input"); }
    // expand arrays of logs (getLogs result, receipt.logs) into one request each
    let mut items = vec![];
    match serde_json::from_str::<Value>(input.trim()) {
        Ok(v) if v.is_object() || v.is_array() => {
            let r = v.get("result").cloned().unwrap_or(v.clone());
            match (&r, r.get("logs")) {
                (Value::String(x), _) => items.push(x.clone()),
                (Value::Array(xs), _) => items.extend(xs.iter().map(|x| x.to_string())),
                (_, Some(Value::Array(xs))) if r.get("input").is_none() => items.extend(xs.iter().map(|x| x.to_string())),
                _ => items.push(r.to_string()),
            }
        }
        Ok(Value::String(x)) => items.push(x), // `jq .result.input` without -r
        _ => items.push(input.trim().to_string()),
    }
    let mut rc = 0;
    for it in items {
        match api::decode_with(&it, &sigs, types.as_deref(), output, l) {
            Ok(v) => outln!("{v}"),
            Err(e) => { rc = 2; outln!("{}", json!({"status": "bad_input", "error": e})); }
        }
    }
    std::process::exit(rc);
}
