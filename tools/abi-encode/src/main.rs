//! abi-encode: Solidity ABI-encode calldata (selector + args) or a bare type list, offline.
//! Arrays/tuples are JSON arrays; integers decimal or 0x-hex; bytes 0x-hex. Inverse of abi-decode.
//!   abi-encode 'transfer(address,uint256)' 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed 1000000
//!   abi-encode '(address,address,uint24)' 0x..a 0x..b 500 --raw
//!   echo '{"sig":"f(uint256[])","args":[["1","2"]]}' | abi-encode
use blocktools_evm::api;
use blocktools_io::outln;
use serde_json::{json, Value};
use std::io::Read;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "abi-encode", "status": "bad_input", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help("abi-encode [SIGNATURE ARG...] [--raw]
  --raw   print only the 0x-hex data, for piping
SIGNATURE 'name(T,..)' prepends the 4-byte selector; '(T,..)' encodes the bare arguments.
An ARG starting with [ is parsed as JSON (arrays, tuples). With no SIGNATURE, reads {\"sig\":..,\"args\":[..]} from stdin.");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let raw = a.iter().any(|x| x == "--raw");
    if let Some(x) = a.iter().find(|x| x.starts_with("--") && *x != "--raw") { let _ = x; die("unknown_option"); }
    let pos: Vec<&String> = a.iter().filter(|x| *x != "--raw").collect();
    let r = if pos.is_empty() {
        let mut s = String::new();
        std::io::stdin().take(16 << 20).read_to_string(&mut s).ok();
        let v: Value = serde_json::from_str(s.trim()).unwrap_or_else(|_| die("stdin_needs_json_sig_args"));
        api::encode_json(&v)
    } else {
        let args: Vec<Value> = pos[1..].iter().map(|x| if x.starts_with('[') {
            serde_json::from_str(x).unwrap_or_else(|_| die("bad_json_arg"))
        } else if *x == "true" || *x == "false" { json!(*x == "true") } else { json!(x) }).collect();
        api::encode_call(pos[0], &args)
    };
    match r {
        Ok(v) => if raw { outln!("{}", v["data"].as_str().unwrap_or_default()) } else { outln!("{v}") },
        Err(e) => die(&e),
    }
}
