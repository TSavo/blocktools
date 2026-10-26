//! bytecode-inspect: classify runtime bytecode (EIP-1167 proxy, EIP-7702 delegation, EOF, plain code),
//! check the EIP-170 size limit, parse the Solidity CBOR metadata trailer, count notable opcodes
//! and list dispatcher selector candidates (heuristic), offline.
//!   jq -r .result getCode.json | bytecode-inspect
//!   bytecode-inspect < eth_getCode-response.json
use blocktools_evm::{bytecode, unhex};
use blocktools_io::outln;
use serde_json::{json, Value};
use std::io::Read;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "bytecode-inspect", "status": "error", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help("bytecode-inspect [HEX]
HEX (or stdin): runtime code as 0x-hex, or an eth_getCode JSON-RPC response ({\"result\": \"0x..\"}) as-is.
Prints kind (empty, code, eip1167_proxy + implementation, eip7702_delegation + delegate, eof), size,
exceeds_eip170, keccak256 (the code hash), metadata (solc version, ipfs/bzzr hash), opcode counts and
selector_candidates: PUSH4 values compared with EQ (heuristic; confirm with sig-hash --lookup).");
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.iter().any(|x| x.starts_with("--")) { die("unknown_option"); }
    if a.len() > 1 { die("one_input_only"); }
    let text = match a.first() {
        Some(x) => x.clone(),
        None => { let mut s = String::new(); std::io::stdin().take(64 << 20).read_to_string(&mut s).ok(); s }
    };
    let t = text.trim();
    let h = if t.starts_with('{') || t.starts_with('"') {
        match serde_json::from_str::<Value>(t) {
            Ok(Value::String(s)) => s,
            Ok(v) => match (v.get("result"), v.get("error")) {
                (Some(Value::String(s)), _) => s.clone(),
                (_, Some(_)) => die("rpc_error"),
                _ => die("json_has_no_result_code"),
            },
            Err(_) => die("bad_input_json"),
        }
    } else { t.to_string() };
    let code = unhex(&h).unwrap_or_else(|e| die(&e));
    outln!("{}", bytecode::inspect(&code));
}
