//! bytecode-inspect: classify runtime bytecode (EIP-1167 proxy, EIP-7702 delegation, EOF, plain code),
//! check the EIP-170 size limit, parse the Solidity CBOR metadata trailer, count notable opcodes
//! and list dispatcher selector candidates (heuristic), offline.
//!   jq -r .result getCode.json | bytecode-inspect
//!   bytecode-inspect < eth_getCode-response.json
//!   bytecode-inspect --metadata metadata.json [--sources DIR] < code.hex   offline source/metadata check, no compiler
use blocktools_evm::{bytecode, metadata, unhex};
use blocktools_io::outln;
use serde_json::{json, Value};
use std::io::Read;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "bytecode-inspect", "status": "bad_input", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help("bytecode-inspect [HEX]
HEX (or stdin): runtime code as 0x-hex, or an eth_getCode JSON-RPC response ({\"result\": \"0x..\"}) as-is.
Prints kind (empty, code, eip1167_proxy + implementation, eip7702_delegation + delegate, eof), size,
exceeds_eip170, keccak256 (the code hash), metadata (solc version, ipfs/bzzr hash), opcode counts and
selector_candidates: PUSH4 values compared with EQ (heuristic; confirm with sig-hash --lookup).
  --metadata FILE   check FILE (the exact metadata.json bytes solc wrote) against the ipfs hash in the code's CBOR
                    trailer (runtime code, or creation code with constructor args appended), and compare the
                    compiler version; prints {\"status\":\"ok\"|\"mismatch\",\"metadata_match\",\"sources\":{path:{status}}}
  --sources DIR     re-hash each source named in the metadata (DIR/<path>) against its keccak256 and dweb:/ipfs URL;
                    sources inlined in the metadata (\"content\") are checked without DIR; absent ones are not_provided
Exit 0 ok, 1 mismatch or no_metadata, 2 bad input. No compiler is run: this proves the files are the ones the
build hashed, not that the code compiles to this bytecode beyond that hash.");
    let mut a: Vec<String> = vec![]; let (mut meta, mut dir) = (None, None);
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--metadata" => meta = Some(std::fs::read(it.next().unwrap_or_else(|| die("--metadata needs FILE"))).unwrap_or_else(|_| die("cannot read --metadata"))),
            "--sources" => dir = Some(std::path::PathBuf::from(it.next().unwrap_or_else(|| die("--sources needs DIR")))),
            s if s.starts_with("--") => die("unknown_option"),
            _ => a.push(x),
        }
    }
    if dir.is_some() && meta.is_none() { die("--sources needs --metadata"); }
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
    if meta.is_none() { outln!("{}", bytecode::inspect(&code)); return; }
    let read = |p: &str| dir.as_ref().and_then(|d| std::fs::read(d.join(p)).ok());
    let (mut o, good) = metadata::check(&code, meta.as_deref(), &read);
    if o["status"] == "bad_input" { die(o["error"].as_str().unwrap_or("bad_input")); }
    o["tool"] = serde_json::json!("bytecode-inspect");
    outln!("{}", o);
    std::process::exit(if good { 0 } else { 1 });
}
