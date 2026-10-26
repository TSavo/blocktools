//! create-address: contract address from CREATE (deployer, nonce) or CREATE2 (EIP-1014: deployer, salt, init code), offline.
//! Reads a deployment tx (eth_getTransactionByHash response, `from` + `nonce`) from stdin when no flags are given.
//!   create-address --deployer 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0 --nonce 1
//!   create-address --deployer 0x1F98431c8aD98523631AE4a59f267346ea31F984 --salt 0x.. --init-code-hash 0x..
//!   create-address < deploy-tx.json
use blocktools_evm::api;
use blocktools_io::outln;
use serde_json::{json, Map, Value};
use std::io::Read;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "create-address", "status": "bad_input", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help("create-address [--deployer ADDR (--nonce N | --salt HEX32 (--init-code-hash HEX32 | --init-code HEX))]
  --deployer ADDR        deploying account or factory (EIP-55 checked when mixed case)
  --nonce N              CREATE: deployer nonce, decimal or 0x-hex
  --salt HEX32           CREATE2: 32-byte salt
  --init-code-hash HEX32 CREATE2: keccak256 of the init code
  --init-code HEX        CREATE2: the init code itself (hashed here)
With no flags, reads JSON from stdin: a tx / eth_getTransactionByHash response (from, nonce) or {deployer, ...}.");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let req = if a.is_empty() {
        let mut s = String::new();
        std::io::stdin().take(16 << 20).read_to_string(&mut s).ok();
        serde_json::from_str::<Value>(s.trim()).unwrap_or_else(|_| die("stdin_needs_json"))
    } else {
        let mut m = Map::new();
        let mut i = 0;
        while i < a.len() {
            let k = match a[i].as_str() {
                "--deployer" => "deployer", "--nonce" => "nonce", "--salt" => "salt",
                "--init-code-hash" => "init_code_hash", "--init-code" => "init_code", _ => die("unknown_option"),
            };
            m.insert(k.into(), json!(a.get(i + 1).unwrap_or_else(|| die("option_needs_a_value"))));
            i += 2;
        }
        Value::Object(m)
    };
    match api::create_json(&req) { Ok(v) => outln!("{v}"), Err(e) => die(&e) }
}
