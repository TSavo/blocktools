//! multisig: build an m-of-n P2WSH witness script + address from compressed pubkeys. Offline, no keys.
//!   multisig 3 --pubkey 02ab… --pubkey 02cd… --pubkey 02ef… --pubkey 03… --pubkey 03…  [--network bitcoin]
//! stdout: one JSON line {witness_script, address, descriptor}. The pubkey ORDER is consensus-significant
//! for OP_CHECKMULTISIG, so later sign (and combine) in the SAME order. Only public pubkeys are read.
use blocktools_io::outln;
use serde_json::json;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "multisig", "status": "bad_input", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help(
        "multisig M --pubkey HEX [--pubkey HEX ...] [--network bitcoin|testnet|signet|regtest]
  Build an m-of-n P2WSH: OP_M <pk>… OP_N OP_CHECKMULTISIG, its address, and a wsh(multi(…)) descriptor.
  Compressed pubkeys only; the pubkey ORDER is consensus-significant, so sign in the same order. Offline, no keys.",
    );
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (mut m, mut pubs, mut net) = (None::<usize>, Vec::<String>::new(), "bitcoin".to_string());
    let mut i = 0;
    while i < a.len() {
        match a[i].as_str() {
            "--pubkey" => {
                i += 1;
                pubs.push(a.get(i).cloned().unwrap_or_else(|| die("--pubkey needs a value")));
            }
            "--network" => {
                i += 1;
                net = a.get(i).cloned().unwrap_or_else(|| die("--network needs a value"));
            }
            s if !s.starts_with("--") && m.is_none() => {
                m = Some(s.parse().unwrap_or_else(|_| die("threshold M must be a number")))
            }
            _ => die("unexpected argument"),
        }
        i += 1;
    }
    let m = m.unwrap_or_else(|| die("threshold M (first argument) is required"));
    if pubs.is_empty() {
        die("at least one --pubkey is required")
    }
    match blocktools_tx::multisig::multisig_from_hex(m, &pubs, &net) {
        Ok((witness_script, address, descriptor)) => outln!(
            "{}",
            json!({"tool":"multisig","status":"ok","chain":"btc","witness_script":witness_script,"address":address,"descriptor":descriptor})
        ),
        Err(e) => die(&e),
    }
}
