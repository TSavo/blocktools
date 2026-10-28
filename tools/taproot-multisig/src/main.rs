//! taproot-multisig: build a script-path m-of-n (BIP341/342 tapscript CHECKSIGADD) committed under the
//! unspendable NUMS internal key, from x-only (or compressed) pubkeys. Offline, no keys.
//!   taproot-multisig 2 --pubkey ab… --pubkey cd… --pubkey ef…  [--network bitcoin]
//! stdout: one JSON line {leaf_script, address, control_block, merkle_root, internal_key, descriptor}.
//! The pubkey ORDER is consensus-significant (the witness supplies one element per key in reverse),
//! so later sign (and combine) in the SAME order. Only public pubkeys are read.
use blocktools_io::outln;
use serde_json::json;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "taproot-multisig", "status": "bad_input", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help(
        "taproot-multisig M --pubkey HEX [--pubkey HEX ...] [--network bitcoin|testnet|signet|regtest]
  Build a Taproot SCRIPT-PATH m-of-n: one tapleaf `<pk1> CHECKSIG <pk2> CHECKSIGADD … <M> NUMEQUAL`
  under the BIP341 NUMS internal key (no key-path spend), its P2TR address, the control block and
  merkle root. x-only (32-byte) or compressed (33-byte) pubkeys; the ORDER is consensus-significant,
  so sign in the same order. Offline, no keys.",
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
    match blocktools_tx::taproot_multisig::taproot_multisig_from_hex(m, &pubs, &net) {
        Ok((leaf_script, address, control_block, merkle_root, descriptor)) => outln!(
            "{}",
            json!({"tool":"taproot-multisig","status":"ok","chain":"btc",
                   "leaf_script":leaf_script,"address":address,"control_block":control_block,
                   "merkle_root":merkle_root,
                   "internal_key":blocktools_tx::taproot_multisig::NUMS_XONLY_HEX,"descriptor":descriptor})
        ),
        Err(e) => die(&e),
    }
}
