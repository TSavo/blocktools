//! tx-envelope: common signing envelope (public half). Reads one JSON object from stdin
//! (or `--json '{...}'`) and prints one JSON object: decode / verify / check / chain_table
//! across UTXO, EVM, ZEC, Sol and Tron. Never takes a private key. Same schema as the C ABI
//! `bt_envelope` and `blocktools::envelope::run` (`envelope":"blocktools.sign/v1"`).
//!   echo '{"op":"decode","chain":"btc","tx":"<hex|psbt>"}' | tx-envelope
//!   tx-envelope --json '{"op":"chain_table","chain":"_"}'
use std::io::Read;

fn main() {
    blocktools_io::help("tx-envelope [--json OBJ]: common signing envelope (decode|verify|check|chain_table); public data only");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let input = if let Some(i) = a.iter().position(|x| x == "--json") {
        a.get(i + 1).cloned().unwrap_or_else(|| {
            eprintln!("{{\"tool\":\"tx-envelope\",\"status\":\"bad_input\",\"error\":\"--json needs a value\"}}");
            std::process::exit(2);
        })
    } else {
        let mut s = String::new();
        std::io::stdin().take(4 << 20).read_to_string(&mut s).ok();
        s
    };
    if input.trim().is_empty() {
        eprintln!("{{\"tool\":\"tx-envelope\",\"status\":\"bad_input\",\"error\":\"empty_input\"}}");
        std::process::exit(2);
    }
    println!("{}", blocktools::envelope::run(&input));
}
