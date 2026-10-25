//! chain-table: print the chain registry (crates/core chains.rs) as data, one JSON object per
//! chain: name, ticker, SLIP-44 coin type, curve, address encoding and version bytes / hrp,
//! signer kind, whether tx-build signs it, verified flag and parameter source. Public data only.
//! `chain-table` = JSON lines; `chain-table --array` = one JSON array; `chain-table NAME` = one row.
fn main() {
    blocktools_io::help("chain-table [--array | NAME]: the chain registry as JSON (public data, no keys)");
    use blocktools_core::chains;
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        None => for c in chains::CHAINS { println!("{}", chains::chain_json(c)) },
        Some("--array") => println!("{}", chains::table_json()),
        Some(n) => match chains::chain(n) { Some(c) => println!("{}", chains::chain_json(c)), None => { eprintln!("chain-table: unknown chain {n}"); std::process::exit(2) } },
    }
}
