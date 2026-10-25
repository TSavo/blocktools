//! tx-decode: one transaction on stdin (hex/base64 raw tx, PSBT, EVM RLP, or a JSON line with
//! "psbt"/"tx"/"unsigned_tx"/"signed_tx") -> public JSON lines, or --text for a human summary.
//! Offline, no keys. Flags: --chain btc|ltc|doge (address encoding for UTXO txs), --text.
use std::io::Read;
fn main() {
    blocktools_io::help("tx-decode [--chain btc|ltc|doge] [--text] < transaction -> JSON lines (or plain summary)");
    let a: Vec<String> = std::env::args().collect();
    let chain = a.iter().position(|x| x == "--chain").and_then(|i| a.get(i + 1)).map_or("btc", |s| s.as_str());
    let text = a.iter().any(|x| x == "--text");
    let mut s = String::new();
    if std::io::stdin().take(blocktools_tx::MAX_INPUT as u64 + 1).read_to_string(&mut s).is_err() { return fail("bad_input") }
    match blocktools_tx::decode(&s, chain) {
        Ok(d) if text => blocktools_io::outln!("{}", d.text().trim_end()),
        Ok(d) => for l in d.json_lines() { blocktools_io::outln!("{l}") },
        Err(e) => fail(e),
    }
}
fn fail(e: &str) { blocktools_io::outln!("{}", serde_json::json!({"tool":"tx-decode","status":"bad_input","error":e})); std::process::exit(2) }
