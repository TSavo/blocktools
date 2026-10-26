//! tx-decode: one transaction on stdin (hex/base64 raw tx, PSBT, EVM RLP, or a JSON line with
//! "psbt"/"tx"/"unsigned_tx"/"signed_tx") -> public JSON lines, or --text for a human summary.
//! Offline, no keys. Flags: --chain btc|ltc|doge (address encoding for UTXO txs), --text,
//! --nvc-json TXID (Novacoin explorer JSON on stdin -> raw hex, hash-checked against TXID).
use std::io::Read;
fn main() {
    blocktools_io::help("tx-decode [--chain btc|ltc|doge] [--text] < transaction -> JSON lines (or plain summary)\n       tx-decode --nvc-json TXID < api.novaco.in gettransaction JSON -> raw tx hex (fails unless the hash is TXID)");
    let a: Vec<String> = blocktools_core::chain_spec::args_or_exit("tx-decode");
    let chain = a.iter().position(|x| x == "--chain").and_then(|i| a.get(i + 1)).map_or("btc", |s| s.as_str());
    let text = a.iter().any(|x| x == "--text");
    let mut s = String::new();
    if std::io::stdin().take(blocktools_tx::MAX_INPUT as u64 + 1).read_to_string(&mut s).is_err() { return fail("bad_input") }
    if let Some(i) = a.iter().position(|x| x == "--nvc-json") {
        let Some(t) = a.get(i + 1) else { return fail("nvc_json_needs_txid") };
        return match blocktools_tx::nvc_json::serialize_nvc_tx_from_json(&s, t) { Ok(h) => blocktools_io::outln!("{h}"), Err(e) => fail(e) };
    }
    match blocktools_tx::decode(&s, chain) {
        Ok(d) if text => blocktools_io::outln!("{}", d.text().trim_end()),
        Ok(d) => for l in d.json_lines() { blocktools_io::outln!("{l}") },
        Err(e) => fail(e),
    }
}
fn fail(e: &str) { blocktools_io::outln!("{}", serde_json::json!({"tool":"tx-decode","status":"bad_input","error":e})); std::process::exit(2) }
