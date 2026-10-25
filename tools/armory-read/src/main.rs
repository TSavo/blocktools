//! armory-read: Armory (PyBtcWallet) `.wallet` -> {"wif","chain_index"} per stored address
//! (uncompressed keys, as Armory uses). Output CONTAINS SECRETS. Pipe to key-to-addresses
//! --chain btc (addresses) or tx-sign (keys).
//! stdin: line 1 = password (empty for an unencrypted wallet), rest = the wallet file.
//! Thin wrapper around blocktools_secrets::armory; every key reproduces the stored public key.
use blocktools_secrets::armory;
use std::io::Read;
use zeroize::Zeroizing;

fn fail(e: &str) -> ! { blocktools_io::outln!(r#"{{"tool":"armory-read","status":"{e}"}}"#); std::process::exit(if e == "bad_input" { 2 } else { 1 }) }
fn main() {
    blocktools_io::help("armory-read < (password line, then Armory .wallet) -> {\"wif\",\"chain_index\"} per address");
    let mut all = Zeroizing::new(Vec::new());
    if std::io::stdin().take(armory::MAX_FILE as u64 + 4096).read_to_end(&mut all).is_err() { fail("bad_input") }
    let nl = all.iter().position(|&c| c == b'\n').unwrap_or(all.len());
    let pw = Zeroizing::new(String::from_utf8(all[..nl].to_vec()).unwrap_or_else(|_| fail("bad_input")));
    let pw = pw.trim_end_matches('\r');
    match armory::open(&all[(nl + 1).min(all.len())..], pw) {
        Ok(k) => for (i, w) in k { blocktools_io::outln!(r#"{{"tool":"armory-read","status":"ok","format":"armory","chain_index":{i},"wif":"{}"}}"#, w.as_str()) },
        Err(e) => fail(e),
    }
}
