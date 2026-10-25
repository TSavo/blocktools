//! electrum-read: Electrum wallet file (JSON, optionally field-encrypted, or BIE1 whole-file encrypted) -> its seed phrase
//! ({"mnemonic"}) and/or master key ({"xprv"}). Output CONTAINS SECRETS. Pipe to seed-to-master
//! (mnemonic) or derive (xprv). stdin: line 1 = wallet password (empty if none), rest = wallet file.
//! Electrum 1.x files: the keys themselves ({"wif","address","path"}, uncompressed P2PKH, `--count N`
//! per branch, default 20), checked against the file's master_public_key.
//! Thin wrapper around blocktools_secrets::electrum.
use blocktools_secrets::electrum::{old_keys, open, py_to_json, Item, MAX_FILE};
use serde_json::json;
use std::io::Read;
use zeroize::Zeroizing;

fn main() {
    blocktools_io::help("electrum-read < (password line, then Electrum wallet JSON) -> {\"mnemonic\"} / {\"xprv\"}");
    let mut all = Zeroizing::new(String::new());
    if std::io::stdin().take(MAX_FILE as u64).read_to_string(&mut all).is_err() { blocktools_io::outln!(r#"{{"tool":"electrum-read","status":"bad_input"}}"#); std::process::exit(2) }
    let (pw, body) = all.split_once('\n').unwrap_or(("", &all));
    match open(body, pw.trim_end_matches('\r')) {
        Ok(items) => for i in items {
            let v = match &i { Item::Mnemonic(m) => json!({"tool":"electrum-read","status":"ok","mnemonic":m.as_str()}),
                               Item::Xprv(x) => json!({"tool":"electrum-read","status":"ok","xprv":x.as_str()}),
                               Item::OldSeed(s) => {
                                   let a: Vec<String> = std::env::args().collect();
                                   let count = a.iter().position(|x| x == "--count").and_then(|i| a.get(i + 1)).and_then(|n| n.parse().ok()).unwrap_or(20u32).min(10_000);
                                   let mpk = py_to_json(body.trim()).and_then(|j| serde_json::from_str::<serde_json::Value>(&j).ok())
                                       .and_then(|v| v["master_public_key"].as_str().map(String::from));
                                   match old_keys(&s, mpk.as_deref(), count) {
                                       Ok(ks) => for (w, ad, p) in ks { blocktools_io::outln!("{}", json!({"tool":"electrum-read","status":"ok","chain":"btc","kind":"p2pkh-uncompressed","scheme":"electrum-old","path":p,"address":ad,"wif":w.as_str()})) },
                                       Err(e) => { blocktools_io::outln!("{}", json!({"tool":"electrum-read","status":e})); std::process::exit(1) }
                                   }
                                   continue;
                               } };
            blocktools_io::outln!("{v}");
        },
        Err(e) => { blocktools_io::outln!("{}", json!({"tool":"electrum-read","status":e})); std::process::exit(1) }
    }
}
