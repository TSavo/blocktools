//! electrum-read: Electrum wallet file (JSON, optionally field-encrypted) -> its seed phrase
//! ({"mnemonic"}) and/or master key ({"xprv"}). Output CONTAINS SECRETS. Pipe to seed-to-master
//! (mnemonic) or derive (xprv). stdin: line 1 = wallet password (empty if none), rest = wallet file.
//! Thin wrapper around blocktools_secrets::electrum.
use blocktools_secrets::electrum::{open, Item, MAX_FILE};
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
                               Item::Xprv(x) => json!({"tool":"electrum-read","status":"ok","xprv":x.as_str()}) };
            blocktools_io::outln!("{v}");
        },
        Err(e) => { blocktools_io::outln!("{}", json!({"tool":"electrum-read","status":e})); std::process::exit(1) }
    }
}
