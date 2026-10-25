//! dat-read: Bitcoin Core wallet.dat (legacy Berkeley DB or SQLite descriptor
//! wallet) -> private keys on stdout. Thin wrapper around blocktools_secrets::dat.
//! stdin: line 1 = wallet passphrase (empty line if unencrypted), rest = wallet.dat bytes.
//! Output CONTAINS SECRETS ("wif" per legacy key; "xprv" per HD descriptor).
use blocktools_secrets::dat::{self, Item};
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

const T: &str = "dat-read";
fn die(s: &str) -> ! { blocktools_io::outln!(r#"{{"tool":"{T}","status":"{s}"}}"#); std::process::exit(2) }

fn main() {
    blocktools_io::help("dat-read: Bitcoin Core wallet.dat (stdin) -> account keys / legacy keys. Password via stdin JSON or --password-tty.");
    let mut inp = std::io::stdin().lock().take(256 << 20);
    let mut pw = Zeroizing::new(Vec::new());
    if inp.read_until(b'\n', &mut pw).is_err() { die("bad_input"); }
    while matches!(pw.last(), Some(b'\n' | b'\r')) { pw.pop(); }
    let mut file = Zeroizing::new(Vec::new());
    if inp.read_to_end(&mut file).is_err() { die("bad_input"); }
    let items = dat::read(&pw, &file).unwrap_or_else(|e| die(e));
    for (n, it) in items.iter().enumerate() {
        match it {
            Item::Account { kind, path, branch, xprv } => {
                let br = branch.map(|b| format!(r#","branch":{b}"#)).unwrap_or_default();
                blocktools_io::outln!(r#"{{"tool":"{T}","status":"ok","index":{n},"kind":"{kind}","path":"{path}"{br},"xprv":"{}"}}"#, xprv.as_str());
            }
            Item::Key(rows) => for r in rows {
                blocktools_io::outln!(r#"{{"tool":"{T}","status":"ok","index":{n},"kind":"{}","address":"{}","wif":"{}"}}"#, r.kind, r.address, r.secret);
            },
        }
    }
    blocktools_io::outln!(r#"{{"tool":"{T}","status":"done","count":{}}}"#, items.len());
}
