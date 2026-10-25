//! multibit-read: MultiBit Classic .key export, bitcoinj/MultiBit Classic `.wallet` protobuf, or
//! MultiBit HD `mbhd.wallet.aes` -> {"wif"} per key, or {"xprv"} (BIP32 master; MultiBit HD
//! accounts are at m/0') for an HD wallet. Output CONTAINS SECRETS.
//! Pipe to key-to-addresses / derive (addresses) or tx-sign (keys).
//! stdin: line 1 = password (empty for a cleartext wallet), rest = the file (text or binary).
//! Thin wrapper around blocktools_secrets::{multibit, bitcoinj}.
use blocktools_secrets::{bitcoinj, multibit};
use std::io::Read;
use zeroize::Zeroizing;

fn fail(e: &str) -> ! { blocktools_io::outln!(r#"{{"tool":"multibit-read","status":"{e}"}}"#); std::process::exit(if e == "bad_input" { 2 } else { 1 }) }
fn main() {
    blocktools_io::help("multibit-read < (password line, then MultiBit .key / bitcoinj .wallet / mbhd.wallet.aes) -> {\"wif\"} or {\"xprv\"} per key");
    let mut all = Zeroizing::new(Vec::new());
    if std::io::stdin().take(bitcoinj::MAX_FILE as u64 + 4096).read_to_end(&mut all).is_err() { fail("bad_input") }
    let nl = all.iter().position(|&c| c == b'\n').unwrap_or(all.len());
    let pw = Zeroizing::new(String::from_utf8(all[..nl].to_vec()).unwrap_or_else(|_| fail("bad_input")));
    let pw = pw.trim_end_matches('\r');
    let body = &all[(nl + 1).min(all.len())..];
    let text = std::str::from_utf8(body).ok().filter(|t| t.trim_start().starts_with("U2FsdGVk"));
    if let Some(t) = text {
        if t.len() > multibit::MAX_FILE { fail("bad_input") }
        match multibit::open(t, pw) { Ok(k) => for w in k { blocktools_io::outln!(r#"{{"tool":"multibit-read","status":"ok","wif":"{}"}}"#, w.as_str()) }, Err(e) => fail(e) }
        return
    }
    match bitcoinj::open(body, pw) {
        Ok(k) => for s in k { match s {
            bitcoinj::Secret::Wif(w) => blocktools_io::outln!(r#"{{"tool":"multibit-read","status":"ok","format":"bitcoinj","wif":"{}"}}"#, w.as_str()),
            bitcoinj::Secret::Master(x) => blocktools_io::outln!(r#"{{"tool":"multibit-read","status":"ok","format":"bitcoinj-hd","account_path":"m/0'","xprv":"{}"}}"#, x.as_str()),
        } },
        Err(e) => fail(e),
    }
}
