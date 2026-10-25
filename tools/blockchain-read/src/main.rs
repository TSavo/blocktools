//! blockchain-read: Blockchain.com wallet.aes.json (v2/v3) + password -> wif / xprv lines.
//! stdin: line 1 = password, rest = wallet JSON. Output CONTAINS SECRETS.
use std::io::Read;
fn main() {
    blocktools_io::help("blockchain-read < (password line, then Blockchain.com wallet.aes.json v2/v3) -> {\"wif\"} / {\"xprv\"} per key");
    let mut all = Vec::new();
    if std::io::stdin().take(blocktools_secrets::blockchain::MAX_FILE as u64 + 4096).read_to_end(&mut all).is_err() {
        blocktools_io::outln!(r#"{{"tool":"blockchain-read","status":"bad_input"}}"#); std::process::exit(2);
    }
    let n = all.iter().position(|&b| b == b'\n').unwrap_or(all.len());
    let (pw, rest) = all.split_at(n);
    let file = if rest.first() == Some(&b'\n') { &rest[1..] } else { rest };
    let pw = std::str::from_utf8(pw).unwrap_or("").trim_end_matches('\r');
    let json = std::str::from_utf8(file).unwrap_or("");
    match blocktools_secrets::blockchain::decrypt_wrapper(json, pw.as_bytes())
        .and_then(|inner| blocktools_secrets::blockchain::extract_keys(&inner).map(|k| (inner, k)))
    {
        Ok((_inner, keys)) => {
            for k in keys {
                match k {
                    blocktools_secrets::blockchain::KeyOut::Wif(w) => blocktools_io::outln!(r#"{{"tool":"blockchain-read","status":"ok","wif":"{w}"}}"#),
                    blocktools_secrets::blockchain::KeyOut::Xprv(x) => blocktools_io::outln!(r#"{{"tool":"blockchain-read","status":"ok","xprv":"{x}"}}"#),
                }
            }
        }
        Err(e) => { blocktools_io::outln!(r#"{{"tool":"blockchain-read","status":"{e}"}}"#); std::process::exit(1); }
    }
}
