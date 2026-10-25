//! bip38-open: BIP38 encrypted private key + passphrase -> WIF. Spec vectors only for non-EC
//! form (6PR/6PY). stdin: line 1 = passphrase, line 2 = encrypted key (or argv). Output CONTAINS SECRETS.
use std::io::Read;
fn main() {
    blocktools_io::help("bip38-open < (passphrase line, then BIP38 6P... key) -> {\"wif\",\"compressed\"}; non-EC-multiplied only");
    let mut all = String::new();
    if std::io::stdin().take(4096).read_to_string(&mut all).is_err() {
        blocktools_io::outln!(r#"{{"tool":"bip38-open","status":"bad_input"}}"#); std::process::exit(2);
    }
    let mut lines = all.splitn(2, '\n');
    let pw = lines.next().unwrap_or("").trim_end_matches('\r');
    let enc = lines.next().unwrap_or("").trim();
    if enc.is_empty() { blocktools_io::outln!(r#"{{"tool":"bip38-open","status":"bad_input"}}"#); std::process::exit(2); }
    match blocktools_secrets::bip38::decrypt(enc, pw) {
        Ok((key, compressed)) => {
            let mut p = vec![0x80u8]; p.extend_from_slice(&key[..]);
            if compressed { p.push(0x01); }
            let wif = bitcoin::base58::encode_check(&p);
            blocktools_io::outln!(r#"{{"tool":"bip38-open","status":"ok","compressed":{},"wif":"{}"}}"#, compressed, wif);
        }
        Err(e) => { blocktools_io::outln!(r#"{{"tool":"bip38-open","status":"{e}"}}"#); std::process::exit(1); }
    }
}
