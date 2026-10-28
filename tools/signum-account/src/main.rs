//! signum-account < passphrase
//! stdout: one JSON line of PUBLIC data: the numeric account id and the S- Reed-Solomon address.
//! The secret passphrase is read from stdin, hashed in memory (zeroized), and never echoed.
//! Burst/Signum derivation is NOT BIP39/secp256k1: passphrase -> SHA-256 private key ->
//! Curve25519 base multiplication (clamped, as libsodium/NXT) -> public key -> account id.
use std::io::Read;
use zeroize::Zeroizing;
const HELP: &str = " signum-account < passphrase\n stdout: one JSON line of PUBLIC data: {\"account_id\",\"address\":\"S-...\"}. No secret is echoed.\n The passphrase is the exact secret; a single trailing newline (as a file adds) is stripped, nothing else.";
fn main() {
    blocktools_io::help(HELP);
    let mut s = Zeroizing::new(String::new());
    if std::io::stdin().read_to_string(&mut s).is_err() {
        eprintln!("{{\"tool\":\"signum-account\",\"status\":\"bad_input\",\"error\":\"cannot read input\"}}");
        std::process::exit(2);
    }
    // A wallet file adds a trailing newline; the passphrase itself does not. Strip only that.
    let phrase = s.trim_end_matches(['\n', '\r']);
    if phrase.is_empty() {
        eprintln!("{{\"tool\":\"signum-account\",\"status\":\"bad_input\",\"error\":\"empty passphrase\"}}");
        std::process::exit(2);
    }
    let (id, addr) = blocktools_secrets::burst::account_from_passphrase(phrase);
    blocktools_io::outln!(
        "{{\"tool\":\"signum-account\",\"status\":\"ok\",\"chain\":\"signum\",\"kind\":\"signum\",\"address\":\"{addr}\",\"account_id\":\"{id}\"}}"
    );
}
