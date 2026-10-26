//! phrase-to-key: pre-BIP39 brainwallet phrase -> raw 32-byte private key, one line per scheme.
//! stdin lines: a bare phrase (the whole line, byte for byte, without the line end), or a JSON line
//! {"phrase":"...","salt":"..."} (salt = WarpWallet e-mail, default empty). Output lines
//! {"tool":"phrase-to-key","status":"ok","line":N,"scheme":S,"private_key":HEX} feed key-to-addresses,
//! which prints the compressed AND uncompressed addresses (brainwallet.org used uncompressed).
//! Schemes: sha256 (brainwallet.org, bitaddress.org; default) and warpwallet (keybase: scrypt 2^18 +
//! PBKDF2, memory-hungry and about a second per phrase; --scheme warpwallet or all).
//! No scheme has a checksum: a wrong phrase gives a wrong key, never an error. Output CONTAINS SECRETS.
use blocktools_secrets::brain;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

fn main() {
    blocktools_io::help("phrase-to-key [--scheme sha256|warpwallet|all] < phrase lines (or {\"phrase\":...,\"salt\":...}) -> {\"scheme\",\"private_key\"} per scheme; pipe into key-to-addresses\n  --scheme LIST  sha256 (brainwallet.org/bitaddress.org, default), warpwallet (keybase, needs salt = e-mail, slow), or all");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let bad = || -> ! { blocktools_io::outln!(r#"{{"tool":"phrase-to-key","status":"bad_input"}}"#); std::process::exit(2) };
    let schemes: Vec<&str> = match a.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        [] => vec!["sha256"],
        ["--scheme", "all"] => brain::SCHEMES.to_vec(),
        ["--scheme", l] => { let v: Vec<&str> = l.split(',').collect(); if v.iter().any(|s| !brain::SCHEMES.contains(s)) { bad() } v }
        _ => bad(),
    };
    let (mut n, mut lineno) = (0u64, 0u64);
    for line in std::io::stdin().lock().take(16 << 20).lines().map_while(Result::ok) {
        lineno += 1;
        let line = Zeroizing::new(line);
        let t = line.strip_suffix('\r').unwrap_or(&line);
        if t.is_empty() { continue }
        let (phrase, salt) = match serde_json::from_str::<serde_json::Value>(t) {
            Ok(v) if v.is_object() => match v.get("phrase").and_then(|p| p.as_str()) {
                Some(p) => (Zeroizing::new(p.to_string()), Zeroizing::new(v.get("salt").and_then(|s| s.as_str()).unwrap_or("").to_string())),
                None => { blocktools_io::outln!(r#"{{"tool":"phrase-to-key","status":"bad_input","line":{lineno}}}"#); continue }
            },
            _ => (Zeroizing::new(t.to_string()), Zeroizing::new(String::new())),
        };
        if phrase.len() > 4096 || salt.len() > 1024 { blocktools_io::outln!(r#"{{"tool":"phrase-to-key","status":"bad_input","line":{lineno}}}"#); continue }
        for s in &schemes {
            let key = match *s {
                "sha256" => brain::sha256_key(phrase.as_bytes()),
                _ => match brain::warpwallet_key(phrase.as_bytes(), salt.as_bytes()) { Ok(k) => k, Err(e) => { blocktools_io::outln!(r#"{{"tool":"phrase-to-key","status":"{e}","line":{lineno}}}"#); continue } },
            };
            let scheme = if *s == "sha256" { "brainwallet-sha256" } else { "warpwallet" };
            let hex = Zeroizing::new(blocktools_core::hex_enc(&key[..]));
            blocktools_io::outln!(r#"{{"tool":"phrase-to-key","status":"ok","line":{lineno},"scheme":"{scheme}","private_key":"{}"}}"#, hex.as_str());
            n += 1;
        }
    }
    blocktools_io::outln!(r#"{{"tool":"phrase-to-key","status":"done","count":{n}}}"#);
}
