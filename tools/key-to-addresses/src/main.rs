//! key-to-addresses: one raw 32-byte private key per line -> addresses on every chain in the
//! table (BTC-family compressed AND uncompressed, ETH, Tron, XRP, and Solana treating the bytes
//! as an ed25519 seed). Accepted encodings: 64 hex (0x optional), base64, base58, WIF,
//! or a JSON line {"key":"..."} / {"wif":"..."}. An ambiguous string is tried in every encoding that yields
//! exactly 32 bytes; each decoding is a separate "candidate".
//! Output CONTAINS SECRETS. Thin wrapper around blocktools_secrets::keys. Flags: --chain a,b (default all; zec t1 only when listed).
use blocktools_core::chains::{self, Chain, Enc};
use blocktools_io::outln;
use blocktools_secrets::keys;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

fn main() {
    blocktools_io::help(r#"key-to-addresses [--chain LIST] < raw 32-byte key (hex, WIF, base58, base64, {"key":...}) -> addresses on every chain"#);
    let a: Vec<String> = std::env::args().collect();
    let mut sel: Vec<&'static Chain> = chains::CHAINS.iter().filter(|c| c.verified).collect();
    let mut zec = false; // t1 only, on request (not in the chains table)
    match a.get(1).map(String::as_str) {
        None => {}
        Some("--chain") if a.len() == 3 => { zec = a[2].split(',').any(|c| c == "zec"); sel = a[2].split(',').filter_map(chains::chain).collect() }
        _ => { outln!(r#"{{"tool":"key-to-addresses","status":"bad_input"}}"#); std::process::exit(2) }
    }
    let (mut n, mut lineno) = (0u64, 0u64);
    for line in std::io::stdin().lock().take(16 << 20).lines().map_while(Result::ok) {
        lineno += 1;
        let line = Zeroizing::new(line);
        let t = line.trim();
        let tok = Zeroizing::new(match serde_json::from_str::<serde_json::Value>(t) {
            Ok(v) => match v.get("key").or_else(|| v.get("wif")).and_then(|k| k.as_str()) { Some(k) => k.to_string(), None => continue },
            Err(_) => t.to_string(),
        });
        if tok.is_empty() { continue }
        let ds = keys::decodings(&tok);
        if ds.is_empty() { outln!(r#"{{"tool":"key-to-addresses","status":"unsupported","line":{lineno}}}"#); continue }
        for (cand, (enc, bytes, comp)) in ds.iter().enumerate() {
            // A native mnemonic only means something on its own chain family.
            let only = match *enc { "algo-mnemonic" => Some(Enc::Algo), "substrate-mnemonic" => Some(Enc::Ss58 { prefix: 0 }), "ton-mnemonic" => Some(Enc::Ton), "cardano-mnemonic" => Some(Enc::Ada), _ => None };
            let zrows = match (zec && only.is_none(), <[u8; 32]>::try_from(&bytes[..])) { (true, Ok(k)) => keys::zec_rows(&k, *comp), _ => vec![] };
            for r in zrows {
                outln!(r#"{{"tool":"key-to-addresses","status":"ok","line":{lineno},"candidate":{cand},"chain":"{}","kind":"{}","address":"{}","{}":"{}"}}"#,
                    r.chain, r.kind, r.address, r.secret_field, r.secret);
                n += 1;
            }
            for c in sel.iter().filter(|c| only.map_or(true, |e| matches!((e, c.enc), (Enc::Algo, Enc::Algo) | (Enc::Ton, Enc::Ton) | (Enc::Ada, Enc::Ada) | (Enc::Ss58 { .. }, Enc::Ss58 { .. })))) {
                let rows = if *enc == "cardano-mnemonic" { keys::ada_rows(c, bytes) } else { match <[u8; 32]>::try_from(&bytes[..]) { Ok(seed) => keys::rows_for(c, &seed, *comp), Err(_) => vec![] } };
                for r in rows {
                    outln!(r#"{{"tool":"key-to-addresses","status":"ok","line":{lineno},"candidate":{cand},"chain":"{}","kind":"{}","address":"{}","{}":"{}"}}"#,
                        r.chain, r.kind, r.address, r.secret_field, r.secret);
                    n += 1;
                }
            }
        }
    }
    outln!(r#"{{"tool":"key-to-addresses","status":"done","count":{n}}}"#);
}
