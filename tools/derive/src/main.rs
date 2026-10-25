//! derive: master key -> child keys and addresses, per chain, from a data table
//! (kr_core::chains). stdin JSON lines:
//!   {"xprv","candidate"?,"seed"?}  master key (seed-to-master): standard paths for each chain;
//!                                  "seed" (BIP39 seed hex) additionally enables ed25519 chains (sol).
//!   {"xprv","kind","path","branch"?} account-level key (dat-read): path/branch/i for that kind.
//!   lines that already carry an "address" pass through unchanged.
//! Flags: --chain btc,eth (default; or "all"), --count N (default per chain: 10, eth 5).
//! Output CONTAINS SECRETS ("wif"/"private_key").
use bitcoin::bip32::Xpriv;
use kr_core::chains::{self, Chain, Row};
use kr_io::outln;

use std::io::{BufRead, Read};
use std::str::FromStr;
use zeroize::Zeroizing;

fn fail(s: &str) -> ! { outln!(r#"{{"tool":"derive","status":"{s}"}}"#); std::process::exit(2) }

fn print(r: &Row, cand: u64) {
    outln!(r#"{{"tool":"derive","status":"ok","candidate":{cand},"chain":"{}","kind":"{}","path":"{}","address":"{}","{}":"{}"}}"#,
        r.chain, r.kind, r.path, r.address, r.secret_field, r.secret);
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mut count: Option<u32> = None;
    let mut sel: Vec<&'static Chain> = vec![chains::chain("btc").unwrap(), chains::chain("eth").unwrap()];
    let mut i = 1;
    while i < a.len() {
        let v = a.get(i + 1).map(String::as_str).unwrap_or_else(|| fail("bad_input"));
        match a[i].as_str() {
            "--count" => count = Some(v.parse().ok().filter(|n| *n <= 1000).unwrap_or_else(|| fail("bad_input"))),
            "--chain" => sel = if v == "all" { chains::CHAINS.iter().collect() } else {
                v.split(',').map(|n| chains::chain(n).unwrap_or_else(|| fail("unsupported"))).collect() },
            _ => fail("bad_input"),
        }
        i += 2;
    }
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut n = 0u64;
    for line in std::io::stdin().lock().take(16 << 20).lines().map_while(Result::ok) {
        let line = Zeroizing::new(line);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        let Some(x) = v.get("xprv").and_then(|m| m.as_str()) else {
            if v.get("address").is_some() && v.get("status").and_then(|s| s.as_str()) == Some("ok") { outln!("{}", line.as_str()); n += 1; }
            continue
        };
        let cand = v.get("candidate").and_then(|c| c.as_u64()).unwrap_or(0);
        let Ok(master) = Xpriv::from_str(x) else {
            outln!(r#"{{"tool":"derive","status":"bad_input","candidate":{cand}}}"#); continue };
        let mut rows = Vec::new();
        match (v.get("kind").and_then(|k| k.as_str()).and_then(kr_core::kind_name), v.get("path").and_then(|p| p.as_str())) {
            (Some(kind), Some(path)) if path.len() < 128 => {
                let branches: Vec<u32> = match v.get("branch").and_then(|b| b.as_u64()) { Some(b) if b < 1 << 31 => vec![b as u32], _ => vec![0, 1] };
                for b in branches { for r in kr_core::derive_account(&master, kind, path, b, count.unwrap_or(10)) {
                    rows.push(Row { chain: "btc", kind: r.kind, path: r.path, address: r.address, secret_field: "wif", secret: r.secret }) } }
            }
            _ => for c in &sel {
                let cnt = count.unwrap_or(c.default_count);
                if c.enc == chains::Enc::Sol {
                    let seed = Zeroizing::new(v.get("seed").and_then(|s| s.as_str()).and_then(kr_core::hex_dec).unwrap_or_default());
                    if seed.len() == 64 { rows.extend(chains::derive_sol(&seed, cnt)) }
                    else { outln!(r#"{{"tool":"derive","status":"unsupported","candidate":{cand},"chain":"sol"}}"#) }
                } else { rows.extend(chains::derive_chain(&master, c, cnt, &secp)) }
            },
        }
        for r in rows { print(&r, cand); n += 1; }
    }
    outln!(r#"{{"tool":"derive","status":"done","count":{n}}}"#);
}

#[cfg(test)]
mod tests {
    use super::*;
    // Public vector: BIP32 root of "abandon ... about" (empty passphrase).
    const ROOT: &str = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
    fn first(chain: &str) -> Vec<(String, String)> {
        let s = bitcoin::secp256k1::Secp256k1::new();
        chains::derive_chain(&Xpriv::from_str(ROOT).unwrap(), chains::chain(chain).unwrap(), 1, &s)
            .into_iter().map(|r| { assert!(r.path.starts_with("m/") && r.path.ends_with("/0/0"), "{}", r.path); (r.kind.to_string(), r.address) }).collect()
    }
    // Expected values: published BIP44/49/84/86 + chain vectors, cross-checked by scripts/kat.py.
    #[test] fn abandon_about_all_chains() {
        let p = |v: &[(&str, &str)]| v.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect::<Vec<_>>();
        assert_eq!(first("btc"), p(&[("p2pkh", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"), ("p2sh-p2wpkh", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"),
            ("p2wpkh", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"), ("p2tr", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")]));
        assert_eq!(first("eth"), p(&[("eth", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94")]));
        let ltc = first("ltc");
        assert_eq!(ltc[0].1, "LUWPbpM43E2p7ZSh8cyTBEkvpHmr3cB8Ez");
        assert_eq!(ltc[2].1, "ltc1qjmxnz78nmc8nq77wuxh25n2es7rzm5c2rkk4wh");
        assert_eq!(first("doge"), p(&[("p2pkh", "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC")]));
        assert_eq!(first("tron"), p(&[("tron", "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH")]));
        // all public lines survive the boundary schema
        let s = bitcoin::secp256k1::Secp256k1::new();
        for c in chains::CHAINS { for r in chains::derive_chain(&Xpriv::from_str(ROOT).unwrap(), c, 1, &s) {
            let l = format!(r#"{{"status":"ok","chain":"{}","kind":"{}","path":"{}","address":"{}"}}"#, r.chain, r.kind, r.path, r.address);
            assert!(kr_schema::redact_line(&l).is_some(), "schema drops {l}");
        } }
        assert_eq!(first("xrp"), p(&[("xrp", "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3")]));
        let seed = bip39_seed();
        assert_eq!(chains::derive_sol(&seed, 1)[0].address, "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk");
    }
    fn bip39_seed() -> Vec<u8> {
        bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &("abandon ".repeat(11) + "about")).unwrap().to_seed_normalized("").to_vec()
    }}
