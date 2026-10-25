//! derive: BIP32 master key -> child keys and addresses across BIP44/49/84/86
//! and Ethereum m/44'/60'. stdin JSON lines {"xprv":"...","candidate":N}
//! (as printed by seed-to-master). Output CONTAINS SECRETS ("wif"/"private_key").
use bitcoin::bip32::Xpriv;
use std::io::{BufRead, Read};
use std::str::FromStr;
use zeroize::Zeroizing;

fn fail(s: &str) -> ! { println!(r#"{{"tool":"derive","status":"{s}"}}"#); std::process::exit(2) }

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let mut count = 3u32;
    let mut i = 1;
    while i < a.len() {
        match a[i].as_str() {
            "--count" => count = a.get(i + 1).and_then(|s| s.parse().ok()).filter(|n| *n <= 1000).unwrap_or_else(|| fail("bad_input")),
            _ => fail("bad_input"),
        }
        i += 2;
    }
    let mut n = 0u64;
    for line in std::io::stdin().lock().take(16 << 20).lines().map_while(Result::ok) {
        let line = Zeroizing::new(line);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        let Some(x) = v.get("xprv").and_then(|m| m.as_str()) else { continue };
        let cand = v.get("candidate").and_then(|c| c.as_u64()).unwrap_or(0);
        let Ok(master) = Xpriv::from_str(x) else {
            println!(r#"{{"tool":"derive","status":"bad_input","candidate":{cand}}}"#); continue };
        for r in kr_core::derive_from_master(&master, count) {
            let key = if r.kind == "eth" { "private_key" } else { "wif" };
            println!(r#"{{"tool":"derive","status":"ok","candidate":{cand},"kind":"{}","path":"{}","address":"{}","{key}":"{}"}}"#, r.kind, r.path, r.address, r.secret);
            n += 1;
        }
    }
    println!(r#"{{"tool":"derive","status":"done","count":{n}}}"#);
}

#[cfg(test)]
mod tests {
    use super::*;
    // Public vector: BIP32 root of "abandon ... about" (empty passphrase).
    const ROOT: &str = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
    #[test] fn abandon_about() {
        let rows = kr_core::derive_from_master(&Xpriv::from_str(ROOT).unwrap(), 1);
        let got: Vec<(&str, &str)> = rows.iter().map(|r| (r.kind, r.address.as_str())).collect();
        assert_eq!(got, vec![
            ("p2pkh", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"),
            ("p2sh-p2wpkh", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"),
            ("p2wpkh", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
            ("p2tr", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
            ("eth", "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"),
        ]);
    }
}
