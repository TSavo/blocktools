//! derive: BIP32 master key -> child keys and addresses across BIP44/49/84/86
//! and Ethereum m/44'/60'. stdin JSON lines {"xprv":"...","candidate":N}
//! (as printed by seed-to-master: a master key -> all standard kinds), or
//! {"xprv","kind","path","branch"?} (an account-level key, as printed by dat-read:
//! derives path/branch/i for that kind; both branches 0 and 1 if branch is absent). Output CONTAINS SECRETS ("wif"/"private_key").
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
        let Some(x) = v.get("xprv").and_then(|m| m.as_str()) else {
            // Already a leaf key with its address (e.g. a legacy key from dat-read): pass through.
            if v.get("address").is_some() && v.get("status").and_then(|s| s.as_str()) == Some("ok") { println!("{}", line.as_str()); n += 1; }
            continue
        };
        let cand = v.get("candidate").and_then(|c| c.as_u64()).unwrap_or(0);
        let Ok(master) = Xpriv::from_str(x) else {
            println!(r#"{{"tool":"derive","status":"bad_input","candidate":{cand}}}"#); continue };
        // Account-level key (from dat-read etc.): {"xprv","kind","path","branch"?}.
        let rows = match (v.get("kind").and_then(|k| k.as_str()).and_then(kr_core::kind_name), v.get("path").and_then(|p| p.as_str())) {
            (Some(kind), Some(path)) if path.len() < 128 => {
                let branches: Vec<u32> = match v.get("branch").and_then(|b| b.as_u64()) { Some(b) if b < 1 << 31 => vec![b as u32], _ => vec![0, 1] };
                branches.iter().flat_map(|b| kr_core::derive_account(&master, kind, path, *b, count)).collect()
            }
            _ => kr_core::derive_from_master(&master, count),
        };
        for r in rows {
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
