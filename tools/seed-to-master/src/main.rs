//! seed-to-master: BIP39 phrase (+ optional passphrase) -> BIP32 master key.
//! stdin JSON lines: optional {"passphrase":"..."} then {"mnemonic":"...","candidate":N}.
//! Output CONTAINS SECRETS (field "xprv"). One job: phrase -> master key.
use bip39::{Language, Mnemonic};
use bitcoin::bip32::Xpriv;
use bitcoin::Network;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

fn main() {
    let mut passphrase = Zeroizing::new(String::new());
    let mut n = 0u64;
    let reader = std::io::stdin().lock().take(16 << 20);
    for line in reader.lines().map_while(Result::ok) {
        let line = Zeroizing::new(line);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        if let Some(p) = v.get("passphrase").and_then(|m| m.as_str()) {
            if p.len() <= 1024 { passphrase = Zeroizing::new(p.to_string()); }
        }
        let Some(m) = v.get("mnemonic").and_then(|m| m.as_str()) else { continue };
        let cand = v.get("candidate").and_then(|c| c.as_u64()).unwrap_or(0);
        match Mnemonic::parse_in_normalized(Language::English, m) {
            Ok(mn) => {
                let seed = Zeroizing::new(mn.to_seed_normalized(&passphrase));
                let master = Xpriv::new_master(Network::Bitcoin, &seed[..]).expect("seed");
                println!(r#"{{"tool":"seed-to-master","status":"ok","candidate":{cand},"xprv":"{}"}}"#, master);
                n += 1;
            }
            Err(_) => println!(r#"{{"tool":"seed-to-master","status":"checksum_fail","candidate":{cand}}}"#),
        }
    }
    println!(r#"{{"tool":"seed-to-master","status":"done","count":{n}}}"#);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn abandon_about_root() {
        let mn = Mnemonic::parse_in_normalized(Language::English, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        let seed = mn.to_seed_normalized("");
        let m = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        assert_eq!(m.to_string(), "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu");
    }
}
