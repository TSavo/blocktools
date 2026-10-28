//! new-seed: generate a fresh BIP39 mnemonic (keygen). No stdin.
//! `--words 12|24` picks 128 or 256 bits of OS-CSPRNG entropy (default 24). The mnemonic is emitted
//! as {"tool":"new-seed","status":"ok","mnemonic":"..."} — exactly the shape seed-to-master reads
//! ({"mnemonic":...} lines), so `new-seed | seed-to-master | derive --chain eth` makes a wallet.
//! Output CONTAINS A SECRET ("mnemonic"): redact / sealed-run blank it to [REDACTED]. The human
//! backup path is `./blocktools reveal`.
//! A hidden `--entropy <hex>` replaces the CSPRNG with caller-supplied entropy (TEST-ONLY, for the
//! known-answer vectors); it is not shown in --help.
use blocktools_secrets::seed;
use zeroize::Zeroizing;

fn bad() -> ! { blocktools_io::outln!(r#"{{"tool":"new-seed","status":"bad_input"}}"#); std::process::exit(2) }

fn main() {
    blocktools_io::help("new-seed [--words 12|24] -> a fresh BIP39 mnemonic (OS CSPRNG). Default 24 words (256-bit).\n  Pipe into seed-to-master | derive to make a wallet. Output holds a SECRET (\"mnemonic\").");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut words: usize = 24;
    let mut entropy_hex: Option<Zeroizing<String>> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--words" => { i += 1; match args.get(i).map(|s| s.as_str()) { Some("12") => words = 12, Some("24") => words = 24, _ => bad() } }
            // TEST-ONLY: supply the entropy directly (hex) instead of drawing from the CSPRNG.
            "--entropy" => { i += 1; match args.get(i) { Some(h) => entropy_hex = Some(Zeroizing::new(h.clone())), None => bad() } }
            _ => bad(),
        }
        i += 1;
    }
    let mnemonic: Zeroizing<String> = match entropy_hex {
        Some(h) => {
            let h = h.trim();
            if h.len() % 2 != 0 || h.len() > 128 || !h.bytes().all(|b| b.is_ascii_hexdigit()) { bad() }
            let mut bytes = Zeroizing::new(Vec::with_capacity(h.len() / 2));
            for c in h.as_bytes().chunks(2) {
                let hi = (c[0] as char).to_digit(16).unwrap() as u8;
                let lo = (c[1] as char).to_digit(16).unwrap() as u8;
                bytes.push((hi << 4) | lo);
            }
            match seed::from_entropy(&bytes[..]) { Ok(m) => m, Err(_) => bad() }
        }
        None => seed::generate(words * 32 / 3), // 12 words -> 128 bits, 24 words -> 256 bits
    };
    blocktools_io::outln!(r#"{{"tool":"new-seed","status":"ok","mnemonic":"{}"}}"#, mnemonic.as_str());
    blocktools_io::outln!(r#"{{"tool":"new-seed","status":"done","count":1}}"#);
}

#[cfg(test)]
mod tests {
    use blocktools_secrets::seed;
    // KAT: 128-bit all-zero entropy -> the canonical Trezor/BIP39 "abandon ... about" mnemonic,
    // and that line redacts the mnemonic while staying schema-valid.
    #[test] fn kat_abandon_about_redacts() {
        let mn = seed::from_entropy(&[0u8; 16]).unwrap();
        assert_eq!(mn.as_str(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        let line = format!(r#"{{"tool":"new-seed","status":"ok","mnemonic":"{}"}}"#, mn.as_str());
        let red = blocktools_schema::redact_line(&line).expect("schema-valid");
        assert!(red.contains(r#""mnemonic":"[REDACTED]""#), "{red}");
        assert!(!red.contains("abandon"), "{red}");
    }
    #[test] fn done_line_passes_schema() {
        let red = blocktools_schema::redact_line(r#"{"tool":"new-seed","status":"done","count":1}"#).unwrap();
        assert!(red.contains(r#""count":1"#));
    }
}
