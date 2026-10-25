//! dat-read against wallets: self-made (committed, public/throwaway keys) and
//! optional third-party public test wallets (scripts/fetch-fixtures.sh).
use std::io::Write;
use std::process::{Command, Stdio};

fn root() -> std::path::PathBuf { std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..") }
fn run(pw: &str, file: &[u8]) -> (i32, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_dat-read")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    let mut i = c.stdin.take().unwrap();
    let mut data = format!("{pw}\n").into_bytes(); data.extend_from_slice(file);
    let _ = i.write_all(&data); drop(i);
    let o = c.wait_with_output().unwrap();
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned())
}
fn fx(p: &str) -> Option<Vec<u8>> { std::fs::read(root().join(p)).ok() }

#[test] fn self_made_plain_and_encrypted() {
    for (f, pw) in [("fixtures/self-made/descriptor-plain.sqlite", ""), ("fixtures/self-made/descriptor-encrypted.sqlite", "keyrescue-test-password")] {
        let (rc, out) = run(pw, &fx(f).unwrap());
        assert_eq!(rc, 0, "{f}: {out}");
        assert!(out.contains(r#""kind":"p2wpkh","path":"m/84'/0'/0'","branch":0,"xprv":"xprv"#), "{f}: {out}");
        // throwaway bare key; address computed independently by scripts/make-fixtures.py
        assert!(out.contains(r#""address":"13M3vwLduvWviNdwLqrsLYBf6KLNq1cyYM""#), "{f}");
    }
}
#[test] fn wrong_password() {
    let (rc, out) = run("nope", &fx("fixtures/self-made/descriptor-encrypted.sqlite").unwrap());
    assert_eq!(rc, 2); assert!(out.contains("wrong_password")); assert!(!out.contains("xprv") && !out.contains("wif"));
}
#[test] fn hostile_inputs_do_not_panic() {
    let good = fx("fixtures/self-made/descriptor-plain.sqlite").unwrap();
    let mut seed = 0x1234_5678u64;
    let mut rnd = || { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; seed };
    for n in 0..300 {
        let mut b = good.clone();
        match n % 3 {
            0 => b.truncate((rnd() as usize) % good.len()),
            1 => for _ in 0..20 { let i = (rnd() as usize) % b.len(); b[i] = rnd() as u8; },
            _ => { let i = 100 + (rnd() as usize) % 200; b[i] = 0xff; b[i + 1] = 0xff; }
        }
        let (rc, _) = run("", &b);
        assert!(rc == 0 || rc == 2, "case {n}: exit {rc} (panic/abort?)");
    }
    assert_eq!(run("", b"not a wallet").0, 2);
    let mut bdb = vec![0u8; 8192 * 4]; bdb[12..16].copy_from_slice(&[0x62, 0x31, 0x05, 0]); bdb[20..24].copy_from_slice(&8192u32.to_le_bytes());
    bdb[8192 + 25] = 5; bdb[8192 + 20] = 0xff; // leaf page claiming 255 entries with garbage offsets
    assert!(run("", &bdb).0 <= 2);
}
// Third-party public test wallets (btcrecover, password "btcr-test-password"); skipped if absent.
#[test] fn external_core_wallets() {
    for (f, min_keys) in [("bitcoincore-wallet.dat", 1), ("bitcoincore-0.20.1-wallet.dat", 1), ("bitcoincore-0.21.1-wallet.dat", 6)] {
        let Some(b) = fx(&format!("fixtures/external/{f}")) else { eprintln!("skip {f} (run scripts/fetch-fixtures.sh)"); continue };
        let (rc, out) = run("btcr-test-password", &b);
        assert_eq!(rc, 0, "{f}");
        let n: usize = out.lines().last().unwrap().split("\"count\":").nth(1).unwrap().trim_end_matches('}').parse().unwrap();
        assert!(n >= min_keys, "{f}: {n} keys");
        assert!(run("wrong", &b).1.contains("wrong_password"), "{f}");
    }
}
