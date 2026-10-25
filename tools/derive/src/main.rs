//! derive: master key -> child keys and addresses. A Swiss Army knife for "which path
//! did this wallet use?": presets plus composable flags build a PLAN (no key material,
//! see --explain), which is then walked for each master key on stdin.
//! Secrets arrive ONLY on stdin; flags carry public parameters only. Run --help.
//! Output CONTAINS SECRETS ("wif"/"private_key") unless --explain/--list-presets.
use bitcoin::bip32::Xpriv;
use blocktools_core::chains::{Enc, Row};
use blocktools_core::plan::{self, norm, Opts};
use blocktools_io::outln;
use blocktools_secrets::walk;
use std::collections::HashSet;
use std::io::{BufRead, Read};
use std::str::FromStr;
use zeroize::Zeroizing;

const HELP: &str = "derive: master key (stdin, from seed-to-master / dat-read) -> addresses + keys

  --chain LIST         any verified row of `chains` (docs/CHAINS.md) or all (repeatable). Default btc,eth
  --preset NAME        common (default), exhaustive, recovery, exodus, tronlink, ledger-live, legacy-hd
  --list-presets       list presets and what they cover
  --address-type LIST  p2pkh,p2sh-p2wpkh,p2wpkh,p2tr,evm|eth,tron,xrp,solana|sol (filters, or with
                       --path/--purpose: which encodings to apply to every path)
  --purpose LIST       e.g. 44,49,84,86 or custom: m/{purpose}'/{coin}'/{account}'/{change}/{i}
  --path TEMPLATE      repeatable; placeholders {purpose} {coin} {account} {change} {i}
                       e.g. \"m/44'/{coin}'/{account}'/{change}/{i}\" or \"m/0'/0'/{i}'\"
  --coin-type N        override the SLIP-44 coin number in {coin}
  --account RANGE      e.g. 0  0..4  0,2   (inclusive)    --change RANGE  e.g. 0,1
  --index RANGE        e.g. 0..9 (inclusive). --count N = 0..N-1. Default per chain (10; eth 5)
  --compressed | --uncompressed | --both   legacy p2pkh key encodings (default: preset's choice)
  --curve secp256k1|ed25519                restrict to one curve
  --match FILE         public target addresses, one per line: print only hits (with their path)
  --gap-limit N        with --match: keep scanning each branch until N misses after the last hit
  --explain            print the plan (paths, address types, counts) and exit; no stdin, no keys
  --help

  Passphrases are never flags: use seed-to-master (stdin {\"passphrase\":...} or --passphrase-prompt).
  TON and electrum-old derivation are planned (docs/ROADMAP.md).
";

fn fail(s: &str) -> ! { outln!(r#"{{"tool":"derive","status":"{s}"}}"#); std::process::exit(2) }

fn main() {
    blocktools_io::help(HELP);
    let a: Vec<String> = std::env::args().skip(1).collect();
    if a.iter().any(|x| x == "--list-presets") { for (n, d) in plan::PRESETS { outln!(r#"{{"tool":"derive","status":"ok","preset":"{n}","description":"{d}"}}"#) } return }
    let o: Opts = plan::from_args(&a).unwrap_or_else(|e| fail(e));
    let match_set: Option<HashSet<String>> = o.match_file.as_ref().map(|f| {
        let mut b = String::new();
        std::fs::File::open(f).and_then(|h| h.take(16 << 20).read_to_string(&mut b)).unwrap_or_else(|_| fail("bad_input"));
        b.lines().map(|l| norm(l.trim())).filter(|l| !l.is_empty()).collect()
    });
    if o.explain {
        let mut total = 0u64;
        for e in plan::explain(&o) { total += e.count; outln!(r#"{{"tool":"derive","status":"ok","chain":"{}","kind":"{}","template":"{}","path":"{}","count":{}}}"#, e.chain, e.kind, e.template, e.path, e.count) }
        outln!(r#"{{"tool":"derive","status":"done","count":{total}}}"#);
        return
    }
    let mut n = 0u64;
    let mut tried = 0u64;
    for line in std::io::stdin().lock().take(16 << 20).lines().map_while(Result::ok) {
        let line = Zeroizing::new(line);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        let Some(x) = v.get("xprv").and_then(|m| m.as_str()) else {
            // Leaf keys already carrying an address (e.g. legacy keys from dat-read) pass through.
            if let Some(a) = v.get("address").and_then(|a| a.as_str()) {
                if v.get("status").and_then(|s| s.as_str()) == Some("ok") && match_set.as_ref().map_or(true, |m| m.contains(&norm(a))) { outln!("{}", line.as_str()); n += 1; }
            }
            continue
        };
        let cand = v.get("candidate").and_then(|c| c.as_u64()).unwrap_or(0);
        let Ok(master) = Xpriv::from_str(x) else { outln!(r#"{{"tool":"derive","status":"bad_input","candidate":{cand}}}"#); continue };
        let mut seen: HashSet<(String, &'static str, &'static str)> = HashSet::new();
        let mut emit = |r: &Row| {
            if !seen.insert((r.path.clone(), r.chain, r.kind)) { return false }
            if let Some(m) = &match_set { if !m.contains(&norm(&r.address)) { return false } }
            outln!(r#"{{"tool":"derive","status":"ok","candidate":{cand},"chain":"{}","kind":"{}","path":"{}","address":"{}","{}":"{}"}}"#,
                r.chain, r.kind, r.path, r.address, r.secret_field, r.secret);
            n += 1; true
        };
        if let (Some(kind), Some(path)) = (v.get("kind").and_then(|k| k.as_str()).and_then(blocktools_core::kind_name), v.get("path").and_then(|p| p.as_str())) {
            if path.len() < 128 { walk::walk_account(&o, &master, kind, path, v.get("branch").and_then(|b| b.as_u64()), &mut emit); continue }
        }
        let seed = Zeroizing::new(v.get("seed").and_then(|s| s.as_str()).and_then(blocktools_core::hex_dec).filter(|s| s.len() == 64));
        if seed.is_none() && o.specs.iter().any(|s| s.chain.enc == Enc::Sol) {
            outln!(r#"{{"tool":"derive","status":"unsupported","candidate":{cand},"chain":"sol"}}"#);
        }
        let scheme = v.get("scheme").and_then(|s| s.as_str()).unwrap_or("bip39");
        if let Err(e) = walk::walk(&o, &master, seed.as_deref().map(|s| &s[..]), scheme, &mut tried, &mut emit) {
            outln!(r#"{{"tool":"derive","status":"{e}","count":{tried}}}"#); std::process::exit(2)
        }
    }
    if match_set.is_some() && n == 0 { outln!(r#"{{"tool":"derive","status":"no_candidates","count":{tried}}}"#) }
    outln!(r#"{{"tool":"derive","status":"done","count":{n}}}"#);
}
