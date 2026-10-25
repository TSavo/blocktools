//! derive: master key -> child keys and addresses. A Swiss Army knife for "which path
//! did this wallet use?": presets plus composable flags build a PLAN (no key material,
//! see --explain), which is then walked for each master key on stdin.
//! Secrets arrive ONLY on stdin; flags carry public parameters only. Run --help.
//! Output CONTAINS SECRETS ("wif"/"private_key") unless --explain/--list-presets.
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::secp256k1::{All, Secp256k1};
use kr_core::chains::{self, Chain, Enc, Row};
use kr_core::plan::{self, Ranges, Spec};
use kr_io::outln;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, Read};
use std::str::FromStr;
use zeroize::Zeroizing;

const HELP: &str = "derive: master key (stdin, from seed-to-master / dat-read) -> addresses + keys

  --chain LIST         btc,ltc,doge,eth,tron,xrp,sol or all (repeatable). Default btc,eth
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

struct Opts { specs: Vec<Spec>, ranges: Ranges, index_set: bool, match_set: Option<HashSet<String>>, gap: Option<u32>, explain: bool }

fn parse_args() -> Opts {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (mut chains_sel, mut preset, mut types, mut purposes, mut paths) = (Vec::<&'static Chain>::new(), "common".to_string(), None::<Vec<String>>, None::<Vec<u32>>, Vec::<String>::new());
    let (mut coin, mut account, mut change, mut index, mut comp, mut curve) = (None, None, None, None, None::<&str>, None::<String>);
    let (mut match_file, mut gap, mut explain) = (None::<String>, None, false);
    let mut i = 0;
    while i < a.len() {
        let flag = a[i].as_str();
        let val = || a.get(i + 1).cloned().unwrap_or_else(|| fail("bad_input"));
        let mut takes = true;
        match flag {
            "--help" | "-h" => { print!("{HELP}"); std::process::exit(0) }
            "--list-presets" => { for (n, d) in plan::PRESETS { outln!(r#"{{"tool":"derive","status":"ok","preset":"{n}","description":"{d}"}}"#) } std::process::exit(0) }
            "--explain" => { explain = true; takes = false }
            "--compressed" | "--uncompressed" | "--both" => { comp = Some(&flag[2..]); takes = false }
            "--chain" => for n in val().split(',') {
                if n == "all" { chains_sel.extend(chains::CHAINS.iter()) } else { chains_sel.push(chains::chain(n).unwrap_or_else(|| fail("unsupported"))) } },
            "--preset" => { preset = val(); if !plan::PRESETS.iter().any(|p| p.0 == preset) { fail("unsupported") } }
            "--address-type" => types = Some(val().split(',').map(|t| match t { "evm" => "eth", "solana" => "sol", x => x }.to_string()).collect()),
            "--purpose" => purposes = Some(val().split(',').map(|p| p.parse().ok().filter(|n: &u32| *n < 1 << 31).unwrap_or_else(|| fail("bad_input"))).collect()),
            "--path" => { let t = val(); if !plan::template_ok(&t) { fail("bad_input") } paths.push(t) }
            "--coin-type" => coin = Some(val().parse::<u32>().ok().filter(|n| *n < 1 << 31).unwrap_or_else(|| fail("bad_input"))),
            "--account" => account = Some(plan::parse_range(&val()).unwrap_or_else(|| fail("bad_input"))),
            "--change" => change = Some(plan::parse_range(&val()).unwrap_or_else(|| fail("bad_input"))),
            "--index" => index = Some(plan::parse_range(&val()).unwrap_or_else(|| fail("bad_input"))),
            "--count" => { let n: u32 = val().parse().ok().filter(|n| (1..=1_000_000).contains(n)).unwrap_or_else(|| fail("bad_input")); index = Some((0..n).collect()) }
            "--curve" => curve = Some(val()),
            "--match" => match_file = Some(val()),
            "--gap-limit" => gap = Some(val().parse::<u32>().ok().filter(|n| (1..=100_000).contains(n)).unwrap_or_else(|| fail("bad_input"))),
            _ => fail("bad_input"),
        }
        i += if takes { 2 } else { 1 };
    }
    if types.as_ref().map_or(false, |t| t.iter().any(|t| t == "ton")) { fail("unsupported") }
    if types.as_ref().map_or(false, |t| t.iter().any(|t| !plan::ADDRESS_TYPES.contains(&t.as_str()))) { fail("bad_input") }
    if chains_sel.is_empty() { chains_sel = vec![chains::chain("btc").unwrap(), chains::chain("eth").unwrap()] }
    let mut specs = if purposes.is_some() || !paths.is_empty() {
        let mut t = paths.clone();
        for p in purposes.iter().flatten() { t.push(format!("m/{p}'/{{coin}}'/{{account}}'/{{change}}/{{i}}")) }
        let mut v = Vec::new();
        for &c in &chains_sel { for k in plan::kinds_of(c) {
            if types.as_ref().map_or(false, |ts| !ts.iter().any(|x| x == k)) { continue }
            for tt in &t { v.push(plan::sp(c, k, tt, false)) }
        } }
        v
    } else {
        let mut v = plan::preset(&preset, &chains_sel).unwrap();
        if let Some(ts) = &types { v.retain(|s| ts.iter().any(|x| x == s.kind) || (s.kind == "p2pkh" && ts.iter().any(|x| x == "p2pkh-uncompressed"))) }
        v
    };
    for s in &mut specs {
        if let Some(c) = coin { s.coin = c }
        match comp { Some("compressed") => s.uncompressed = false, Some("both") | Some("uncompressed") => s.uncompressed = s.kind == "p2pkh", _ => {} }
        if types.as_ref().map_or(false, |t| t.iter().any(|x| x == "p2pkh-uncompressed")) && s.kind == "p2pkh" { s.uncompressed = true }
    }
    if comp == Some("uncompressed") { specs.retain(|s| s.kind == "p2pkh") }
    match curve.as_deref() { Some("ed25519") => specs.retain(|s| s.chain.enc == Enc::Sol), Some("secp256k1") => specs.retain(|s| s.chain.enc != Enc::Sol), None => {}, _ => fail("bad_input") }
    if specs.is_empty() { fail("no_candidates") }
    let (pa, pc) = plan::preset_ranges(&preset);
    let index_set = index.is_some();
    let ranges = Ranges { account: account.unwrap_or(pa), change: change.unwrap_or(pc), index: index.unwrap_or_default() };
    let match_set = match_file.map(|f| {
        let mut b = String::new();
        std::fs::File::open(&f).and_then(|h| h.take(16 << 20).read_to_string(&mut b)).unwrap_or_else(|_| fail("bad_input"));
        b.lines().map(|l| norm(l.trim())).filter(|l| !l.is_empty()).collect::<HashSet<_>>()
    });
    if gap.is_some() && match_set.is_none() { fail("bad_input") }
    Opts { specs, ranges, index_set, match_set, gap, explain }
}
fn norm(a: &str) -> String { if a.starts_with("0x") { a.to_ascii_lowercase() } else { a.to_string() } }
fn indices<'a>(o: &'a Opts, s: &Spec) -> Vec<u32> { if o.index_set { o.ranges.index.clone() } else { (0..s.chain.default_count).collect() } }
/// Does the template vary with {account} / {change}? If not, iterate them once.
fn axis(t: &str, ph: &str, v: &[u32]) -> Vec<u32> { if t.contains(ph) { v.to_vec() } else { vec![0] } }

struct Walker<'a> { secp: Secp256k1<All>, master: &'a Xpriv, seed: Option<&'a [u8]>, cache: HashMap<String, Xpriv> }
impl Walker<'_> {
    fn rows(&mut self, s: &Spec, path: &str) -> Vec<Row> {
        if s.chain.enc == Enc::Sol {
            let Some(seed) = self.seed else { return vec![] };
            let Ok(dp) = DerivationPath::from_str(path) else { return vec![] };
            let idx: Option<Vec<u32>> = dp.into_iter().map(|c| match c { ChildNumber::Hardened { index } => Some(*index), _ => None }).collect();
            return idx.map(|ix| vec![chains::sol_row(path, &chains::slip10_ed25519(seed, &ix))]).unwrap_or_default();
        }
        let (parent, last) = path.rsplit_once('/').unwrap_or(("m", ""));
        if self.cache.len() > 4096 { self.cache.clear() }
        let pk = match self.cache.get(parent) { Some(k) => *k, None => {
            let Ok(dp) = DerivationPath::from_str(parent) else { return vec![] };
            let Ok(k) = self.master.derive_priv(&self.secp, &dp) else { return vec![] };
            self.cache.insert(parent.to_string(), k); k } };
        let leaf = if last.is_empty() { pk } else {
            let Ok(c) = ChildNumber::from_str(last) else { return vec![] };
            let Ok(k) = pk.derive_priv(&self.secp, &[c]) else { return vec![] }; k };
        chains::secp_rows(s.chain, path, &leaf.private_key, s.uncompressed, &self.secp).into_iter()
            .filter(|r| r.kind == s.kind || (s.uncompressed && s.kind == "p2pkh" && r.kind == "p2pkh-uncompressed"))
            .filter(|r| !(r.kind == "p2pkh" && s.uncompressed && std::env::args().any(|a| a == "--uncompressed")))
            .collect()
    }
}

fn explain(o: &Opts) {
    let mut total = 0u64;
    for s in &o.specs {
        let (acc, ch) = (axis(&s.template, "{account}", &o.ranges.account), axis(&s.template, "{change}", &o.ranges.change));
        let idx = indices(o, s);
        let n = (acc.len() * ch.len() * idx.len()) as u64;
        total += n;
        let first = plan::expand(&s.template, s, acc[0], ch[0], idx[0]).unwrap_or_default();
        let kind = if s.uncompressed && s.kind == "p2pkh" { "p2pkh,p2pkh-uncompressed" } else { s.kind };
        outln!(r#"{{"tool":"derive","status":"ok","chain":"{}","kind":"{kind}","template":"{}","path":"{first}","count":{n}}}"#, s.chain.name, s.template);
    }
    outln!(r#"{{"tool":"derive","status":"done","count":{total}}}"#);
}

fn main() {
    let o = parse_args();
    if o.explain { explain(&o); return }
    let mut n = 0u64;
    let mut tried = 0u64;
    let input_lines = std::io::stdin().lock().take(16 << 20).lines();
    for line in input_lines.map_while(Result::ok) {
        let line = Zeroizing::new(line);
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
        let Some(x) = v.get("xprv").and_then(|m| m.as_str()) else {
            // Leaf keys already carrying an address (e.g. legacy keys from dat-read) pass through.
            if let Some(a) = v.get("address").and_then(|a| a.as_str()) {
                if v.get("status").and_then(|s| s.as_str()) == Some("ok") && o.match_set.as_ref().map_or(true, |m| m.contains(&norm(a))) { outln!("{}", line.as_str()); n += 1; }
            }
            continue
        };
        let cand = v.get("candidate").and_then(|c| c.as_u64()).unwrap_or(0);
        let Ok(master) = Xpriv::from_str(x) else { outln!(r#"{{"tool":"derive","status":"bad_input","candidate":{cand}}}"#); continue };
        let mut seen: HashSet<(String, &'static str, &'static str)> = HashSet::new();
        let mut emit = |r: &Row, n: &mut u64| {
            if !seen.insert((r.path.clone(), r.chain, r.kind)) { return false }
            if let Some(m) = &o.match_set { if !m.contains(&norm(&r.address)) { return false } }
            outln!(r#"{{"tool":"derive","status":"ok","candidate":{cand},"chain":"{}","kind":"{}","path":"{}","address":"{}","{}":"{}"}}"#,
                r.chain, r.kind, r.path, r.address, r.secret_field, r.secret);
            *n += 1; true
        };
        // Account-level key (dat-read): {"xprv","kind","path","branch"?} -> path/branch/i.
        if let (Some(kind), Some(path)) = (v.get("kind").and_then(|k| k.as_str()).and_then(kr_core::kind_name), v.get("path").and_then(|p| p.as_str())) {
            if path.len() < 128 {
                let branches: Vec<u32> = match v.get("branch").and_then(|b| b.as_u64()) { Some(b) if b < 1 << 31 => vec![b as u32], _ => o.ranges.change.clone().into_iter().chain([0, 1]).collect::<std::collections::BTreeSet<_>>().into_iter().collect() };
                let cnt = if o.index_set { *o.ranges.index.iter().max().unwrap() + 1 } else { 10 };
                for b in branches { for r in kr_core::derive_account(&master, kind, path, b, cnt) {
                    emit(&Row { chain: "btc", kind: r.kind, path: r.path, address: r.address, secret_field: "wif", secret: r.secret }, &mut n); } }
                continue;
            }
        }
        let seed = Zeroizing::new(v.get("seed").and_then(|s| s.as_str()).and_then(kr_core::hex_dec).filter(|s| s.len() == 64));
        if seed.is_none() && o.specs.iter().any(|s| s.chain.enc == Enc::Sol) {
            outln!(r#"{{"tool":"derive","status":"unsupported","candidate":{cand},"chain":"sol"}}"#);
        }
        let mut w = Walker { secp: Secp256k1::new(), master: &master, seed: seed.as_deref().map(|s| &s[..]), cache: HashMap::new() };
        for s in &o.specs {
            for &acc in &axis(&s.template, "{account}", &o.ranges.account) {
                for &ch in &axis(&s.template, "{change}", &o.ranges.change) {
                    let idx = indices(&o, s);
                    let fixed = !s.template.contains("{i}");
                    let mut last_hit = idx[0];
                    let mut k = 0usize;
                    let mut i = idx[0];
                    loop {
                        // with --gap-limit: walk upward until gap misses after the last hit
                        if let Some(g) = o.gap { if i >= last_hit.saturating_add(g) || i >= 1 << 31 { break } } else if k >= idx.len() { break } else { i = idx[k] }
                        let Some(p) = plan::expand(&s.template, s, acc, ch, i) else { break };
                        tried += 1;
                        if tried > 5_000_000 { outln!(r#"{{"tool":"derive","status":"too_many_candidates","count":{tried}}}"#); std::process::exit(2) }
                        for r in w.rows(s, &p) { if emit(&r, &mut n) { last_hit = i.saturating_add(1) } }
                        k += 1; i += 1;
                        if fixed { break }
                    }
                }
            }
        }
    }
    if o.match_set.is_some() && n == 0 { outln!(r#"{{"tool":"derive","status":"no_candidates","count":{tried}}}"#) }
    outln!(r#"{{"tool":"derive","status":"done","count":{n}}}"#);
}

#[cfg(test)]
mod tests {
    use super::*;
    // Public vector: BIP32 root of "abandon ... about" (empty passphrase).
    const ROOT: &str = "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu";
    fn first(chain: &str) -> Vec<(String, String)> {
        let s = Secp256k1::new();
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
        assert_eq!(first("xrp"), p(&[("xrp", "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3")]));
        let s = Secp256k1::new();
        for c in chains::CHAINS { for r in chains::derive_chain(&Xpriv::from_str(ROOT).unwrap(), c, 1, &s) {
            let l = format!(r#"{{"status":"ok","chain":"{}","kind":"{}","path":"{}","address":"{}"}}"#, r.chain, r.kind, r.path, r.address);
            assert!(kr_schema::redact_line(&l).is_some(), "schema drops {l}");
        } }
        assert_eq!(chains::derive_sol(&bip39_seed(), 1)[0].address, "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk");
    }
    #[test] fn ranges_and_templates() {
        assert_eq!(plan::parse_range("0..3,7"), Some(vec![0, 1, 2, 3, 7]));
        assert_eq!(plan::parse_range("2-4"), Some(vec![2, 3, 4]));
        for bad in ["", "3..1", "x", "0..2147483648", "-1"] { assert_eq!(plan::parse_range(bad), None, "{bad}") }
        assert!(plan::template_ok("m/44'/{coin}'/{account}'/{change}/{i}"));
        for bad in ["m/{x}", "44'/0'", "m/{i}/../", "m/a"] { assert!(!plan::template_ok(bad), "{bad}") }
    }
    #[test] fn presets_cover_recovery_combos() {
        let all: Vec<_> = chains::CHAINS.iter().collect();
        for (n, _) in plan::PRESETS { assert!(plan::preset(n, &all).is_some(), "{n}") }
        let r = plan::preset("recovery", &all).unwrap();
        let has = |c: &str, k: &str, t: &str| r.iter().any(|s| s.chain.name == c && s.kind == k && s.template == t);
        assert!(has("btc", "p2wpkh", "m/44'/{coin}'/{account}'/{change}/{i}"));   // BIP44 path as P2WPKH
        assert!(has("sol", "sol", "m/44'/{coin}'/{i}'/{change}'"));
        assert_eq!(plan::preset_ranges("recovery").1, vec![0, 1]);              // treasury /1/x
    }
    fn bip39_seed() -> Vec<u8> {
        bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &("abandon ".repeat(11) + "about")).unwrap().to_seed_normalized("").to_vec()
    }
}
