//! Walk a derivation plan over one BIP32 master key: the secret half of `derive`.
//! The plan itself (blocktools_core::plan) is public; rows here carry WIF / hex keys.
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use bitcoin::secp256k1::{All, Secp256k1};
use blocktools_core::chains::{self, Row};
use blocktools_core::plan::{self, axis, indices, Opts, Spec};
use std::collections::HashMap;
use std::str::FromStr;
#[allow(unused_imports)]
use zeroize::Zeroizing;

/// Hard cap on paths tried per process (same as the CLI's old limit).
pub const MAX_TRIED: u64 = 5_000_000;

pub struct Walker<'a> { secp: Secp256k1<All>, master: &'a Xpriv, seed: Option<&'a [u8]>, cache: HashMap<String, Xpriv>, only_uncompressed: bool }
impl Walker<'_> {
    pub fn rows(&mut self, s: &Spec, path: &str) -> Vec<Row> {
        if s.chain.enc.ed25519() {
            let Some(seed) = self.seed else { return vec![] };
            let Ok(dp) = DerivationPath::from_str(path) else { return vec![] };
            let idx: Option<Vec<u32>> = dp.into_iter().map(|c| match c { ChildNumber::Hardened { index } => Some(*index), _ => None }).collect();
            #[cfg(feature = "ed25519")]
            return idx.map(|ix| vec![chains::ed_row(s.chain, path, &Zeroizing::new(chains::slip10_ed25519(seed, &ix)))]).unwrap_or_default();
            #[cfg(not(feature = "ed25519"))]
            { let _ = (seed, idx); return vec![] }
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
            .filter(|r| !(r.kind == "p2pkh" && s.uncompressed && self.only_uncompressed))
            .collect()
    }
}

impl<'a> Walker<'a> {
    pub fn new(master: &'a Xpriv, seed: Option<&'a [u8]>, only_uncompressed: bool) -> Self {
        Walker { secp: Secp256k1::new(), master, seed, cache: HashMap::new(), only_uncompressed }
    }
}

/// Walk the plan for one master. `scheme` comes from seed-to-master ("bip39", "electrum-*").
/// `emit` returns true when it printed the row (a hit, for --gap-limit). `tried` is shared
/// across masters. Err("too_many_candidates") past MAX_TRIED.
pub fn walk(o: &Opts, master: &Xpriv, seed: Option<&[u8]>, scheme: &str, tried: &mut u64, emit: &mut dyn FnMut(&Row) -> bool) -> Result<(), &'static str> {
    let el_specs;
    let mut el_ranges = None;
    let specs: &[Spec] = match (&o.auto, scheme) {
        (Some((cs, _)), "electrum-standard" | "electrum-segwit") => {
        el_specs = plan::preset(scheme, cs).unwrap();
        el_ranges = Some(plan::preset_ranges(scheme).1);
        &el_specs
        }
        _ => &o.specs,
    };
    let changes = el_ranges.unwrap_or_else(|| o.ranges.change.clone());
    let mut w = Walker::new(master, seed, o.only_uncompressed);
    for s in specs {
        for &acc in &axis(&s.template, "{account}", &o.ranges.account) {
        for &ch in &axis(&s.template, "{change}", &changes) {
            let idx = indices(o, s);
            let fixed = !s.template.contains("{i}");
            let mut last_hit = idx[0];
            let mut k = 0usize;
            let mut i = idx[0];
            loop {
            // with --gap-limit: walk upward until gap misses after the last hit
            if let Some(g) = o.gap { if i >= last_hit.saturating_add(g) || i >= 1 << 31 { break } } else if k >= idx.len() { break } else { i = idx[k] }
            let Some(p) = plan::expand(&s.template, s, acc, ch, i) else { break };
            *tried += 1;
            if *tried > MAX_TRIED { return Err("too_many_candidates") }
            for r in w.rows(s, &p) { if emit(&r) { last_hit = i.saturating_add(1) } }
            k += 1; i += 1;
            if fixed { break }
            }
        }
        }
    }
    Ok(())
}

/// Account-level key (dat-read): rows for path/branch/i. Branches default to --change plus 0 and 1.
pub fn walk_account(o: &Opts, acct: &Xpriv, kind: &'static str, path: &str, branch: Option<u64>, emit: &mut dyn FnMut(&Row) -> bool) {
    let branches: Vec<u32> = match branch { Some(b) if b < 1 << 31 => vec![b as u32], _ => o.ranges.change.clone().into_iter().chain([0, 1]).collect::<std::collections::BTreeSet<_>>().into_iter().collect() };
    let cnt = if o.index_set { *o.ranges.index.iter().max().unwrap() + 1 } else { 10 };
    for b in branches { for r in blocktools_core::derive_account(acct, kind, path, b, cnt) {
        emit(&Row { chain: "btc", kind: r.kind, path: r.path, address: r.address, secret_field: "wif", secret: r.secret }); } }
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
            assert!(blocktools_schema::redact_line(&l).is_some(), "schema drops {l}");
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
