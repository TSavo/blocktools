//! Derivation plans: which (chain, address type, path) combinations `derive` walks.
//! A plan is built from a preset and/or flags, contains NO key material, and can be
//! printed (`derive --explain`) before any key is touched.
use crate::chains::{self, Chain, Enc};

/// One path family: template with {purpose} {coin} {account} {change} {i}.
#[derive(Clone, Debug)]
/// `label`: wallet name(s) known to use this path family (e.g. "Ledger Live EVM"), "" when none.
pub struct Spec { pub chain: &'static Chain, pub coin: u32, pub kind: &'static str, pub template: String, pub uncompressed: bool, pub label: &'static str }

#[derive(Clone, Debug)]
pub struct Ranges { pub account: Vec<u32>, pub change: Vec<u32>, pub index: Vec<u32> }

pub const ADDRESS_TYPES: &[&str] = &["p2pkh", "p2pkh-uncompressed", "p2sh-p2wpkh", "p2wpkh", "p2tr", "eth", "tron", "xrp", "sol", "xlm", "aptos", "sui", "near", "xtz", "egld"];
/// Name, description. TON / electrum-old are listed in docs/ROADMAP.md (planned).
pub const PRESETS: &[(&str, &str)] = &[
    ("common", "standard wallet paths per chain: BIP44/49/84/86 by script type, EVM/Tron/XRP m/44'/c'/0'/0/i, Solana m/44'/501'/i'/0'"),
    ("exhaustive", "every purpose (44/49/84/86) x every script type, change 0 and 1, uncompressed too, plus EVM Ledger-Live/MEW-legacy, Solana variants, legacy HD layouts"),
    ("recovery", "exhaustive for account 0 only (includes BIP44 path as native segwit, treasury /1/0, Solana m/44'/501'/i'/0')"),
    ("exodus", "Exodus-style BIP44 per chain (BTC 44 and 84, LTC m/44'/2', DOGE m/44'/3', ETH m/44'/60'/0'/0/i, Solana m/44'/501'/i'/0'); verify against the wallet"),
    ("tronlink", "TronLink: m/44'/195'/{i}'/0/0 and m/44'/195'/0'/0/{i}"),
    ("ledger-live", "Ledger Live EVM m/44'/60'/{i}'/0/0, BTC m/{purpose}'/0'/{i}'/0/0"),
    ("electrum", "Electrum 2.x+ wallets: standard seed m/{change}/{i} p2pkh, segwit seed m/0'/{change}/{i} p2wpkh (picked automatically from the seed scheme)"),
    ("scan-js", "exactly SwapChan's SCAN_JS rows: 15 labeled paths (EVM MetaMask/Ledger Live/Ledger legacy, Tron, Solana x2, BTC 44/49/84/86, LTC 44/84, DOGE, BCH, BTG), 20 addresses each (--index overrides); default chains eth,tron,sol,btc,ltc,doge,bch,btg"),
    ("legacy-hd", "pre-BIP44 HD layouts, compressed and uncompressed p2pkh: Core 0.13+ m/0'/{change}'/{i}', MultiBit HD / BRD m/0'/{change}/{i}, Electrum 2.x m/{change}/{i}"),
];

fn purpose_of(kind: &str) -> u32 { match kind { "p2sh-p2wpkh" => 49, "p2wpkh" => 84, "p2tr" => 86, _ => 44 } }
pub fn kinds_of(c: &Chain) -> Vec<&'static str> {
    match c.enc {
        Enc::Utxo { hrp: Some(_), taproot: true, .. } => vec!["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr"],
        Enc::Utxo { hrp: Some(_), .. } => vec!["p2pkh", "p2sh-p2wpkh", "p2wpkh"],
        Enc::Utxo { .. } => vec!["p2pkh"],
        Enc::Eth => vec!["eth"], Enc::Tron => vec!["tron"], Enc::Xrp => vec!["xrp"], Enc::Sol => vec!["sol"], Enc::Xlm => vec!["xlm"], Enc::Ed(_) => vec![c.name], Enc::Cosmos { .. } => vec!["cosmos"], Enc::Algo | Enc::Ton | Enc::Ada => vec![], Enc::Ss58 { .. } => vec![], Enc::Xmr => vec![],
    }
}
pub fn std_template(c: &Chain) -> &'static str {
    if c.enc == Enc::Sol { "m/44'/{coin}'/{i}'/{change}'" } else if matches!(c.enc, Enc::Ed(crate::chains::EdAddr::Aptos | crate::chains::EdAddr::Sui)) { "m/44'/{coin}'/{i}'/0'/0'" } else if c.enc == Enc::Ed(crate::chains::EdAddr::Tezos) { "m/44'/{coin}'/{i}'/0'" } else if c.enc == Enc::Ed(crate::chains::EdAddr::Mvx) { "m/44'/{coin}'/0'/0'/{i}'" } else if matches!(c.enc, Enc::Xlm | Enc::Ed(_)) { "m/44'/{coin}'/{i}'" } else { "m/{purpose}'/{coin}'/{account}'/{change}/{i}" }
}
pub fn sp(c: &'static Chain, kind: &'static str, t: &str, unc: bool) -> Spec { Spec { chain: c, coin: c.coin, kind, template: t.into(), uncompressed: unc, label: "" } }
fn spl(c: &'static Chain, kind: &'static str, t: &str, label: &'static str) -> Spec { Spec { label, ..sp(c, kind, t, false) } }

/// SwapChan SCAN_JS (apps/api/src/keyrecovery.ts PATHS), in its order: label, chain, address type, path.
/// Labels are SCAN_JS's own strings so its `label path address` lines can be compared as-is.
pub const SCAN_JS: &[(&str, &str, &str, &str)] = &[
    ("MetaMask/Trezor/Trust/Exodus/Rabby EVM", "eth", "eth", "m/44'/60'/0'/0/{i}"),
    ("Ledger Live EVM", "eth", "eth", "m/44'/60'/{i}'/0/0"),
    ("Ledger legacy/MEW EVM", "eth", "eth", "m/44'/60'/0'/{i}"),
    ("TronLink/Trust Tron", "tron", "tron", "m/44'/195'/0'/0/{i}"),
    ("Phantom/Solflare/Backpack/Trust/Exodus Solana", "sol", "sol", "m/44'/501'/{i}'/0'"),
    ("Solflare legacy/Sollet Solana", "sol", "sol", "m/44'/501'/{i}'"),
    ("BTC legacy (1...)", "btc", "p2pkh", "m/44'/0'/0'/0/{i}"),
    ("BTC nested SegWit (3...)", "btc", "p2sh-p2wpkh", "m/49'/0'/0'/0/{i}"),
    ("BTC native SegWit (bc1q...) Exodus/Trezor/Ledger", "btc", "p2wpkh", "m/84'/0'/0'/0/{i}"),
    ("BTC Taproot (bc1p...)", "btc", "p2tr", "m/86'/0'/0'/0/{i}"),
    ("LTC legacy (L...)", "ltc", "p2pkh", "m/44'/2'/0'/0/{i}"),
    ("LTC SegWit (ltc1q...)", "ltc", "p2wpkh", "m/84'/2'/0'/0/{i}"),
    ("DOGE (D...)", "doge", "p2pkh", "m/44'/3'/0'/0/{i}"),
    ("BCH (legacy-format 1...)", "bch", "p2pkh", "m/44'/145'/0'/0/{i}"),
    ("BTG (G...)", "btg", "p2pkh", "m/44'/156'/0'/0/{i}"),
];
/// Chains `--preset scan-js` covers when no --chain is given.
pub const SCAN_JS_CHAINS: &[&str] = &["eth", "tron", "sol", "btc", "ltc", "doge", "bch", "btg"];

/// Specs for one preset on the given chains.
pub fn preset(name: &str, chains_sel: &[&'static Chain]) -> Option<Vec<Spec>> {
    let mut v = Vec::new();
    if name == "scan-js" {
        for &(l, cn, k, t) in SCAN_JS { if let Some(&c) = chains_sel.iter().find(|c| c.name == cn) { v.push(spl(c, k, t, l)) } }
        return Some(v)
    }
    for &c in chains_sel {
        // Monero keys come from its own 25-word seed (crates/monero, xmr-keys), not BIP32 paths.
        if c.enc.native_seed() { continue }
        let utxo = matches!(c.enc, Enc::Utxo { .. });
        match name {
            "common" => for k in kinds_of(c) { v.push(sp(c, k, std_template(c), false)) },
            "exhaustive" | "recovery" => {
                if utxo {
                    for k in kinds_of(c) { for p in [44, 49, 84, 86] {
                        if k == "p2tr" && p != 86 && p != 44 { continue }
                        v.push(sp(c, k, &format!("m/{p}'/{{coin}}'/{{account}}'/{{change}}/{{i}}"), k == "p2pkh"));
                    } }
                    for t in ["m/0'/{change}'/{i}'", "m/0'/{change}/{i}", "m/{change}/{i}"] { v.push(sp(c, "p2pkh", t, true)); v.push(sp(c, "p2wpkh", t, false)) }
                } else if c.enc == Enc::Xlm {
                    for t in ["m/44'/{coin}'/{i}'", "m/44'/{coin}'/{account}'/{i}'", "m/44'/{coin}'/{i}'/0'"] { v.push(sp(c, "xlm", t, false)) }
                } else if matches!(c.enc, Enc::Ed(_)) {
                    v.push(sp(c, c.name, std_template(c), false))
                } else if c.enc == Enc::Sol {
                    for t in ["m/44'/{coin}'/{i}'/{change}'", "m/44'/{coin}'/{i}'", "m/44'/{coin}'/{account}'/{i}'"] { v.push(sp(c, "sol", t, false)) }
                } else {
                    let k = kinds_of(c)[0];
                    for t in ["m/44'/{coin}'/{account}'/{change}/{i}", "m/44'/{coin}'/{i}'/0/0", "m/44'/{coin}'/{account}'/{i}"] { v.push(sp(c, k, t, false)) }
                }
            }
            "exodus" => match c.name {
                "btc" => { v.push(spl(c, "p2pkh", "m/44'/{coin}'/{account}'/{change}/{i}", "Exodus BTC legacy")); v.push(spl(c, "p2wpkh", "m/84'/{coin}'/{account}'/{change}/{i}", "Exodus BTC SegWit")) }
                _ => v.push(spl(c, kinds_of(c)[0], std_template(c), "Exodus")),
            },
            "tronlink" => if c.name == "tron" { v.push(spl(c, "tron", "m/44'/{coin}'/{i}'/0/0", "TronLink account")); v.push(spl(c, "tron", "m/44'/{coin}'/0'/0/{i}", "TronLink/Trust Tron")) },
            "ledger-live" => match c.enc {
                Enc::Eth => v.push(spl(c, "eth", "m/44'/{coin}'/{i}'/0/0", "Ledger Live EVM")),
                Enc::Utxo { .. } => for k in kinds_of(c) { v.push(spl(c, k, "m/{purpose}'/{coin}'/{i}'/0/0", "Ledger Live")) },
                _ => {}
            },
            "electrum" | "electrum-standard" | "electrum-segwit" => if utxo {
                if name != "electrum-segwit" { v.push(spl(c, "p2pkh", "m/{change}/{i}", "Electrum standard seed")) }
                if name != "electrum-standard" && kinds_of(c).contains(&"p2wpkh") { v.push(spl(c, "p2wpkh", "m/0'/{change}/{i}", "Electrum segwit seed")) }
            },
            "legacy-hd" => if utxo { for (t, l) in [("m/0'/{change}'/{i}'", "Bitcoin Core 0.13+ HD"), ("m/0'/{change}/{i}", "MultiBit HD/BRD"), ("m/{change}/{i}", "Electrum 2.x")] { v.push(Spec { label: l, ..sp(c, "p2pkh", t, true) }) } },
            _ => return None,
        }
    }
    Some(v)
}
/// Default ranges for a preset (accounts / change branches); index comes from --index/--count or the chain default.
pub fn preset_ranges(name: &str) -> (Vec<u32>, Vec<u32>) {
    match name { "exhaustive" => (vec![0, 1, 2], vec![0, 1]), "recovery" | "electrum" | "electrum-standard" | "electrum-segwit" => (vec![0], vec![0, 1]), _ => (vec![0], vec![0]) }
}

/// Expand a template. Errors on unknown placeholders or malformed result.
pub fn expand(t: &str, s: &Spec, account: u32, change: u32, i: u32) -> Option<String> {
    let p = t.replace("{purpose}", &purpose_of(s.kind).to_string()).replace("{coin}", &s.coin.to_string())
        .replace("{account}", &account.to_string()).replace("{change}", &change.to_string()).replace("{i}", &i.to_string());
    if p.contains('{') || !p.starts_with('m') || p.len() > 96 { return None }
    Some(p)
}
pub fn template_ok(t: &str) -> bool {
    let probe = sp(chains::chain("btc").unwrap(), "p2pkh", t, false);
    expand(t, &probe, 0, 0, 0).map_or(false, |p| p.parse::<bitcoin::bip32::DerivationPath>().is_ok())
}
/// Parse "3", "0..9" (inclusive), "0-9", "0,1,5", or combinations "0..2,7".
pub fn parse_range(s: &str) -> Option<Vec<u32>> {
    let mut v = Vec::new();
    for part in s.split(',') {
        let (a, b) = match part.split_once("..").or_else(|| part.split_once('-')) {
            Some((a, b)) => (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?),
            None => { let n = part.parse::<u32>().ok()?; (n, n) }
        };
        if b < a || b - a > 1_000_000 || b >= 1 << 31 { return None }
        v.extend(a..=b);
    }
    if v.is_empty() || v.len() > 1_000_000 { None } else { Some(v) }
}

/// A full derivation plan from flags: specs (chain, kind, template) and ranges. No key material.
pub struct Opts {
    /// Plain `derive` (no --preset/--path/--purpose): chains + compression choice, so Electrum
    /// masters get Electrum paths automatically.
    pub auto: Option<(Vec<&'static Chain>, Option<String>)>,
    pub specs: Vec<Spec>, pub ranges: Ranges, pub index_set: bool,
    /// --match FILE (the CLI reads it; the library never opens files).
    pub match_file: Option<String>,
    pub gap: Option<u32>, pub explain: bool, pub only_uncompressed: bool,
    /// --stop-on-match: with --match, end the walk after the first hit.
    pub stop_on_match: bool,
    /// --public-only: rows without the private key field. --address-list: `label<TAB>path<TAB>address`
    /// lines (implies public_only). Neither prints key material.
    pub public_only: bool, pub address_list: bool,
}
/// Build a plan from `derive` flags (argv without the program name). `--help` and
/// `--list-presets` are the CLI's business and are rejected here. Public parameters only.
pub fn from_args(a: &[String]) -> Result<Opts, &'static str> {
    let (mut chains_sel, mut preset_name, mut types, mut purposes, mut paths) = (Vec::<&'static Chain>::new(), "common".to_string(), None::<Vec<String>>, None::<Vec<u32>>, Vec::<String>::new());
    let (mut coin, mut account, mut change, mut index, mut comp, mut curve) = (None, None, None, None, None::<&str>, None::<String>);
    let (mut match_file, mut gap, mut explain, mut stop_on_match) = (None::<String>, None, false, false);
    let (mut public_only, mut address_list) = (false, false);
    let mut i = 0;
    while i < a.len() {
        let flag = a[i].as_str();
        let val = || a.get(i + 1).cloned().ok_or("bad_input");
        let mut takes = true;
        match flag {
            "--explain" => { explain = true; takes = false }
            "--compressed" | "--uncompressed" | "--both" => { comp = Some(&flag[2..]); takes = false }
            "--chain" => for n in val()?.split(',') {
                if n == "all" { chains_sel.extend(chains::CHAINS.iter().filter(|c| c.verified)) } else { chains_sel.push(chains::supported(n).ok_or("unsupported or unverified chain")?) } },
            "--preset" => { preset_name = val()?; if !PRESETS.iter().any(|p| p.0 == preset_name) { return Err("unsupported") } }
            "--address-type" => types = Some(val()?.split(',').map(|t| match t { "evm" => "eth", "solana" => "sol", x => x }.to_string()).collect()),
            "--purpose" => purposes = Some(val()?.split(',').map(|p| p.parse().ok().filter(|n: &u32| *n < 1 << 31).ok_or("bad_input")).collect::<Result<Vec<_>, _>>()?),
            "--path" => { let t = val()?; if !template_ok(&t) { return Err("bad_input") } paths.push(t) }
            "--coin-type" => coin = Some(val()?.parse::<u32>().ok().filter(|n| *n < 1 << 31).ok_or("bad_input")?),
            "--account" => account = Some(parse_range(&val()?).ok_or("bad_input")?),
            "--change" => change = Some(parse_range(&val()?).ok_or("bad_input")?),
            "--index" => index = Some(parse_range(&val()?).ok_or("bad_input")?),
            "--count" => { let n: u32 = val()?.parse().ok().filter(|n| (1..=1_000_000).contains(n)).ok_or("bad_input")?; index = Some((0..n).collect()) }
            "--curve" => curve = Some(val()?),
            "--match" => match_file = Some(val()?),
            "--gap-limit" => gap = Some(val()?.parse::<u32>().ok().filter(|n| (1..=100_000).contains(n)).ok_or("bad_input")?),
            "--stop-on-match" => { stop_on_match = true; takes = false },
            "--public-only" => { public_only = true; takes = false },
            "--address-list" => { address_list = true; public_only = true; takes = false },
            _ => return Err("bad_input"),
        }
        i += if takes { 2 } else { 1 };
    }
    if types.as_ref().map_or(false, |t| t.iter().any(|t| t == "ton")) { return Err("unsupported") }
    if types.as_ref().map_or(false, |t| t.iter().any(|t| !ADDRESS_TYPES.contains(&t.as_str()))) { return Err("bad_input") }
    if chains_sel.is_empty() && preset_name == "scan-js" { chains_sel = SCAN_JS_CHAINS.iter().map(|n| chains::chain(n).unwrap()).collect() }
    if chains_sel.is_empty() { chains_sel = vec![chains::chain("btc").unwrap(), chains::chain("eth").unwrap()] }
    let mut specs = if purposes.is_some() || !paths.is_empty() {
        let mut t = paths.clone();
        for p in purposes.iter().flatten() { t.push(format!("m/{p}'/{{coin}}'/{{account}}'/{{change}}/{{i}}")) }
        let mut v = Vec::new();
        for &c in &chains_sel { for k in kinds_of(c) {
            if types.as_ref().map_or(false, |ts| !ts.iter().any(|x| x == k)) { continue }
            for tt in &t { v.push(sp(c, k, tt, false)) }
        } }
        v
    } else {
        let mut v = preset(&preset_name, &chains_sel).unwrap();
        if let Some(ts) = &types { v.retain(|s| ts.iter().any(|x| x == s.kind) || (s.kind == "p2pkh" && ts.iter().any(|x| x == "p2pkh-uncompressed"))) }
        v
    };
    for s in &mut specs {
        if let Some(c) = coin { s.coin = c }
        match comp { Some("compressed") => s.uncompressed = false, Some("both") | Some("uncompressed") => s.uncompressed = s.kind == "p2pkh", _ => {} }
        if types.as_ref().map_or(false, |t| t.iter().any(|x| x == "p2pkh-uncompressed")) && s.kind == "p2pkh" { s.uncompressed = true }
    }
    if comp == Some("uncompressed") { specs.retain(|s| s.kind == "p2pkh") }
    match curve.as_deref() { Some("ed25519") => specs.retain(|s| s.chain.enc.ed25519()), Some("secp256k1") => specs.retain(|s| !s.chain.enc.ed25519()), None => {}, _ => return Err("bad_input") }
    if specs.is_empty() { return Err("no_candidates") }
    let (pa, pc) = preset_ranges(&preset_name);
    if preset_name == "scan-js" && index.is_none() { index = Some((0..20).collect()) }  // SCAN_JS GAP default
    let index_set = index.is_some();
    let ranges = Ranges { account: account.unwrap_or(pa), change: change.unwrap_or(pc), index: index.unwrap_or_default() };
    if gap.is_some() && match_file.is_none() { return Err("bad_input") }
    if stop_on_match && match_file.is_none() { return Err("bad_input") }
    // Plain `derive` (no --preset/--path/--purpose): Electrum masters get Electrum paths.
    let explicit = a.iter().any(|x| x == "--preset" || x == "--path" || x == "--purpose");
    let auto = (!explicit).then(|| (chains_sel.clone(), comp.map(|c| c.to_string())));
    let only_uncompressed = comp == Some("uncompressed");
    Ok(Opts { auto, specs, ranges, index_set, match_file, gap, explain, only_uncompressed, stop_on_match, public_only, address_list })
}
/// Normalise an address for matching (EVM hex is case-insensitive).
pub fn norm(a: &str) -> String { if a.starts_with("0x") { a.to_ascii_lowercase() } else { a.to_string() } }
pub fn indices(o: &Opts, s: &Spec) -> Vec<u32> { if o.index_set { o.ranges.index.clone() } else { (0..s.chain.default_count).collect() } }
/// Does the template vary with {account} / {change}? If not, iterate them once.
pub fn axis(t: &str, ph: &str, v: &[u32]) -> Vec<u32> { if t.contains(ph) { v.to_vec() } else { vec![0] } }

/// One line of `derive --explain`.
#[derive(Debug, Clone, PartialEq)]
pub struct ExplainRow { pub chain: &'static str, pub kind: String, pub template: String, pub path: String, pub count: u64, pub label: &'static str }
/// The plan as rows (first path of each family and how many paths it covers). No keys.
pub fn explain(o: &Opts) -> Vec<ExplainRow> {
    o.specs.iter().map(|s| {
        let (acc, ch) = (axis(&s.template, "{account}", &o.ranges.account), axis(&s.template, "{change}", &o.ranges.change));
        let idx = indices(o, s);
        let count = (acc.len() * ch.len() * idx.len()) as u64;
        let path = expand(&s.template, s, acc[0], ch[0], idx[0]).unwrap_or_default();
        let kind = if s.uncompressed && s.kind == "p2pkh" { "p2pkh,p2pkh-uncompressed".into() } else { s.kind.to_string() };
        ExplainRow { chain: s.chain.name, kind, template: s.template.clone(), path, count, label: s.label }
    }).collect()
}
