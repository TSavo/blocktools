//! Derivation plans: which (chain, address type, path) combinations `derive` walks.
//! A plan is built from a preset and/or flags, contains NO key material, and can be
//! printed (`derive --explain`) before any key is touched.
use crate::chains::{self, Chain, Enc};

/// One path family: template with {purpose} {coin} {account} {change} {i}.
#[derive(Clone, Debug)]
pub struct Spec { pub chain: &'static Chain, pub coin: u32, pub kind: &'static str, pub template: String, pub uncompressed: bool }

#[derive(Clone, Debug)]
pub struct Ranges { pub account: Vec<u32>, pub change: Vec<u32>, pub index: Vec<u32> }

pub const ADDRESS_TYPES: &[&str] = &["p2pkh", "p2pkh-uncompressed", "p2sh-p2wpkh", "p2wpkh", "p2tr", "eth", "tron", "xrp", "sol"];
/// Name, description. TON / electrum-old are listed in docs/ROADMAP.md (planned).
pub const PRESETS: &[(&str, &str)] = &[
    ("common", "standard wallet paths per chain: BIP44/49/84/86 by script type, EVM/Tron/XRP m/44'/c'/0'/0/i, Solana m/44'/501'/i'/0'"),
    ("exhaustive", "every purpose (44/49/84/86) x every script type, change 0 and 1, uncompressed too, plus EVM Ledger-Live/MEW-legacy, Solana variants, legacy HD layouts"),
    ("recovery", "exhaustive for account 0 only (includes BIP44 path as native segwit, treasury /1/0, Solana m/44'/501'/i'/0')"),
    ("exodus", "Exodus-style BIP44 per chain (BTC 44 and 84, LTC m/44'/2', DOGE m/44'/3', ETH m/44'/60'/0'/0/i, Solana m/44'/501'/i'/0'); verify against the wallet"),
    ("tronlink", "TronLink: m/44'/195'/{i}'/0/0 and m/44'/195'/0'/0/{i}"),
    ("ledger-live", "Ledger Live EVM m/44'/60'/{i}'/0/0, BTC m/{purpose}'/0'/{i}'/0/0"),
    ("electrum", "Electrum 2.x+ wallets: standard seed m/{change}/{i} p2pkh, segwit seed m/0'/{change}/{i} p2wpkh (picked automatically from the seed scheme)"),
    ("legacy-hd", "pre-BIP44 HD layouts, compressed and uncompressed p2pkh: Core 0.13+ m/0'/{change}'/{i}', MultiBit HD / BRD m/0'/{change}/{i}, Electrum 2.x m/{change}/{i}"),
];

fn purpose_of(kind: &str) -> u32 { match kind { "p2sh-p2wpkh" => 49, "p2wpkh" => 84, "p2tr" => 86, _ => 44 } }
pub fn kinds_of(c: &Chain) -> Vec<&'static str> {
    match c.enc {
        Enc::Utxo { hrp: Some(_), taproot: true, .. } => vec!["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr"],
        Enc::Utxo { hrp: Some(_), .. } => vec!["p2pkh", "p2sh-p2wpkh", "p2wpkh"],
        Enc::Utxo { .. } => vec!["p2pkh"],
        Enc::Eth => vec!["eth"], Enc::Tron => vec!["tron"], Enc::Xrp => vec!["xrp"], Enc::Sol => vec!["sol"],
    }
}
pub fn std_template(c: &Chain) -> &'static str {
    if c.enc == Enc::Sol { "m/44'/{coin}'/{i}'/{change}'" } else { "m/{purpose}'/{coin}'/{account}'/{change}/{i}" }
}
pub fn sp(c: &'static Chain, kind: &'static str, t: &str, unc: bool) -> Spec { Spec { chain: c, coin: c.coin, kind, template: t.into(), uncompressed: unc } }

/// Specs for one preset on the given chains.
pub fn preset(name: &str, chains_sel: &[&'static Chain]) -> Option<Vec<Spec>> {
    let mut v = Vec::new();
    for &c in chains_sel {
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
                } else if c.enc == Enc::Sol {
                    for t in ["m/44'/{coin}'/{i}'/{change}'", "m/44'/{coin}'/{i}'", "m/44'/{coin}'/{account}'/{i}'"] { v.push(sp(c, "sol", t, false)) }
                } else {
                    let k = kinds_of(c)[0];
                    for t in ["m/44'/{coin}'/{account}'/{change}/{i}", "m/44'/{coin}'/{i}'/0/0", "m/44'/{coin}'/{account}'/{i}"] { v.push(sp(c, k, t, false)) }
                }
            }
            "exodus" => match c.name {
                "btc" => { v.push(sp(c, "p2pkh", "m/44'/{coin}'/{account}'/{change}/{i}", false)); v.push(sp(c, "p2wpkh", "m/84'/{coin}'/{account}'/{change}/{i}", false)) }
                _ => v.push(sp(c, kinds_of(c)[0], std_template(c), false)),
            },
            "tronlink" => if c.name == "tron" { for t in ["m/44'/{coin}'/{i}'/0/0", "m/44'/{coin}'/0'/0/{i}"] { v.push(sp(c, "tron", t, false)) } },
            "ledger-live" => match c.enc {
                Enc::Eth => v.push(sp(c, "eth", "m/44'/{coin}'/{i}'/0/0", false)),
                Enc::Utxo { .. } => for k in kinds_of(c) { v.push(sp(c, k, "m/{purpose}'/{coin}'/{i}'/0/0", false)) },
                _ => {}
            },
            "electrum" | "electrum-standard" | "electrum-segwit" => if utxo {
                if name != "electrum-segwit" { v.push(sp(c, "p2pkh", "m/{change}/{i}", false)) }
                if name != "electrum-standard" && kinds_of(c).contains(&"p2wpkh") { v.push(sp(c, "p2wpkh", "m/0'/{change}/{i}", false)) }
            },
            "legacy-hd" => if utxo { for t in ["m/0'/{change}'/{i}'", "m/0'/{change}/{i}", "m/{change}/{i}"] { v.push(sp(c, "p2pkh", t, true)) } },
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
