//! Agent-facing public schema. The ONLY thing that may cross the container
//! boundary toward the agent is a line produced by `redact_line`.
//! Design: allowlist of fields, each with a strict type validator, followed by
//! a defense-in-depth leak scan over the serialized line.
use serde_json::{Map, Value};

pub const STATUSES: &[&str] = &[
    "ok", "checksum_ok", "checksum_fail", "no_candidates", "too_many_candidates",
    "bad_input", "wrong_password", "unsupported", "error", "done", "failed", "refused", "aborted",
];
// Single source for the failure vocabulary: blocktools_tx include!s the same file (D1-12).
include!("tx_failures.rs");
pub const TOOLS: &[&str] = &["zec-sapling", "seed-repair", "seed-to-master", "derive", "keystore-open", "redact", "sealed-run", "read-file", "dat-read",
    "key-to-addresses", "classify", "tx-decode", "tx-verify", "tx-build", "tx-build-sweep", "tx-sign", "tx-broadcast", "electrum-read", "multibit-read", "armory-read", "xpub-addresses", "xmr-keys", "xrp-tx", "acct-tx", "phrase-to-key"];
pub const KINDS: &[&str] = &["p2pkh", "p2pkh-uncompressed", "p2sh-p2wpkh", "p2wpkh", "p2tr", "eth", "tron", "xrp", "sol", "xlm", "aptos", "sui", "near", "xtz", "egld", "cosmos", "algo", "sr25519", "ton-v4r2", "ada-base", "sapling", "unified", "xmr",
    "p2pk", "p2sh", "p2wsh", "op_return", "nonstandard", "unknown"];
pub const CHAINS: &[&str] = &["btc", "ltc", "doge", "eth", "tron", "xrp", "sol", "xlm", "aptos", "sui", "near", "xtz", "egld", "atom", "algo", "dot", "ton", "ada", "zec", "xmr", "qtum", "ftc", "nmc", "dash", "vtc", "dgb", "via", "mona", "rvn", "xpm", "trc", "mec", "aur", "bch", "bsv", "btg", "ppc", "nvc", "clam", "blk", "rdd", "pot", "qrk", "wdc", "anc", "bcc", "grs", "pivx", "sys", "firo", "ksm", "polyx", "strd", "axl", "cre", "kuji", "cmdx", "ntrn", "somm", "fet", "mars", "umee", "noble", "sei", "tia", "coreum", "qsr", "xprt", "akt", "kava", "blz", "band", "cro", "bld", "dydx", "rune", "inj", "evmos", "canto", "zeta"];
pub const SCHEMES: &[&str] = &["bip39", "electrum-standard", "electrum-segwit", "electrum-2fa", "electrum-2fa-segwit", "electrum-old", "brainwallet-sha256", "warpwallet"];
/// Fields whose VALUE is secret. They are kept as a labelled placeholder so the agent can see
/// that a key exists (and which kind), never its value.
pub const SECRET_FIELDS: &[&str] = &["wif", "private_key", "xprv", "seed", "mnemonic", "passphrase", "password", "secret", "signed_tx_secret"];
/// tx-decode warning vocabulary (public). Anything else drops the line.
pub const TX_WARNINGS: &[&str] = &["input_amounts_unknown", "outputs_exceed_inputs", "high_fee", "high_fee_pct", "high_fee_rate",
    "nonstandard_output", "op_return_output", "dust_output", "locktime_set", "unsigned", "partially_signed", "utxo_txid_mismatch",
    "no_inputs_or_outputs", "no_chain_id", "contract_creation", "high_gas_price", "token_approve", "unlimited_approve",
    "token_transfer_from", "unknown_calldata", "bad_signature"];
pub const TX_TYPES: &[&str] = &["btc-tx", "psbt", "evm-legacy", "evm-1559"];
pub const PLACEHOLDER: &str = "[REDACTED]";

const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
fn all_in(s: &str, set: &str) -> bool { s.chars().all(|c| set.contains(c)) }
fn is_b58(c: char) -> bool { B58.contains(c) }

/// Address shapes: base58 (btc/ltc/doge/tron/xrp 25-35 chars; sol 32-44 is only accepted with
/// "chain":"sol", see redact_line), bech32 bc1/ltc1, 0x+40 hex.
/// Cosmos SDK account hrps (20-byte bech32 accounts: 39 chars after the hrp).
pub const COSMOS_HRPS: &[&str] = &["cosmos", "stride", "axelar", "cre", "kujira", "comdex", "neutron", "somm", "fetch", "mars", "umee", "noble", "sei", "celestia", "core", "quasar", "persistence", "akash", "kava", "bluzelle", "band", "cro", "agoric", "dydx", "thor", "inj", "evmos", "canto", "zeta"];
/// Segwit hrps of the chain table (blocktools-core chains.rs; a core test checks they match).
pub const HRPS: &[&str] = &["cosmos", "bc", "ltc", "qc", "fc", "nc", "vtc", "dgb", "via", "mona", "mec", "btg", "pc", "rdd", "grs", "sys", "stride", "axelar", "cre", "kujira", "comdex", "neutron", "somm", "fetch", "mars", "umee", "noble", "sei", "celestia", "core", "quasar", "persistence", "akash", "kava", "bluzelle", "band", "cro", "agoric", "dydx", "thor", "inj", "evmos", "canto", "zeta"];
fn is_bech(s: &str) -> bool {
    HRPS.iter().any(|h| s.len() > h.len() + 1 && s.starts_with(h) && s.as_bytes()[h.len()] == b'1'
        && (if COSMOS_HRPS.contains(h) { 39..=39 } else { 40..=60 }).contains(&(s.len() - h.len())) && all_in(&s[h.len() + 1..], BECH))
}
/// Monero standard address: 95 base58 chars, mainnet prefix 4 (stagenet/testnet 5/9). It is public.
pub fn is_xmr_address(s: &str) -> bool { s.len() == 95 && s.starts_with(['4', '5', '9']) && all_in(s, B58) }
/// Stellar account id: StrKey 'G' + 55 base32 chars (public). Seeds start with 'S' and never match.
/// Accepted only with "chain":"xlm" (redact_line).
pub fn is_xlm_address(s: &str) -> bool { s.len() == 56 && s.starts_with('G') && all_in(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") }
/// Algorand address: 58 base32 chars (public). Accepted only with "chain":"algo".
pub fn is_algo_address(s: &str) -> bool { s.len() == 58 && all_in(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") }
/// Polkadot SS58 (prefix 0): '1' + 47 base58 chars (public). Accepted only with "chain":"dot".
pub fn is_dot_address(s: &str) -> bool { s.len() == 48 && s.starts_with('1') && all_in(s, B58) }
/// Kusama SS58 (prefix 2): 47 base58 chars starting C..J (public). Accepted only with "chain":"ksm".
pub fn is_ksm_address(s: &str) -> bool { s.len() == 47 && s.starts_with(['C', 'D', 'E', 'F', 'G', 'H', 'J']) && all_in(s, B58) }
/// Polymesh SS58 (prefix 12): '2' + 47 base58 chars (public). Accepted only with "chain":"polyx".
pub fn is_polyx_address(s: &str) -> bool { s.len() == 48 && s.starts_with('2') && all_in(s, B58) }
/// TON user-friendly address: 48 base64url chars starting EQ/UQ (public). Only with "chain":"ton".
pub fn is_ton_address(s: &str) -> bool { s.len() == 48 && (s.starts_with("EQ") || s.starts_with("UQ")) && all_in(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") }
/// Cardano mainnet Shelley address: "addr1" + bech32 chars, 58..=120 long (public). Only with "chain":"ada".
pub fn is_ada_address(s: &str) -> bool { (58..=120).contains(&s.len()) && s.starts_with("addr1") && all_in(&s[5..], BECH) }
/// Zcash Sapling payment address: "zs1" + 75 bech32 chars (public). Only with "chain":"zec".
pub fn is_zs_address(s: &str) -> bool { s.len() == 78 && s.starts_with("zs1") && all_in(&s[3..], BECH) }
/// Zcash ZIP-316 unified address: "u1" + bech32m chars, 100..=600 long (public). Only with "chain":"zec".
pub fn is_ua_address(s: &str) -> bool { (100..=600).contains(&s.len()) && s.starts_with("u1") && all_in(&s[2..], BECH) }
pub fn is_address(s: &str) -> bool {
    let n = s.len();
    is_xmr_address(s) || is_ua_address(s) || is_dot_address(s) || is_ksm_address(s) || is_polyx_address(s) || is_ton_address(s) || is_ada_address(s) || is_zs_address(s) || is_xlm_address(s) || is_algo_address(s) || ((25..=44).contains(&n) && all_in(s, B58))
        || is_bech(s)
        || (s.starts_with("0x") && n == 42 && s[2..].chars().all(|c| c.is_ascii_hexdigit()))
}
pub fn is_path(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('m') else { return false };
    if s.len() > 64 { return false; }
    if rest.is_empty() { return true; }
    let Some(rest) = rest.strip_prefix('/') else { return false };
    let parts: Vec<&str> = rest.split('/').collect();
    parts.len() <= 8 && parts.iter().all(|p| {
        let d = p.strip_suffix('\'').unwrap_or(p);
        (1..=10).contains(&d.len()) && d.chars().all(|c| c.is_ascii_digit())
    })
}
fn small_uint(v: &Value) -> bool {
    v.as_u64().map_or(false, |n| n <= 1_000_000_000)
}

/// Field allowlist. Anything not listed is dropped; anything listed but
/// failing validation causes the whole line to be dropped.
fn validate(key: &str, v: &Value) -> Option<bool> {
    let s = v.as_str();
    Some(match key {
        "tool" => s.map_or(false, |s| TOOLS.contains(&s)),
        "status" => s.map_or(false, |s| STATUSES.contains(&s)),
        "kind" => s.map_or(false, |s| KINDS.contains(&s)),
        "chain" => s.map_or(false, |s| CHAINS.contains(&s)),
        "scheme" => s.map_or(false, |s| SCHEMES.contains(&s)),
        "preset" => s.map_or(false, |s| s.len() <= 16 && s.chars().all(|c| c.is_ascii_lowercase() || c == '-')),
        k if SECRET_FIELDS.contains(&k) => return None, // replaced by a placeholder in redact_line
        "address" => s.map_or(false, is_address),
        "class" => s.map_or(false, |s| s.len() <= 32 && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit())),
        "fp" => s.map_or(false, |s| s.len() == 10 && &s[4..6] == ".." && s[..4].bytes().chain(s[6..].bytes()).all(|b| b.is_ascii_hexdigit())),
        "path" => s.map_or(false, is_path),
        // Transactions (tx-decode). txids are deliberately NOT allowlisted: 64 hex is key-shaped.
        "role" => s.map_or(false, |s| ["summary", "input", "output"].contains(&s)),
        "type" => s.map_or(false, |s| TX_TYPES.contains(&s)),
        "selector" => s.map_or(false, |s| ["transfer", "approve", "transferFrom"].contains(&s)),
        "signed" | "rbf" => v.is_boolean(),
        "warnings" => v.as_array().map_or(false, |a| a.len() <= 32 && a.iter().all(|w| w.as_str().map_or(false, |w| TX_WARNINGS.contains(&w)))),
        "failures" => v.as_array().map_or(false, |a| a.len() <= 32 && a.iter().all(|w| w.as_str().map_or(false, |w| TX_FAILURES.contains(&w)))),
        "from" | "to" | "token" | "token_to" => s.map_or(false, is_address),
        "amount" | "fee" => v.as_u64().map_or(false, |n| n <= i64::MAX as u64),
        "amount_str" | "fee_str" => s.map_or(false, |s| (1..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())),
        "value" | "max_fee" | "max_fee_per_gas" | "max_priority_fee_per_gas" | "token_amount" =>
            s.map_or(false, |s| (1..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())),
        "inputs" | "outputs" | "signed_inputs" | "vout" | "vsize" | "fee_rate" | "locktime" | "nonce" | "gas" | "chain_id" | "data_len" => v.as_u64().map_or(false, |n| n <= u32::MAX as u64),
        "candidate" | "count" | "index" | "changed_words" | "line" | "branch" => small_uint(v),
        _ => return None,
    })
}

/// Decoded byte length of a base58 (Bitcoin alphabet) string, no checksum.
fn b58_len(s: &str) -> Option<usize> {
    let mut n: Vec<u8> = vec![];
    for c in s.bytes() {
        let mut carry = B58.find(c as char)? as u32;
        for b in n.iter_mut().rev() { carry += (*b as u32) * 58; *b = carry as u8; carry >>= 8; }
        while carry > 0 { n.insert(0, carry as u8); carry >>= 8; }
    }
    Some(s.bytes().take_while(|&b| b == b'1').count() + n.len())
}

/// Defense in depth: true if the text looks like it contains key material.
pub fn looks_secret(text: &str) -> bool {
    let cs: Vec<char> = text.chars().collect();
    // Maximal runs of hex digits / base58 chars.
    let run = |pred: &dyn Fn(char) -> bool| -> Vec<String> {
        let mut out = vec![]; let mut cur = String::new();
        for &c in &cs { if pred(c) { cur.push(c) } else if !cur.is_empty() { out.push(std::mem::take(&mut cur)) } }
        if !cur.is_empty() { out.push(cur) } out
    };
    if run(&|c: char| c.is_ascii_hexdigit()).iter().any(|r| r.len() >= 64) { return true; }
    // Long base58 tokens that are not addresses (e.g. a 64-byte ed25519 keypair, 88 chars).
    for tok in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if tok.len() >= 45 && all_in(tok, B58) && !is_address(tok) { return true; }
    }
    for r in run(&is_b58) {
        if r.len() >= 24 && ["xprv", "yprv", "zprv", "tprv", "uprv", "vprv"].iter().any(|p| r.contains(p)) { return true; }
        // WIF-shaped: 51-52 base58 chars starting 5/9/K/L/c.
        if (51..=52).contains(&r.len()) && r.starts_with(['5', '9', 'K', 'L', 'c']) { return true; }
        // XRP family seed: 's' + base58 (ripple alphabet, same charset), 16-byte entropy -> 29 chars.
        if (28..=31).contains(&r.len()) && r.starts_with('s') { return true; }
        // Bitcoin mini private key (Casascius): 'S' + 21/29 base58 chars.
        if [22, 26, 30].contains(&r.len()) && r.starts_with('S') { return true; }
    }
    // Mnemonic: 3+ consecutive BIP39 words.
    let wl = bip39::Language::English;
    let mut run = 0;
    for tok in text.split(|c: char| !c.is_ascii_alphabetic()) {
        if tok.is_empty() { continue; }
        if wl.find_word(&tok.to_ascii_lowercase()).is_some() { run += 1; if run >= 3 { return true; } } else { run = 0; }
    }
    false
}

/// Turn one raw tool output line (may contain secrets) into a public line, or None.
/// Public address-list line from `derive --address-list`: `label<TAB>path[ [passphrase #N]]<TAB>address`.
/// Passed through unchanged only when every field has its narrow shape: label 1..=64 chars of
/// [A-Za-z0-9 ()./_+-], at most 6 words, no token over 19 chars; path is a BIP32 path; address is an
/// address (a 32-byte base58 value, the Solana seed shape, only on a "Solana" label); and the whole
/// line passes looks_secret. Anything else returns None (the line is dropped).
pub fn address_list_line(raw: &str) -> Option<String> {
    let f: Vec<&str> = raw.split('\t').collect();
    let [label, path, addr] = f[..] else { return None };
    if label.is_empty() || label.len() > 64 || !label.chars().all(|c| c.is_ascii_alphanumeric() || " ()./_+-".contains(c)) { return None; }
    if label.split_whitespace().count() > 6 || label.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| t.len() > 19) { return None; }
    let p = match path.split_once(" [passphrase #") {
        Some((p, n)) => { let n = n.strip_suffix(']')?; if n.is_empty() || n.len() > 5 || !n.bytes().all(|b| b.is_ascii_digit()) { return None; } p }
        None => path,
    };
    if !is_path(p) || !is_address(addr) { return None; }
    if (32..=44).contains(&addr.len()) && all_in(addr, B58) && b58_len(addr) == Some(32) && !label.contains("Solana") { return None; }
    // Leak check on label+path, and on the address unless it is a whole bech32 or 0x token (a bech32
    // address can contain an 's'+base58 run that the XRP-seed rule would flag).
    if looks_secret(&raw[..label.len() + 1 + path.len()]) { return None; }
    if !(is_bech(addr) || addr.starts_with("0x")) && looks_secret(addr) { return None; }
    Some(raw.to_string())
}
/// One raw output line -> public line: JSON lines via redact_line, anything else via address_list_line.
pub fn redact_output_line(raw: &str) -> Option<String> {
    let t = raw.trim_end_matches(['\n', '\r']);
    if t.starts_with('{') { redact_line(t.trim_end()) } else { address_list_line(t) }
}
pub fn redact_line(raw: &str) -> Option<String> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let obj = v.as_object()?;
    let mut out = Map::new();
    for (k, val) in obj {
        if SECRET_FIELDS.contains(&k.as_str()) { out.insert(k.clone(), Value::String(PLACEHOLDER.into())); continue; }
        match validate(k, val) {
            Some(true) => { out.insert(k.clone(), val.clone()); }
            Some(false) => return None,
            None => {} // not allowlisted: drop silently
        }
    }
    if !out.contains_key("status") { return None; }
    // A 32-44 char base58 "address" is only plausible for Solana (a base58 32-byte key has the same shape).
    // Every address-type field, not just "address" (to/from/token too).
    for a in ["address", "from", "to", "token", "token_to"].iter().filter_map(|k| out.get(*k).and_then(|a| a.as_str())) {
        if a.len() > 35 && all_in(a, B58) && !is_bech(a) && !is_xmr_address(a) && !is_dot_address(a) && !is_ksm_address(a) && !is_polyx_address(a) && !is_ton_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("sol") { return None; }
    }
    if let Some(a) = out.get("address").and_then(|a| a.as_str()) {
        if is_xlm_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("xlm") { return None; }
        if is_ua_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("zec") { return None; }
        if is_zs_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("zec") { return None; }
        if is_ada_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("ada") { return None; }
        if is_ton_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("ton") { return None; }
        if is_dot_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("dot") { return None; }
        if is_ksm_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("ksm") { return None; }
        if is_polyx_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("polyx") { return None; }
        if is_algo_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("algo") { return None; }
    }
    // A 32-byte base58 value (ed25519 secret seed shape, e.g. a Solana key) is only allowed as an
    // address-type field value; anywhere else in the line it is treated as a secret.
    let addrs: Vec<&str> = ["address", "from", "to", "token", "token_to"].iter().filter_map(|k| out.get(*k).and_then(|v| v.as_str())).collect();
    for (k, v) in &out {
        if ["address", "from", "to", "token", "token_to"].contains(&k.as_str()) { continue; }
        if let Some(s) = v.as_str() {
            for tok in s.split(|c: char| !c.is_ascii_alphanumeric()) {
                if (32..=44).contains(&tok.len()) && all_in(tok, B58) && !addrs.contains(&tok) && b58_len(tok) == Some(32) { return None; }
            }
        }
    }
    let line = serde_json::to_string(&Value::Object(out)).ok()?;
    if line.len() > 512 || looks_secret(&line) { return None; }
    Some(line)
}

#[cfg(test)]
mod tests {
    // Security review 2026-10-25 (group 5). Test values are public (generated, never funded).
    #[test] fn rejects_xrp_seed_minikey_sol_secret() {
        let xrp = "snoPBrXtMeMyMHUVTgbuqAfg1SUTb"; // XRPL docs example family seed
        assert!(looks_secret(xrp));
        assert!(redact_line(&format!(r#"{{"status":"ok","address":"{xrp}"}}"#)).is_none());
        let mini = "S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy"; // Bitcoin wiki mini private key example
        assert!(looks_secret(mini));
        // 32 bytes base58: fine as a Solana address, refused in any other field.
        let k32 = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";
        assert_eq!(b58_len(k32), Some(32));
        assert!(redact_line(&format!(r#"{{"status":"ok","chain":"sol","address":"{k32}"}}"#)).is_some());
        assert!(redact_line(&format!(r#"{{"status":"ok","chain":"btc","address":"{k32}"}}"#)).is_none());
        assert!(redact_line(&format!(r#"{{"status":"ok","chain":"eth","to":"{k32}"}}"#)).is_none());
        assert!(redact_line(&format!(r#"{{"status":"ok","to":"{k32}"}}"#)).is_none());
        assert!(!looks_secret("rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh")); // XRP address stays public
    }
    #[test] fn tx_decode_lines() {
        let l = r#"{"tool":"tx-decode","status":"ok","role":"summary","chain":"eth","type":"evm-1559","signed":true,"from":"0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F","value":"1000000000000000000","warnings":["unsigned"],"txid":"0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"}"#;
        let o = super::redact_line(l).unwrap();
        assert!(o.contains("evm-1559") && !o.contains("txid"));
        assert!(super::redact_line(&l.replace("unsigned", "evil")).is_none());
    }
    use super::*;
    #[test] fn unified_address_only_with_zec() {
        let l = r#"{"tool":"zec-sapling","status":"ok","chain":"zec","kind":"unified","address":"UA"}"#.replace("UA", "u1vu0zkreyef83369fn3dr94zkg2djqlcgtghxf2jmdcdmxp2z4l70dlh6yfdf5v33cteezva2c528syqtmu7uxgzss6fumh3tzjumnqh45z3yewkqplrfdz4f68aahg8x35yknyf7vjh4wy5sn4cc8edkxlef2p4q8ez6e0xuzrmr4rzff54m5t5whyzdgfg2cujtjdjlx2zqu46h7ty");
        assert!(redact_line(&l).unwrap().contains("u1vu0z"));
        assert!(redact_line(&l.replace(r#""chain":"zec""#, r#""chain":"btc""#)).is_none());
    }
    const MN: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    #[test] fn xmr_address_passes_hex_key_does_not() {
        let a = "44cWztNFdAqNnycvZbUoj44vsbAEmKnx9aNgkjHdjtMsBrSeKiY8J4s2raH7EMawA2Fwo9utaRTV7Aw8EcTMNMxhH4YtKdH";
        let o = redact_line(&format!(r#"{{"tool":"xmr-keys","status":"ok","chain":"xmr","kind":"xmr","address":"{a}","spend_public":"ab"}}"#)).unwrap();
        assert!(o.contains(a) && !o.contains("spend_public"));
        assert!(redact_line(&format!(r#"{{"status":"ok","address":"{}"}}"#, "8".repeat(95))).is_none());
    }
    #[test] fn passes_public() {
        let l = r#"{"tool":"derive","status":"ok","kind":"p2wpkh","path":"m/84'/0'/0'/0/0","address":"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu","wif":"KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"}"#;
        let o = redact_line(l).unwrap();
        assert!(o.contains(r#""wif":"[REDACTED]""#) && o.contains("bc1q") && !o.contains("KyZp"));
    }
    #[test] fn drops_secret_fields() {
        for l in [
            format!(r#"{{"status":"ok","mnemonic":"{MN}"}}"#),
            r#"{"status":"ok","private_key":"1ab2"}"#.to_string(),
        ] { let o = redact_line(&l).unwrap(); assert!(o.contains("[REDACTED]") && !o.contains("abandon") && !o.contains("1ab2"), "{o}"); }
    }
    // All key-like strings below are public test vectors / textbook examples, not real keys.
    #[test] fn rejects_secret_smuggled_in_allowed_field() {
        let cases = [
            format!(r#"{{"status":"{MN}"}}"#),
            r#"{"status":"ok","address":"KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"}"#.into(),
            r#"{"status":"ok","path":"xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu"}"#.into(),
            r#"{"status":"ok","address":"0x7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"}"#.into(),
            r#"{"status":"ok","count":"5KQNQrchLtW4bXRQ2ZQhgNDZnHVaAw9vP3pvWNaYT5RzmWJbuyR"}"#.into(),
            r#"not json"#.into(),
            r#"{"tool":"derive"}"#.into(),
        ];
        for c in cases { assert!(redact_line(&c).is_none(), "leaked: {c}"); }
    }
    #[test] fn bech_without_zero_is_not_sol_shaped() {
        let l = r#"{"status":"ok","chain":"vtc","kind":"p2wpkh","address":"vtc1qfe8v6c4r39fq8xnjgcpunt5spdfcxw63zzfwru"}"#;
        assert!(redact_line(l).is_some());
    }
    #[test] fn xlm_shape_only_with_chain_xlm() {
        let a = "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6";
        assert!(redact_line(&format!(r#"{{"status":"ok","chain":"xlm","address":"{a}"}}"#)).is_some());
        assert!(redact_line(&format!(r#"{{"status":"ok","chain":"btc","address":"{a}"}}"#)).is_none());
        let s = format!("S{}", &a[1..]);
        assert!(redact_line(&format!(r#"{{"status":"ok","chain":"xlm","address":"{s}"}}"#)).is_none());
    }
    #[test] fn sol_shape_only_with_chain_sol() {
        let a = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"; // public vector address
        assert!(redact_line(&format!(r#"{{"status":"ok","chain":"sol","address":"{a}"}}"#)).is_some());
        assert!(redact_line(&format!(r#"{{"status":"ok","address":"{a}"}}"#)).is_none());
        // 88-char base58 (keypair-shaped, made of public-vector address twice) anywhere -> dropped
        assert!(looks_secret(&format!("{a}{a}")));
    }
    #[test] fn scanner() {
        assert!(looks_secret(MN));
        assert!(looks_secret("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"));
        assert!(looks_secret("x 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ y"));
        assert!(!looks_secret(r#"{"address":"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA","status":"ok"}"#));
    }
}

#[cfg(test)]
// finding:D1-12 guard: every tx-verify/tx-sign failure code survives redact.
mod d1_12 {
    // Every code the verifier may emit (blocktools_tx's code! macro only accepts TX_FAILURES members)
    // must survive redact; before D1-12 the whole refusal line was dropped.
    #[test] fn every_tx_failure_survives_redact() {
        for c in super::TX_FAILURES {
            let line = serde_json::json!({"tool":"tx-verify","status":"failed","failures":[c]}).to_string();
            let out = super::redact_line(&line).unwrap_or_else(|| panic!("redact dropped failure {c}"));
            assert!(out.contains(c), "{c}: {out}");
        }
    }
}

#[cfg(test)]
mod address_list_tests {
    use super::address_list_line as a;
    #[test] fn public_lines_pass() {
        for l in ["MetaMask/Trezor/Trust/Exodus/Rabby EVM\tm/44'/60'/0'/0/0\t0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
                  "BTG (G...)\tm/44'/156'/0'/0/19\tGQJkUbRZqCnvvqpL5nLdxxVSEVbqsndAta",
                  "BTC legacy (1...)\tm/44'/0'/0'/0/0 [passphrase #1]\t1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
                  "BTC native SegWit (bc1q...) Exodus/Trezor/Ledger\tm/84'/0'/0'/0/17\tbc1qrz46a4gt0sghvvyt4gy5kp2rswmhtufv6sdq9v"] {
            assert_eq!(a(l).as_deref(), Some(l), "{l}");
        }
    }
    #[test] fn key_material_dropped() {
        // public test vectors only (BIP39 "abandon ... about" and its well-known keys)
        for l in ["BTC legacy (1...)\tm/44'/0'/0'/0/0\tL4p2b9VAf8k5aUahF1JCJUzZkgNEAqLfq8DDdQiyAprQAKSbu8hf",
                  "BTC legacy (1...)\tm/44'/0'/0'/0/0\t1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA\tL4p2b9VAf8k5aUahF1JCJUzZkgNEAqLfq8DDdQiyAprQAKSbu8hf",
                  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\tm/0\t1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
                  "a22ddec5c567b4488bb00f69b6146c50da2ee883e2c096db098726394d585730\tm/0\t1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
                  "BTC\txprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu\t1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
                  "EVM\tm/44'/60'/0'/0/0\t1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727",
                  "BTC native SegWit\tm/84'/0'/0'/0/0\t4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
                  "XRP\tm/0\tsnoPBrXtMeMyMHUVTgbuqAfg1SUTb",
                  "BTC\tm/0 [passphrase #TREZOR]\t1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"] {
            assert_eq!(a(l), None, "{l}");
        }
    }
}
