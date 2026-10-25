//! Agent-facing public schema. The ONLY thing that may cross the container
//! boundary toward the agent is a line produced by `redact_line`.
//! Design: allowlist of fields, each with a strict type validator, followed by
//! a defense-in-depth leak scan over the serialized line.
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::OnceLock;

pub const STATUSES: &[&str] = &[
    "ok", "checksum_ok", "checksum_fail", "no_candidates", "too_many_candidates",
    "bad_input", "wrong_password", "unsupported", "error", "done",
];
pub const TOOLS: &[&str] = &["seed-repair", "derive", "keystore-open", "kr-redact"];
pub const KINDS: &[&str] = &["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr", "eth"];

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).unwrap())
}
static R_BTC_B58: OnceLock<Regex> = OnceLock::new();
static R_BECH: OnceLock<Regex> = OnceLock::new();
static R_ETH: OnceLock<Regex> = OnceLock::new();
static R_PATH: OnceLock<Regex> = OnceLock::new();

pub fn is_address(s: &str) -> bool {
    re(&R_BTC_B58, r"^[13][1-9A-HJ-NP-Za-km-z]{25,34}$").is_match(s)
        || re(&R_BECH, r"^bc1[02-9ac-hj-np-z]{39,59}$").is_match(s)
        || re(&R_ETH, r"^0x[0-9a-fA-F]{40}$").is_match(s)
}
pub fn is_path(s: &str) -> bool {
    s.len() <= 64 && re(&R_PATH, r"^m(/[0-9]{1,10}'?){0,8}$").is_match(s)
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
        "address" => s.map_or(false, is_address),
        "path" => s.map_or(false, is_path),
        "candidate" | "count" | "index" | "changed_words" | "line" => small_uint(v),
        _ => return None,
    })
}

static R_HEX64: OnceLock<Regex> = OnceLock::new();
static R_XKEY: OnceLock<Regex> = OnceLock::new();
static R_WIF: OnceLock<Regex> = OnceLock::new();

/// Defense in depth: true if the text looks like it contains key material.
pub fn looks_secret(text: &str) -> bool {
    if re(&R_HEX64, r"(?i)(0x)?[0-9a-f]{64}").is_match(text) { return true; }
    if re(&R_XKEY, r"[xyztuv]prv[1-9A-HJ-NP-Za-km-z]{20,}").is_match(text) { return true; }
    if re(&R_WIF, r"(^|[^1-9A-HJ-NP-Za-km-z])[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}($|[^1-9A-HJ-NP-Za-km-z])").is_match(text) { return true; }
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
pub fn redact_line(raw: &str) -> Option<String> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let obj = v.as_object()?;
    let mut out = Map::new();
    for (k, val) in obj {
        match validate(k, val) {
            Some(true) => { out.insert(k.clone(), val.clone()); }
            Some(false) => return None,
            None => {} // not allowlisted: drop silently
        }
    }
    if !out.contains_key("status") { return None; }
    let line = serde_json::to_string(&Value::Object(out)).ok()?;
    if line.len() > 512 || looks_secret(&line) { return None; }
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    const MN: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    #[test] fn passes_public() {
        let l = r#"{"tool":"derive","status":"ok","kind":"p2wpkh","path":"m/84'/0'/0'/0/0","address":"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu","wif":"KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d"}"#;
        let o = redact_line(l).unwrap();
        assert!(!o.contains("wif") && o.contains("bc1q"));
    }
    #[test] fn drops_secret_fields() {
        for l in [
            format!(r#"{{"status":"ok","mnemonic":"{MN}"}}"#),
            r#"{"status":"ok","private_key":"1ab2"}"#.to_string(),
        ] { let o = redact_line(&l).unwrap(); assert_eq!(o, r#"{"status":"ok"}"#); }
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
    #[test] fn scanner() {
        assert!(looks_secret(MN));
        assert!(looks_secret("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d"));
        assert!(looks_secret("x 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ y"));
        assert!(!looks_secret(r#"{"address":"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA","status":"ok"}"#));
    }
}
