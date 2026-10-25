//! Agent-facing public schema. The ONLY thing that may cross the container
//! boundary toward the agent is a line produced by `redact_line`.
//! Design: allowlist of fields, each with a strict type validator, followed by
//! a defense-in-depth leak scan over the serialized line.
use serde_json::{Map, Value};

pub const STATUSES: &[&str] = &[
    "ok", "checksum_ok", "checksum_fail", "no_candidates", "too_many_candidates",
    "bad_input", "wrong_password", "unsupported", "error", "done",
];
pub const TOOLS: &[&str] = &["seed-repair", "seed-to-master", "derive", "keystore-open", "kr-redact", "kr-run"];
pub const KINDS: &[&str] = &["p2pkh", "p2sh-p2wpkh", "p2wpkh", "p2tr", "eth"];

const B58: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BECH: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
fn all_in(s: &str, set: &str) -> bool { s.chars().all(|c| set.contains(c)) }
fn is_b58(c: char) -> bool { B58.contains(c) }

pub fn is_address(s: &str) -> bool {
    let n = s.len();
    ((s.starts_with('1') || s.starts_with('3')) && (26..=35).contains(&n) && all_in(s, B58))
        || (s.starts_with("bc1") && (42..=62).contains(&n) && all_in(&s[3..], BECH))
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
        "address" => s.map_or(false, is_address),
        "path" => s.map_or(false, is_path),
        "candidate" | "count" | "index" | "changed_words" | "line" => small_uint(v),
        _ => return None,
    })
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
    for r in run(&is_b58) {
        if r.len() >= 24 && ["xprv", "yprv", "zprv", "tprv", "uprv", "vprv"].iter().any(|p| r.contains(p)) { return true; }
        // WIF-shaped: 51-52 base58 chars starting 5/9/K/L/c.
        if (51..=52).contains(&r.len()) && r.starts_with(['5', '9', 'K', 'L', 'c']) { return true; }
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
