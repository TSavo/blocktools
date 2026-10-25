//! Agent-facing public schema. The ONLY thing that may cross the container
//! boundary toward the agent is a line produced by `redact_line`.
//! Design: allowlist of fields, each with a strict type validator, followed by
//! a defense-in-depth leak scan over the serialized line.
use serde_json::{Map, Value};

pub const STATUSES: &[&str] = &[
    "ok", "checksum_ok", "checksum_fail", "no_candidates", "too_many_candidates",
    "bad_input", "wrong_password", "unsupported", "error", "done", "failed", "refused", "aborted",
];
/// tx-verify / tx-sign policy failures (blocktools_tx::policy).
pub const TX_FAILURES: &[&str] = &["has_warnings", "fee_above_cap", "fee_unknown", "chain_id_mismatch", "no_chain_id", "no_replay_protection",
    "token_call_not_transfer", "unknown_contract_call", "destination_not_expected", "unexpected_output", "expected_destination_missing", "input_without_key"];
pub const TOOLS: &[&str] = &["seed-repair", "seed-to-master", "derive", "keystore-open", "redact", "sealed-run", "read-file", "dat-read",
    "key-to-addresses", "classify", "tx-decode", "tx-verify", "tx-build", "tx-build-sweep", "tx-sign", "tx-broadcast", "electrum-read", "multibit-read", "armory-read", "xpub-addresses", "xmr-keys", "xrp-tx"];
pub const KINDS: &[&str] = &["p2pkh", "p2pkh-uncompressed", "p2sh-p2wpkh", "p2wpkh", "p2tr", "eth", "tron", "xrp", "sol", "xlm", "xmr",
    "p2pk", "p2sh", "p2wsh", "op_return", "nonstandard", "unknown"];
pub const CHAINS: &[&str] = &["btc", "ltc", "doge", "eth", "tron", "xrp", "sol", "xlm", "xmr", "qtum", "ftc", "nmc", "dash", "vtc", "dgb", "via", "mona", "rvn", "xpm", "trc", "mec", "aur", "bch", "bsv", "btg", "ppc", "nvc", "clam", "blk", "rdd", "pot", "qrk", "wdc", "anc", "grs"];
pub const SCHEMES: &[&str] = &["bip39", "electrum-standard", "electrum-segwit", "electrum-2fa", "electrum-2fa-segwit", "electrum-old"];
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
/// Segwit hrps of the chain table (blocktools-core chains.rs; a core test checks they match).
pub const HRPS: &[&str] = &["bc", "ltc", "qc", "fc", "nc", "vtc", "dgb", "via", "mona", "mec", "btg", "pc", "rdd", "grs"];
fn is_bech(s: &str) -> bool {
    HRPS.iter().any(|h| s.len() > h.len() + 1 && s.starts_with(h) && s.as_bytes()[h.len()] == b'1'
        && (40..=60).contains(&(s.len() - h.len())) && all_in(&s[h.len() + 1..], BECH))
}
/// Monero standard address: 95 base58 chars, mainnet prefix 4 (stagenet/testnet 5/9). It is public.
pub fn is_xmr_address(s: &str) -> bool { s.len() == 95 && s.starts_with(['4', '5', '9']) && all_in(s, B58) }
/// Stellar account id: StrKey 'G' + 55 base32 chars (public). Seeds start with 'S' and never match.
/// Accepted only with "chain":"xlm" (redact_line).
pub fn is_xlm_address(s: &str) -> bool { s.len() == 56 && s.starts_with('G') && all_in(s, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") }
pub fn is_address(s: &str) -> bool {
    let n = s.len();
    is_xmr_address(s) || is_xlm_address(s) || ((25..=44).contains(&n) && all_in(s, B58))
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
        "amount" | "fee" => v.as_u64().map_or(false, |n| n <= 21_000_000 * 100_000_000),
        "value" | "max_fee" | "max_fee_per_gas" | "max_priority_fee_per_gas" | "token_amount" =>
            s.map_or(false, |s| (1..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())),
        "inputs" | "outputs" | "signed_inputs" | "vout" | "vsize" | "fee_rate" | "locktime" | "nonce" | "gas" | "chain_id" | "data_len" => v.as_u64().map_or(false, |n| n <= u32::MAX as u64),
        "candidate" | "count" | "index" | "changed_words" | "line" | "branch" => small_uint(v),
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
    // Long base58 tokens that are not addresses (e.g. a 64-byte ed25519 keypair, 88 chars).
    for tok in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        if tok.len() >= 45 && all_in(tok, B58) && !is_address(tok) { return true; }
    }
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
        if SECRET_FIELDS.contains(&k.as_str()) { out.insert(k.clone(), Value::String(PLACEHOLDER.into())); continue; }
        match validate(k, val) {
            Some(true) => { out.insert(k.clone(), val.clone()); }
            Some(false) => return None,
            None => {} // not allowlisted: drop silently
        }
    }
    if !out.contains_key("status") { return None; }
    // A 32-44 char base58 "address" is only plausible for Solana (a base58 32-byte key has the same shape).
    if let Some(a) = out.get("address").and_then(|a| a.as_str()) {
        if a.len() > 35 && all_in(a, B58) && !is_bech(a) && !is_xmr_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("sol") { return None; }
    }
    if let Some(a) = out.get("address").and_then(|a| a.as_str()) {
        if is_xlm_address(a) && out.get("chain").and_then(|c| c.as_str()) != Some("xlm") { return None; }
    }
    let line = serde_json::to_string(&Value::Object(out)).ok()?;
    if line.len() > 512 || looks_secret(&line) { return None; }
    Some(line)
}

#[cfg(test)]
mod tests {
    #[test] fn tx_decode_lines() {
        let l = r#"{"tool":"tx-decode","status":"ok","role":"summary","chain":"eth","type":"evm-1559","signed":true,"from":"0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F","value":"1000000000000000000","warnings":["unsigned"],"txid":"0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"}"#;
        let o = super::redact_line(l).unwrap();
        assert!(o.contains("evm-1559") && !o.contains("txid"));
        assert!(super::redact_line(&l.replace("unsigned", "evil")).is_none());
    }
    use super::*;
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
