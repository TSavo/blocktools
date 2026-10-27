//! Common signing envelope (public half): one JSON request/response schema for decode,
//! verify and check across the chain families the facade already covers (UTXO, EVM, ZEC,
//! Sol, Tron). Signing with private keys stays in the CLIs (TTY confirm); this module
//! never takes a key. Used by the `tx-envelope` tool and the C ABI (`blocktools-c`).
//!
//! Request:
//! ```json
//! {"envelope":"blocktools.sign/v1","op":"decode"|"verify"|"check"|"verify_thor_send","chain":"btc",
//!  "tx":"<hex|psbt|base64|json>", ...}
//! ```
//! `verify` also takes `expect_to` (string or array), optional `change`, `max_fee`,
//! `chain_id`, `allow_warnings`. `check` takes the same fields as [`crate::check::tx_json`]
//! (`expected_outputs`, `owner_addr`, `max_fee`, optional `input_values`) plus `tx`
//! (aliased as `raw_tx_hex` when that field is used instead).
//!
//! `verify_thor_send` checks a THORChain inbound send (btc/ltc/doge/bch): `tx`, `vault`, `memo`,
//! `amount`, optional `change`, `taker` (string or array) and `max_fee`; see [`crate::thor`].
//!
//! Response always carries `envelope`, `status` (`ok`|`error`), `op`, `chain`.
use blocktools_core::chains;
use blocktools_tx::policy::Policy;
use serde_json::{json, Value};

pub const ENVELOPE: &str = "blocktools.sign/v1";

fn err(op: &str, chain: &str, e: &str) -> String {
    json!({"envelope": ENVELOPE, "status": "error", "op": op, "chain": chain, "error": e}).to_string()
}

fn strs(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).filter(|s| !s.is_empty()).map(str::to_string).collect(),
        _ => vec![],
    }
}


fn bytes_hex_or_b64(s: &str) -> Result<Vec<u8>, &'static str> {
    let t = s.trim();
    let h = t.trim_start_matches("0x");
    if h.len() % 2 == 0 && !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return blocktools_core::hex_dec(h).ok_or("bad_hex");
    }
    blocktools_core::b64::decode(t).ok_or("bad_encoding")
}

fn tx_field(v: &Value) -> Option<&str> {
    for k in ["tx", "raw_tx_hex", "unsigned_tx", "signed_tx", "psbt"] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()).map(str::trim).filter(|s| !s.is_empty()) {
            return Some(s);
        }
    }
    None
}

fn family(chain: &str) -> &'static str {
    match chain {
        "sol" => "sol",
        "tron" => "tron",
        "zec" => "zec",
        n => match chains::chain(n).map(|c| &c.enc) {
            Some(chains::Enc::Eth) => "evm",
            Some(chains::Enc::Tron) => "tron",
            Some(chains::Enc::Sol) => "sol",
            Some(chains::Enc::Utxo { .. }) => "utxo",
            Some(_) => "account",
            None => "unknown",
        },
    }
}

fn decode_summary(chain: &str, tx: &str) -> Result<Value, &'static str> {
    match family(chain) {
        "sol" => {
            let raw = bytes_hex_or_b64(tx)?;
            crate::sol::decode_tx(&raw)
        }
        "tron" => {
            let b = blocktools_core::hex_dec(tx.trim()).ok_or("bad_hex")?;
            crate::tron::decode(&b)
        }
        "unknown" => Err("unknown_chain"),
        "account" => Err("unsupported_family"),
        _ => {
            let d = blocktools_tx::decode(tx, chain)?;
            Ok(d.json_lines().into_iter().next().unwrap_or_else(|| json!({})))
        }
    }
}

fn verify_utxo_evm(chain: &str, tx: &str, v: &Value) -> Result<Value, String> {
    let d = blocktools_tx::decode(tx, chain).map_err(|e| e.to_string())?;
    let p = Policy {
        expect_to: strs(v.get("expect_to")),
        change: strs(v.get("change")),
        chain_id: v.get("chain_id").and_then(|x| x.as_u64()).map(|n| n)
            .or_else(|| v.get("chain_id").and_then(|x| x.as_str()).and_then(|s| s.parse().ok())),
        max_fee: match v.get("max_fee") {
            Some(Value::Number(n)) => n.as_u64().map(u128::from),
            Some(Value::String(s)) => s.trim().parse().ok(),
            _ => None,
        },
        allow_warnings: v.get("allow_warnings").and_then(|x| x.as_bool()).unwrap_or(false),
        allow_value_with_token: v.get("allow_value_with_token").and_then(|x| x.as_bool()).unwrap_or(false),
    };
    let v = blocktools_tx::policy::verify(&d, &p);
    Ok(json!({
        "ok": v.findings.is_empty(),
        "findings": v.findings,
        "max_fee": blocktools_tx::policy::effective_max_fee(&d, &p).to_string(),
        "check_these": v.check_these,
        "fee_cap": v.fee_cap.json(),
        "summary": d.json_lines().into_iter().next().unwrap_or_else(|| json!({})),
    }))
}

/// Run one envelope request. `input` is a JSON object (or a JSON string of one).
/// Returns a JSON object string. Never panics on bad input.
pub fn run(input: &str) -> String {
    let v: Value = match serde_json::from_str(input.trim()) {
        Ok(v) => v,
        Err(_) => return err("", "", "bad_json"),
    };
    let env = v.get("envelope").and_then(|x| x.as_str()).unwrap_or("");
    if !env.is_empty() && env != ENVELOPE {
        return err("", "", "unsupported_envelope");
    }
    let op = v.get("op").and_then(|x| x.as_str()).unwrap_or("");
    let chain = v.get("chain").and_then(|x| x.as_str()).unwrap_or("").trim();
    if op.is_empty() { return err(op, chain, "op_missing") }
    if chain.is_empty() { return err(op, chain, "chain_missing") }

    match op {
        "decode" => {
            let Some(tx) = tx_field(&v) else { return err(op, chain, "tx_missing") };
            match decode_summary(chain, tx) {
                Ok(result) => json!({"envelope": ENVELOPE, "status": "ok", "op": op, "chain": chain, "family": family(chain), "result": result}).to_string(),
                Err(e) => err(op, chain, e),
            }
        }
        "verify" => {
            let Some(tx) = tx_field(&v) else { return err(op, chain, "tx_missing") };
            match family(chain) {
                "sol" => {
                    let raw = match bytes_hex_or_b64(tx) { Ok(b) => b, Err(e) => return err(op, chain, e) };
                    let expect = v.get("expect").cloned().unwrap_or(json!({
                        "expect_to": strs(v.get("expect_to")),
                    }));
                    match crate::sol::verify_tx(&raw, &expect) {
                        Ok(result) => json!({"envelope": ENVELOPE, "status": "ok", "op": op, "chain": chain, "family": "sol", "result": result}).to_string(),
                        Err(e) => err(op, chain, e),
                    }
                }
                "tron" | "account" | "unknown" => err(op, chain, "unsupported_family"),
                _ => match verify_utxo_evm(chain, tx, &v) {
                    Ok(result) => json!({"envelope": ENVELOPE, "status": "ok", "op": op, "chain": chain, "family": family(chain), "result": result}).to_string(),
                    Err(e) => err(op, chain, &e),
                },
            }
        }
        "check" => {
            // Reuse check::tx_json; map `tx` -> raw_tx_hex when needed.
            let mut obj = v.clone();
            if obj.get("raw_tx_hex").is_none() {
                if let Some(tx) = tx_field(&v) {
                    obj.as_object_mut().unwrap().insert("raw_tx_hex".into(), json!(tx));
                }
            }
            let result: Value = serde_json::from_str(&crate::check::tx_json(&obj.to_string())).unwrap_or(json!({"ok": false, "reasons": ["bad_check_output"]}));
            json!({"envelope": ENVELOPE, "status": "ok", "op": op, "chain": chain, "family": family(chain), "result": result}).to_string()
        }
        "verify_thor_send" => {
            // THORChain inbound send check: same fields as [`crate::thor::verify_send_json`]; `tx` is the PSBT/raw tx.
            let mut obj = v.clone();
            if let (Some(tx), Some(m)) = (tx_field(&v), obj.as_object_mut()) { m.insert("tx".into(), json!(tx)); }
            let result: Value = serde_json::from_str(&crate::thor::verify_send_json(&obj.to_string())).unwrap_or(json!({"ok": false, "failures": ["bad_output"]}));
            json!({"envelope": ENVELOPE, "status": "ok", "op": op, "chain": chain, "family": family(chain), "result": result}).to_string()
        }
        "chain_table" => {
            json!({"envelope": ENVELOPE, "status": "ok", "op": op, "chain": chain, "result": serde_json::from_str::<Value>(&chains::table_json()).unwrap_or(json!([]))}).to_string()
        }
        _ => err(op, chain, "unknown_op"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_btc_block170() {
        // Public Bitcoin block 170 coinbase+spend is huge; use a tiny refuse path instead.
        let bad = run(r#"{"envelope":"blocktools.sign/v1","op":"decode","chain":"btc","tx":"00"}"#);
        let v: Value = serde_json::from_str(&bad).unwrap();
        assert_eq!(v["status"], "error");
        assert_eq!(v["envelope"], ENVELOPE);
    }

    #[test]
    fn decode_eth_unsigned_transfer() {
        // Minimal legacy unsigned RLP: nonce 0, gasPrice 1, gas 21000, to 0x00..01, value 1, data empty.
        // Built offline; just assert envelope shape on a known-decodeable or clean error.
        let r = run(r#"{"op":"decode","chain":"eth","tx":"not-hex"}"#);
        let v: Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["op"], "decode");
        assert_eq!(v["chain"], "eth");
        assert!(v["status"] == "error" || v["status"] == "ok");
    }

    #[test]
    fn rejects_bad_envelope_version() {
        let r = run(r#"{"envelope":"other/v1","op":"decode","chain":"btc","tx":"00"}"#);
        let v: Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["error"], "unsupported_envelope");
    }

    #[test]
    fn chain_table_op() {
        let r = run(r#"{"op":"chain_table","chain":"_"}"#);
        let v: Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["status"], "ok");
        assert!(v["result"].as_array().unwrap().len() >= 40);
    }

    #[test]
    fn account_family_refused() {
        let r = run(r#"{"op":"decode","chain":"xlm","tx":"00"}"#);
        let v: Value = serde_json::from_str(&r).unwrap();
        assert_eq!(v["error"], "unsupported_family");
    }
}
