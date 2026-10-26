//! Solana / Tron chain auto-detect for the `sol-tron-tx` CLI. Public data only, no keys.
use serde_json::Value;

/// Wire bytes from hex (optional 0x) or base64.
pub fn raw(s: &str) -> Result<Vec<u8>, &'static str> {
    let t = s.trim(); let h = t.trim_start_matches("0x");
    if !h.is_empty() && h.len() % 2 == 0 && h.bytes().all(|b| b.is_ascii_hexdigit()) { return crate::hex_dec(h).ok_or("bad_hex") }
    crate::b64::decode(t).ok_or("bad_encoding")
}
/// Which chain a transaction's bytes parse as. Both parsers are strict (Solana rejects trailing bytes
/// and bad indices; Tron needs a contract field), and bytes that parse as both are refused.
pub fn detect_tx(b: &[u8]) -> Result<&'static str, &'static str> {
    match (crate::sol::parse_tx(b).is_ok(), crate::tron::decode(b).is_ok()) {
        (true, false) => Ok("sol"), (false, true) => Ok("tron"), (true, true) => Err("ambiguous_chain"), (false, false) => Err("not_sol_or_tron"),
    }
}
/// Which chain a plan is for, from its `from` address: a Tron T-address (base58check, 0x41) or a
/// Solana 32-byte base58 key. Anything else is refused.
pub fn detect_plan(v: &Value) -> Result<&'static str, &'static str> {
    let f = v["from"].as_str().ok_or("bad_address")?;
    match (crate::tron::parse_address(f).is_ok(), crate::sol::pubkey(f).is_ok()) {
        (true, false) => Ok("tron"), (false, true) => Ok("sol"), (true, true) => Err("ambiguous_chain"), _ => Err("bad_address"),
    }
}
/// Build unsigned bytes for `chain` from a plan.
pub fn build(chain: &str, v: &Value) -> Result<Vec<u8>, &'static str> {
    match chain { "sol" => crate::sol::build_transfer(&crate::sol::plan_from_json(v)?), "tron" => crate::tron::build_transfer(&crate::tron::plan_from_json(v)?), _ => Err("unsupported_chain") }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn sol_plan() -> Value { json!({"from": "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T", "to": crate::sol::SYSTEM, "blockhash": crate::sol::SYSTEM, "lamports": "1000"}) }
    fn tron_plan() -> Value {
        let a = |n: u8| crate::tron::address(&[0x41, n, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]).unwrap();
        json!({"from": a(1), "to": a(9), "ref_block_bytes": "abcd", "ref_block_hash": "0102030405060708", "expiration_ms": 1, "timestamp_ms": 0, "amount_sun": "5"})
    }
    #[test]
    fn detects_each_chain_and_refuses_junk() {
        let (sp, tp) = (sol_plan(), tron_plan());
        assert_eq!(detect_plan(&sp), Ok("sol"));
        assert_eq!(detect_plan(&tp), Ok("tron"));
        assert_eq!(detect_plan(&json!({"from": "0xabc"})), Err("bad_address"));
        let s = build("sol", &sp).unwrap(); let t = build("tron", &tp).unwrap();
        assert_eq!(detect_tx(&s), Ok("sol"));
        assert_eq!(detect_tx(&t), Ok("tron"));
        assert_eq!(detect_tx(&[0xff; 7]), Err("not_sol_or_tron"));
        assert_eq!(raw(&format!("0x{}", crate::hex_enc(&s))), Ok(s.clone()));
        assert_eq!(build("eth", &sp), Err("unsupported_chain"));
    }
}
