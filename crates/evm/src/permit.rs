//! Signed-permit content checks for EIP-712 typed data (typed-data-verify and the wasm `evmTypedDataVerify`):
//! who the permit lets spend, how much, until when. A 2^128 "unlimited" check alone misses a drainer that asks
//! for exactly the balance; the spender is what matters, so the caller asserts it.
//!
//! Recognised shapes, strictly by primaryType plus the exact (name, type) field set of every struct involved:
//!   eip2612                 Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)
//!   dai                     Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)
//!   permit2_single          PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)
//!   permit2_batch           PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)
//!                           PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)
//!   permit2_transfer        PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)
//!   permit2_batch_transfer  PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)
//!                           TokenPermissions(address token,uint256 amount)
//! Anything else is not guessed at: address fields whose name looks like a spender (spender, operator, delegate,
//! approved, allowed) are listed in `unrecognised_spender_fields`. No ERC-721/1155 typed-data permit is recognised.
//!
//! Findings (`permit_findings`): spender_not_expected, amount_not_expected (every entry of a batch must match),
//! unlimited_approval (an amount >= 2^128 or DAI allowed=true, without expect_unlimited), spender_not_checkable /
//! amount_not_checkable (asserted, but not a recognised permit). Amounts compare as exact integers, spenders as
//! addresses (case-insensitive).
use crate::abi::{Param, Ty};
use crate::approval::UNLIMITED_MIN;
use crate::{checksum_address, hex, parse_address, u256, unhex};
use serde_json::{json, Map, Value};

const UINT256_MAX: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
const DETAILS: &[(&str, &str)] = &[("token", "address"), ("amount", "uint160"), ("expiration", "uint48"), ("nonce", "uint48")];
const TOKPERM: &[(&str, &str)] = &[("token", "address"), ("amount", "uint256")];
const LIKE: &[&str] = &["spender", "operator", "delegate", "approved", "allowed"];

/// The permit assertions (wasm options / CLI flags), normalized: spender lowercase 0x hex, amount decimal.
#[derive(Default, Debug, Clone, PartialEq)]
pub struct PermitExpect { pub spender: Option<String>, pub amount: Option<String>, pub unlimited: bool }

impl PermitExpect {
    pub fn asserted(&self) -> bool { self.spender.is_some() || self.amount.is_some() || self.unlimited }
    /// From raw values. Errors: expect_spender_bad_address, expect_amount_not_decimal,
    /// expect_unlimited_needs_expect_spender, expect_unlimited_conflicts_with_expect_amount.
    pub fn new(spender: Option<&str>, amount: Option<&str>, unlimited: bool) -> Result<Self, String> {
        if unlimited && spender.is_none() { return Err("expect_unlimited_needs_expect_spender".into()) }
        if unlimited && amount.is_some() { return Err("expect_unlimited_conflicts_with_expect_amount".into()) }
        let spender = spender.map(|s| parse_address(s).map(|a| hex(&a)).map_err(|_| "expect_spender_bad_address".to_string())).transpose()?;
        let amount = amount.map(|s| dec_norm(s).ok_or_else(|| "expect_amount_not_decimal".to_string())).transpose()?;
        Ok(PermitExpect { spender, amount, unlimited })
    }
    /// From the wasm options object: expect_spender / expect_amount strings, expect_unlimited bool. A wrong JSON
    /// type is `<key>_must_be_string` / `expect_unlimited_must_be_bool` (the verifyTx convention).
    pub fn from_json(opt: &Value) -> Result<Self, String> {
        let st = |k: &str| match opt.get(k) { None => Ok(None), Some(Value::String(s)) => Ok(Some(s.clone())), _ => Err(format!("{k}_must_be_string")) };
        let (s, a) = (st("expect_spender")?, st("expect_amount")?);
        let u = match opt.get("expect_unlimited") { None | Some(Value::Bool(false)) => false, Some(Value::Bool(true)) => true, _ => return Err("expect_unlimited_must_be_bool".into()) };
        Self::new(s.as_deref(), a.as_deref(), u)
    }
}

fn dec_norm(s: &str) -> Option<String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) { return None }
    let t = s.trim_start_matches('0');
    Some(if t.is_empty() { "0".into() } else { t.into() })
}
fn dec_ge(a: &str, b: &str) -> bool { a.len() > b.len() || (a.len() == b.len() && a >= b) }

fn field_set<'a>(types: &'a Map<String, Value>, t: &str) -> Option<Vec<(&'a str, &'a str)>> {
    let mut v: Vec<(&str, &str)> = types.get(t)?.as_array()?.iter().map(|f| Some((f.get("name")?.as_str()?, f.get("type")?.as_str()?))).collect::<Option<_>>()?;
    v.sort(); Some(v)
}
fn is_shape(types: &Map<String, Value>, t: &str, want: &[(&str, &str)]) -> bool {
    let mut w = want.to_vec(); w.sort();
    field_set(types, t).is_some_and(|f| f == w)
}
/// An EIP-712 uint value (number, decimal or 0x string) as a decimal string, range-checked against `ty`.
fn uint(v: &Value, ty: &str) -> Option<String> {
    let e = crate::abi::encode(&[Param::new(Ty::parse(ty).ok()?)], std::slice::from_ref(v)).ok()?;
    let mut w = [0u8; 32]; w.copy_from_slice(&e[..32]); Some(u256::to_dec(&w))
}
fn addr(v: &Value) -> Option<[u8; 20]> {
    let b = unhex(v.as_str()?.trim()).ok()?;
    if b.len() != 20 { return None }
    let mut a = [0u8; 20]; a.copy_from_slice(&b); Some(a)
}
fn entry(token: Option<Value>, amount: String, extra: Option<(&str, Value)>) -> Value {
    let unlimited = dec_ge(&amount, UNLIMITED_MIN);
    let mut e = json!({"token": token.unwrap_or(Value::Null), "amount": amount, "unlimited": unlimited});
    if let Some((k, v)) = extra { e[k] = v }
    e
}

/// The recognised permit in `td`, as {kind, primary_type, spender, entries:[{token, amount, unlimited, ..}],
/// deadline, owner?}; None when the typed data is not one of the shapes above (or a value does not parse).
pub fn summarize(td: &Value) -> Option<Value> {
    let types = td.get("types")?.as_object()?;
    let p = td.get("primaryType")?.as_str()?;
    let m = td.get("message")?.as_object()?;
    let vc = td.get("domain").and_then(|d| d.get("verifyingContract")).and_then(addr).map(|a| json!(checksum_address(&a)));
    let s = |k: &str| m.get(k).and_then(addr).map(|a| checksum_address(&a));
    let (kind, entries, deadline, owner) = match p {
        "Permit" if is_shape(types, p, &[("owner", "address"), ("spender", "address"), ("value", "uint256"), ("nonce", "uint256"), ("deadline", "uint256")]) =>
            ("eip2612", vec![entry(vc, uint(m.get("value")?, "uint256")?, None)], uint(m.get("deadline")?, "uint256")?, Some(s("owner")?)),
        "Permit" if is_shape(types, p, &[("holder", "address"), ("spender", "address"), ("nonce", "uint256"), ("expiry", "uint256"), ("allowed", "bool")]) => {
            let allowed = m.get("allowed")?.as_bool()?;
            ("dai", vec![entry(vc, (if allowed { UINT256_MAX } else { "0" }).into(), Some(("allowed", json!(allowed))))], uint(m.get("expiry")?, "uint256")?, Some(s("holder")?))
        }
        "PermitSingle" | "PermitBatch" => {
            let arr = p == "PermitBatch";
            let dt = if arr { "PermitDetails[]" } else { "PermitDetails" };
            if !is_shape(types, p, &[("details", dt), ("spender", "address"), ("sigDeadline", "uint256")]) || !is_shape(types, "PermitDetails", DETAILS) { return None }
            let one = |d: &Value| -> Option<Value> { Some(entry(Some(json!(checksum_address(&addr(d.get("token")?)?))), uint(d.get("amount")?, "uint160")?, Some(("expiration", json!(uint(d.get("expiration")?, "uint48")?))))) };
            let es: Vec<Value> = if arr { m.get("details")?.as_array()?.iter().map(one).collect::<Option<_>>()? } else { vec![one(m.get("details")?)?] };
            (if arr { "permit2_batch" } else { "permit2_single" }, es, uint(m.get("sigDeadline")?, "uint256")?, None)
        }
        "PermitTransferFrom" | "PermitBatchTransferFrom" => {
            let arr = p == "PermitBatchTransferFrom";
            let pt = if arr { "TokenPermissions[]" } else { "TokenPermissions" };
            if !is_shape(types, p, &[("permitted", pt), ("spender", "address"), ("nonce", "uint256"), ("deadline", "uint256")]) || !is_shape(types, "TokenPermissions", TOKPERM) { return None }
            let one = |d: &Value| -> Option<Value> { Some(entry(Some(json!(checksum_address(&addr(d.get("token")?)?))), uint(d.get("amount")?, "uint256")?, None)) };
            let es: Vec<Value> = if arr { m.get("permitted")?.as_array()?.iter().map(one).collect::<Option<_>>()? } else { vec![one(m.get("permitted")?)?] };
            (if arr { "permit2_batch_transfer" } else { "permit2_transfer" }, es, uint(m.get("deadline")?, "uint256")?, None)
        }
        _ => return None,
    };
    if entries.is_empty() { return None }
    let mut o = json!({"kind": kind, "primary_type": p, "spender": s("spender")?, "entries": entries, "deadline": deadline});
    if let Some(w) = owner { o["owner"] = json!(w) }
    Some(o)
}

/// Spender-like address fields of an unrecognised shape, as "Type.field" (every struct reachable from primaryType).
pub fn spender_like_fields(td: &Value) -> Vec<String> {
    let (Some(types), Some(p)) = (td.get("types").and_then(Value::as_object), td.get("primaryType").and_then(Value::as_str)) else { return vec![] };
    let (mut seen, mut todo, mut out) = (vec![p.to_string()], vec![p.to_string()], vec![]);
    while let Some(t) = todo.pop() {
        for (n, ty) in field_set(types, &t).unwrap_or_default() {
            let b = ty.split('[').next().unwrap_or(ty);
            if b == "address" && LIKE.iter().any(|l| n.to_ascii_lowercase().contains(l)) { out.push(format!("{t}.{n}")) }
            if types.contains_key(b) && !seen.iter().any(|s| s == b) && seen.len() < 64 { seen.push(b.to_string()); todo.push(b.to_string()) }
        }
    }
    out.sort(); out
}

/// Statuses that an earlier check already set and that a permit finding does not overwrite.
const KEEP: &[&str] = &["signer_mismatch", "chain_id_mismatch", "verifying_contract_mismatch"];

/// Adds the permit fields to a [`crate::eip712::verify`] result `o` (after `apply_expect`):
///   permit                       the summary from [`summarize`] (absent when not a recognised permit)
///   unlimited_approval           true when any entry is unlimited and expect_unlimited was not given
///   spender_unasserted           true when a recognised permit has a spender and no expect_spender was given
///   unrecognised_spender_fields  ["Type.field", ..] for an unrecognised shape (absent when empty)
///   permit_findings              the findings above (absent when empty)
/// Status: changed only when an assertion (expect_spender / expect_amount / expect_unlimited) was given and a
/// finding exists, to the first finding; signer_mismatch / chain_id_mismatch / verifying_contract_mismatch win.
/// Without assertions the call stays backward compatible: the new fields are advisory.
pub fn apply(o: &mut Value, td: &Value, e: &PermitExpect) {
    let mut f: Vec<String> = vec![];
    match summarize(td) {
        Some(p) => {
            let es = p["entries"].as_array().cloned().unwrap_or_default();
            if let Some(w) = &e.spender { if hex(&addr(&p["spender"]).unwrap_or([0; 20])) != *w { f.push("spender_not_expected".into()) } }
            if let Some(w) = &e.amount { if es.iter().any(|x| x["amount"].as_str() != Some(w.as_str())) { f.push("amount_not_expected".into()) } }
            let unl = es.iter().any(|x| x["unlimited"] == true);
            if unl && !e.unlimited { f.push("unlimited_approval".into()) }
            o["unlimited_approval"] = json!(unl && !e.unlimited);
            o["spender_unasserted"] = json!(e.spender.is_none());
            o["permit"] = p;
        }
        None => {
            if e.spender.is_some() { f.push("spender_not_checkable".into()) }
            if e.amount.is_some() { f.push("amount_not_checkable".into()) }
            let u = spender_like_fields(td);
            if !u.is_empty() { o["unrecognised_spender_fields"] = json!(u) }
        }
    }
    if !f.is_empty() {
        if e.asserted() && !KEEP.contains(&o["status"].as_str().unwrap_or("")) { o["status"] = json!(f[0]) }
        o["permit_findings"] = json!(f);
    }
}

/// Exit-1 statuses of a typed-data verify result.
pub const FAIL_STATUSES: &[&str] = &["signer_mismatch", "chain_id_mismatch", "verifying_contract_mismatch", "spender_not_expected", "amount_not_expected", "unlimited_approval", "spender_not_checkable", "amount_not_checkable"];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eip712;
    const LEGIT: &str = "0x000000000022d473030f116ddee9f6b43ac78ba3";
    const DRAINER: &str = "0x1111111111111111111111111111111111111111";
    const TOKEN: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    fn dom() -> Value { json!([{"name":"name","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}]) }
    fn eip2612(spender: &str, value: &str) -> Value {
        json!({"types":{"EIP712Domain":dom(),"Permit":[{"name":"owner","type":"address"},{"name":"spender","type":"address"},{"name":"value","type":"uint256"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}]},
            "primaryType":"Permit","domain":{"name":"USD Coin","chainId":1,"verifyingContract":TOKEN},
            "message":{"owner":"0x2222222222222222222222222222222222222222","spender":spender,"value":value,"nonce":0,"deadline":"1893456000"}})
    }
    fn dai(allowed: bool) -> Value {
        json!({"types":{"EIP712Domain":dom(),"Permit":[{"name":"holder","type":"address"},{"name":"spender","type":"address"},{"name":"nonce","type":"uint256"},{"name":"expiry","type":"uint256"},{"name":"allowed","type":"bool"}]},
            "primaryType":"Permit","domain":{"name":"Dai Stablecoin","chainId":1,"verifyingContract":"0x6b175474e89094c44da98b954eedeac495271d0f"},
            "message":{"holder":"0x2222222222222222222222222222222222222222","spender":LEGIT,"nonce":3,"expiry":1893456000,"allowed":allowed}})
    }
    fn p2types(batch: bool) -> Value {
        let (p, d) = if batch { ("PermitBatch", "PermitDetails[]") } else { ("PermitSingle", "PermitDetails") };
        json!({"EIP712Domain":[{"name":"name","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],
            p:[{"name":"details","type":d},{"name":"spender","type":"address"},{"name":"sigDeadline","type":"uint256"}],
            "PermitDetails":[{"name":"token","type":"address"},{"name":"amount","type":"uint160"},{"name":"expiration","type":"uint48"},{"name":"nonce","type":"uint48"}]})
    }
    fn p2(batch: bool, amounts: &[&str], spender: &str) -> Value {
        let det: Vec<Value> = amounts.iter().map(|a| json!({"token":TOKEN,"amount":a,"expiration":1893456000u64,"nonce":0})).collect();
        json!({"types":p2types(batch),"primaryType":if batch {"PermitBatch"} else {"PermitSingle"},"domain":{"name":"Permit2","chainId":1,"verifyingContract":LEGIT},
            "message":{"details": if batch { json!(det) } else { det[0].clone() },"spender":spender,"sigDeadline":"1893456000"}})
    }
    fn xfer(batch: bool, amounts: &[&str], spender: &str) -> Value {
        let (p, t) = if batch { ("PermitBatchTransferFrom", "TokenPermissions[]") } else { ("PermitTransferFrom", "TokenPermissions") };
        let per: Vec<Value> = amounts.iter().map(|a| json!({"token":TOKEN,"amount":a})).collect();
        json!({"types":{"EIP712Domain":dom(),p:[{"name":"permitted","type":t},{"name":"spender","type":"address"},{"name":"nonce","type":"uint256"},{"name":"deadline","type":"uint256"}],
            "TokenPermissions":[{"name":"token","type":"address"},{"name":"amount","type":"uint256"}]},"primaryType":p,"domain":{"name":"Permit2","chainId":1,"verifyingContract":LEGIT},
            "message":{"permitted": if batch { json!(per) } else { per[0].clone() },"spender":spender,"nonce":7,"deadline":1893456000}})
    }
    fn run(td: &Value, e: PermitExpect) -> Value { let mut o = eip712::verify(td, None, None).unwrap(); apply(&mut o, td, &e); o }
    fn ex(s: Option<&str>, a: Option<&str>, u: bool) -> PermitExpect { PermitExpect::new(s, a, u).unwrap() }

    #[test]
    fn exact_balance_drainer_permit_refused_by_spender() {
        // the headline regression: amount far below 2^128 (exactly the victim's balance), drainer spender
        let td = eip2612(DRAINER, "1234567890");
        let o = run(&td, PermitExpect::default());
        assert_eq!(o["status"], "ok"); // backward compatible without assertions
        assert_eq!(o["unlimited_approval"], false); assert_eq!(o["spender_unasserted"], true);
        assert_eq!(o["permit"]["kind"], "eip2612"); assert_eq!(o["permit"]["entries"][0]["amount"], "1234567890");
        let o = run(&td, ex(Some(LEGIT), None, false));
        assert_eq!(o["status"], "spender_not_expected"); assert_eq!(o["spender_unasserted"], false);
        let o = run(&td, ex(Some(&DRAINER.to_uppercase().replace("0X", "0x")), Some("1234567890"), false));
        assert_eq!(o["status"], "ok", "{o}"); assert!(o.get("permit_findings").is_none());
        assert_eq!(run(&td, ex(Some(DRAINER), Some("1234567889"), false))["status"], "amount_not_expected");
    }
    #[test]
    fn signed_drainer_permit_valid_signature_still_fails() {
        use secp256k1::{Message, Secp256k1, SecretKey};
        let td = eip2612(DRAINER, "1234567890");
        let (_, _, d) = eip712::digest(&td).unwrap();
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let (rid, rs) = Secp256k1::new().sign_ecdsa_recoverable(&Message::from_digest(d), &sk).serialize_compact();
        let mut sig = rs.to_vec(); sig.push(27 + rid.to_i32() as u8);
        let rec = eip712::verify(&td, Some(&hex(&sig)), None).unwrap()["recovered"].as_str().unwrap().to_string();
        let mut o = eip712::verify(&td, Some(&hex(&sig)), Some(&rec)).unwrap();
        assert_eq!(o["status"], "valid");
        apply(&mut o, &td, &ex(Some(LEGIT), None, false));
        assert_eq!(o["status"], "spender_not_expected");
        let mut o = eip712::verify(&td, Some(&hex(&sig)), Some(DRAINER)).unwrap();
        apply(&mut o, &td, &ex(Some(LEGIT), None, false));
        assert_eq!(o["status"], "signer_mismatch"); assert_eq!(o["permit_findings"], json!(["spender_not_expected"]));
    }
    #[test]
    fn unlimited_threshold_and_opt_in() {
        let o = run(&eip2612(LEGIT, UNLIMITED_MIN), PermitExpect::default());
        assert_eq!(o["status"], "ok"); assert_eq!(o["unlimited_approval"], true); assert_eq!(o["permit_findings"], json!(["unlimited_approval"]));
        assert_eq!(run(&eip2612(LEGIT, UNLIMITED_MIN), ex(Some(LEGIT), None, false))["status"], "unlimited_approval");
        let o = run(&eip2612(LEGIT, UNLIMITED_MIN), ex(Some(LEGIT), None, true));
        assert_eq!(o["status"], "ok"); assert_eq!(o["unlimited_approval"], false);
        assert_eq!(run(&eip2612(LEGIT, "340282366920938463463374607431768211455"), PermitExpect::default())["unlimited_approval"], false);
        assert_eq!(PermitExpect::new(None, None, true).unwrap_err(), "expect_unlimited_needs_expect_spender");
        assert_eq!(PermitExpect::new(Some(LEGIT), Some("1"), true).unwrap_err(), "expect_unlimited_conflicts_with_expect_amount");
    }
    #[test]
    fn dai_style() {
        let o = run(&dai(true), PermitExpect::default());
        assert_eq!(o["permit"]["kind"], "dai"); assert_eq!(o["unlimited_approval"], true); assert_eq!(o["permit"]["entries"][0]["allowed"], true);
        assert_eq!(o["permit"]["deadline"], "1893456000");
        assert_eq!(run(&dai(true), ex(Some(DRAINER), None, true))["status"], "spender_not_expected");
        assert_eq!(run(&dai(true), ex(Some(LEGIT), None, true))["status"], "ok");
        let o = run(&dai(false), ex(Some(LEGIT), Some("0"), false));
        assert_eq!(o["status"], "ok"); assert_eq!(o["unlimited_approval"], false);
    }
    #[test]
    fn permit2_single_and_batch() {
        let max160 = "1461501637330902918203684832716283019655932542975";
        let o = run(&p2(false, &[max160], LEGIT), PermitExpect::default());
        assert_eq!(o["permit"]["kind"], "permit2_single"); assert_eq!(o["unlimited_approval"], true);
        assert_eq!(run(&p2(false, &["500"], DRAINER), ex(Some(LEGIT), Some("500"), false))["status"], "spender_not_expected");
        assert_eq!(run(&p2(false, &["500"], LEGIT), ex(Some(LEGIT), Some("500"), false))["status"], "ok");
        let b = p2(true, &["500", "501"], LEGIT);
        assert_eq!(run(&b, PermitExpect::default())["permit"]["entries"].as_array().unwrap().len(), 2);
        assert_eq!(run(&b, ex(Some(LEGIT), Some("500"), false))["status"], "amount_not_expected"); // every entry must match
        assert_eq!(run(&p2(true, &["500", "500"], LEGIT), ex(Some(LEGIT), Some("500"), false))["status"], "ok");
        assert_eq!(run(&p2(true, &["500", max160], LEGIT), ex(Some(LEGIT), None, false))["status"], "unlimited_approval");
    }
    #[test]
    fn permit2_transfer_from() {
        let o = run(&xfer(false, &["42"], DRAINER), ex(Some(LEGIT), None, false));
        assert_eq!(o["permit"]["kind"], "permit2_transfer"); assert_eq!(o["status"], "spender_not_expected");
        let o = run(&xfer(true, &["42", "0x2a"], LEGIT), ex(Some(LEGIT), Some("42"), false));
        assert_eq!(o["permit"]["kind"], "permit2_batch_transfer"); assert_eq!(o["status"], "ok", "{o}");
    }
    #[test]
    fn unknown_shape_not_guessed() {
        // extra field: not the EIP-2612 shape, so not recognised; spender reported, assertions fail closed
        let mut td = eip2612(DRAINER, "5");
        td["types"]["Permit"].as_array_mut().unwrap().push(json!({"name":"extra","type":"uint256"})); td["message"]["extra"] = json!(1);
        let o = run(&td, PermitExpect::default());
        assert_eq!(o["status"], "ok"); assert!(o.get("permit").is_none());
        assert_eq!(o["unrecognised_spender_fields"], json!(["Permit.spender"]));
        let o = run(&td, ex(Some(LEGIT), Some("5"), false));
        assert_eq!(o["status"], "spender_not_checkable"); assert_eq!(o["permit_findings"], json!(["spender_not_checkable", "amount_not_checkable"]));
        let mail = json!({"types":{"EIP712Domain":[{"name":"name","type":"string"}],"Mail":[{"name":"to","type":"address"}]},"primaryType":"Mail","domain":{"name":"x"},"message":{"to":DRAINER}});
        let o = run(&mail, PermitExpect::default());
        assert!(o.get("unrecognised_spender_fields").is_none() && o.get("spender_unasserted").is_none());
    }
    #[test]
    fn from_json_types() {
        for (k, v, err) in [("expect_spender", json!(1), "expect_spender_must_be_string"), ("expect_amount", json!(5), "expect_amount_must_be_string"),
            ("expect_unlimited", json!("yes"), "expect_unlimited_must_be_bool"), ("expect_spender", json!("0x12"), "expect_spender_bad_address"), ("expect_amount", json!("1e3"), "expect_amount_not_decimal")] {
            assert_eq!(PermitExpect::from_json(&json!({k: v})).unwrap_err(), err);
        }
        assert!(!PermitExpect::from_json(&json!({"expect_chain_id": "1"})).unwrap().asserted());
    }
}
