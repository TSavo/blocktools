//! Pre-sign content checks for an EVM call: what an approval grants (spender, amount), where a token
//! transfer sends (recipient, amount), and which inner calls a batch (multicall, Multicall3, Universal
//! Router execute, Safe execTransaction / multiSend) hides. Pure: calldata in, report + findings out.
//!
//! Deny by default. Findings (short fixed strings) are added to tx-verify's failures:
//!   unlimited_approval       an approval at or above UNLIMITED_MIN (2^128), or setApprovalForAll(true) /
//!                            DAI-style permit(allowed=true), without --expect-unlimited (which needs --expect-spender)
//!   spender_not_expected     a decoded spender differs from --expect-spender (every approval must match)
//!   amount_not_expected      a decoded approval or token-transfer amount differs from --expect-amount
//!   recipient_not_expected   a decoded transfer/transferFrom recipient differs from --expect-recipient
//!   value_not_expected       the native value (wei) differs from --expect-value
//!   spender_not_checkable / amount_not_checkable / recipient_not_checkable
//!                            the caller asserted a value but the call has nothing of that kind to compare
//!   inner_calls_not_asserted a batch's inner call is not named by an --allow-inner-call TO:SELECTOR
//!   delegatecall             a Safe call with operation=1 whose target is not named by --allow-delegatecall TO
//!   bad_inner_calldata       a batch whose inner-call encoding does not decode strictly
//! A token amount is compared as an exact decimal integer; addresses case-insensitively.
use crate::abi;
use crate::sig::Sig;
use crate::{hex, parse_address};
use serde_json::{json, Value};

/// Amounts at or above 2^128 count as unlimited (covers uint256 max, Permit2's uint160 max and any
/// "practically infinite" allowance). setApprovalForAll(true) and DAI permit(allowed=true) always do.
pub const UNLIMITED_MIN: &str = "340282366920938463463374607431768211456";

/// (signature, spender arg path, amount: Some(path) | None = bool "all" flag at path in `all`, token path)
struct Kind { sig: &'static str, spender: &'static [usize], amount: Option<&'static [usize]>, all: Option<&'static [usize]>, token: Option<&'static [usize]> }
const APPROVALS: &[Kind] = &[
    Kind { sig: "approve(address,uint256)", spender: &[0], amount: Some(&[1]), all: None, token: None },
    Kind { sig: "increaseAllowance(address,uint256)", spender: &[0], amount: Some(&[1]), all: None, token: None },
    // EIP-2612 permit(owner, spender, value, deadline, v, r, s), calldata form
    Kind { sig: "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", spender: &[1], amount: Some(&[2]), all: None, token: None },
    // DAI-style permit(holder, spender, nonce, expiry, allowed, v, r, s)
    Kind { sig: "permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)", spender: &[1], amount: None, all: Some(&[4]), token: None },
    // ERC-721 / ERC-1155 operator approval
    Kind { sig: "setApprovalForAll(address,bool)", spender: &[0], amount: None, all: Some(&[1]), token: None },
    // Permit2 approve(token, spender, amount, expiration)
    Kind { sig: "approve(address,address,uint160,uint48)", spender: &[1], amount: Some(&[2]), all: None, token: Some(&[0]) },
    // Permit2 permit(owner, PermitSingle{details{token, amount, expiration, nonce}, spender, sigDeadline}, signature)
    Kind { sig: "permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)", spender: &[1, 1], amount: Some(&[1, 0, 1]), all: None, token: Some(&[1, 0, 0]) },
];
const TRANSFERS: &[(&str, usize, usize)] = &[("transfer(address,uint256)", 0, 1), ("transferFrom(address,address,uint256)", 1, 2)];

/// What the caller asserts. Empty = nothing asserted (findings for unlimited approvals, batches and
/// delegatecall still apply).
#[derive(Default, Debug, Clone)]
pub struct Expect {
    pub spender: Option<String>,
    pub amount: Option<String>,
    pub unlimited: bool,
    pub recipient: Option<String>,
    pub value: Option<String>,
    /// (to lowercase hex, selector lowercase hex: 4 bytes, or 1 byte for a Universal Router command)
    pub inner: Vec<(String, String)>,
    pub delegatecall: Vec<String>,
}

impl Expect {
    /// Validate and normalize assertion values. Errors are bad-input codes.
    pub fn normalized(mut self) -> Result<Self, String> {
        if self.unlimited && self.spender.is_none() { return Err("expect_unlimited_needs_expect_spender".into()) }
        if self.unlimited && self.amount.is_some() { return Err("expect_unlimited_conflicts_with_expect_amount".into()) }
        let addr = |s: &str| parse_address(s).map(|a| hex(&a));
        if let Some(s) = &self.spender { self.spender = Some(addr(s).map_err(|e| format!("--expect-spender: {e}"))?) }
        if let Some(s) = &self.recipient { self.recipient = Some(addr(s).map_err(|e| format!("--expect-recipient: {e}"))?) }
        for d in self.delegatecall.iter_mut() { *d = addr(d).map_err(|e| format!("--allow-delegatecall: {e}"))? }
        if let Some(s) = &self.amount { self.amount = Some(dec_norm(s).ok_or("--expect-amount: decimal integer")?) }
        if let Some(s) = &self.value { self.value = Some(dec_norm(s).ok_or("--expect-value: decimal integer (wei)")?) }
        for (t, s) in self.inner.iter_mut() {
            *t = addr(t).map_err(|e| format!("--allow-inner-call: {e}"))?;
            let b = crate::unhex(s).map_err(|_| "--allow-inner-call: TO:SELECTOR (0x + 4-byte selector or 1-byte router command)")?;
            if b.len() != 4 && b.len() != 1 { return Err("--allow-inner-call: TO:SELECTOR (0x + 4-byte selector or 1-byte router command)".into()) }
            *s = hex(&b);
        }
        Ok(self)
    }
    /// Parse `TO:SELECTOR`.
    pub fn inner_arg(s: &str) -> Result<(String, String), String> {
        let (t, sel) = s.split_once(':').ok_or("--allow-inner-call: TO:SELECTOR")?;
        Ok((t.to_string(), sel.to_string()))
    }
}

fn dec_norm(s: &str) -> Option<String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) { return None }
    let t = s.trim_start_matches('0');
    Some(if t.is_empty() { "0".into() } else { t.into() })
}
/// a >= b for normalized decimal strings.
fn dec_ge(a: &str, b: &str) -> bool { a.len() > b.len() || (a.len() == b.len() && a >= b) }
fn at<'a>(v: &'a Value, path: &[usize]) -> Option<&'a Value> { path.iter().try_fold(v, |v, &i| v.get(i)) }
fn lc(s: &str) -> String { s.to_ascii_lowercase() }

/// Strictly decode `data` against one signature (must re-encode byte-for-byte).
fn strict(sig: &str, data: &[u8]) -> Option<Value> {
    let s = Sig::parse(sig).ok()?;
    if data.len() < 4 || s.selector()[..] != data[..4] { return None }
    let v = abi::decode(&s.inputs, &data[4..]).ok()?;
    (abi::encode(&s.inputs, &v).ok().as_deref() == Some(&data[4..])).then_some(Value::Array(v))
}
fn sel_is(sig: &str, data: &[u8]) -> bool { data.len() >= 4 && Sig::parse(sig).map(|s| s.selector()[..] == data[..4]).unwrap_or(false) }

#[derive(Default)]
struct Acc { approvals: Vec<Value>, transfers: Vec<Value>, inner: Vec<Value>, bad_inner: bool, delegate: Vec<(String, String)> }

const MAX_DEPTH: usize = 4;

/// Classify one call (to, data) at `path` ("" for the top level), recursing into batches.
fn walk(to: &str, data: &[u8], path: &str, depth: usize, acc: &mut Acc) {
    if data.len() < 4 { return }
    for k in APPROVALS {
        let Some(v) = strict(k.sig, data) else { continue };
        let spender = at(&v, k.spender).and_then(Value::as_str).unwrap_or("").to_string();
        let (amount, unlimited) = match (k.amount, k.all) {
            (Some(p), _) => { let a = at(&v, p).and_then(Value::as_str).unwrap_or("0").to_string(); let u = dec_ge(&a, UNLIMITED_MIN); (json!(a), u) }
            (None, Some(p)) => { let all = at(&v, p).and_then(Value::as_bool).unwrap_or(false); (json!(if all { "all" } else { "none" }), all) }
            _ => (Value::Null, false),
        };
        let token = k.token.and_then(|p| at(&v, p)).and_then(Value::as_str).map(str::to_string).unwrap_or(to.to_string());
        acc.approvals.push(json!({"path": path, "signature": k.sig, "token": token, "spender": spender, "amount": amount, "unlimited": unlimited}));
        return;
    }
    for (sig, r, a) in TRANSFERS {
        let Some(v) = strict(sig, data) else { continue };
        acc.transfers.push(json!({"path": path, "signature": sig, "token": to, "recipient": v[*r], "amount": v[*a]}));
        return;
    }
    if depth >= MAX_DEPTH { if is_batch(data) { acc.bad_inner = true } return }
    let push = |acc: &mut Acc, via: &str, i: usize, to: &str, value: &str, op: u8, d: &[u8]| {
        let p = format!("{path}{}{via}[{i}]", if path.is_empty() { "" } else { "." });
        let sel = if d.len() >= 4 { hex(&d[..4]) } else { "0x".into() };
        acc.inner.push(json!({"path": p, "via": via, "to": to, "value": value, "operation": if op == 1 { "delegatecall" } else { "call" }, "selector": sel, "data_len": d.len()}));
        if op == 1 { acc.delegate.push((p.clone(), to.to_string())) }
        walk(to, d, &p, depth + 1, acc);
    };
    let bytes_of = |x: &Value| x.as_str().and_then(|s| crate::unhex(s).ok());
    // multicall(bytes[]) / multicall(uint256 deadline, bytes[]) / multicall(bytes32 prevBlockHash, bytes[]): self-calls on `to`
    for (sig, idx) in [("multicall(bytes[])", 0), ("multicall(uint256,bytes[])", 1), ("multicall(bytes32,bytes[])", 1)] {
        if !sel_is(sig, data) { continue }
        let Some(v) = strict(sig, data) else { acc.bad_inner = true; return };
        for (i, c) in v[idx].as_array().into_iter().flatten().enumerate() {
            match bytes_of(c) { Some(d) => push(acc, "multicall", i, to, "0", 0, &d), None => acc.bad_inner = true }
        }
        return;
    }
    // Multicall3: aggregate((address,bytes)[]), tryAggregate(bool,(address,bytes)[]), aggregate3((address,bool,bytes)[]), aggregate3Value((address,bool,uint256,bytes)[])
    for (sig, idx, ti, vi, di) in [("aggregate((address,bytes)[])", 0, 0, None, 1), ("tryAggregate(bool,(address,bytes)[])", 1, 0, None, 1),
                                   ("aggregate3((address,bool,bytes)[])", 0, 0, None, 2), ("aggregate3Value((address,bool,uint256,bytes)[])", 0, 0, Some(2), 3)] {
        if !sel_is(sig, data) { continue }
        let Some(v) = strict(sig, data) else { acc.bad_inner = true; return };
        for (i, c) in v[idx].as_array().into_iter().flatten().enumerate() {
            let t = c[ti].as_str().unwrap_or("").to_string();
            let val = vi.and_then(|j: usize| c[j].as_str()).unwrap_or("0").to_string();
            match bytes_of(&c[di]) { Some(d) => push(acc, "aggregate", i, &t, &val, 0, &d), None => acc.bad_inner = true }
        }
        return;
    }
    // Universal Router execute(bytes commands, bytes[] inputs[, uint256 deadline]): one command byte per input.
    for sig in ["execute(bytes,bytes[],uint256)", "execute(bytes,bytes[])"] {
        if !sel_is(sig, data) { continue }
        let Some(v) = strict(sig, data) else { acc.bad_inner = true; return };
        let cmds = bytes_of(&v[0]).unwrap_or_default();
        let ins = v[1].as_array().cloned().unwrap_or_default();
        if cmds.len() != ins.len() { acc.bad_inner = true }
        for (i, c) in cmds.iter().enumerate() {
            let p = format!("{path}{}execute[{i}]", if path.is_empty() { "" } else { "." });
            let n = ins.get(i).and_then(bytes_of).map(|d| d.len()).unwrap_or(0);
            acc.inner.push(json!({"path": p, "via": "universal_router", "to": to, "value": "0", "operation": "call", "selector": hex(&[*c]), "data_len": n}));
        }
        return;
    }
    // Safe execTransaction(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures)
    let es = "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)";
    if sel_is(es, data) {
        let Some(v) = strict(es, data) else { acc.bad_inner = true; return };
        let op = v[3].as_str().and_then(|s| s.parse::<u8>().ok()).unwrap_or(255);
        if op > 1 { acc.bad_inner = true; return }
        let d = bytes_of(&v[2]).unwrap_or_default();
        push(acc, "safe", 0, v[0].as_str().unwrap_or(""), v[1].as_str().unwrap_or("0"), op, &d);
        return;
    }
    // Safe multiSend(bytes transactions): packed operation(1) to(20) value(32) len(32) data(len)
    if sel_is("multiSend(bytes)", data) {
        let Some(v) = strict("multiSend(bytes)", data) else { acc.bad_inner = true; return };
        let b = bytes_of(&v[0]).unwrap_or_default();
        let (mut o, mut i) = (0usize, 0usize);
        while o < b.len() {
            if o + 85 > b.len() { acc.bad_inner = true; return }
            let op = b[o]; let t = crate::checksum_address(b[o + 1..o + 21].try_into().unwrap());
            let val = crate::u256::to_dec(b[o + 21..o + 53].try_into().unwrap());
            let lw = &b[o + 53..o + 85];
            if lw[..24].iter().any(|&x| x != 0) || op > 1 { acc.bad_inner = true; return }
            let n = u64::from_be_bytes(lw[24..].try_into().unwrap()) as usize;
            let Some(d) = b.get(o + 85..(o + 85).saturating_add(n)) else { acc.bad_inner = true; return };
            push(acc, "multisend", i, &t, &val, op, d);
            o += 85 + n; i += 1;
        }
    }
}

fn is_batch(data: &[u8]) -> bool {
    ["multicall(bytes[])", "multicall(uint256,bytes[])", "multicall(bytes32,bytes[])", "aggregate((address,bytes)[])", "tryAggregate(bool,(address,bytes)[])",
     "aggregate3((address,bool,bytes)[])", "aggregate3Value((address,bool,uint256,bytes)[])", "execute(bytes,bytes[],uint256)", "execute(bytes,bytes[])",
     "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)", "multiSend(bytes)"].iter().any(|s| sel_is(s, data))
}

/// Check one EVM call. `to` None = contract creation (nothing to check here). Returns the report
/// object (keys `approvals`, `transfers`, `inner_calls` only when non-empty) and the findings.
pub fn check(to: Option<&[u8; 20]>, value_wei: &str, data: &[u8], e: &Expect) -> (Value, Vec<String>) {
    let mut f: Vec<String> = Vec::new();
    let mut acc = Acc::default();
    if let Some(t) = to { walk(&crate::checksum_address(t), data, "", 0, &mut acc) }
    let mut o = json!({});
    if let Some(v) = &e.value { if dec_norm(value_wei).as_deref() != Some(v) { f.push("value_not_expected".into()) } }
    for a in &acc.approvals {
        if a["unlimited"] == true && !e.unlimited { f.push("unlimited_approval".into()) }
        if let Some(s) = &e.spender { if lc(a["spender"].as_str().unwrap_or("")) != *s { f.push("spender_not_expected".into()) } }
        if let Some(x) = &e.amount { if a["amount"].as_str().and_then(dec_norm).as_ref() != Some(x) { f.push("amount_not_expected".into()) } }
    }
    for t in &acc.transfers {
        if let Some(r) = &e.recipient { if lc(t["recipient"].as_str().unwrap_or("")) != *r { f.push("recipient_not_expected".into()) } }
        if let Some(x) = &e.amount { if t["amount"].as_str().and_then(dec_norm).as_ref() != Some(x) { f.push("amount_not_expected".into()) } }
    }
    if e.spender.is_some() && acc.approvals.is_empty() { f.push("spender_not_checkable".into()) }
    if e.recipient.is_some() && acc.transfers.is_empty() { f.push("recipient_not_checkable".into()) }
    if e.amount.is_some() && acc.approvals.is_empty() && acc.transfers.is_empty() { f.push("amount_not_checkable".into()) }
    for c in &acc.inner {
        let k = (lc(c["to"].as_str().unwrap_or("")), c["selector"].as_str().unwrap_or("").to_string());
        if !e.inner.contains(&k) { f.push("inner_calls_not_asserted".into()); break }
    }
    for (_, t) in &acc.delegate { if !e.delegatecall.contains(&lc(t)) { f.push("delegatecall".into()); break } }
    if acc.bad_inner { f.push("bad_inner_calldata".into()) }
    f.dedup();
    if !acc.approvals.is_empty() { o["approvals"] = json!(acc.approvals) }
    if !acc.transfers.is_empty() { o["transfers"] = json!(acc.transfers) }
    if !acc.inner.is_empty() { o["inner_calls"] = json!(acc.inner) }
    (o, f)
}

/// True when the top-level call is exactly one approval whose token contract, spender and amount
/// the caller asserted and that matched (no findings): the explicit, exact-value opt-in that lets
/// tx-verify lift the generic `token_call_not_transfer` / `unknown_contract_call` refusal.
pub fn fully_asserted_approval(report: &Value, findings: &[String], e: &Expect, expect_to: &[String], to: &[u8; 20]) -> bool {
    let a = report["approvals"].as_array();
    findings.is_empty() && report.get("inner_calls").is_none() && a.is_some_and(|a| a.len() == 1 && a[0]["path"] == "")
        && e.spender.is_some() && (e.amount.is_some() || e.unlimited)
        && expect_to.iter().any(|x| lc(x) == hex(to))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn enc(sig: &str, args: Value) -> Vec<u8> {
        crate::unhex(crate::api::encode_call(sig, args.as_array().unwrap()).unwrap()["data"].as_str().unwrap()).unwrap()
    }
    const SP: &str = "0x000000000022d473030f116ddee9f6b43ac78ba3";
    const OTHER: &str = "0x1111111111111111111111111111111111111111";
    const MAX: &str = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    const TOK: [u8; 20] = [0xaa; 20];
    fn ex(f: impl FnOnce(&mut Expect)) -> Expect { let mut e = Expect::default(); f(&mut e); e.normalized().unwrap() }

    #[test]
    fn unlimited_approve_flagged_and_opt_in_needs_spender() {
        let d = enc("approve(address,uint256)", json!([SP, MAX]));
        let (o, f) = check(Some(&TOK), "0", &d, &Expect::default());
        assert_eq!(f, vec!["unlimited_approval"]);
        assert_eq!(o["approvals"][0]["unlimited"], true);
        let mut e = Expect::default(); e.unlimited = true;
        assert_eq!(e.normalized().unwrap_err(), "expect_unlimited_needs_expect_spender");
        assert!(check(Some(&TOK), "0", &d, &ex(|e| { e.unlimited = true; e.spender = Some(SP.into()) })).1.is_empty());
        assert_eq!(check(Some(&TOK), "0", &d, &ex(|e| { e.unlimited = true; e.spender = Some(OTHER.into()) })).1, vec!["spender_not_expected"]);
    }
    #[test]
    fn threshold_is_2_pow_128() {
        let below = "340282366920938463463374607431768211455";
        assert!(check(Some(&TOK), "0", &enc("increaseAllowance(address,uint256)", json!([SP, below])), &Expect::default()).1.is_empty());
        assert_eq!(check(Some(&TOK), "0", &enc("increaseAllowance(address,uint256)", json!([SP, UNLIMITED_MIN])), &Expect::default()).1, vec!["unlimited_approval"]);
    }
    #[test]
    fn amount_and_spender_assertions() {
        let d = enc("approve(address,uint256)", json!([SP, "1000"]));
        assert!(check(Some(&TOK), "0", &d, &ex(|e| { e.spender = Some(SP.into()); e.amount = Some("0001000".into()) })).1.is_empty());
        assert_eq!(check(Some(&TOK), "0", &d, &ex(|e| e.amount = Some("999".into()))).1, vec!["amount_not_expected"]);
        let t = enc("transfer(address,uint256)", json!([OTHER, "5"]));
        assert_eq!(check(Some(&TOK), "0", &t, &ex(|e| e.spender = Some(SP.into()))).1, vec!["spender_not_checkable"]);
        assert_eq!(check(Some(&TOK), "0", &t, &ex(|e| e.recipient = Some(SP.into()))).1, vec!["recipient_not_expected"]);
        assert!(check(Some(&TOK), "0", &t, &ex(|e| { e.recipient = Some(OTHER.into()); e.amount = Some("5".into()); e.value = Some("0".into()) })).1.is_empty());
        assert_eq!(check(Some(&TOK), "7", &t, &ex(|e| e.value = Some("0".into()))).1, vec!["value_not_expected"]);
    }
    #[test]
    fn set_approval_for_all_and_permits() {
        assert_eq!(check(Some(&TOK), "0", &enc("setApprovalForAll(address,bool)", json!([SP, true])), &Expect::default()).1, vec!["unlimited_approval"]);
        assert!(check(Some(&TOK), "0", &enc("setApprovalForAll(address,bool)", json!([SP, false])), &Expect::default()).1.is_empty());
        let z = "0x0000000000000000000000000000000000000000000000000000000000000001";
        let p = enc("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)", json!([OTHER, SP, MAX, "1", "27", z, z]));
        let (o, f) = check(Some(&TOK), "0", &p, &Expect::default());
        assert_eq!(f, vec!["unlimited_approval"]); assert_eq!(o["approvals"][0]["spender"].as_str().unwrap().to_lowercase(), SP);
        let p2 = enc("permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)", json!([OTHER, [[OTHER, "1461501637330902918203684832716283019655932542975", "1", "0"], SP, "1"], "0x00"]));
        let (o, f) = check(Some(&TOK), "0", &p2, &Expect::default());
        assert_eq!(f, vec!["unlimited_approval"]); assert_eq!(o["approvals"][0]["token"].as_str().unwrap().to_lowercase(), OTHER);
    }
    #[test]
    fn multicall_surfaces_inner_and_needs_assertion() {
        let inner = enc("approve(address,uint256)", json!([SP, MAX]));
        let d = enc("multicall(bytes[])", json!([[hex(&inner)]]));
        let (o, f) = check(Some(&TOK), "0", &d, &Expect::default());
        assert_eq!(f, vec!["unlimited_approval", "inner_calls_not_asserted"]);
        assert_eq!(o["inner_calls"][0]["selector"], "0x095ea7b3"); assert_eq!(o["approvals"][0]["path"], "multicall[0]");
        let ok = ex(|e| { e.inner = vec![(hex(&TOK), "0x095ea7b3".into())]; e.spender = Some(SP.into()); e.unlimited = true });
        assert!(check(Some(&TOK), "0", &d, &ok).1.is_empty());
    }
    #[test]
    fn safe_delegatecall_and_multisend() {
        let ms_to = [0x40u8; 20];
        let t = enc("transfer(address,uint256)", json!([OTHER, "5"]));
        let mut packed = vec![0u8]; packed.extend([0xaa; 20]); packed.extend([0u8; 32]);
        let mut l = [0u8; 32]; l[31] = t.len() as u8; packed.extend(l); packed.extend(&t);
        let ms = enc("multiSend(bytes)", json!([hex(&packed)]));
        let z = "0x0000000000000000000000000000000000000000";
        let ex_tx = enc("execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)", json!([hex(&ms_to), "0", hex(&ms), "1", "0", "0", "0", z, z, "0x"]));
        let (o, f) = check(Some(&[0x55; 20]), "0", &ex_tx, &Expect::default());
        assert_eq!(f, vec!["inner_calls_not_asserted", "delegatecall"]);
        assert_eq!(o["inner_calls"][1]["path"], "safe[0].multisend[0]"); assert_eq!(o["transfers"][0]["path"], "safe[0].multisend[0]");
        let e = ex(|e| { e.delegatecall = vec![hex(&ms_to)]; e.inner = vec![(hex(&ms_to), "0x8d80ff0a".into()), (hex(&TOK), "0xa9059cbb".into())] });
        assert!(check(Some(&[0x55; 20]), "0", &ex_tx, &e).1.is_empty());
        // truncated packed multiSend payload refused
        let bad = enc("multiSend(bytes)", json!([hex(&packed[..60])]));
        assert!(check(Some(&TOK), "0", &bad, &Expect::default()).1.contains(&"bad_inner_calldata".to_string()));
    }
    #[test]
    fn universal_router_commands_surfaced() {
        let d = enc("execute(bytes,bytes[],uint256)", json!(["0x0a00", ["0x01", "0x02"], "1"]));
        let (o, f) = check(Some(&TOK), "0", &d, &Expect::default());
        assert_eq!(f, vec!["inner_calls_not_asserted"]);
        assert_eq!(o["inner_calls"][0]["selector"], "0x0a"); assert_eq!(o["inner_calls"][1]["selector"], "0x00");
    }
}
