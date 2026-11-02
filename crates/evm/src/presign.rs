//! The tx-verify pre-sign content step as one shared function (CLI tx-verify and wasm verifyTx), and the
//! JSON form of its assertions. The checks themselves are [`crate::approval::check`].
use crate::approval::{check, fully_asserted_approval, Expect};
use serde_json::Value;

impl Expect {
    /// True when any assertion or opt-in is given (they are EVM only).
    pub fn asserted(&self) -> bool {
        self.spender.is_some() || self.amount.is_some() || self.unlimited || self.recipient.is_some() || self.value.is_some() || !self.inner.is_empty() || !self.delegatecall.is_empty()
    }
    /// The wasm form of the tx-verify flags, from a JSON request object (unknown keys ignored, like callJson):
    /// `expect_spender`, `expect_amount`, `expect_recipient`, `expect_value`: strings; `expect_unlimited`: bool;
    /// `allow_inner_call`: ["TO:SELECTOR", ...]; `allow_delegatecall`: ["TO", ...]. A wrong JSON type throws
    /// `<key>_must_be_string` / `_must_be_bool` / `_must_be_string_array`. Not normalized (call [`Expect::normalized`]).
    pub fn from_json(req: &Value) -> Result<Self, String> {
        let st = |k: &str| match req.get(k) { None => Ok(None), Some(Value::String(s)) => Ok(Some(s.clone())), _ => Err(format!("{k}_must_be_string")) };
        let arr = |k: &str| match req.get(k) {
            None => Ok(vec![]),
            Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(str::to_string).ok_or(format!("{k}_must_be_string_array"))).collect(),
            _ => Err(format!("{k}_must_be_string_array")),
        };
        let unlimited = match req.get("expect_unlimited") { None | Some(Value::Bool(false)) => false, Some(Value::Bool(true)) => true, _ => return Err("expect_unlimited_must_be_bool".into()) };
        Ok(Expect {
            spender: st("expect_spender")?, amount: st("expect_amount")?, unlimited, recipient: st("expect_recipient")?, value: st("expect_value")?,
            inner: arr("allow_inner_call")?.iter().map(|s| Expect::inner_arg(s)).collect::<Result<_, _>>()?,
            delegatecall: arr("allow_delegatecall")?,
        })
    }
}

/// The tx-verify content step, shared by the CLI and the wasm `verifyTx` (one code path): runs [`check`] on an EVM
/// call, applies the fully-asserted-approval lift to `f` (the policy findings), appends the content findings and copies
/// `approvals` / `transfers` / `inner_calls` into `o`. `e` must be normalized; `warnings` are the decoder's warnings.
#[allow(clippy::too_many_arguments)]
pub fn apply(to: Option<&[u8; 20]>, value_wei: &str, data: &[u8], warnings: &[&str], e: &Expect, expect_to: &[String], f: &mut Vec<String>, o: &mut Value) {
    let (r, mut g) = check(to, value_wei, data, e);
    if let Some(to) = to {
        if fully_asserted_approval(&r, &g, e, expect_to, to) {
            f.retain(|x| !["token_call_not_transfer", "unknown_contract_call", "destination_not_expected"].contains(&x.as_str()));
            if warnings.iter().all(|w| ["unsigned", "token_approve", "unlimited_approve", "unknown_calldata"].contains(w)) { f.retain(|x| x != "has_warnings") }
        }
    }
    for k in ["approvals", "transfers", "inner_calls"] { if let Some(v) = r.get(k) { o[k] = v.clone() } }
    f.append(&mut g); f.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    const SP: &str = "0x000000000022d473030f116ddee9f6b43ac78ba3";
    const OTHER: &str = "0x1111111111111111111111111111111111111111";
    #[test]
    fn from_json_typed_errors_and_same_expect_as_flags() {
        let e = Expect::from_json(&json!({"expect_spender": SP, "expect_unlimited": true, "allow_inner_call": [format!("{OTHER}:0xa9059cbb")], "allow_delegatecall": [OTHER]})).unwrap();
        assert!(e.asserted() && e.unlimited && e.inner == vec![(OTHER.to_string(), "0xa9059cbb".to_string())]);
        assert!(!Expect::from_json(&json!({"sigs": []})).unwrap().asserted());
        for (k, v, err) in [("expect_unlimited", json!("yes"), "expect_unlimited_must_be_bool"), ("expect_amount", json!(5), "expect_amount_must_be_string"),
            ("allow_inner_call", json!("x:0x01"), "allow_inner_call_must_be_string_array"), ("allow_delegatecall", json!([1]), "allow_delegatecall_must_be_string_array")] {
            assert_eq!(Expect::from_json(&json!({k: v})).unwrap_err(), err);
        }
    }
}
