//! OP_RETURN memo acceptance is opt-in: a single zero-value OP_RETURN is a non-destination output only
//! when `expect_memo` equals its payload byte-for-byte. Without expect_memo, with a different memo, with
//! two OP_RETURNs or with a non-zero-value OP_RETURN it is refused (`unexpected_output`, `has_warnings`).
use blocktools_tx::policy::{check, Policy};
use blocktools_tx::{op_return_data, Decoded, Io};

const MEMO: &[u8] = b"=:r:thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu";
fn script(m: &[u8]) -> Vec<u8> { let mut s = vec![0x6a, m.len() as u8]; s.extend_from_slice(m); s }
fn out(addr: Option<&str>, kind: &'static str, amt: u64) -> Io {
    Io { data: None, txid: None, vout: None, address: addr.map(Into::into), kind, amount: Some(amt) }
}
fn opret(m: &[u8], amt: u64) -> Io { Io { data: op_return_data(&script(m)), ..out(None, "op_return", amt) } }
fn tx(extra: Vec<Io>) -> Decoded {
    let mut outputs = vec![out(Some("VAULT"), "p2pkh", 100_000_000), out(Some("CHANGE"), "p2pkh", 399_998_000)];
    outputs.extend(extra);
    Decoded { chain: "doge".into(), ty: "psbt", signed: false, txid: None,
        inputs: vec![out(Some("IN"), "p2pkh", 500_000_000)], outputs,
        fee: Some(2000), vsize: Some(250), locktime: Some(0), rbf: Some(false), evm: None,
        warnings: vec!["unsigned", "op_return_output"], unproven_inputs: 0 }
}
fn pol(m: Option<&[u8]>) -> Policy { Policy { expect_to: vec!["VAULT".into()], change: vec!["CHANGE".into()], expect_memo: m.map(<[u8]>::to_vec), ..Default::default() } }
fn refused(f: &[&str]) { assert!(f.contains(&"unexpected_output") && f.contains(&"has_warnings"), "{f:?}") }

#[test] fn exact_memo_accepted() { let f = check(&tx(vec![opret(MEMO, 0)]), &pol(Some(MEMO))); assert!(f.is_empty(), "{f:?}") }
#[test] fn no_expect_memo_refused() { refused(&check(&tx(vec![opret(MEMO, 0)]), &pol(None))) }
#[test] fn one_byte_different_refused() {
    let mut m = MEMO.to_vec(); *m.last_mut().unwrap() ^= 1;
    refused(&check(&tx(vec![opret(MEMO, 0)]), &pol(Some(&m))));
    refused(&check(&tx(vec![opret(MEMO, 0)]), &pol(Some(&MEMO[..MEMO.len() - 1])))); // prefix is not equal
}
#[test] fn two_op_returns_refused() { refused(&check(&tx(vec![opret(MEMO, 0), opret(MEMO, 0)]), &pol(Some(MEMO)))) }
#[test] fn non_zero_value_op_return_refused() { refused(&check(&tx(vec![opret(MEMO, 1)]), &pol(Some(MEMO)))) }
#[test] fn unknown_amount_refused() { refused(&check(&tx(vec![Io { amount: None, ..opret(MEMO, 0) }]), &pol(Some(MEMO)))) }
#[test] fn payload_parse() {
    assert_eq!(op_return_data(&script(MEMO)).as_deref(), Some(MEMO));
    assert_eq!(op_return_data(&[0x6a, 0x4c, 2, b'a', b'b']).as_deref(), Some(&b"ab"[..]));
    assert_eq!(op_return_data(&[0x6a, 2, b'a']), None);            // truncated
    assert_eq!(op_return_data(&[0x6a, 1, b'a', 1, b'b']), None);   // two pushes
    assert_eq!(op_return_data(&[0x76, 1, b'a']), None);            // not OP_RETURN
}
