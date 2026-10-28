//! A single zero-value OP_RETURN (THORChain inbound memo) is accepted by the signing policy as a
//! non-destination output; two OP_RETURNs or a non-zero-value OP_RETURN stay refused.
use blocktools_tx::policy::{check, Policy};
use blocktools_tx::{Decoded, Io};

fn out(addr: Option<&str>, kind: &'static str, amt: u64) -> Io {
    Io { txid: None, vout: None, address: addr.map(Into::into), kind, amount: Some(amt) }
}
fn tx(outputs: Vec<Io>) -> Decoded {
    Decoded { chain: "doge".into(), ty: "psbt", signed: false, txid: None,
        inputs: vec![out(Some("IN"), "p2pkh", 500_000_000)], outputs,
        fee: Some(2000), vsize: Some(250), locktime: Some(0), rbf: Some(false), evm: None,
        warnings: vec!["unsigned", "op_return_output"], unproven_inputs: 0 }
}
fn pol() -> Policy { Policy { expect_to: vec!["VAULT".into()], change: vec!["CHANGE".into()], ..Default::default() } }

#[test] fn single_zero_value_op_return_is_a_memo() {
    let d = tx(vec![out(Some("VAULT"), "p2pkh", 100_000_000), out(Some("CHANGE"), "p2pkh", 399_998_000), out(None, "op_return", 0)]);
    assert!(check(&d, &pol()).is_empty(), "{:?}", check(&d, &pol()));
}

#[test] fn two_op_returns_refused() {
    let d = tx(vec![out(Some("VAULT"), "p2pkh", 100_000_000), out(Some("CHANGE"), "p2pkh", 399_998_000), out(None, "op_return", 0), out(None, "op_return", 0)]);
    let f = check(&d, &pol());
    assert!(f.contains(&"unexpected_output"), "{f:?}");
    assert!(f.contains(&"has_warnings"), "{f:?}");
}

#[test] fn non_zero_value_op_return_refused() {
    let d = tx(vec![out(Some("VAULT"), "p2pkh", 100_000_000), out(Some("CHANGE"), "p2pkh", 399_998_000), out(None, "op_return", 1)]);
    let f = check(&d, &pol());
    assert!(f.contains(&"unexpected_output"), "{f:?}");
    assert!(f.contains(&"has_warnings"), "{f:?}");
}
