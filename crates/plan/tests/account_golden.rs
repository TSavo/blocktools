//! Account family golden: the real mainnet `swapchan` THORName register tx (crates/acct/tests/thorchain.rs,
//! accepted by thorchain-1 on 2026-10-27). The RFC #15 round-trip law for the Account family: the Plan path
//! (`account::resolve`) and the direct lib path (`thor::Deposit::sign_doc`) must produce identical SignDoc bytes.
use blocktools_acct::thor::Deposit;
use blocktools_plan::{account, context, Plan, Step};

const PUBKEY: &str = "02db731fc490a4107583546391517f26d0196a1e8ac777560cccda03c702c86023";
const OWNER: &str = "thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu";

fn memo() -> String { format!("~:swapchan:THOR:{OWNER}:{OWNER}:ETH.ETH") }
fn pk() -> [u8; 33] {
    (0..PUBKEY.len()).step_by(2).map(|i| u8::from_str_radix(&PUBKEY[i..i + 2], 16).unwrap())
        .collect::<Vec<_>>().try_into().unwrap()
}

fn plan() -> Plan {
    Plan { chain: "rune".into(), chain_id: None, steps: vec![
        Step::Deposit { asset: "THOR.RUNE".into(), amount: "1105120000".into(), memo: memo() },
    ]}
}
fn cx() -> context::Account {
    context::Account { sequence: 0, account_number: 157891, gas: 20000000, pubkey: PUBKEY.into() }
}

#[test]
fn account_resolve_matches_direct_lib_path() {
    // The direct lib path: reconstruct the same Deposit from the same fields.
    let direct = Deposit {
        asset_chain: "THOR".into(), asset_symbol: "RUNE".into(), asset_ticker: "RUNE".into(),
        amount: 1105120000, memo: memo(), pubkey: pk(),
        sequence: 0, gas: 20000000, chain_id: "thorchain-1".into(), account_number: 157891,
    };
    let from_plan = account::resolve(&plan(), &cx()).expect("resolve");
    assert_eq!(from_plan, direct.sign_doc(), "plan path == direct lib path, byte for byte");
    // and the address derived from the pubkey is the mainnet owner.
    assert_eq!(direct.thor_address(), OWNER);
}

#[test]
fn account_check_memo_assertion() {
    let mut p = plan();
    p.steps.push(Step::ExpectMemo { memo: memo() });
    let doc = account::resolve(&p, &cx()).expect("resolve");
    assert!(account::check(&p, &doc).is_empty(), "matching ExpectMemo passes");

    let mut bad = plan();
    bad.steps.push(Step::ExpectMemo { memo: "~:wrong:THOR:x:x:ETH.ETH".into() });
    let doc = account::resolve(&bad, &cx()).expect("resolve"); // bytes carry the (correct) Deposit memo
    let findings = account::check(&bad, &doc);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "memo_not_expected", "mismatched ExpectMemo fails");
}

#[test]
fn deposit_sign_doc_represent_round_trips() {
    // RFC #15 round-trip for the Account family: build the SignDoc, lift it back with `represent`, then
    // recompile against the SAME context. The MsgDeposit lifts to a structured Deposit (not Raw) and the
    // SignDoc bytes are reproduced exactly.
    let doc = account::resolve(&plan(), &cx()).expect("resolve");
    let represented = account::represent(&doc);
    match represented.steps.as_slice() {
        [Step::Deposit { asset, amount, memo: m }] => {
            assert_eq!(asset, "THOR.RUNE");
            assert_eq!(amount, "1105120000");
            assert_eq!(m, &memo());
        }
        other => panic!("MsgDeposit must lift to a single Deposit step, got {other:?}"),
    }
    let rebuilt = account::resolve(&represented, &cx()).expect("resolve represented");
    assert_eq!(rebuilt, doc, "resolve(represent(doc)) == doc, byte for byte");
}

#[test]
fn opaque_sign_doc_round_trips_through_raw() {
    // Totality: a doc neither decoder accepts is held verbatim in Raw{kind:"account.sign_doc"} and
    // rebuilt exactly, so representability never fails.
    let doc = vec![0xde_u8, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03];
    let represented = account::represent(&doc);
    assert!(matches!(represented.steps.as_slice(), [Step::Raw { kind, .. }] if kind == "account.sign_doc"));
    let rebuilt = account::resolve(&represented, &cx()).expect("resolve raw");
    assert_eq!(rebuilt, doc, "opaque SignDoc round-trips verbatim through Raw");
}

#[test]
fn account_check_fails_open_on_unasserted_deposit() {
    // FIX (BLOCKING): a Deposit with no ExpectMemo must be a finding -- the memo is the whole security
    // payload of a THORChain MsgDeposit, so an unasserted deposit can never verify silently clean.
    let doc = account::resolve(&plan(), &cx()).expect("resolve"); // plan() is a bare Deposit, no assertions
    let findings = account::check(&plan(), &doc);
    assert!(findings.iter().any(|f| f.code == "memo_not_expected"),
        "unasserted Deposit must fail closed, got {findings:?}");
}

#[test]
fn account_check_never_sees_the_bytes() {
    // The old check compared the ExpectMemo against the plan's OWN Deposit step and passed even when the
    // resolved SignDoc said something else. Resolve a Deposit whose memo is evil; then hand check a plan
    // whose Deposit and ExpectMemo both say the good memo. check must read the bytes (evil) and flag it.
    let mut evil = plan();
    for s in &mut evil.steps { if let Step::Deposit { memo, .. } = s { *memo = "=:e:thor1evil".into(); } }
    let doc = account::resolve(&evil, &cx()).expect("resolve"); // bytes carry the evil memo

    let mut good = plan(); // Deposit memo == memo()
    good.steps.push(Step::ExpectMemo { memo: memo() });
    let findings = account::check(&good, &doc);
    assert!(findings.iter().any(|f| f.code == "memo_not_expected"),
        "check must compare the bytes, not the plan's own step: {findings:?}");
}

#[test]
fn opaque_sign_doc_lifts_to_an_account_family_chain() {
    // FIX (HIGH): represent's Raw fallback must emit a chain family_of maps to Account (not ""), so the
    // CLI can still dispatch a represented opaque Account doc.
    let doc = vec![0xde_u8, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03];
    let represented = account::represent(&doc);
    assert_eq!(represented.family(), Some(blocktools_plan::Family::Account),
        "opaque doc lifts to an Account-family chain, got {:?}", represented.chain);
    let rebuilt = account::resolve(&represented, &cx()).expect("resolve raw");
    assert_eq!(rebuilt, doc, "opaque SignDoc round-trips verbatim through Raw");
}
