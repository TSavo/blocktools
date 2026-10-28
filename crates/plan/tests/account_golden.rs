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
    assert!(account::check(&p).is_empty(), "matching ExpectMemo passes");

    let mut bad = plan();
    bad.steps.push(Step::ExpectMemo { memo: "~:wrong:THOR:x:x:ETH.ETH".into() });
    let findings = account::check(&bad);
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
