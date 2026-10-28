//! blocktools-plan: a universal, declarative representation of a transaction.
//! RFC: https://github.com/TSavo/blocktools/issues/15
//!
//! The goal is representability: **every** transaction blocktools can build or decode maps into this
//! one model, and back out to the exact wire bytes. A `Plan` is durable intent + assertions; the live
//! facts needed to build (nonce, gas, UTXO set, fee-rate, vault, ...) are supplied per-build as a
//! `Context` and are never stored in the plan.
//!
//! A family is a bidirectional codec between the IR and a wire format:
//!   - `resolve(plan, cx) -> Unsigned`   compiles the IR to unsigned bytes (calls the existing builders)
//!   - `represent(decoded) -> Plan`      the inverse; this is what `tx-decode` produces
//!   - `check(plan, decoded) -> Findings` asserts the bytes satisfy the plan (composes policy::check,
//!                                        verify_thor_send, the acct guards — never its own crypto)
//!
//! Laws the test-suite enforces, per chain:
//!   round-trip:   resolve(represent(tx), cx) == tx            (bytes, modulo the signature)
//!   agreement:    Plan::check and the raw tools never disagree
//!   totality:     represent never fails — unmodelled bytes land in `Step::Raw`, lifted into
//!                 structured steps later without ever losing representability.
//!
//! This crate ORCHESTRATES; it adds no encoding and no crypto of its own.
use serde::{Deserialize, Serialize};
pub mod evm;
pub mod utxo;
pub mod account;

/// Which transaction family a chain belongs to: picks the Context, the Unsigned target, and which
/// structural steps are legal. (Solana/Tron/XRP/Stellar/Algo/TON/ADA/DOT join as the model grows;
/// until then they are representable via `Step::Raw`.)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Family { Utxo, Evm, Account }

/// Chain name as the CLIs use it (btc, ltc, doge, bch, eth, rune, atom, ...).
pub fn family_of(chain: &str) -> Option<Family> {
    match chain {
        "btc" | "ltc" | "doge" | "bch" | "bsv" | "btg" | "zec" | "dash" | "dgb" | "rvn" => Some(Family::Utxo),
        "eth" | "bsc" | "base" | "avax" | "arbitrum" | "optimism" | "polygon" => Some(Family::Evm),
        "rune" | "atom" | "osmo" | "xlm" | "algo" | "ton" | "ada" | "dot" => Some(Family::Account),
        _ => None,
    }
}

/// A transaction as intent + assertions. serde-stable: this is the only thing kept and re-verified.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// Chain name as the CLIs use it; the family is derived from it (`family_of`).
    pub chain: String,
    /// EVM: the chain id pinned into the tx (UTXO/Account carry their id in the chain/Context).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    pub steps: Vec<Step>,
}

/// An address or script in the chain's own string form (0x..., bc1..., thor1...).
pub type Addr = String;
/// A base-unit amount as a decimal string (wei, sats, uatom, 1e8-RUNE) — never a float.
pub type Amount = String;
/// 0x / hex bytes.
pub type Hex = String;

/// One step. Structural steps describe what the transaction IS; assertion steps describe what the
/// signer must enforce. `Raw` is the totality escape hatch: faithful bytes/fields not yet modelled.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Step {
    // ---- UTXO structural (resolve target: PSBT; import/combine/export) ----
    AddInput { txid: String, vout: u32, amount: u64, address: Addr,
               #[serde(default, skip_serializing_if = "Option::is_none")] prev_tx: Option<Hex> },
    AddOutput { to: Addr, amount: Amount },
    Change { address: Addr },
    OpReturn { memo: Hex },
    Locktime { value: u32 },
    Rbf { enabled: bool },
    FeeRate { sat_per_vb: u64 },

    // ---- EVM structural ----
    Call { to: Addr, sig: String, #[serde(default)] args: Vec<String> },
    Create { initcode: Hex },
    Value { amount: Amount },
    Approve { token: Addr, spender: Addr, amount: Amount },

    // ---- Account structural (cosmos / thorchain MsgDeposit / xlm / ...) ----
    Transfer { to: Addr, amount: Amount },
    Deposit { asset: String, amount: Amount, memo: String },

    // ---- shared assertions (checked at verify and sign, every family) ----
    ExpectTo { address: Addr },
    ExpectOut { #[serde(default, skip_serializing_if = "Option::is_none")] token: Option<Addr>, min: Amount },
    ExpectMemo { memo: String },
    CapFee { max: Amount },

    // ---- totality: a faithful region not yet lifted into a structured step ----
    Raw { kind: String, fields: serde_json::Value },
}

impl Step {
    /// The family a structural step belongs to; `None` = shared (assertions) or `Raw` (any family).
    pub fn family(&self) -> Option<Family> {
        use Step::*;
        match self {
            AddInput { .. } | AddOutput { .. } | Change { .. } | OpReturn { .. } | Locktime { .. } | Rbf { .. } | FeeRate { .. } => Some(Family::Utxo),
            Call { .. } | Create { .. } | Value { .. } | Approve { .. } => Some(Family::Evm),
            Transfer { .. } | Deposit { .. } => Some(Family::Account),
            _ => None,
        }
    }
}

/// A verification finding, reusing the string codes the tools already emit (`unexpected_output`,
/// `token_approve`, `destination_not_expected`, ...) so `check` and the raw tools stay in lockstep.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding { pub code: String }

/// Fail-closed assertion coverage: one `assertion_unsupported` Finding per assertion step present in the
/// plan whose op a family's `check` does not actually consult. A representable assertion that no family
/// enforces must never silently pass, so every family appends this to its own findings, naming the set
/// of assertion ops it does enforce. Non-assertion steps are ignored.
pub fn unsupported_assertions(plan: &Plan, enforced: &[&str]) -> Vec<Finding> {
    plan.steps.iter().filter_map(|s| {
        let op = match s {
            Step::ExpectTo { .. } => "expect-to",
            Step::ExpectOut { .. } => "expect-out",
            Step::ExpectMemo { .. } => "expect-memo",
            Step::CapFee { .. } => "cap-fee",
            _ => return None,
        };
        (!enforced.contains(&op)).then(|| Finding { code: "assertion_unsupported".into() })
    }).collect()
}

/// Per-family live facts, fetched at build time, never stored in the plan.
pub mod context {
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Evm { pub nonce: u64, pub gas: u64, pub max_fee_per_gas: u128, pub priority_fee: u128 }
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Utxo { pub fee_rate: u64 }
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    pub struct Account { pub sequence: u64, pub account_number: u64, pub gas: u64, /// compressed secp256k1 signer pubkey, 33-byte hex
        pub pubkey: String }
}

impl Plan {
    pub fn family(&self) -> Option<Family> { family_of(&self.chain) }
    /// Structural steps whose family does not match the plan's chain (a legality check for `resolve`).
    pub fn misplaced_steps(&self) -> Vec<&Step> {
        let fam = self.family();
        self.steps.iter().filter(|s| s.family().is_some() && s.family() != fam).collect()
    }
}

/// The signer guard set derived from a Plan's assertions: the `blocktools_tx::policy::Policy` that each
/// family's `check()` builds (`chain_id`, `expect_to`, `change`, `max_fee`, `expect_memo`), the `ExpectOut`
/// assertion (representable; no family enforces it yet, so it is surfaced, never silently dropped), and the
/// fail-closed `findings` a `tx-plan check` raises on the plan alone -- an unparsable `CapFee`, an assertion
/// op the family does not consult, and a structural step whose destination/memo assertion the plan omits.
///
/// `tx-sign --plan` feeds `policy` to the same `policy::check` path the `--expect-to`/`--max-fee`/... flags
/// drive and refuses to sign on any `findings`, so a Plan that passes `tx-plan check` and one signed with
/// `tx-sign --plan` enforce the identical assertions **by construction** (RFC #15). `tx-sign` can sign only
/// the Evm and Utxo families; an Account plan resolves to a Cosmos SignDoc that `acct-tx` signs instead.
#[derive(Clone, Debug)]
pub struct SignGuards {
    pub family: Option<Family>,
    pub policy: blocktools_tx::policy::Policy,
    /// `ExpectOut { token, min }` if the plan carries one; representable but unenforced today.
    pub expect_out: Option<(Option<Addr>, Amount)>,
    /// Fail-closed findings `tx-sign --plan` must refuse on, before touching keys.
    pub findings: Vec<Finding>,
}

/// Derive the signer guards for a plan, dispatched by family (`family_of`/`plan.family`). Reuses each
/// family's `guards()` construction (the same mapping its `check()` consumes); adds the `unsupported_assertions`
/// findings and the fail-closed structural coverage the signer must not sign without.
pub fn sign_guards(plan: &Plan) -> SignGuards {
    let family = plan.family();
    let expect_out = plan.steps.iter().find_map(|s| match s {
        Step::ExpectOut { token, min } => Some((token.clone(), min.clone())),
        _ => None,
    });
    let (policy, mut findings, enforced): (blocktools_tx::policy::Policy, Vec<Finding>, &[&str]) = match family {
        Some(Family::Evm) => { let (p, f) = evm::guards(plan); (p, f, &["expect-to", "cap-fee"][..]) }
        Some(Family::Utxo) => { let (p, f) = utxo::guards(plan); (p, f, &["expect-to", "expect-memo", "cap-fee"][..]) }
        Some(Family::Account) => { let (p, f) = account::guards(plan); (p, f, &["expect-memo", "expect-to"][..]) }
        None => (blocktools_tx::policy::Policy::default(), vec![], &[][..]),
    };
    findings.extend(unsupported_assertions(plan, enforced));
    // Fail-closed structural coverage: the signer must never sign a structural step whose destination or
    // memo the plan left unasserted (mirrors each family's check(): utxo returns `vault` without an
    // ExpectTo and refuses a bare OP_RETURN; the evm/utxo CLIs already require --expect-to). One finding
    // per uncovered step kind.
    let (mut dto, mut dmemo) = (false, false);
    for s in &plan.steps {
        let (missing, code, dup): (bool, &str, &mut bool) = match (family, s) {
            (Some(Family::Utxo), Step::AddOutput { .. }) => (policy.expect_to.is_empty(), "destination_not_asserted", &mut dto),
            (Some(Family::Utxo), Step::OpReturn { .. }) => (policy.expect_memo.is_none(), "memo_not_asserted", &mut dmemo),
            (Some(Family::Evm), Step::Call { .. } | Step::Approve { .. }) => (policy.expect_to.is_empty(), "destination_not_asserted", &mut dto),
            _ => continue,
        };
        if missing && !*dup { *dup = true; findings.push(Finding { code: code.into() }); }
    }
    SignGuards { family, policy, expect_out, findings }
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn serde_round_trip() {
        let p = Plan { chain: "eth".into(), chain_id: Some(56), steps: vec![
            Step::Approve { token: "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c".into(), spender: "0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b".into(), amount: "500112480000000".into() },
            Step::ExpectTo { address: "0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b".into() },
            Step::CapFee { max: "60000000000000".into() },
        ]};
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<Plan>(&j).unwrap(), p);
        assert!(j.contains("\"op\":\"approve\"") && j.contains("\"op\":\"expect-to\""));
        assert_eq!(p.family(), Some(Family::Evm));
        assert!(p.misplaced_steps().is_empty());
    }
    #[test]
    fn totality_raw_is_any_family_and_round_trips() {
        let p = Plan { chain: "xlm".into(), chain_id: None, steps: vec![
            Step::Raw { kind: "stellar.AccountMerge".into(), fields: serde_json::json!({"destination":"G..."}) },
        ]};
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<Plan>(&j).unwrap(), p);
        assert!(p.misplaced_steps().is_empty(), "Raw is representable on any chain");
    }
    #[test]
    fn unknown_plan_field_is_rejected() {
        // deny_unknown_fields on Plan: a stray top-level key (here `allow_any`) must fail, not be ignored.
        let j = r#"{"chain":"bsc","chain_id":56,"steps":[],"allow_any":true}"#;
        assert!(serde_json::from_str::<Plan>(j).is_err(), "unknown Plan field must be rejected");
    }
    #[test]
    fn unknown_step_field_is_rejected() {
        // deny_unknown_fields on Step: a stray key alongside a known op must fail.
        let j = r#"{"chain":"eth","steps":[{"op":"expect-to","address":"0xabc","bogus":1}]}"#;
        assert!(serde_json::from_str::<Plan>(j).is_err(), "unknown Step field must be rejected");
    }
    #[test]
    fn raw_free_form_fields_still_parse() {
        // Raw keeps its free-form data inside `fields`, so only op/kind/fields are top-level keys and
        // deny_unknown_fields does not constrain the nested payload.
        let j = r#"{"chain":"xlm","steps":[{"op":"raw","kind":"stellar.X","fields":{"a":1,"b":{"c":[2,3],"d":"e"}}}]}"#;
        let p = serde_json::from_str::<Plan>(j).expect("Raw with arbitrary nested fields must parse");
        assert!(matches!(p.steps[0], Step::Raw { .. }));
    }
}
