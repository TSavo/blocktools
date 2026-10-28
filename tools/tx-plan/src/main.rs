//! tx-plan: build a declarative transaction Plan (RFC #15) step by step and resolve it to unsigned bytes.
//! A thin Unix-filter skin over blocktools-plan: it adds no encoding and no crypto, it only composes a
//! `Plan` as JSON and hands it to the library's family resolve/check, which orchestrate the shipped tools.
//! Builder subcommands read a Plan on stdin and write the augmented Plan on stdout, so they compose:
//!   tx-plan new --chain bsc --chain-id 56 | tx-plan call --to 0x.. --sig 'f(uint256)' --arg 1 | tx-plan resolve --context ctx.json
//!
//! Plan builders (JSON Plan in on stdin, augmented JSON Plan out; `new` ignores stdin):
//!   new --chain NAME [--chain-id N]                            empty Plan
//!   call --to ADDR --sig SOLIDITY_SIG [--arg V ...]            EVM Step::Call
//!   approve --token ADDR --spender ADDR --amount UNITS         EVM Step::Approve
//!   create --initcode HEX                                      EVM Step::Create
//!   value --amount WEI                                         EVM Step::Value
//!   output --to ADDR [--amount SATS]                           UTXO Step::AddOutput (empty amount = sweep)
//!   change --to ADDR                                           UTXO Step::Change
//!   op-return --memo HEX                                       UTXO Step::OpReturn
//!   input --txid TXID --vout N --amount SATS --address ADDR [--prev-tx HEX]   UTXO Step::AddInput
//!   fee-rate --satvb N        rbf [--off]        locktime --n N               UTXO steps
//!   transfer --to ADDR --amount UNITS                          Account Step::Transfer
//!   deposit --asset A --amount UNITS --memo S                  Account Step::Deposit
//!   expect-to --address ADDR     expect-out [--token ADDR] --min UNITS
//!   expect-memo --memo S         cap-fee --max UNITS           shared assertions
//!   raw --kind K --fields JSON                                 totality escape hatch
//!
//! Terminals (Plan in on stdin or via --plan FILE):
//!   resolve --context FILE|-   compile to unsigned bytes (evm/utxo hex, account sign-doc hex), via
//!                              blocktools_plan::{evm,utxo,account}::resolve, dispatched by family_of.
//!   check   --context FILE|-   resolve, then assert the bytes against the plan's assertions via the
//!                              family check(); prints each Finding and a status line (exit 1 if any).
//! Context JSON (live facts, never stored in the plan): evm {"nonce","gas","max_fee_per_gas","priority_fee"};
//! utxo {"fee_rate"}; account {"sequence","account_number","gas","pubkey"}.
use blocktools_plan::{account, context, evm, utxo, Family, Plan, Step};
use serde_json::{json, Value};
use std::io::Read;

fn out(v: &Value) { blocktools_io::outln!("{v}"); }
fn fail(e: &str) -> ! { blocktools_io::outln!("{}", json!({"tool":"tx-plan","status":"bad_input","error":e})); std::process::exit(2) }

struct A(Vec<String>);
impl A {
    fn get(&self, k: &str) -> Option<&str> { self.0.iter().position(|x| x == k).and_then(|i| self.0.get(i + 1)).map(|s| s.as_str()) }
    fn req(&self, k: &str) -> &str { self.get(k).unwrap_or_else(|| fail(&format!("missing {k}"))) }
    fn has(&self, k: &str) -> bool { self.0.iter().any(|x| x == k) }
    /// Every value that follows an occurrence of `k` (for repeatable flags like --arg).
    fn all(&self, k: &str) -> Vec<String> { self.0.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).collect() }
}

fn read_all(what: &str) -> String {
    let mut s = String::new();
    if std::io::stdin().take(16 << 20).read_to_string(&mut s).is_err() { fail(what) }
    s
}
/// Read the inbound Plan: from --plan FILE if given, else from stdin. Empty stdin -> an error that names
/// the pipe (a builder step with nothing upstream is almost always a missing `new`).
fn read_plan(a: &A) -> Plan {
    let text = match a.get("--plan") {
        Some(p) => read_file(p),
        None => {
            let s = read_all("cannot read plan from stdin");
            if s.trim().is_empty() { fail("no Plan on stdin (start the pipe with `tx-plan new --chain ...`, or pass --plan FILE)") }
            s
        }
    };
    serde_json::from_str(&text).unwrap_or_else(|e| fail(&format!("bad Plan JSON: {e}")))
}
fn read_file(p: &str) -> String {
    let mut s = String::new();
    std::fs::File::open(p).and_then(|f| f.take(16 << 20).read_to_string(&mut s)).unwrap_or_else(|_| fail(&format!("cannot read file {p}")));
    s
}
/// Context JSON from --context (FILE, or `-` for stdin). When the plan is also on stdin, the context
/// must be a file (both cannot be stdin).
fn read_context(a: &A) -> Value {
    let src = a.get("--context").unwrap_or_else(|| fail("--context FILE|- required"));
    let text = if src == "-" {
        if a.get("--plan").is_none() { fail("--context - reads stdin, so pass the plan with --plan FILE") }
        read_all("cannot read context from stdin")
    } else { read_file(src) };
    serde_json::from_str(&text).unwrap_or_else(|e| fail(&format!("bad context JSON: {e}")))
}

/// Append `step` to the Plan on stdin and re-emit it (the composable builder output).
fn append(a: &A, step: Step) {
    let mut plan = read_plan(a);
    plan.steps.push(step);
    out(&serde_json::to_value(&plan).unwrap());
}

fn amount_opt(a: &A, k: &str) -> String { a.get(k).unwrap_or("").to_string() }

fn cx_u64(cx: &Value, k: &str) -> u64 { cx.get(k).and_then(num_of).unwrap_or(0) }
fn cx_u128(cx: &Value, k: &str) -> u128 {
    match cx.get(k) {
        Some(Value::Number(n)) => n.as_u64().map(u128::from).unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or_else(|_| fail(&format!("bad context number: {k}"))),
        _ => 0,
    }
}
fn num_of(v: &Value) -> Option<u64> {
    match v { Value::Number(n) => n.as_u64(), Value::String(s) => s.parse().ok(), _ => None }
}

fn main() {
    blocktools_io::help(
        "tx-plan new --chain C [--chain-id N] | tx-plan <step> ... | tx-plan resolve|check --context FILE|-  (declarative Plan builder; RFC #15)",
    );
    let argv = blocktools_core::chain_spec::args_or_exit("tx-plan");
    // argv[0] is the program path; argv[1] is the subcommand.
    let sub = argv.get(1).cloned().unwrap_or_default();
    let a = A(argv);
    match sub.as_str() {
        // ---- start a plan ----
        "new" => {
            let plan = Plan {
                chain: a.req("--chain").to_string(),
                chain_id: a.get("--chain-id").map(|s| s.parse().unwrap_or_else(|_| fail("--chain-id"))),
                steps: vec![],
            };
            out(&serde_json::to_value(&plan).unwrap());
        }
        // ---- EVM steps ----
        "call" => append(&a, Step::Call { to: a.req("--to").into(), sig: a.req("--sig").into(), args: a.all("--arg") }),
        "approve" => append(&a, Step::Approve { token: a.req("--token").into(), spender: a.req("--spender").into(), amount: a.req("--amount").into() }),
        "create" => append(&a, Step::Create { initcode: a.req("--initcode").into() }),
        "value" => append(&a, Step::Value { amount: a.req("--amount").into() }),
        // ---- UTXO steps ----
        "output" => append(&a, Step::AddOutput { to: a.req("--to").into(), amount: amount_opt(&a, "--amount") }),
        "change" => append(&a, Step::Change { address: a.req("--to").into() }),
        "op-return" => append(&a, Step::OpReturn { memo: a.req("--memo").into() }),
        "input" => append(&a, Step::AddInput {
            txid: a.req("--txid").into(),
            vout: a.req("--vout").parse().unwrap_or_else(|_| fail("--vout")),
            amount: a.req("--amount").parse().unwrap_or_else(|_| fail("--amount")),
            address: a.req("--address").into(),
            prev_tx: a.get("--prev-tx").map(Into::into),
        }),
        "fee-rate" => append(&a, Step::FeeRate { sat_per_vb: a.req("--satvb").parse().unwrap_or_else(|_| fail("--satvb")) }),
        "rbf" => append(&a, Step::Rbf { enabled: !a.has("--off") }),
        "locktime" => append(&a, Step::Locktime { value: a.req("--n").parse().unwrap_or_else(|_| fail("--n")) }),
        // ---- Account steps ----
        "transfer" => append(&a, Step::Transfer { to: a.req("--to").into(), amount: a.req("--amount").into() }),
        "deposit" => append(&a, Step::Deposit { asset: a.req("--asset").into(), amount: a.req("--amount").into(), memo: a.req("--memo").into() }),
        // ---- shared assertions ----
        "expect-to" => append(&a, Step::ExpectTo { address: a.req("--address").into() }),
        "expect-out" => append(&a, Step::ExpectOut { token: a.get("--token").map(Into::into), min: a.req("--min").into() }),
        "expect-memo" => append(&a, Step::ExpectMemo { memo: a.req("--memo").into() }),
        "cap-fee" => append(&a, Step::CapFee { max: a.req("--max").into() }),
        // ---- totality ----
        "raw" => {
            let fields: Value = serde_json::from_str(a.req("--fields")).unwrap_or_else(|e| fail(&format!("--fields JSON: {e}")));
            append(&a, Step::Raw { kind: a.req("--kind").into(), fields });
        }
        // ---- terminals ----
        "resolve" => resolve(&a),
        "check" => check(&a),
        "" => fail("a subcommand is required (new|call|approve|create|value|output|change|op-return|input|fee-rate|rbf|locktime|transfer|deposit|expect-to|expect-out|expect-memo|cap-fee|raw|resolve|check)"),
        other => fail(&format!("unknown subcommand: {other}")),
    }
}

fn family(plan: &Plan) -> Family {
    plan.family().unwrap_or_else(|| fail(&format!("unknown chain / family: {}", plan.chain)))
}

fn resolve(a: &A) {
    let plan = read_plan(a);
    let cx = read_context(a);
    let fam = family(&plan);
    let mut o = json!({"tool":"tx-plan","status":"ok","chain":plan.chain,"family":fam});
    match fam {
        Family::Evm => {
            let c = context::Evm { nonce: cx_u64(&cx, "nonce"), gas: cx_u64(&cx, "gas"),
                max_fee_per_gas: cx_u128(&cx, "max_fee_per_gas"), priority_fee: cx_u128(&cx, "priority_fee") };
            let tx = evm::resolve(&plan, &c).unwrap_or_else(|e| fail(&e));
            o["type"] = json!("evm-1559");
            o["unsigned_tx"] = json!(blocktools_core::hex_enc(tx.encode_unsigned()));
        }
        Family::Utxo => {
            let c = context::Utxo { fee_rate: cx_u64(&cx, "fee_rate") };
            let v = utxo::resolve(&plan, &c).unwrap_or_else(|e| fail(&e));
            o["type"] = json!("psbt");
            if let Some(obj) = v.as_object() { for (k, val) in obj { o[k.clone()] = val.clone(); } }
        }
        Family::Account => {
            let c = context::Account { sequence: cx_u64(&cx, "sequence"), account_number: cx_u64(&cx, "account_number"),
                gas: cx_u64(&cx, "gas"), pubkey: cx.get("pubkey").and_then(|v| v.as_str()).unwrap_or("").to_string() };
            let doc = account::resolve(&plan, &c).unwrap_or_else(|e| fail(&e));
            o["type"] = json!("cosmos-signdoc");
            o["sign_doc"] = json!(blocktools_core::hex_enc(&doc));
        }
    }
    out(&o);
}

fn check(a: &A) {
    let plan = read_plan(a);
    let cx = read_context(a);
    let fam = family(&plan);
    // Resolve, then assert the resolved bytes against the plan via the SAME family check() the library
    // exposes -- which composes policy::check / thor::verify_send, never its own crypto.
    let findings: Vec<String> = match fam {
        Family::Evm => {
            let c = context::Evm { nonce: cx_u64(&cx, "nonce"), gas: cx_u64(&cx, "gas"),
                max_fee_per_gas: cx_u128(&cx, "max_fee_per_gas"), priority_fee: cx_u128(&cx, "priority_fee") };
            let tx = evm::resolve(&plan, &c).unwrap_or_else(|e| fail(&e));
            evm::check(&plan, &tx).into_iter().map(|f| f.code).collect()
        }
        Family::Utxo => {
            let c = context::Utxo { fee_rate: cx_u64(&cx, "fee_rate") };
            let v = utxo::resolve(&plan, &c).unwrap_or_else(|e| fail(&e));
            utxo::check(&plan, &v).into_iter().map(|f| f.code).collect()
        }
        Family::Account => {
            let c = context::Account { sequence: cx_u64(&cx, "sequence"), account_number: cx_u64(&cx, "account_number"),
                gas: cx_u64(&cx, "gas"), pubkey: cx.get("pubkey").and_then(|v| v.as_str()).unwrap_or("").to_string() };
            // resolve first so a malformed plan is reported the same way as the raw tool.
            account::resolve(&plan, &c).unwrap_or_else(|e| fail(&e));
            account::check(&plan).into_iter().map(|f| f.code).collect()
        }
    };
    for code in &findings { out(&json!({"tool":"tx-plan","finding":code})); }
    let status = if findings.is_empty() { "ok" } else { "failed" };
    out(&json!({"tool":"tx-plan","status":status,"chain":plan.chain,"family":fam,"findings":findings}));
    if !findings.is_empty() { std::process::exit(1) }
}
