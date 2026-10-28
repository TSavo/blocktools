//! End-to-end CLI tests for tx-plan: the composable builder pipe produces the exact on-chain unsigned
//! bytes (the RFC #15 round-trip law, through the CLI skin), and resolve+check agrees with the family
//! verdict. Vectors mirror crates/plan/tests/{evm_golden,account_golden}.rs.
use std::io::Write;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_tx-plan");

/// The real BNB-chain BTCB->DOGE THORChain deposit, unsigned (crates/plan/tests/evm_golden.rs).
const UNSIGNED: &str = "02f9016e380e843b9aca00843b9aca008303d09094b30ec53f98ff5947ede720d32ac2da7e52a5f56b80b9014444bc937b000000000000000000000000718f6c9df785bc4e323086de024ca822efbe8ab90000000000000000000000007130d2a12b9bcbfae4f2634d864a1ee1ce3ead9c0000000000000000000000000000000000000000000000000001c6d982b7d80000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000006ae1250c00000000000000000000000000000000000000000000000000000000000000613d3a643a44545764396b4d6d3345554c6e56526d6b564665686144547a50514a336e715135722f3078656230654337613238453442364231373538303645323144394433616645343537393243356337423a35303038303138363139392f312f3000000000000000000000000000000000000000000000000000000000000000c0";

/// Run `tx-plan <args>` with `input` on stdin; assert success; return stdout.
fn run(args: &[&str], input: &str) -> String {
    let mut c = Command::new(BIN)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tx-plan");
    c.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    assert!(o.status.success(), "tx-plan {args:?} failed: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).unwrap()
}

#[test]
fn btcb_to_doge_pipe_resolves_to_on_chain_bytes() {
    let ctx = std::env::temp_dir().join("tx-plan-evm-ctx.json");
    std::fs::write(&ctx, r#"{"nonce":14,"gas":250000,"max_fee_per_gas":1000000000,"priority_fee":1000000000}"#).unwrap();

    let memo = "=:d:DTWd9kMm3EULnVRmkVFehaDTzPQJ3nqQ5r/0xeb0eC7a28E4B6B175806E21D9D3afE45792C5c7B:50080186199/1/0";
    let p = run(&["new", "--chain", "bsc", "--chain-id", "56"], "");
    let p = run(
        &[
            "call",
            "--to", "0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b",
            "--sig", "depositWithExpiry(address,address,uint256,string,uint256)",
            "--arg", "0x718f6C9df785BC4e323086De024CA822efbE8aB9",
            "--arg", "0x7130d2A12B9BCbFAe4f2634d864A1Ee1Ce3Ead9c",
            "--arg", "500112480000000",
            "--arg", memo,
            "--arg", "1793139980",
        ],
        &p,
    );
    let p = run(&["expect-to", "--address", "0xb30ec53f98ff5947ede720d32ac2da7e52a5f56b"], &p);
    let resolved = run(&["resolve", "--context", ctx.to_str().unwrap()], &p);

    assert!(resolved.contains(UNSIGNED), "resolved unsigned tx must equal the on-chain bytes; got: {resolved}");
    assert!(resolved.contains("\"status\":\"ok\""));
    let _ = std::fs::remove_file(&ctx);
}

#[test]
fn thorchain_register_pipe_checks_clean() {
    // The mainnet `swapchan` THORName register deposit (crates/plan/tests/account_golden.rs).
    let owner = "thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu";
    let memo = format!("~:swapchan:THOR:{owner}:{owner}:ETH.ETH");
    let ctx = std::env::temp_dir().join("tx-plan-acct-ctx.json");
    std::fs::write(
        &ctx,
        r#"{"sequence":0,"account_number":157891,"gas":20000000,"pubkey":"02db731fc490a4107583546391517f26d0196a1e8ac777560cccda03c702c86023"}"#,
    )
    .unwrap();

    let p = run(&["new", "--chain", "rune"], "");
    let p = run(&["deposit", "--asset", "THOR.RUNE", "--amount", "1105120000", "--memo", &memo], &p);
    let p = run(&["expect-memo", "--memo", &memo], &p);

    // resolve produces the unsigned Cosmos SignDoc...
    let resolved = run(&["resolve", "--context", ctx.to_str().unwrap()], &p);
    assert!(resolved.contains("\"sign_doc\":\""), "account resolve emits sign-doc bytes: {resolved}");
    assert!(resolved.contains("\"status\":\"ok\""));

    // ...and check agrees with the family verdict: zero blocking findings.
    let checked = run(&["check", "--context", ctx.to_str().unwrap()], &p);
    assert!(checked.contains("\"status\":\"ok\""), "clean check: {checked}");
    assert!(checked.contains("\"findings\":[]"), "no findings: {checked}");
    let _ = std::fs::remove_file(&ctx);
}
