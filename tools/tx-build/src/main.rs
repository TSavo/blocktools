//! tx-build: build an UNSIGNED transaction offline from files and flags. Never touches the network.
//! UTXO chains -> {"psbt": base64}; EVM -> {"unsigned_tx": hex}. Pipe the result to tx-decode.
//!   tx-build --chain btc|ltc|doge --utxos FILE --to ADDR (--sweep | --consolidate | --send SATS --change ADDR)
//!            --fee-rate SAT_PER_VB [--rbf] [--dust-limit 546] [--locktime N]
//!   tx-build --chain ppc|nvc|clam|rdd --utxos FILE --to ADDR --sweep --fee-rate UNITS_PER_BYTE [--time UNIX]
//!            -> {"unsigned_tx": hex, "pos_prevouts": [...]} (PoS nTime format; P2PKH inputs only)
//!   tx-build --chain zec --utxos FILE --to t1... --sweep [--fee-rate N] [--branch-id HEX] [--expiry-height H]
//!            -> {"unsigned_tx": hex, "zec_prevouts": [...], "branch_id"} (transparent v5, ZIP-244; fee >= ZIP-317)
//!   tx-build --chain eth --chain-id N [--account FILE] [--nonce N] [--gas N] --max-fee-per-gas WEI
//!            [--priority-fee WEI | --legacy] --to ADDR (--send WEI | --sweep [--balance WEI] | --topup GAS_UNITS
//!            | --token CONTRACT --token-amount UNITS)
//! --account FILE is one JSON object with any of nonce, balance, max_fee_per_gas, max_priority_fee_per_gas
//! (utxo-fetch writes it); flags override it. ERC-20 sends need native gas at the old address:
//! build the gas top-up first with --topup GAS_UNITS from a funded address.
use blocktools_tx::build;
use serde_json::{json, Value};
use std::io::Read;

struct A(Vec<String>);
impl A {
    fn get(&self, k: &str) -> Option<&str> { self.0.iter().position(|x| x == k).and_then(|i| self.0.get(i + 1)).map(|s| s.as_str()) }
    fn has(&self, k: &str) -> bool { self.0.iter().any(|x| x == k) }
}
fn fail(e: &str) -> ! { blocktools_io::outln!("{}", json!({"tool":"tx-build","status":"bad_input","error":e})); std::process::exit(2) }
fn num(s: Option<&str>, what: &'static str) -> Option<u128> { s.map(|s| s.parse::<u128>().unwrap_or_else(|_| fail(what))) }
fn file(p: &str, max: u64) -> String {
    let mut s = String::new();
    std::fs::File::open(p).and_then(|f| f.take(max).read_to_string(&mut s)).unwrap_or_else(|_| fail("cannot read file"));
    s
}
fn main() {
    blocktools_io::help("tx-build --chain btc|ltc|doge|eth ... (see --help in source docs / recipes) -> unsigned PSBT or EVM tx");
    let a = A(std::env::args().collect());
    let chain = a.get("--chain").unwrap_or("btc");
    if chain == "eth" { return evm_build(&a) }
    if chain == "zec" { // transparent-only v5 sweep, P2PKH inputs, ZIP-244 (branch id is consensus-critical)
        if !a.has("--sweep") { fail("zec: only --sweep is supported") }
        let branch = a.get("--branch-id").map(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or_else(|_| fail("--branch-id (hex)"))).unwrap_or(blocktools_tx::zcash::MAINNET_BRANCH_ID);
        let expiry = num(a.get("--expiry-height"), "--expiry-height").map(|t| u32::try_from(t).unwrap_or_else(|_| fail("--expiry-height"))).unwrap_or(0);
        let (tx, prev) = blocktools_tx::zcash::build_sweep(&file(a.get("--utxos").unwrap_or_else(|| fail("--utxos FILE required")), 16 << 20), a.get("--to").unwrap_or_else(|| fail("--to required")),
            num(a.get("--fee-rate"), "--fee-rate").unwrap_or(0) as u64, branch, expiry, num(a.get("--dust-limit"), "--dust-limit").unwrap_or(546) as u64).unwrap_or_else(|e| fail(&e));
        let mut o = blocktools_tx::zcash::envelope(&tx, &prev);
        o["tool"] = json!("tx-build"); o["status"] = json!("ok"); o["type"] = json!("zcash-v5");
        blocktools_io::outln!("{o}"); return
    }
    let c = blocktools_core::chains::chain(chain).filter(|c| matches!(c.enc, blocktools_core::chains::Enc::Utxo { .. })).unwrap_or_else(|| fail("unknown chain"));
    // Only verified rows with Bitcoin-standard signing are built; fork-id (BCH/BSV/BTG), PoS
    // tx-time (PPC/NVC/CLAM/BLK/RDD/POT) and unknown formats are refused, not guessed.
    if !c.verified { fail("unverified chain parameters: not supported") }
    let pos = blocktools_tx::pos::layout(chain).is_some();
    if !c.sign.buildable() && !pos { fail("unsupported signing scheme for this chain (fork-id / unknown / PoS tx time without a verified layout)") }
    let utxos = build::parse_utxos(c, &file(a.get("--utxos").unwrap_or_else(|| fail("--utxos FILE required")), 16 << 20)).unwrap_or_else(|e| fail(&e));
    if pos { // PPC/NVC/CLAM/RDD: sweep only, P2PKH inputs, tx time = --time or now
        if !a.has("--sweep") { fail("pos-ntime chains: only --sweep is supported") }
        let time = num(a.get("--time"), "--time").map(|t| u32::try_from(t).unwrap_or_else(|_| fail("--time"))).unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0));
        let (tx, prev) = build::build_pos_sweep(c, &utxos, a.get("--to").unwrap_or_else(|| fail("--to required")), num(a.get("--fee-rate"), "--fee-rate").unwrap_or_else(|| fail("--fee-rate required")) as u64,
            time, num(a.get("--dust-limit"), "--dust-limit").unwrap_or(546) as u64).unwrap_or_else(|e| fail(&e));
        let mut o = blocktools_tx::pos::envelope(chain, &tx, &prev, &utxos.iter().map(|u| u.prev_raw.clone()).collect::<Vec<_>>());
        o["tool"] = json!("tx-build"); o["status"] = json!("ok"); o["type"] = json!("pos-ntime");
        blocktools_io::outln!("{o}"); return
    }
    let sweep = a.has("--sweep") || a.has("--consolidate");
    let send = num(a.get("--send"), "--send").map(|x| x as u64);
    if sweep == send.is_some() { fail("choose exactly one of --sweep/--consolidate or --send") }
    let plan = build::BtcPlan { to: a.get("--to").unwrap_or_else(|| fail("--to required")).into(), send, change: a.get("--change").map(Into::into),
        fee_rate: num(a.get("--fee-rate"), "--fee-rate").unwrap_or_else(|| fail("--fee-rate required")) as u64, rbf: a.has("--rbf"),
        dust: num(a.get("--dust-limit"), "--dust-limit").unwrap_or(546) as u64, op_return: None, locktime: num(a.get("--locktime"), "--locktime").unwrap_or(0) as u32 };
    let p = build::build_btc(c, utxos, &plan).unwrap_or_else(|e| fail(&e));
    blocktools_io::outln!("{}", json!({"tool":"tx-build","status":"ok","chain":chain,"type":"psbt","psbt":blocktools_core::b64::encode(&p.serialize())}));
}
fn eaddr(s: &str) -> [u8; 20] {
    blocktools_core::validate::validate("eth", s).unwrap_or_else(|_| fail("bad address"));
    let b = blocktools_core::hex_dec(&s[2..]).unwrap_or_else(|| fail("bad address"));
    let mut o = [0; 20]; o.copy_from_slice(&b); o
}
fn evm_build(a: &A) {
    let acct: Value = a.get("--account").map(|p| serde_json::from_str(&file(p, 1 << 16)).unwrap_or_else(|_| fail("bad account file"))).unwrap_or(Value::Null);
    let pick = |flag: &str, key: &str| -> Option<u128> {
        num(a.get(flag), "number").or_else(|| match &acct[key] { Value::String(s) => Some(s.parse().unwrap_or_else(|_| fail("bad account file"))), Value::Number(n) => n.as_u64().map(Into::into), _ => None })
    };
    let chain_id = num(a.get("--chain-id"), "--chain-id").unwrap_or_else(|| fail("--chain-id required")) as u64;
    let nonce = pick("--nonce", "nonce").unwrap_or_else(|| fail("--nonce or account nonce required")) as u64;
    let max_fee = pick("--max-fee-per-gas", "max_fee_per_gas").unwrap_or_else(|| fail("--max-fee-per-gas required"));
    let legacy = a.has("--legacy");
    let prio = if legacy { None } else { Some(pick("--priority-fee", "max_priority_fee_per_gas").unwrap_or(1_000_000_000).min(max_fee)) };
    let to = eaddr(a.get("--to").unwrap_or_else(|| fail("--to required")));
    let amount = if let Some(t) = a.get("--token").map(eaddr) {
        build::EvmAmount::Token { token: t, amount: num(a.get("--token-amount"), "--token-amount").unwrap_or_else(|| fail("--token-amount required")) }
    } else if let Some(units) = num(a.get("--topup"), "--topup") { build::EvmAmount::Topup(units) }
    else if a.has("--sweep") { build::EvmAmount::Sweep { balance: pick("--balance", "balance").unwrap_or_else(|| fail("--sweep needs --balance or account balance")) } }
    else { build::EvmAmount::Send(num(a.get("--send"), "--send").unwrap_or_else(|| fail("choose --send, --sweep, --topup or --token"))) };
    let gas = num(a.get("--gas"), "--gas").map(|g| g as u64);
    let tx = build::build_evm(&build::EvmPlan { chain_id, nonce, max_fee, priority_fee: prio, gas, to, amount }).unwrap_or_else(|e| fail(e));
    blocktools_io::outln!("{}", json!({"tool":"tx-build","status":"ok","chain":"eth","type":if legacy {"evm-legacy"} else {"evm-1559"},"unsigned_tx":blocktools_core::hex_enc(tx.encode_unsigned())}));
}
