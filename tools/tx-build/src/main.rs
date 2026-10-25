//! tx-build: build an UNSIGNED transaction offline from files and flags. Never touches the network.
//! UTXO chains -> {"psbt": base64}; EVM -> {"unsigned_tx": hex}. Pipe the result to tx-decode.
//!   tx-build --chain btc|ltc|doge --utxos FILE --to ADDR (--sweep | --consolidate | --send SATS --change ADDR)
//!            --fee-rate SAT_PER_VB [--rbf] [--dust-limit 546] [--locktime N]
//!   tx-build --chain eth --chain-id N [--account FILE] [--nonce N] [--gas N] --max-fee-per-gas WEI
//!            [--priority-fee WEI | --legacy] --to ADDR (--send WEI | --sweep [--balance WEI] | --topup GAS_UNITS
//!            | --token CONTRACT --token-amount UNITS)
//! --account FILE is one JSON object with any of nonce, balance, max_fee_per_gas, max_priority_fee_per_gas
//! (utxo-fetch writes it); flags override it. ERC-20 sends need native gas at the old address:
//! build the gas top-up first with --topup GAS_UNITS from a funded address.
use kr_tx::build;
use kr_tx::evm::{self, Kind, Tx};
use kr_tx::rlp::Rlp;
use serde_json::{json, Value};
use std::io::Read;

struct A(Vec<String>);
impl A {
    fn get(&self, k: &str) -> Option<&str> { self.0.iter().position(|x| x == k).and_then(|i| self.0.get(i + 1)).map(|s| s.as_str()) }
    fn has(&self, k: &str) -> bool { self.0.iter().any(|x| x == k) }
}
fn fail(e: &str) -> ! { kr_io::outln!("{}", json!({"tool":"tx-build","status":"bad_input","error":e})); std::process::exit(2) }
fn num(s: Option<&str>, what: &'static str) -> Option<u128> { s.map(|s| s.parse::<u128>().unwrap_or_else(|_| fail(what))) }
fn file(p: &str, max: u64) -> String {
    let mut s = String::new();
    std::fs::File::open(p).and_then(|f| f.take(max).read_to_string(&mut s)).unwrap_or_else(|_| fail("cannot read file"));
    s
}
fn main() {
    kr_io::help("tx-build --chain btc|ltc|doge|eth ... (see --help in source docs / docs/recipes) -> unsigned PSBT or EVM tx");
    let a = A(std::env::args().collect());
    let chain = a.get("--chain").unwrap_or("btc");
    if chain == "eth" { return evm_build(&a) }
    let c = kr_core::chains::chain(chain).filter(|c| matches!(c.enc, kr_core::chains::Enc::Utxo { .. })).unwrap_or_else(|| fail("unknown chain"));
    let utxos = build::parse_utxos(c, &file(a.get("--utxos").unwrap_or_else(|| fail("--utxos FILE required")), 16 << 20)).unwrap_or_else(|e| fail(&e));
    let sweep = a.has("--sweep") || a.has("--consolidate");
    let send = num(a.get("--send"), "--send").map(|x| x as u64);
    if sweep == send.is_some() { fail("choose exactly one of --sweep/--consolidate or --send") }
    let plan = build::BtcPlan { to: a.get("--to").unwrap_or_else(|| fail("--to required")).into(), send, change: a.get("--change").map(Into::into),
        fee_rate: num(a.get("--fee-rate"), "--fee-rate").unwrap_or_else(|| fail("--fee-rate required")) as u64, rbf: a.has("--rbf"),
        dust: num(a.get("--dust-limit"), "--dust-limit").unwrap_or(546) as u64, locktime: num(a.get("--locktime"), "--locktime").unwrap_or(0) as u32 };
    let p = build::build_btc(c, utxos, &plan).unwrap_or_else(|e| fail(&e));
    kr_io::outln!("{}", json!({"tool":"tx-build","status":"ok","chain":chain,"type":"psbt","psbt":kr_core::b64::encode(&p.serialize())}));
}
fn eaddr(s: &str) -> [u8; 20] {
    kr_core::validate::validate("eth", s).unwrap_or_else(|_| fail("bad address"));
    let b = kr_core::hex_dec(&s[2..]).unwrap_or_else(|| fail("bad address"));
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
    let token = a.get("--token").map(eaddr);
    let gas = num(a.get("--gas"), "--gas").unwrap_or(if token.is_some() { 100_000 } else { 21_000 }) as u64;
    let fee = max_fee.checked_mul(gas as u128).unwrap_or_else(|| fail("fee overflow"));
    let (dest, value, data) = if let Some(t) = token {
        let amt = num(a.get("--token-amount"), "--token-amount").unwrap_or_else(|| fail("--token-amount required"));
        (t, 0, evm::transfer_calldata(&to, amt))
    } else if let Some(units) = num(a.get("--topup"), "--topup") {
        (to, units.checked_mul(max_fee).unwrap_or_else(|| fail("overflow")), vec![])
    } else if a.has("--sweep") {
        let bal = pick("--balance", "balance").unwrap_or_else(|| fail("--sweep needs --balance or account balance"));
        (to, bal.checked_sub(fee).filter(|&v| v > 0).unwrap_or_else(|| fail("balance does not cover gas")), vec![])
    } else {
        (to, num(a.get("--send"), "--send").unwrap_or_else(|| fail("choose --send, --sweep, --topup or --token")), vec![])
    };
    let tx = Tx { kind: if legacy { Kind::Legacy } else { Kind::Eip1559 }, chain_id: Some(chain_id), nonce, max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: prio, gas, to: Some(dest), value, data, access_list: Rlp::L(vec![]), sig: None };
    kr_io::outln!("{}", json!({"tool":"tx-build","status":"ok","chain":"eth","type":if legacy {"evm-legacy"} else {"evm-1559"},"unsigned_tx":kr_core::hex_enc(tx.encode_unsigned())}));
}
