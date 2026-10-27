//! verify_send (verifyThorSend) on public synthetic fixtures: an honest LTC/DOGE/BCH/BTC memo PSBT from
//! psbtmemo::build passes; each SwapChan refusal case (#15-18, #23-26) fails with its named reason.
use bitcoin::hashes::{hash160, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use blocktools::thor::verify_send;
use blocktools_core::chains;
use blocktools_tx::digest;
use serde_json::Value;

const MEMO: &[u8] = b"=:THOR.RUNE:thor1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
fn h(n: u8) -> [u8; 20] { hash160::Hash::hash(&[n; 33]).to_byte_array() }
fn p2pkh(h: &[u8; 20]) -> Vec<u8> { let mut s = vec![0x76, 0xa9, 20]; s.extend(h); s.extend([0x88, 0xac]); s }
fn p2wpkh(h: &[u8; 20]) -> Vec<u8> { let mut s = vec![0, 20]; s.extend(h); s }
fn addr(c: &str, s: &[u8]) -> String { chains::script_to_address(chains::chain(c).unwrap(), s).unwrap().1 }
fn spk(chain: &str, n: u8) -> Vec<u8> { if matches!(chain, "ltc" | "btc") { p2wpkh(&h(n)) } else { p2pkh(&h(n)) } }
fn prev(spk: &[u8], a: u64, tag: u8) -> Transaction {
    Transaction { version: Version::ONE, lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::from_bytes(vec![1, tag]), sequence: Sequence::MAX, witness: Witness::new() }],
        output: vec![TxOut { value: Amount::from_sat(a), script_pubkey: ScriptBuf::from_bytes(spk.to_vec()) }] }
}
struct Fx { chain: &'static str, psbt: Psbt, vault: String, change: String, taker: String }
fn fx(chain: &'static str) -> Fx {
    let c = chains::chain(chain).unwrap();
    let (s, a) = (spk(chain, 1), if chain == "doge" { 5_000_000_000u64 } else { 50_000_000 });
    let t = prev(&s, a, 1);
    let line = format!("{{\"txid\":\"{}\",\"vout\":0,\"amount\":{a},\"address\":\"{}\",\"prev_tx\":\"{}\"}}\n", digest::txid_hex(&t, digest::Digest::for_chain(c)), addr(chain, &s), blocktools_core::hex_enc(bitcoin::consensus::serialize(&t)));
    let vault = addr(chain, &spk(chain, 9));
    let taker = addr(chain, &s);
    let v = blocktools::psbtmemo::build(chain, &line, &vault, Some(20_000_000), Some(&taker), 10, MEMO).unwrap();
    let psbt = Psbt::deserialize(&blocktools_core::b64::decode(v["psbt"].as_str().unwrap()).unwrap()).unwrap();
    Fx { chain, psbt, vault, change: taker.clone(), taker }
}
fn run(f: &Fx, p: &Psbt, memo: &[u8], amount: u64) -> Value {
    verify_send(f.chain, &blocktools_core::b64::encode(&p.serialize()), &f.vault, memo, amount, Some(&f.change), std::slice::from_ref(&f.taker), None)
}
fn reasons(v: &Value) -> Vec<String> { v["failures"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect() }
const ALL: [&str; 4] = ["ltc", "doge", "bch", "btc"];

#[test] fn honest_passes() {
    for c in ALL {
        let f = fx(c); let v = run(&f, &f.psbt, MEMO, 20_000_000);
        assert_eq!(v["ok"], true, "{c} {v}"); assert_eq!(v["rbf"], false); assert_eq!(v["memo"], std::str::from_utf8(MEMO).unwrap());
        assert_eq!(v["outputs"].as_array().unwrap().len(), 3);
    }
}
/// #15 wrong vault.
#[test] fn wrong_vault() {
    for c in ALL { let mut f = fx(c); f.vault = addr(c, &spk(c, 8)); assert!(reasons(&run(&f, &f.psbt, MEMO, 20_000_000)).contains(&"vault".into()), "{c}") }
}
/// #16-18 memo bytes differ: other recipient, case, other coin, missing OP_RETURN.
#[test] fn memo_mismatch() {
    for c in ALL {
        let f = fx(c);
        for m in [&b"=:THOR.RUNE:thor1evil"[..], b"=:thor.rune:thor1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", b"=:b:thor1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"] {
            assert_eq!(reasons(&run(&f, &f.psbt, m, 20_000_000)), ["memo"], "{c}");
        }
        let mut p = f.psbt.clone(); p.unsigned_tx.output.pop(); p.outputs.pop();
        assert!(reasons(&run(&f, &p, MEMO, 20_000_000)).contains(&"memo".into()), "{c}");
    }
}
#[test] fn amount_mismatch() { for c in ALL { let f = fx(c); assert_eq!(reasons(&run(&f, &f.psbt, MEMO, 20_000_001)), ["amount"], "{c}") } }
/// #23 input not owned by the taker.
#[test] fn foreign_input() {
    for c in ALL { let mut f = fx(c); f.taker = addr(c, &spk(c, 7)); assert_eq!(reasons(&run(&f, &f.psbt, MEMO, 20_000_000)), ["input_foreign"], "{c}") }
}
/// #26 no utxo info at all; #25 non_witness_utxo only with a prevout from another tx.
#[test] fn input_info() {
    for c in ALL {
        let f = fx(c);
        let mut p = f.psbt.clone(); p.inputs[0].witness_utxo = None; p.inputs[0].non_witness_utxo = None;
        assert!(reasons(&run(&f, &p, MEMO, 20_000_000)).contains(&"input_unknown".into()), "{c} none");
        let mut p = f.psbt.clone(); p.inputs[0].witness_utxo = None; p.inputs[0].non_witness_utxo = Some(prev(&spk(c, 1), 90_000_000, 2));
        assert!(reasons(&run(&f, &p, MEMO, 20_000_000)).contains(&"input_unknown".into()), "{c} foreign prevout");
    }
}
/// #24 extra output / output count / change elsewhere / reordered.
#[test] fn outputs() {
    for c in ALL {
        let f = fx(c);
        let mut p = f.psbt.clone(); p.unsigned_tx.output.insert(2, TxOut { value: Amount::from_sat(1_000_000), script_pubkey: ScriptBuf::from_bytes(spk(c, 8)) }); p.outputs.push(Default::default());
        assert!(reasons(&run(&f, &p, MEMO, 20_000_000)).contains(&"output_count".into()), "{c} extra");
        let mut p = f.psbt.clone(); p.unsigned_tx.output[1].script_pubkey = ScriptBuf::from_bytes(spk(c, 8));
        assert_eq!(reasons(&run(&f, &p, MEMO, 20_000_000)), ["change"], "{c} change");
        let mut p = f.psbt.clone(); p.unsigned_tx.output.swap(0, 1);
        assert!(reasons(&run(&f, &p, MEMO, 20_000_000)).contains(&"vault".into()), "{c} order");
    }
}
#[test] fn rbf_and_fee() {
    for c in ALL {
        let f = fx(c);
        let mut p = f.psbt.clone(); p.unsigned_tx.input[0].sequence = Sequence(0xffff_fffd);
        assert_eq!(reasons(&run(&f, &p, MEMO, 20_000_000)), ["rbf"], "{c}");
        let v = run(&f, &f.psbt, MEMO, 20_000_000); let fee: u64 = v["fee"].as_str().unwrap().parse().unwrap();
        let tx = blocktools_core::b64::encode(&f.psbt.serialize());
        assert_eq!(verify_send(c, &tx, &f.vault, MEMO, 20_000_000, Some(&f.change), &[], Some(fee - 1))["failures"][0], "fee", "{c}");
        assert_eq!(verify_send(c, &tx, &f.vault, MEMO, 20_000_000, Some(&f.change), &[], Some(fee))["ok"], true, "{c}");
        // fee far above the chain's default cap: shrink change so the rest goes to fees.
        let mut p = f.psbt.clone(); p.unsigned_tx.output[1].value = Amount::from_sat(1_000_000);
        assert_eq!(reasons(&run(&f, &p, MEMO, 20_000_000)), ["fee"], "{c} default cap");
    }
}
/// #24 garbage: never ok, never panics, always a reason.
#[test] fn garbage() {
    let f = fx("ltc");
    for t in ["", "zz", "00", "cHNidP8=", "{\"psbt\":1}", "deadbeef"] {
        let v = verify_send("ltc", t, &f.vault, MEMO, 1, None, &[], None);
        assert_eq!(v["ok"], false); assert!(!reasons(&v).is_empty(), "{t}");
    }
    assert_eq!(reasons(&verify_send("eth", "00", &f.vault, MEMO, 1, None, &[], None)), ["chain"]);
    assert_eq!(blocktools::thor::verify_send_json("nope"), r#"{"failures":["bad_json"],"fee":null,"memo":null,"ok":false,"outputs":[],"rbf":null}"#);
}
/// BCH vault as THORChain serves it (prefixless CashAddr) and its legacy form both match.
#[test] fn bch_vault_forms() {
    let mut f = fx("bch");
    let legacy = f.vault.clone();
    let cash = blocktools::cashaddr::from_legacy(&legacy, "bitcoincash").unwrap();
    for v in [cash.clone(), cash.trim_start_matches("bitcoincash:").to_string(), legacy] { f.vault = v; assert_eq!(run(&f, &f.psbt, MEMO, 20_000_000)["ok"], true, "{}", f.vault) }
}
