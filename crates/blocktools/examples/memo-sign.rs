//! e2e helper (scripts/e2e.d/memo-regtest.sh): build a THORChain memo PSBT with psbtmemo::build and sign it
//! with the PUBLIC throwaway key 1 (private key 0x..01). Never for real funds.
//!   memo-sign CHAIN UTXOS_FILE VAULT AMOUNT CHANGE RATE MEMO_HEX [over]  -> {"psbt","raw","fee"}
//! `over` (negative probes only): after the builder accepted AMOUNT = dust and MEMO = the limit, sign a tx whose
//! vault output is N-1 for `dust:N` (the difference goes to change) or and whose OP_RETURN carries one more byte, so the node's own limits are measured.
use bitcoin::psbt::Psbt;
use blocktools_core::chains;
use blocktools_tx::{digest, sign};

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    assert!(a.len() == 7 || a.len() == 8, "memo-sign CHAIN UTXOS_FILE VAULT AMOUNT CHANGE RATE MEMO_HEX [dust:N|memo]");
    let c = chains::chain(&a[0]).expect("chain");
    let utxos = std::fs::read_to_string(&a[1]).expect("utxos");
    let memo = blocktools_core::hex_dec(&a[6]).expect("memo hex");
    let v = match blocktools::psbtmemo::build(&a[0], &utxos, &a[2], Some(a[3].parse().unwrap()), Some(&a[4]), a[5].parse().unwrap(), &memo) {
        Ok(v) => v, Err(e) => { println!("{}", serde_json::json!({"error": e})); std::process::exit(1) }
    };
    let psbt = v["psbt"].as_str().unwrap().to_string();
    let mut p = Psbt::deserialize(&blocktools_core::b64::decode(&psbt).unwrap()).unwrap();
    match a.get(7).map(String::as_str) {
        Some(d) if d.starts_with("dust:") => { let n: u64 = d[5..].parse().unwrap(); let o = &mut p.unsigned_tx.output; let cut = o[0].value.to_sat() - (n - 1);
            o[0].value = bitcoin::Amount::from_sat(n - 1); o[1].value = o[1].value + bitcoin::Amount::from_sat(cut); }
        Some("memo") => { let mut m = memo.clone(); m.push(b'0'); let n = p.unsigned_tx.output.len() - 1;
            p.unsigned_tx.output[n].script_pubkey = bitcoin::script::Builder::new().push_opcode(bitcoin::opcodes::all::OP_RETURN)
                .push_slice(<&bitcoin::script::PushBytes>::try_from(m.as_slice()).unwrap()).into_script(); p.outputs[n] = Default::default(); }
        _ => {}
    }
    let mut k = [0u8; 32]; k[31] = 1;
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&k).unwrap();
    match c.sign { chains::Sign::ForkId(f) => sign::sign_psbt_forkid(&mut p, &[sk], f, false), _ => sign::sign_psbt_digest(&mut p, &[sk], digest::Digest::for_chain(c)) }.expect("sign");
    let raw = blocktools_core::hex_enc(bitcoin::consensus::serialize(&sign::extract(&p).expect("extract")));
    println!("{}", serde_json::json!({"psbt": psbt, "raw": raw, "fee": v["fee"]}));
}
