//! buildPsbtWithMemo vs SwapChan buildBtcPsbt (btc.ts verbatim, bitcoinjs-lib 7) — tools/psbt-parity/gen.mts.
use bitcoin::psbt::Psbt;
use serde_json::Value;
fn b64d(s: &str) -> Vec<u8> { blocktools::b64::decode(s).unwrap() }
#[test] fn corpus() {
    let c: Value = serde_json::from_str(include_str!("data/psbt-memo-corpus.json")).unwrap();
    let mut bad = vec![];
    for k in c.as_array().unwrap() {
        let jl: String = k["utxos"].as_array().unwrap().iter().map(|u| format!("{{\"txid\":\"{}\",\"vout\":{},\"amount\":{},\"address\":\"{}\"}}\n", u["txid"].as_str().unwrap(), u["vout"], u["value"], k["from"].as_str().unwrap())).collect();
        let amt: u64 = k["amount"].as_str().unwrap().parse().unwrap();
        let got = blocktools::psbtmemo::build("btc", &jl, k["to"].as_str().unwrap(), Some(amt), k["from"].as_str(), k["feeRate"].as_u64().unwrap(), k["memo"].as_str().unwrap().as_bytes());
        let want = Psbt::deserialize(&b64d(k["psbt"].as_str().unwrap())).unwrap().unsigned_tx;
        match got {
            Err(e) => bad.push(format!("{}: error {e}", k["name"])),
            Ok(v) => {
                let g = Psbt::deserialize(&b64d(v["psbt"].as_str().unwrap())).unwrap().unsigned_tx;
                let ins = |t: &bitcoin::Transaction| t.input.iter().map(|i| i.previous_output).collect::<Vec<_>>();
                if ins(&g) != ins(&want) { bad.push(format!("{}: inputs", k["name"])) }
                // Default is non-RBF, like btc.ts (bitcoinjs leaves nSequence 0xffffffff); gen.mts records it per input.
                let seq: Vec<String> = g.input.iter().map(|i| format!("{:x}", i.sequence.0)).collect();
                let want_seq: Vec<String> = k["sequences"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().into()).collect();
                if seq != want_seq || want.input.iter().any(|i| i.sequence.0 != 0xffff_ffff) { bad.push(format!("{}: sequence {seq:?}", k["name"])) }
                // Intentional diff: memo > 75 bytes needs OP_PUSHDATA1, so the OP_RETURN output is 8+1+(3+len) = 12+len bytes.
                // btc.ts counts 11+len (1 vB short); we charge the measured size, so change is exactly feeRate sats lower.
                let mut want = want;
                if k["memo"].as_str().unwrap().len() > 75 && want.output.len() == 3 {
                    let r = k["feeRate"].as_u64().unwrap();
                    want.output[1].value = bitcoin::Amount::from_sat(want.output[1].value.to_sat() - r);
                    assert_eq!(bitcoin::consensus::serialize(&want.output[2]).len(), 12 + k["memo"].as_str().unwrap().len());
                }
                if g.output != want.output { bad.push(format!("{}: outputs got {:?} want {:?}", k["name"], g.output.iter().map(|o| o.value.to_sat()).collect::<Vec<_>>(), want.output.iter().map(|o| o.value.to_sat()).collect::<Vec<_>>())) }
            }
        }
    }
    assert!(bad.is_empty(), "{} of {}:\n{}", bad.len(), c.as_array().unwrap().len(), bad[..bad.len().min(12)].join("\n"));
}
