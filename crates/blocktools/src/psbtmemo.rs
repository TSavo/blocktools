//! Unsigned PSBT with an optional OP_RETURN memo (THORChain inbound style). Output order is
//! VOUT0 = `to` (vault), VOUT1 = change (when above dust), last = `OP_RETURN <memo>`, per THORChain's
//! "Sending Transactions" UTXO checklist (dev.thorchain.org/concepts/sending-transactions.html):
//! vault as VOUT0, change to VIN0 in a subsequent output (e.g. VOUT1), memo OP_RETURN typically VOUT2. Built on blocktools-tx `build_btc`, then the memo output is inserted and the fee re-checked.
use bitcoin::{Amount, ScriptBuf, TxOut};
use blocktools_core::chains;
use blocktools_tx::build::{self, BtcPlan};
use serde_json::{json, Value};

pub fn op_return(memo: &[u8]) -> Result<Vec<u8>, &'static str> {
    if memo.len() > 80 { return Err("memo_length") }
    let mut s = vec![0x6a]; if memo.len() <= 75 { s.push(memo.len() as u8) } else { s.extend([0x4c, memo.len() as u8]) } s.extend_from_slice(memo); Ok(s)
}
/// `send` None = sweep everything to `to`. Returns {psbt (base64), fee, vsize, outputs:[{address, script, value}]}.
pub fn build(chain: &str, utxos_jsonl: &str, to: &str, send: Option<u64>, change: Option<&str>, fee_rate: u64, memo: &[u8]) -> Result<Value, String> {
    let c = chains::supported(chain).ok_or("unknown_or_unverified_chain")?;
    if !matches!(c.enc, chains::Enc::Utxo { .. }) { return Err("not_utxo_chain".into()) }
    let opr = if memo.is_empty() { None } else { Some(op_return(memo)?) };
    let utxos = build::parse_utxos(c, utxos_jsonl)?;
    let mut p = build::build_btc(c, utxos, &BtcPlan { to: to.into(), send, change: change.map(String::from), fee_rate, rbf: true, dust: 546, locktime: 0 })?;
    // Size only the inputs build_btc selected (was: every supplied UTXO, which overcharged by 68 vB per unused input).
    let kinds: Vec<&str> = p.inputs.iter().map(|i| i.witness_utxo.as_ref().and_then(|o| chains::script_to_address(c, o.script_pubkey.as_bytes())).map(|x| x.0).unwrap_or("unknown")).collect();
    let tx = &mut p.unsigned_tx;
    let had_change = tx.output.len() == 2;
    if let Some(opr) = opr { tx.output.push(TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(opr) }) }
    let vsize = 11 + kinds.iter().map(|k| build::in_vb(k)).sum::<u64>() + tx.output.iter().map(|o| build::out_vb(o.script_pubkey.as_bytes())).sum::<u64>();
    let total_in: u64 = p.inputs.iter().map(|i| i.witness_utxo.as_ref().map(|o| o.value.to_sat()).unwrap_or(0)).sum();
    let out = |t: &bitcoin::Transaction| t.output.iter().map(|o| o.value.to_sat()).sum::<u64>();
    let need = vsize * fee_rate;
    let have = total_in - out(tx);
    if have < need {
        let short = need - have;
        // Take the memo's fee from change (last output when present), else from the swept output.
        let idx = if had_change { 1 } else if send.is_none() { 0 } else { return Err("memo fee not covered: add inputs or lower the amount".into()) };
        let v = tx.output[idx].value.to_sat().checked_sub(short).filter(|&v| v >= 546).ok_or("memo fee leaves dust")?;
        tx.output[idx].value = Amount::from_sat(v);
    }
    while p.outputs.len() < p.unsigned_tx.output.len() { p.outputs.push(Default::default()) }
    let fee = total_in - out(&p.unsigned_tx);
    let outs: Vec<Value> = p.unsigned_tx.output.iter().map(|o| json!({"address": chains::script_to_address(c, o.script_pubkey.as_bytes()).map(|x| x.1), "script": crate::hex_enc(o.script_pubkey.as_bytes()), "value": o.value.to_sat().to_string()})).collect();
    Ok(json!({"psbt": blocktools_core::b64::encode(&p.serialize()), "fee": fee.to_string(), "vsize": vsize, "outputs": outs}))
}

#[cfg(test)]
mod t {
    pub const U: &str = r#"{"txid":"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9","vout":0,"amount":100000,"address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}"#;
    // Expected PSBTs built independently with embit (same inputs/outputs) and compared byte-for-byte.
    pub const P1: &str = "cHNidP8BALACAAAAAcmXpeVuEEEC+iCcaoUt2QZgogstnDUkI+3OJYV/zTcEAAAAAAD9////A1DDAAAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOJUvwAAAAAAABYAFJyQ+TTqUfoPZQQXcEPgkI2mkpmDAAAAAAAAAAA2ajQ9OkVUSC5FVEg6MHgwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAxAAAAAAABAR+ghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAAAA==";
    pub const P2: &str = "cHNidP8BAF8CAAAAAcmXpeVuEEEC+iCcaoUt2QZgogstnDUkI+3OJYV/zTcEAAAAAAD9////AjmEAQAAAAAAFgAUwM681sPTyox13F7GLr5VMw75EOIAAAAAAAAAAARqAmhpAAAAAAABAR+ghgEAAAAAABYAFHUedugZkZbUVJQcRdGzoyPxQzvWAAAA";
    #[test] fn embit_parity() {
        let v = super::build("btc", U, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", Some(50000), Some("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"), 5, b"=:ETH.ETH:0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(v["psbt"], P1); assert_eq!(v["fee"], "1020"); assert_eq!(v["vsize"], 204);
        let v = super::build("btc", U, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", None, None, 5, b"hi").unwrap();
        assert_eq!(v["psbt"], P2); assert_eq!(v["fee"], "615");
        assert!(super::build("btc", U, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", None, None, 5, &[0; 81]).is_err());
        // Empty memo = no OP_RETURN: plain [to, change].
        let v = super::build("btc", U, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", Some(50000), Some("bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"), 5, b"").unwrap();
        assert_eq!(v["outputs"].as_array().unwrap().len(), 2); assert_eq!(v["vsize"], 141); assert_eq!(v["fee"], "705");
    }
}
