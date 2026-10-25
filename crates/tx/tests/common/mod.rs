//! Test helper: a UTXO line that carries a synthetic previous transaction (public data), so
//! legacy inputs pass the prev-tx proof that tx-build / tx-sign require.
#![allow(dead_code)]
use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use blocktools_core::chains::{self, Chain};

/// Previous tx whose output `vout` pays `amount` to `addr`; returns (txid, raw hex).
pub fn prev_tx(c: &Chain, vout: u32, amount: u64, addr: &str) -> (String, String) {
    let spk = chains::address_to_script(c, addr).expect("addr");
    if blocktools_tx::pos::layout(c.name).is_some() {
        use blocktools_tx::pos::{layout, PIn, PosTx};
        let t = PosTx { layout: layout(c.name).unwrap(), time: 1_700_000_000, inputs: vec![PIn { txid: [7; 32], vout: 0, script_sig: vec![0x51], sequence: 0xffff_ffff }],
            outputs: vec![(amount, spk); vout as usize + 1], locktime: 0, speech: vec![] };
        return (t.txid_hex(), blocktools_core::hex_enc(t.serialize()))
    }
    let t = Transaction { version: Version::ONE, lock_time: LockTime::ZERO,
        input: vec![TxIn { previous_output: OutPoint::null(), script_sig: ScriptBuf::from_bytes(vec![1, 1]), sequence: Sequence::MAX, witness: Witness::new() }],
        output: vec![TxOut { value: Amount::from_sat(amount), script_pubkey: ScriptBuf::from_bytes(spk) }; vout as usize + 1] };
    (blocktools_tx::digest::txid_hex(&t, blocktools_tx::digest::Digest::for_chain(c)), blocktools_core::hex_enc(bitcoin::consensus::serialize(&t)))
}
/// A utxos.json line with `prev_tx`.
pub fn line(c: &Chain, vout: u32, amount: u64, addr: &str) -> String {
    let (t, h) = prev_tx(c, vout, amount, addr);
    format!("{{\"txid\":\"{t}\",\"vout\":{vout},\"amount\":{amount},\"address\":\"{addr}\",\"prev_tx\":\"{h}\"}}\n")
}
