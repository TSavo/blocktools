//! CashAddr (Bitcoin Cash / eCash) encode/decode, legacy conversion, and address -> output script
//! for any UTXO chain (CashAddr accepted on bch). Public data only.
pub use blocktools_core::cashaddr::{decode, encode};
/// CashAddr -> legacy base58 (bch versions 0/5).
pub fn to_legacy(addr: &str) -> Result<String, &'static str> {
    let (_, t, h) = decode(addr, "bitcoincash")?; if h.len() != 20 { return Err("bad_hash_length") }
    let c = blocktools_core::chains::chain("bch").ok_or("unknown_chain")?;
    let s: Vec<u8> = match t { 0 => [&[0x76, 0xa9, 0x14][..], &h, &[0x88, 0xac]].concat(), 1 => [&[0xa9, 0x14][..], &h, &[0x87]].concat(), _ => return Err("bad_type") };
    blocktools_core::chains::script_to_address(c, &s).map(|x| x.1).ok_or("bad_type")
}
/// Legacy base58 (bch) -> CashAddr with `prefix` ("bitcoincash", "bchtest", "ecash").
pub fn from_legacy(addr: &str, prefix: &str) -> Result<String, &'static str> {
    let c = blocktools_core::chains::chain("bch").ok_or("unknown_chain")?;
    match blocktools_core::chains::address_to_script(c, addr).ok_or("bad_address")?.as_slice() {
        [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] => encode(prefix, 0, h),
        [0xa9, 0x14, h @ .., 0x87] => encode(prefix, 1, h),
        _ => Err("bad_address"),
    }
}
/// Output script for a destination on `chain`. bch also accepts CashAddr (with or without prefix).
pub fn address_to_script(chain: &str, addr: &str) -> Result<Vec<u8>, &'static str> {
    if chain == "zec" { return blocktools_tx::zcash::address_to_script(addr).ok_or("bad_address") }
    let c = blocktools_core::chains::chain(chain).ok_or("unknown_chain")?;
    if chain == "bch" { if let Ok(l) = to_legacy(addr) { return blocktools_core::chains::address_to_script(c, &l).ok_or("bad_address") } }
    blocktools_core::chains::address_to_script(c, addr).ok_or("bad_address")
}
/// Standard output script -> (kind, address). None for non-standard.
pub fn script_to_address(chain: &str, s: &[u8]) -> Result<Option<(&'static str, String)>, &'static str> {
    if chain == "zec" { return Ok(blocktools_tx::zcash::script_to_address(s)) }
    Ok(blocktools_core::chains::script_to_address(blocktools_core::chains::chain(chain).ok_or("unknown_chain")?, s))
}

#[cfg(test)]
mod t {
    use super::*;
    // Vectors: the CashAddr spec (bitcoincashorg spec/cashaddr.md) and its legacy-conversion table.
    #[test] fn spec() {
        assert_eq!(to_legacy("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a").unwrap(), "1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu");
        assert_eq!(to_legacy("qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy").unwrap(), "1KXrWXciRDZUpQwQmuM1DbwsKDLYAYsVLR");
        assert_eq!(to_legacy("bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq").unwrap(), "3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC");
        assert_eq!(from_legacy("1BpEi6DfDAUFd7GtittLSdBeYJvcoaVggu", "bitcoincash").unwrap(), "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a");
        assert_eq!(from_legacy("3CWFddi6m4ndiGyKqzYvsFYagqDLPVMTzC", "bitcoincash").unwrap(), "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq");
        let h = crate::hex_dec("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9").unwrap();
        assert_eq!(encode("bitcoincash", 0, &h).unwrap(), "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2");
        assert_eq!(encode("bchtest", 1, &h).unwrap(), "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t");
        assert_eq!(decode("bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg3", "").unwrap_err(), "bad_checksum");
        assert_eq!(decode("bitcoincash:Qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2", "").unwrap_err(), "mixed_case");
        assert_eq!(crate::hex_enc(address_to_script("bch", "qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a").unwrap()), "76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac");
        assert_eq!(script_to_address("btc", &address_to_script("btc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()).unwrap().unwrap().0, "p2wpkh");
    }
}
