//! Firo EXX and PIVX EXM exchange addresses, PIVX S... staking addresses (validate + detect only).
//! Firo pair: firoorg/firo wiki "Information for Exchanges" mainnet examples (same key, published).
//! PIVX: version bytes from PIVX-Project/PIVX src/chainparams.cpp (EXCHANGE_ADDRESS 01 b9 a2,
//! STAKING_ADDRESS 63) applied to the Firo example's hash160 with an independent Python base58check
//! (hashlib only); PIVX publishes no literal exchange/staking address vector.
use blocktools::address::{detect, validate, AddrKind};

#[test]
fn firo_exx_wiki_pair() {
    assert_eq!(validate("firo", "aGvQU2rzQpZpWGyYoFR9Fc7aVsECU9UPvK"), Ok(AddrKind::P2pkh));
    assert_eq!(validate("firo", "EXXWfijX9yuZDpkF6hUDvBjxFzrL98nFYsCa"), Ok(AddrKind::Exchange));
    assert_eq!(detect("EXXWfijX9yuZDpkF6hUDvBjxFzrL98nFYsCa"), vec![("firo", AddrKind::Exchange)]);
    // one character changed: checksum fails
    assert!(validate("firo", "EXXWfijX9yuZDpkF6hUDvBjxFzrL98nFYsCb").is_err());
    // Firo testnet EXT (01 b9 b1) is not mainnet
    assert!(validate("firo", "EXTVHgtSB6okb4ZuhqE2azthY8ZHZhh1qd2B").is_err());
    assert!(detect("EXTVHgtSB6okb4ZuhqE2azthY8ZHZhh1qd2B").is_empty());
}

#[test]
fn pivx_exchange_and_staking() {
    assert_eq!(validate("pivx", "DMM3GPN1VSUFyjj3XS6a35xfmdq9UzStAN"), Ok(AddrKind::P2pkh));
    assert_eq!(validate("pivx", "EXMTDe7ohnA3dvJQcXrjbDcpTL7ihZ4YjpLa"), Ok(AddrKind::Exchange));
    assert_eq!(validate("pivx", "SdVwkyCWvPmAy3KuLH663DwdYHLH32ye2S"), Ok(AddrKind::Staking));
    assert_eq!(detect("EXMTDe7ohnA3dvJQcXrjbDcpTL7ihZ4YjpLa"), vec![("pivx", AddrKind::Exchange)]);
    assert!(detect("SdVwkyCWvPmAy3KuLH663DwdYHLH32ye2S").contains(&("pivx", AddrKind::Staking)));
    // the exchange prefix of one chain is not valid on the other
    assert!(validate("pivx", "EXXWfijX9yuZDpkF6hUDvBjxFzrL98nFYsCa").is_err());
    assert!(validate("firo", "EXMTDe7ohnA3dvJQcXrjbDcpTL7ihZ4YjpLa").is_err());
}

#[test]
fn no_script_for_exchange_or_staking() {
    // EXX/EXM need OP_EXCHANGEADDR and S... a P2CS script: blocktools builds neither.
    for (c, a) in [("firo", "EXXWfijX9yuZDpkF6hUDvBjxFzrL98nFYsCa"), ("pivx", "EXMTDe7ohnA3dvJQcXrjbDcpTL7ihZ4YjpLa"), ("pivx", "SdVwkyCWvPmAy3KuLH663DwdYHLH32ye2S")] {
        assert!(blocktools::chains::address_to_script(blocktools::chains::chain(c).unwrap(), a).is_none(), "{a}");
    }
}
