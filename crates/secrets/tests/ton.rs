//! TON KAT: test-only mnemonic generated with tonsdk 1.0.x (`mnemonic_new(24)`, never funded);
//! expected wallet v4r2 workchain-0 addresses from tonsdk `Wallets.from_mnemonics(.., v4r2, 0)`.
#![cfg(feature = "ton")]
use blocktools_core::chains;
const M: &str = "elbow ramp code slogan cigar note auto solution leaf bunker process essence armed burger item blossom achieve normal vault whip switch artefact parrot coffee";

#[test] fn tonsdk_vector() {
    let k = chains::ton_mnemonic_key(M).unwrap();
    let r = chains::ton_row("", &k);
    assert_eq!(r.address, "UQCCZtVXlbxxKJbbZti9ESdAkizMyK_CTl0x65osWV1TnALb");
    let acct = chains::ton_decode(&r.address).unwrap();
    assert_eq!(chains::ton_address(&acct, true), "EQCCZtVXlbxxKJbbZti9ESdAkizMyK_CTl0x65osWV1TnF8e");
    let v = |a: &str| blocktools_core::validate::validate("ton", a).is_ok();
    assert!(v("EQCCZtVXlbxxKJbbZti9ESdAkizMyK_CTl0x65osWV1TnF8e") && v(&r.address));
    assert!(!v("EQCCZtVXlbxxKJbbZti9ESdAkizMyK_CTl0x65osWV1TnF8f"));
    // one changed word: not a TON mnemonic (or a different key)
    let bad = M.replacen(M.split(' ').next().unwrap(), "zoo", 1);
    assert!(chains::ton_mnemonic_key(&bad).map_or(true, |b| *b != *k));
    assert!(chains::ton_mnemonic_key("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").is_err());
}
