//! Vectors produced by the chains' own SDKs (py-stellar-sdk 16.1.1, py-algorand-sdk), keys = ed25519 seeds [1;32] (source) and [2;32] (destination).
use blocktools_acct::*;
fn b64(s: &str) -> Vec<u8> { blocktools_core::b64::decode(s).unwrap() }
const S1: [u8; 32] = [1; 32];

#[test]
fn xlm_payment_and_merge_match_stellar_sdk() {
    use xlm::*;
    let src = decode_address("GCFIRY65OQE7DFP5KLNS2PF2LVZMUZYJX4OZIEQ36N2IQANUB5XVYOJR").unwrap();
    let dest = decode_address("GCATS5YOVB6ROX2WUNKGNQ2MP3GMXDMKSG2O4N5CLX3A6W4PZGZZI55U").unwrap();
    let cases = [
        (Op::Payment { dest, amount: 125_000_000 }, 123456789013i64,
         "AAAAAgAAAACKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXAAAAGQAAAAcvpkaFQAAAAEAAAAAAAAAAAAAAABrSdIAAAAAAgAAAAAAAAAqAAAAAQAAAAAAAAABAAAAAIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOUAAAAAAAAAAAHc1lAAAAAAAAAAAA=",
         "AAAAAgAAAACKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXAAAAGQAAAAcvpkaFQAAAAEAAAAAAAAAAAAAAABrSdIAAAAAAgAAAAAAAAAqAAAAAQAAAAAAAAABAAAAAIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOUAAAAAAAAAAAHc1lAAAAAAAAAAAG0D29cAAAAQC4Y2enTepaRAPTDF9gL0XCtVvFUOHpKqEGVs6qtgz2TG/qK11ktI0RU7wT+OZujGsGFxJZ1/xzJ32+GMIeHdgY=",
         "6f3d9d0e3539e9080977adf0f908e25c17de3f7ba9147a0e90da34ae7d7dc1c7"),
        (Op::Merge { dest }, 123456789014,
         "AAAAAgAAAACKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXAAAAGQAAAAcvpkaFgAAAAEAAAAAAAAAAAAAAABrSdIAAAAAAgAAAAAAAAAqAAAAAQAAAAAAAAAIAAAAAIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOUAAAAAAAAAAA=",
         "AAAAAgAAAACKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXAAAAGQAAAAcvpkaFgAAAAEAAAAAAAAAAAAAAABrSdIAAAAAAgAAAAAAAAAqAAAAAQAAAAAAAAAIAAAAAIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOUAAAAAAAAAAG0D29cAAAAQEW1M6jTiw0wfiIOYlcy9I7Lw9X4h16GPj+0izeLxofCpnbudnfYSxEXns6SXk659SxchQ6Kzb2b5z3gvX1Z9gw=",
         "bb1ba47d2afb037cc4184607db645d54efc82058e11e35e7b4894e06b6f82871"),
    ];
    for (op, seq, unsigned, signed, hash) in cases {
        let mut t = Tx { source: src, fee: 100, seq, time: Some((0, 1_800_000_000)), memo: Memo::Id(42), op, sigs: vec![] };
        assert_eq!(t.envelope(), b64(unsigned));
        assert_eq!(Tx::decode(&b64(unsigned)).unwrap(), t);
        let h: String = t.hash(PUBLIC).iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(h, hash);
        assert!(t.sign(&[2; 32], PUBLIC).is_err());
        t.sign(&S1, PUBLIC).unwrap();
        assert_eq!(t.envelope(), b64(signed));
        let d = Tx::decode(&b64(signed)).unwrap();
        assert!(d.verify(PUBLIC) && !d.verify(TESTNET));
    }
    let t = Tx { source: src, fee: 100, seq: 1, time: None, memo: Memo::Text("hello".into()), op: Op::Merge { dest }, sigs: vec![] };
    assert_eq!(Tx::decode(&t.envelope()).unwrap(), t);
}

#[test]
fn algo_pay_and_close_match_algosdk() {
    use algo::*;
    let snd = decode_address("RKEOHXLUBHYZL7KS3MWTZOS5OLFGOCN7DWKBEG7TOSEADNAPN5OOTUNSLE").unwrap();
    let rcv = decode_address("QE4XODVIPULV6VVDKRTMGTD6ZTFY3CURWTXDPIS56YHVXD6JWOKORTLPBU").unwrap();
    let gh: [u8; 32] = b64(MAINNET_GH).try_into().unwrap();
    let cases = [
        (12_500_000u64, None, b"bt".to_vec(),
         "iqNhbXTOAL68IKNmZWXNA+iiZnbOAmJaAKNnZW6sbWFpbm5ldC12MS4womdoxCDAYcTY/B293tLXYEvkVo4/bQQZh6w3veS2ILWrOSSK36Jsds4CYl3opG5vdGXEAmJ0o3JjdsQggTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Sjc25kxCCKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXKR0eXBlo3BheQ==",
         "gqNzaWfEQGD+adPqYelcfnDd4Hz7UPcTlDzkEZd/HsTkkpwGhFgaTcRakeYI/jFl/Mdql2JzXmD6bhZJEqwPZgoRqMNDQAOjdHhuiqNhbXTOAL68IKNmZWXNA+iiZnbOAmJaAKNnZW6sbWFpbm5ldC12MS4womdoxCDAYcTY/B293tLXYEvkVo4/bQQZh6w3veS2ILWrOSSK36Jsds4CYl3opG5vdGXEAmJ0o3JjdsQggTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5Sjc25kxCCKiOPddAnxlf1S2y08ul1yymcJvx2UEhvzdIgBtA9vXKR0eXBlo3BheQ==",
         "PY44AWANM2K4W6VEJMSFOIGTWJACARERZPW4PMMK5KSY46DJAJYA"),
        (0, Some(rcv), vec![],
         "iaVjbG9zZcQggTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5SjZmVlzQPoomZ2zgJiWgCjZ2VurG1haW5uZXQtdjEuMKJnaMQgwGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit+ibHbOAmJd6KNyY3bEIIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOUo3NuZMQgiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1ykdHlwZaNwYXk=",
         "gqNzaWfEQE5QP6/t0rTXTW1Ip8K2vgeO0/Aau98kOc9CNyZ33MH5RqVRoGf6twdG0w3610lFsTp4z5acTvchFoZBdh/pVg+jdHhuiaVjbG9zZcQggTl3Dqh9F19Wo1Rmw0x+zMuNipG07jeiXfYPW4/Js5SjZmVlzQPoomZ2zgJiWgCjZ2VurG1haW5uZXQtdjEuMKJnaMQgwGHE2Pwdvd7S12BL5FaOP20EGYesN73ktiC1qzkkit+ibHbOAmJd6KNyY3bEIIE5dw6ofRdfVqNUZsNMfszLjYqRtO43ol32D1uPybOUo3NuZMQgiojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1ykdHlwZaNwYXk=",
         "ZKIVMCE4N2INEZVB2VCJNA7QZVOJWIWDWD6HPBPDJ44E4QATNWKA"),
    ];
    for (amt, close, note, unsigned, signed, txid) in cases {
        let mut p = Pay { snd, rcv, amt, close, fee: 1000, fv: 40_000_000, lv: 40_001_000, gen: MAINNET_GEN.into(), gh, note, sig: None };
        assert_eq!(p.encode(), b64(unsigned));
        assert_eq!(Pay::decode(&b64(unsigned)).unwrap(), p);
        assert_eq!(p.txid(), txid);
        assert!(p.sign(&[2; 32]).is_err());
        p.sign(&S1).unwrap();
        assert_eq!(p.encode(), b64(signed));
        let d = Pay::decode(&b64(signed)).unwrap();
        assert!(d.verify());
        let mut bad = d.clone(); bad.amt += 1; assert!(!bad.verify());
    }
}

#[test]
fn fmt_units_trims() { assert_eq!(fmt_units(125_000_000, 7), "12.5"); assert_eq!(fmt_units(1_000_000, 6), "1"); assert_eq!(fmt_units(5, 6), "0.000005"); }
