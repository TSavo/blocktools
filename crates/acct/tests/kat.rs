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

fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
#[test]
fn atom_msgsend_matches_cosmjs() {
    // @cosmjs/proto-signing DirectSecp256k1Wallet.fromKey([1;32]) -> [2;32]; makeAuthInfoBytes/makeSignDoc/signDirect.
    use atom::*;
    let pubkey = atom::pubkey_of(&S1).unwrap();
    assert_eq!(atom::address(&pubkey), "cosmos10xcqpzrky6eff2g52qdye53xkk9jxkvrpq6uqr");
    let t = Send { from: address(&pubkey), to: "cosmos1a0qwuze2h85zw7nqpsj3ga0z9geyrgwphl8j6w".into(), denom: "uatom".into(), amount: 1234567, memo: "42".into(),
        pubkey, sequence: 7, fee: 5000, gas: 200000, chain_id: "cosmoshub-4".into(), account_number: 123456 };
    assert_eq!(t.body(), unhex("0a90010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e6412700a2d636f736d6f733130786371707a726b793665666632673532716479653533786b6b396a786b7672707136757172122d636f736d6f733161307177757a65326838357a77376e7170736a336761307a3967657972677770686c386a36771a100a057561746f6d12073132333435363712023432"));
    assert_eq!(t.auth_info(), unhex("0a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f12040a020801180712130a0d0a057561746f6d12043530303010c09a0c"));
    assert_eq!(Send::decode_sign_doc(&t.sign_doc()).unwrap(), t);
    assert!(t.sign(&[2; 32]).is_err());
    let sig = t.sign(&S1).unwrap();
    let raw = t.tx_raw(&sig);
    assert_eq!(raw, b64("CpcBCpABChwvY29zbW9zLmJhbmsudjFiZXRhMS5Nc2dTZW5kEnAKLWNvc21vczEweGNxcHpya3k2ZWZmMmc1MnFkeWU1M3hrazlqeGt2cnBxNnVxchItY29zbW9zMWEwcXd1emUyaDg1enc3bnFwc2ozZ2EwejlnZXlyZ3dwaGw4ajZ3GhAKBXVhdG9tEgcxMjM0NTY3EgI0MhJnClAKRgofL2Nvc21vcy5jcnlwdG8uc2VjcDI1NmsxLlB1YktleRIjCiEDG4TFVnsSZECZXT7VqroFZdceGDRgSBn/nBf16dXdB48SBAoCCAEYBxITCg0KBXVhdG9tEgQ1MDAwEMCaDBpA+sNvNt/ARWjxfrx1LC4t29i0j8CRASmrTMA9oWuq1gAuzuJPc96+3ETQcVcGZA3TuO7YYtKxOqGyRbiAg3MkXQ=="));
    assert_eq!(Send::txid(&raw), "EA467ABCA0270EBC959BEBC2A256A7592FD3C05F985CE04F4D5D49C54ED28F03");
    let (d, s2) = Send::decode_tx_raw(&raw, "cosmoshub-4", 123456).unwrap();
    assert!(d.verify(&s2));
    let (d, s2) = Send::decode_tx_raw(&raw, "cosmoshub-4", 123457).unwrap();
    assert!(!d.verify(&s2));
}
