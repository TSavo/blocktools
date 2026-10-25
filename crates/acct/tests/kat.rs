//! Vectors produced by the chains' own SDKs (py-stellar-sdk 16.1.1, py-algorand-sdk), keys = ed25519 seeds [1;32] (source) and [2;32] (destination).
use blocktools_acct::*;
fn b64(s: &str) -> Vec<u8> { blocktools_core::b64::decode(s).unwrap() }
const S1: [u8; 32] = [1; 32];
fn hex(b: &[u8]) -> String { blocktools_core::hex_enc(b) }

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

// tonsdk 1.0.15 WalletV4ContractR2, key [1;32] -> key [2;32]'s wallet, seqno 5, valid_until 1767225600, to_boc(False) (/tmp/vec/ton.py).
#[test]
fn ton_v4r2_matches_tonsdk() {
    use blocktools_acct::ton;
    let src = "UQDvr_S6wiD4iy6Y6x2c_8yjv-O2bs4xp9bFiQ0w39evpYZV";
    let (wallet, _) = ton::parse_address(src).unwrap();
    let pk = blocktools_acct::ed_sign(&[1; 32], b"").0;
    assert_eq!(blocktools_core::chains::ton_v4r2_account(&pk), wallet);
    let cases = [
        ("UQAaDUFwU_NsWLK1DA5VSF80Kvlj55rB-P6K-3wxAjuMOdQl", 1_500_000_000u128, ton::MODE_PAY, Some("42"),
         "77a057991b08a34eb83d38cbf34cc220f55011c7701962baf08d95d3813abc32", "5c166d6404936aa257cd9b49985af86f1c61428907fbd96cb7e0728072433958",
         "te6cckEBAgEAsAAB4YgB31/pdYRB8RZdMdY7Of+ZR3/HbN2cY0+tixIaYb+vX0oC4DnmBK3Xbv0PF4xWODy1x9N0Rq24MYojMh3TvGtp6ItF2mrZdCPnBxL2MyOHIvcpGvdg0Ha7vo8HSTHMdEDAQU1NGLtKrcgAAAAAKAAcAQB0QgANBqC4Kfm2LFlahgcqpC+aFXyx881g/H9Ffb4YgR3GHKLLQXgAAAAAAAAAAAAAAAAAAAAAAAA0Mnt4ook="),
        ("EQAaDUFwU_NsWLK1DA5VSF80Kvlj55rB-P6K-3wxAjuMOYng", 0, ton::MODE_SWEEP, None,
         "f85d605def9adb7403a3f2d99be557a914b148bf64c4761bcba6a3d3a2fcbf2b", "42ff468128bff5dea49c820ad9c42db8cb43a86b16b9effa8e461308ceee0c41",
         "te6cckEBAgEApgAB4YgB31/pdYRB8RZdMdY7Of+ZR3/HbN2cY0+tixIaYb+vX0oDqbA3thDZPkxSQqYbPH5FgtYyYQSDkfED1yc3NV/TeYuP6pMI4V5YgPdcONMhxOBgT+NwbZ2gRl6yYEZOnjcYUU1NGLtKrcgAAAAAKAQEAQBgYgANBqC4Kfm2LFlahgcqpC+aFXyx881g/H9Ffb4YgR3GHIAAAAAAAAAAAAAAAAAAzM64ww=="),
    ];
    for (to, amount, mode, c, sh, mh, b) in cases {
        let (to, bounce) = ton::parse_address(to).unwrap();
        let mut t = ton::Transfer { wallet, wallet_id: ton::WALLET_ID, valid_until: 1767225600, seqno: 5, mode, to, bounce, amount, comment: c.map(String::from), sig: [0; 64] };
        assert_eq!(hex(&t.signing_hash()), sh);
        let u = t.encode();
        assert_eq!(ton::Transfer::decode(&u).unwrap(), t);
        t.sign(&[1; 32]).unwrap();
        assert_eq!(hex(&t.msg_hash()), mh);
        assert_eq!(blocktools_core::b64::encode(&t.encode()), b);
        let d = ton::Transfer::decode(&blocktools_core::b64::decode(b).unwrap()).unwrap();
        assert!(d.verify(&pk) && d == t);
        assert!(t.clone().sign(&[2; 32]).is_err());
    }
}

// pycardano 0.19.2 (/tmp/vec/ada.py): "abandon x11 about", m/1852'/1815'/0'/0/0 -> 0/1, two inputs, fee 172221, ttl 150000000.
#[test]
fn ada_matches_pycardano() {
    use blocktools_acct::ada;
    let m = blocktools_core::chains::ada_icarus_master("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "").unwrap();
    let rows = blocktools_core::chains::ada_rows(&m, 2);
    let (src, dst) = ("addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv", "addr1qyz85693g4fr8c55mfyxhae8j2u04pydxrgqr73vmwpx3a8927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqu2c0f9");
    assert_eq!((rows[0].address.as_str(), rows[1].address.as_str()), (src, dst));
    let xk: [u8; 64] = blocktools_core::hex_dec(&rows[0].secret).unwrap().try_into().unwrap();
    let (s, d) = (ada::decode_address(src).unwrap(), ada::decode_address(dst).unwrap());
    assert_eq!(ada::payment_key_hash(&s).unwrap(), &ada::key_hash(&ada::ext_pub(&xk))[..]);
    let ins = vec![(blocktools_core::hex_dec("1ca4b3296f0b31b9f584e06c4dfc59119ecc408ba0395047c8d616f4c88a20c6").unwrap().try_into().unwrap(), 0),
                   (blocktools_core::hex_dec("87dac51506d06652be02110bd1e34c2156faa5fa37253dc885da93b840b4bdec").unwrap().try_into().unwrap(), 1)];
    let pay_tx = "84a400828258201ca4b3296f0b31b9f584e06c4dfc59119ecc408ba0395047c8d616f4c88a20c60082582087dac51506d06652be02110bd1e34c2156faa5fa37253dc885da93b840b4bdec01018282583901047a68b1455233e294da486bf72792b8fa848d30d001fa2cdb8268f4e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d1761a0016e360825839010fdc780023d8be7c9ff3a6bdc0d8d3b263bd0cc12448c40948efbf42e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d1761a007f1263021a0002a0bd031a08f0d180a100818258207ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a5840502db032be107f0e8b98e1df645f421427796ad80c8589b723dd077935b470b28582cc8212104f44a7e4758da93d308de7b6d1e1ccab3adf2e9794105783fb03f5f6";
    let sweep_tx = "84a400828258201ca4b3296f0b31b9f584e06c4dfc59119ecc408ba0395047c8d616f4c88a20c60082582087dac51506d06652be02110bd1e34c2156faa5fa37253dc885da93b840b4bdec01018182583901047a68b1455233e294da486bf72792b8fa848d30d001fa2cdb8268f4e557890352095f1cf6fd2b7d1a28e3c3cb029f48cf34ff890a28d1761a0095f5c3021a0002a0bd031a08f0d180a100818258207ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a5840050d5d1d6cd669fe4730bdde9d69b5844b96a615cde0bea5dc92f7ed3d1110d734541e473f018a6abec03df2bdf25bed5e330042672c0086bf011868f5fc3f08f5f6";
    for (outs, txid, raw) in [(vec![(d.clone(), 1_500_000), (s.clone(), 8_327_779)], "6a43c08a66cd05f196353499e9f8851847a097f6b0e20d0ea3f987bdc5e83da3", pay_tx),
                              (vec![(d.clone(), 9_827_779)], "3fad6a20aea89730f508185de6cc28fe03fcad4f09c681b54368439abf002a5e", sweep_tx)] {
        let mut t = ada::Tx { inputs: ins.clone(), outputs: outs, fee: 172_221, ttl: 150_000_000, wit: None };
        assert_eq!(hex(&t.txid()), txid);
        assert_eq!(ada::Tx::decode(&t.encode()).unwrap(), t);
        t.sign(&xk);
        assert_eq!(hex(&t.encode()), raw);
        let back = ada::Tx::decode(&blocktools_core::hex_dec(raw).unwrap()).unwrap();
        assert!(back.verify() && back == t);
        assert!(t.min_fee() <= t.fee);
    }
}

/// Polkadot Asset Hub: call + signing payload + whole signed extrinsic == py-substrate-interface 1.7.11
/// (metadata-driven, spec 2005000 / tx 15), abandon..about sr25519 -> //Bob. Not an official vector: UNVERIFIED.
#[test]
fn dot_assethub_matches_substrate_interface() {
    use blocktools_acct::dot::*;
    let mini = blocktools_core::chains::substrate_mini_secret("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "").unwrap();
    let from = parse_address("13KVd4f2a4S5pLp4gTTFezyXdPWx27vQ9vS6xBXJ9yWVd7xo").unwrap();
    let to = parse_address("14E5nqKAp3oAJcmzgZhUD2RcptBeUBScxKHgJKU4HPNcKVf3").unwrap();
    let mut t = Transfer { from, to, kind: Kind::Pay(12345678901), era: None, nonce: 7, tip: 0, spec: SPEC, tx_version: TX_VERSION, genesis: GENESIS, sig: None };
    assert_eq!(hex(&t.call()), "0a03008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4807351cdcdf02");
    assert_eq!(hex(&t.signing_payload()), "0a03008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4807351cdcdf02001c00000008981e000f00000068d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f68d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f00");
    let si = unhex("4502840066933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed797201bedf4fd243e535a51089084da5dc43716f9d6e8fb97ab2df8b9fe28c0d2d097e9a5a92a760252d3730ebaba89fc5f6bc6097728bbe7782883da512683dff8e8d001c0000000a03008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4807351cdcdf02");
    let d = Transfer::decode(&si, SPEC, TX_VERSION, GENESIS, None).unwrap();
    assert!(d.verify(), "substrate-interface signature verifies");
    assert_eq!(d.encode(), si);
    t.sign(&mini).unwrap(); assert!(t.verify()); assert_eq!(Transfer { sig: None, ..t.clone() }, Transfer { sig: None, ..d.clone() });
    let mut s = Transfer { kind: Kind::Sweep, ..t.clone() }; s.sig = None;
    assert_eq!(hex(&s.signing_payload()), "0a04008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4800001c00000008981e000f00000068d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f68d56f15f85d3136970ec16946040bc1752654e906147f7e43e9d539d7c3de2f00");
    let si2 = unhex("3102840066933bd1f37070ef87bd1198af3dacceb095237f803f3d32b173e6b425ed79720190e23a4694704560c2adb4840dea5edee372800845b33dcb853252fd69bb066c4f573eb88d5914b5feb69bccd820e1bbd4affd10467f02ec2b89a533927c8885001c0000000a04008eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a4800");
    assert!(Transfer::decode(&si2, SPEC, TX_VERSION, GENESIS, None).unwrap().verify());
    assert_eq!(hex(&era_bytes(&Some((64, 12345678, [0; 32])))), "e500");
    let mut w = t.clone(); w.nonce = 8; assert!(!w.verify());
    assert!(t.clone().sign(&[1; 32]).is_err());
}
