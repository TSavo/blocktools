// External vectors, all from XRPLF/xrpl.js (public test seeds):
//  ripple-keypairs/test/fixtures/api.json, ripple-address-codec/test/index.test.ts,
//  xrpl/test/wallet/index.test.ts ("sign with lowercase hex data in memo").
use blocktools_xrp::*;
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02X}")).collect() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }

#[test] fn keypairs_api_json() {
    let (a, e) = decode_seed("sp5fghtJtpUorTwvof1NpDXAzNwf5").unwrap();
    assert_eq!(a, Algo::Secp256k1);
    let k = key_from_seed(a, &e);
    assert_eq!(hex(&k.public), "030D58EB48B4420B1F7B9DF55087E0E29FEF0E8468F9A6825B01CA2C361042D435");
    assert_eq!(k.address(), "rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1");
    assert_eq!(hex(&sign_bytes(&k, b"test message")), "30440220583A91C95E54E6A651C47BEC22744E0B101E2C4060E7B08F6341657DAD9BC3EE02207D1489C7395DB0188D3A56A977ECBA54B36FA9371B40319655B1B4429E33EF2D");
    let (a, e) = decode_seed("sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r").unwrap();
    assert_eq!(a, Algo::Ed25519);
    let k = key_from_seed(a, &e);
    assert_eq!(hex(&k.public), "ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63");
    assert_eq!(k.address(), "rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD");
    assert_eq!(hex(&sign_bytes(&k, b"test message")), "CB199E1BFD4E3DAA105E4832EEDFA36413E1F44205E4EFB9E27E826044C21E3E2E848BBC8195E8959BADF887599B7310AD1B7047EF11B682E0D068F73749750E");
}

#[test] fn x_addresses() {
    let cases = [("r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59", None, "X7AcgcsBL6XDcUb289X4mJ8djcdyKaB5hJDWMArnXr61cqZ", "T719a5UwUCnEs54UsxG9CJYYDhwmFCqkr7wxCcNcfZ6p5GZ"),
        ("r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59", Some(1), "X7AcgcsBL6XDcUb289X4mJ8djcdyKaGZMhc9YTE92ehJ2Fu", "T719a5UwUCnEs54UsxG9CJYYDhwmFCvbJNZbi37gBGkRkbE"),
        ("r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59", Some(14), "X7AcgcsBL6XDcUb289X4mJ8djcdyKaGo2K5VpXpmCqbV2gS", "T719a5UwUCnEs54UsxG9CJYYDhwmFCvqXVCALUGJGSbNV3x"),
        ("r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59", Some(11747), "X7AcgcsBL6XDcUb289X4mJ8djcdyKaLFuhLRuNXPrDeJd9A", "T719a5UwUCnEs54UsxG9CJYYDhwmFCziiNHtUukubF2Mg6t"),
        ("rLczgQHxPhWtjkaQqn3Q6UM8AbRbbRvs5K", None, "XVZVpQj8YSVpNyiwXYSqvQoQqgBttTxAZwMcuJd4xteQHyt", "TVVrSWtmQQssgVcmoMBcFQZKKf56QscyWLKnUyiuZW8ALU4"),
        ("rpZc4mVfWUif9CRoHRKKcmhu1nx2xktxBo", None, "X7YenJqxv3L66CwhBSfd3N8RzGXxYqPopMGMsCcpho79rex", "T77wVQzA8ntj9wvCTNiQpNYLT5hmhRsFyXDoMLqYC4BzQtV")];
    for (r, tag, x, t) in cases {
        let id = decode_classic(r).unwrap();
        assert_eq!(classic(&id), r);
        assert_eq!(x_address(&id, tag, false), x);
        assert_eq!(x_address(&id, tag, true), t);
        assert_eq!(decode_x(x), Some((id, tag, false)));
        assert_eq!(parse_destination(x).unwrap(), (id, tag));
    }
    assert!(parse_destination("T719a5UwUCnEs54UsxG9CJYYDhwmFCqkr7wxCcNcfZ6p5GZ").is_err());
}

const BLOB: &str = "120000228000000023000022B8240000000C2E0000270F201B00D5A36761400000000098968068400000000000000C73210305E09ED602D40AB1AF65646A4007C2DAC17CB6CDACDE301E74FB2D728EA057CF744730450221009C00E8439E017CA622A5A1EE7643E26B4DE9C808DE2ABE45D33479D49A4CEC66022062175BE8733442FA2A4D9A35F85A57D58252AE7B19A66401FE238B36FA28E5A081146C1856D0E36019EA75C56D7E8CBA6E35F9B3F71583147FB49CD110A1C46838788CD12764E3B0F837E0DDF9EA7C1F687474703A2F2F6578616D706C652E636F6D2F6D656D6F2F67656E657269637D0472656E74E1F1";

#[test] fn payment_decode_reencode_sign_hash() {
    let p = Payment::decode(&unhex(BLOB)).unwrap();
    assert_eq!(classic(&p.account), "rwiZ3q3D3QuG4Ga2HyGdq3kPKJRGctVG8a");
    assert_eq!(classic(&p.destination), "rUeEBYXHo8vF86Rqir3zWGRQ84W9efdAQd");
    assert_eq!((p.amount_drops, p.fee_drops, p.sequence, p.flags), (10_000_000, 12, 12, 2147483648));
    assert_eq!((p.source_tag, p.destination_tag, p.last_ledger_sequence), (Some(8888), Some(9999), Some(14000999)));
    assert_eq!(hex(&p.encode(false)), BLOB);
    assert!(verify(&p));
    assert_eq!(hex(&p.hash()), "41B9CB78D8E18A796CDD4B0BC6FB0EA19F64C4F25FDE23049197852CAB71D10D");
    // rebuild from fields, sign with the published test seed: must reproduce the exact blob
    let (a, e) = decode_seed("shd2nxpFD6iBRKWsRss2P4tKMWyy9").unwrap();
    let k = key_from_seed(a, &e);
    let mut q = Payment { txn_signature: None, signing_pub_key: vec![], ..p.clone() };
    sign(&mut q, &k).unwrap();
    assert_eq!(hex(&q.encode(false)), BLOB);
    // tampering breaks verification
    let mut bad = p.clone(); bad.amount_drops += 1; assert!(!verify(&bad));
}

#[test] fn refusals() {
    assert!(decode_seed("rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1").is_err());
    assert!(decode_seed("sp5fghtJtpUorTwvof1NpDXAzNwf6").is_err());
    let mut b = unhex(BLOB); b[2] = 0x07; // TransactionType != Payment
    assert!(Payment::decode(&b).is_err());
}
