//! Known-answer tests from public standards. Sources per block.
use blocktools_evm::{abi, api, create, hex, keccak, parse_address, sig::Sig, unhex};
use serde_json::{json, Value};

fn sel(s: &str) -> String { hex(&Sig::parse(s).unwrap().selector()) }

#[test]
fn keccak_empty() {
    // Keccak-256("") (Ethereum Yellow Paper; KECCAK_EMPTY in geth)
    assert_eq!(hex(&keccak(b"")), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}

#[test]
fn erc20_erc721_selectors_and_topics() {
    // EIP-20 / EIP-721 published interface ids and selectors
    for (s, h) in [
        ("transfer(address,uint256)", "0xa9059cbb"), ("balanceOf(address)", "0x70a08231"),
        ("approve(address,uint256)", "0x095ea7b3"), ("transferFrom(address,address,uint256)", "0x23b872dd"),
        ("totalSupply()", "0x18160ddd"), ("allowance(address,address)", "0xdd62ed3e"),
        ("decimals()", "0x313ce567"), ("symbol()", "0x95d89b41"), ("name()", "0x06fdde03"),
        ("setApprovalForAll(address,bool)", "0xa22cb465"), ("safeTransferFrom(address,address,uint256)", "0x42842e0e"),
        ("supportsInterface(bytes4)", "0x01ffc9a7"),
        // Solidity built-in revert payloads
        ("Error(string)", "0x08c379a0"), ("Panic(uint256)", "0x4e487b71"),
        // Solidity ABI spec examples
        ("baz(uint32,bool)", "0xcdcd77c0"), ("bar(bytes3[2])", "0xfce353f6"), ("sam(bytes,bool,uint256[])", "0xa5643bf2"),
        ("f(uint256,uint32[],bytes10,bytes)", "0x8be65246"), ("g(uint256[][],string[])", "0x2289b18c"),
    ] { assert_eq!(sel(s), h, "{s}"); }
    // human-readable forms canonicalise to the same selector
    assert_eq!(sel("function transfer(address to, uint amount) external returns (bool)"), "0xa9059cbb");
    let t = Sig::parse("event Transfer(address indexed from, address indexed to, uint256 value)").unwrap();
    assert_eq!(hex(&t.hash()), "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef");
    let a = Sig::parse("event Approval(address indexed owner, address indexed spender, uint value)").unwrap();
    assert_eq!(hex(&a.hash()), "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925");
    // tuples: canonical (..) form
    assert_eq!(Sig::parse("f(tuple(uint a, address b)[] xs, bytes)").unwrap().canonical(), "f((uint256,address)[],bytes)");
}

#[test]
fn spec_encodings() {
    // Solidity ABI spec, "Examples"
    let r = api::encode_call("baz(uint32,bool)", &[json!("69"), json!(true)]).unwrap();
    assert_eq!(r["data"], format!("0xcdcd77c0{:064x}{:064x}", 69, 1));
    let r = api::encode_call("sam(bytes,bool,uint256[])", &[json!(hex(b"dave")), json!(true), json!(["1", "2", "3"])]).unwrap();
    let w = |x: u64| format!("{x:064x}");
    let dave = format!("{:0<64}", "64617665");
    assert_eq!(r["data"], format!("0xa5643bf2{}{}{}{}{}{}{}{}{}", w(0x60), w(1), w(0xa0), w(4), dave, w(3), w(1), w(2), w(3)));
    let r = api::encode_call("bar(bytes3[2])", &[json!(["0x616263", "0x646566"])]).unwrap();
    assert_eq!(r["data"], format!("0xfce353f6{:0<64}{:0<64}", "616263", "646566"));
}

#[test]
fn eth_abi_corpus_roundtrip() {
    // 400 random cases encoded by eth_abi (independent implementation): encode must match bytes, decode must match values.
    let c: Value = serde_json::from_str(include_str!("data/abi-corpus.json")).unwrap();
    let mut n = 0;
    for case in c["cases"].as_array().unwrap() {
        let ps = abi::parse_types(case["types"].as_str().unwrap()).unwrap();
        let args = case["args"].as_array().unwrap();
        let data = unhex(case["data"].as_str().unwrap()).unwrap();
        assert_eq!(hex(&abi::encode(&ps, args).unwrap()), case["data"].as_str().unwrap(), "encode {}", case["types"]);
        assert_eq!(&abi::decode(&ps, &data).unwrap(), args, "decode {}", case["types"]);
        n += 1;
    }
    assert_eq!(n, 400);
}

#[test]
fn strict_decoder_refuses_malformed() {
    let p = |s| abi::parse_types(s).unwrap();
    let d = |s: &str| unhex(s).unwrap();
    let w1 = format!("{:064x}", 1);
    assert!(abi::decode(&p("(uint8)"), &d(&format!("{:064x}", 256))).is_err(), "dirty uint8");
    assert!(abi::decode(&p("(bool)"), &d(&format!("{:064x}", 2))).is_err(), "bool 2");
    assert!(abi::decode(&p("(address)"), &d(&format!("01{:062x}", 0))).is_err(), "dirty address");
    assert!(abi::decode(&p("(int8)"), &d(&format!("{:064x}", 0x80))).is_err(), "int8 not sign-extended");
    assert_eq!(abi::decode(&p("(int8)"), &d(&format!("{}80", "f".repeat(62)))).unwrap(), vec![json!("-128")]);
    assert!(abi::decode(&p("(bytes)"), &d(&format!("{:064x}", 0x1000))).is_err(), "offset out of bounds");
    assert!(abi::decode(&p("(bytes)"), &d(&format!("{:064x}{:064x}", 32, 100))).is_err(), "length past end");
    assert!(abi::decode(&p("(uint256[])"), &d(&format!("{:064x}{:064x}", 32, u32::MAX))).is_err(), "huge array length");
    assert!(abi::decode(&p("(string)"), &d(&format!("{:064x}{:064x}{:0<64}", 32, 1, "ff"))).is_err(), "bad utf8");
    assert!(abi::decode(&p("(bytes)"), &d(&format!("{:064x}{:064x}{:0<62}01", 32, 1, "aa"))).is_err(), "dirty tail padding");
    assert!(abi::decode(&p("(uint256)"), &d(&w1[..62])).is_err(), "short");
    // pointer aliasing: many array elements pointing at the same big array -> capped, not exponential
    let mut s = format!("{:064x}{:064x}", 32, 3000);
    for _ in 0..3000 { s += &format!("{:064x}", 0); }
    let r = abi::decode(&p("(uint256[][][])"), &d(&s));
    assert!(r.is_ok() || r.unwrap_err() == "too_many_values");
    assert!(Sig::parse("f(uint7)").is_err() && Sig::parse("f(bytes33)").is_err() && Sig::parse("f(uint256[0])").is_err());
    assert!(Sig::parse("f(uint256").is_err() && Sig::parse("1f()").is_err());
}

#[test]
fn eip1014_create2_vectors() {
    // EIP-1014 "Examples", all seven
    let z = "0x0000000000000000000000000000000000000000";
    let s0 = format!("0x{:064x}", 0);
    for (addr, salt, code, want) in [
        (z, s0.as_str(), "0x00", "0x4D1A2e2bB4F88F0250f26Ffff098B0b30B26BF38"),
        ("0xdeadbeef00000000000000000000000000000000", s0.as_str(), "0x00", "0xB928f69Bb1D91Cd65274e3c79d8986362984fDA3"),
        ("0xdeadbeef00000000000000000000000000000000", "0x000000000000000000000000feed000000000000000000000000000000000000", "0x00", "0xD04116cDd17beBE565EB2422F2497E06cC1C9833"),
        (z, s0.as_str(), "0xdeadbeef", "0x70f2b2914A2a4b783FaEFb75f459A580616Fcb5e"),
        ("0x00000000000000000000000000000000deadbeef", "0x00000000000000000000000000000000000000000000000000000000cafebabe", "0xdeadbeef", "0x60f3f640a8508fC6a86d45DF051962668E1e8AC7"),
        ("0x00000000000000000000000000000000deadbeef", "0x00000000000000000000000000000000000000000000000000000000cafebabe", "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "0x1d8bfDC5D46DC4f61D6b6115972536eBE6A8854C"),
        (z, s0.as_str(), "0x", "0xE33C0C7F7df4809055C3ebA6c09CFe4BaF1BD9e0"),
    ] {
        let r = api::create_json(&json!({"deployer": addr, "salt": salt, "init_code": code})).unwrap();
        assert_eq!(r["address"], want, "{addr} {salt} {code}");
    }
}

#[test]
fn create_vectors() {
    // Widely published CREATE example (deployer 0x6ac7…dbf0, nonces 0..3), plus nonce encodings 0x7f/0x80 (RLP boundary)
    let d = parse_address("0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0").unwrap();
    for (n, want) in [(0, "cd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"), (1, "343c43a37d37dff08ae8c4a11544c718abb4fcf8"),
                      (2, "f778b86fa74e846c4f0a1fbd1335fe81c00a0c91"), (3, "fffd933a0bc612844eaf0c6fe3e5b8e9b6c1d19c")] {
        assert_eq!(&hex(&create::create(&d, n))[2..], want);
    }
}

#[test]
fn eip55_vectors() {
    // EIP-55 test cases
    for a in ["0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
              "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"] {
        let b = parse_address(a).unwrap();
        assert_eq!(blocktools_evm::checksum_address(&b), a);
    }
    assert!(parse_address("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD").is_err(), "bad checksum refused");
}
