//! Strict ABI decoder: malformed-input cases (r/ethdev feedback). Every case must be REJECTED with
//! the exact error code listed; none may panic or allocate in proportion to a claimed length.
//! "Strict" = canonical encoding as produced by solc / the Solidity ABI spec encoder: zero padding,
//! bool 0/1, every dynamic tail starts exactly where the previous one ended (in head order, no gaps,
//! no overlap, no aliasing) and the data ends exactly after the last tail. See docs/ABI-STRICT.md.
use blocktools_evm::{abi, hex, unhex};

fn w(x: u64) -> String { format!("{x:064x}") }
fn p(s: &str) -> Vec<abi::Param> { abi::parse_types(s).unwrap() }
fn dec(t: &str, h: &str) -> Result<Vec<serde_json::Value>, String> { abi::decode(&p(t), &unhex(h).unwrap()) }

/// (name, types, hex data, expected error code)
fn cases() -> Vec<(&'static str, &'static str, String, &'static str)> {
    let ff = "f".repeat(64);
    let hi64 = format!("{:0>64}", "ffffffffffffffff"); // 2^64-1
    let two64 = format!("{:0>64}", "10000000000000000"); // 2^64
    vec![
        // offsets outside the data
        ("offset_past_end", "(bytes)", w(0x1000), "offset_or_length_out_of_bounds"),
        ("offset_2^256-1", "(bytes)", ff.clone(), "offset_or_length_too_large"),
        ("offset_2^64-1", "(bytes)", hi64.clone(), "offset_or_length_out_of_bounds"),
        ("offset_2^64", "(bytes)", two64.clone(), "offset_or_length_too_large"),
        ("offset_at_end_no_len_word", "(bytes)", w(32), "data_too_short"),
        // lengths: past end, near 2^64 / 2^256 (offset + length overflow)
        ("len_past_end", "(bytes)", w(32) + &w(100), "offset_or_length_out_of_bounds"),
        ("len_past_end_within_size", "(bytes)", w(32) + &w(40) + &w(0), "bytes_out_of_bounds"),
        ("len_2^64-1", "(bytes)", w(32) + &hi64, "offset_or_length_out_of_bounds"),
        ("len_2^256-1", "(string)", w(32) + &ff, "offset_or_length_too_large"),
        ("array_len_2^64-1", "(uint256[])", w(32) + &hi64, "offset_or_length_out_of_bounds"),
        ("array_len_u32max", "(uint256[])", w(32) + &w(u32::MAX as u64), "offset_or_length_out_of_bounds"),
        ("array_len_exceeds_data", "(uint256[])", w(32) + &w(3) + &w(1), "array_length_out_of_bounds"),
        // huge length of zero-size elements: must not allocate a vector of that length
        ("empty_tuple_array_huge_len", "(()[])", w(32) + &w(150_000) + &"00".repeat(150_000), "too_many_values"),
        // tails: non-canonical offsets
        ("offset_into_head", "(uint256,bytes)", w(7) + &w(0) + &w(0), "non_canonical_offset"),
        ("gap_before_tail", "(bytes)", w(64) + &w(0) + &w(0), "non_canonical_offset"),
        ("tails_out_of_order", "(bytes,bytes)", w(0x80) + &w(0x40) + &w(1) + &format!("{:0<64}", "aa") + &w(1) + &format!("{:0<64}", "bb"), "non_canonical_offset"),
        ("tails_overlap_alias", "(bytes,bytes)", w(0x40) + &w(0x40) + &w(1) + &format!("{:0<64}", "aa"), "non_canonical_offset"),
        ("unaligned_offset", "(bytes)", w(33) + "00" + &w(0), "non_canonical_offset"),
        // trailing garbage
        ("trailing_byte_static", "(uint256)", w(1) + "00", "trailing_data"),
        ("trailing_word_after_tail", "(bytes)", w(32) + &w(1) + &format!("{:0<64}", "aa") + &w(0), "trailing_data"),
        ("trailing_after_empty", "()", w(0), "trailing_data"),
        // truncated head
        ("truncated_head_static", "(uint256,uint256)", w(1), "data_too_short"),
        ("truncated_head_partial_word", "(uint256)", w(1)[..62].to_string(), "data_too_short"),
        ("truncated_head_dynamic", "(uint256,bytes)", w(1), "data_too_short"),
        ("truncated_tail_padding", "(bytes)", w(32) + &w(1) + "aa", "bytes_padding_missing"),
        // padding
        ("dirty_address", "(address)", format!("01{:062x}", 0), "dirty_address"),
        ("dirty_uint8", "(uint8)", w(256), "dirty_uint8"),
        ("dirty_uint160", "(uint160)", format!("01{:062x}", 0), "dirty_uint160"),
        ("dirty_uint248", "(uint248)", format!("01{:062x}", 0), "dirty_uint248"),
        ("dirty_int8_not_sign_extended", "(int8)", w(0x80), "dirty_int8"),
        ("dirty_bytes1", "(bytes1)", format!("aa{:062x}", 1), "dirty_bytes1"),
        ("dirty_bytes31", "(bytes31)", format!("{}01", "aa".repeat(31)), "dirty_bytes31"),
        ("dirty_bytes_tail_padding", "(bytes)", w(32) + &w(1) + &format!("{:0<62}01", "aa"), "dirty_bytes_padding"),
        // bool
        ("bool_2", "(bool)", w(2), "dirty_bool"),
        ("bool_ff", "(bool)", w(0xff), "dirty_bool"),
        ("bool_high_bit", "(bool)", format!("80{:062x}", 1), "dirty_bool"),
        // string
        ("string_bad_utf8", "(string)", w(32) + &w(1) + &format!("{:0<64}", "ff"), "string_not_utf8"),
        // nested dynamic arrays / tuples with bad offsets
        ("nested_inner_offset_oob", "(uint256[][])", w(32) + &w(1) + &w(0x1000), "offset_or_length_out_of_bounds"),
        ("nested_inner_offset_noncanonical", "(uint256[][])", w(32) + &w(1) + &w(0x40) + &w(0) + &w(0), "non_canonical_offset"),
        ("nested_tuple_bad_offset", "((uint256,bytes))", w(32) + &w(1) + &w(0x60) + &w(0) + &w(0), "non_canonical_offset"),
        ("nested_tuple_inner_trailing_gap", "((bytes),uint256)", w(64) + &w(5) + &w(32) + &w(0) + &w(0), "trailing_data"),
        ("string_array_alias", "(string[])", w(32) + &w(2) + &w(0x40) + &w(0x40) + &w(0), "non_canonical_offset"),
        ("too_deep", "(uint256[][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][])", w(32) + &w(0), "too_deep"),
    ]
}

#[test]
fn each_malformed_case_is_rejected_with_its_code() {
    let mut bad = vec![];
    for (name, t, h, want) in cases() {
        let got = std::panic::catch_unwind(|| dec(t, &h));
        match got {
            Err(_) => bad.push(format!("{name}: PANIC")),
            Ok(Ok(v)) => bad.push(format!("{name}: ACCEPTED {v:?}")),
            Ok(Err(e)) if e != want => bad.push(format!("{name}: rejected as {e}, want {want}")),
            _ => {}
        }
    }
    assert!(bad.is_empty(), "{} of {} cases wrong:\n{}", bad.len(), cases().len(), bad.join("\n"));
}

#[test]
fn canonical_vectors_still_decode() {
    // Solidity ABI spec "Examples": sam(bytes,bool,uint256[]) and f(uint256,uint32[],bytes10,bytes)
    let dave = format!("{:0<64}", "64617665");
    let sam = w(0x60) + &w(1) + &w(0xa0) + &w(4) + &dave + &w(3) + &w(1) + &w(2) + &w(3);
    assert_eq!(dec("(bytes,bool,uint256[])", &sam).unwrap().len(), 3);
    let f = w(0x123) + &w(0x80) + &format!("{:0<64}", "31323334353637383930") + &w(0xe0) + &w(2) + &w(0x456) + &w(0x789)
        + &w(0x0d) + &format!("{:0<64}", hex(b"Hello, world!").trim_start_matches("0x"));
    assert_eq!(dec("(uint256,uint32[],bytes10,bytes)", &f).unwrap().len(), 4);
    // g(uint256[][],string[]) spec example
    let g = w(0x40) + &w(0x140) + &w(2) + &w(0x40) + &w(0xa0) + &w(2) + &w(1) + &w(2) + &w(1) + &w(3)
        + &w(3) + &w(0x60) + &w(0xa0) + &w(0xe0)
        + &w(3) + &format!("{:0<64}", "6f6e65") + &w(3) + &format!("{:0<64}", "74776f") + &w(5) + &format!("{:0<64}", "7468726565");
    let v = dec("(uint256[][],string[])", &g).unwrap();
    assert_eq!(v[1], serde_json::json!(["one", "two", "three"]));
    // empty bytes, empty array, empty tuple
    assert!(dec("(bytes)", &(w(32) + &w(0))).is_ok());
    assert!(dec("(uint256[])", &(w(32) + &w(0))).is_ok());
    assert!(dec("()", "").is_ok());
}

// ---- opt-in lenient mode: only `trailing_data` is lifted (abi-decode --allow-trailing, evmAbiDecode allow_trailing) ----

#[test]
fn allow_trailing_keeps_every_other_rejection() {
    for (name, t, h, want) in cases() {
        let r = std::panic::catch_unwind(|| abi::decode_prefix(&p(t), &unhex(&h).unwrap()));
        match r {
            Err(_) => panic!("{name}: PANIC in lenient mode"),
            Ok(Ok((_, end))) => assert_eq!(want, "trailing_data", "{name}: lenient accepted (consumed {end}) a case that must stay {want}"),
            Ok(Err(e)) => assert_eq!(e, want, "{name}: lenient error differs from strict"),
        }
    }
}

#[test]
fn allow_trailing_returns_exact_suffix() {
    use blocktools_evm::api::decode_json;
    use serde_json::json;
    let transfer = format!("a9059cbb{}{}", format!("{:0>64}", "1111111111111111111111111111111111111111"), w(1000));
    let approve = format!("095ea7b3{}{}", format!("{:0>64}", "1111111111111111111111111111111111111111"), "f".repeat(64));
    let sig_t = "transfer(address,uint256)";
    let sig_a = "approve(address,uint256)";
    let suffix20 = "22".repeat(20);
    let three = format!("{}{}{}", w(1), w(2), w(3));
    // (request without allow_trailing, expected trailing_hex)
    let cases = [
        (json!({"input": format!("0x{transfer}{suffix20}"), "sig": sig_t}), format!("0x{suffix20}")),
        (json!({"input": format!("0x{transfer}deadbeef"), "sig": sig_t}), "0xdeadbeef".to_string()),
        (json!({"input": format!("0x{approve}{}", w(0)), "sig": sig_a}), format!("0x{}", w(0))),
        (json!({"input": format!("0x{}{}", w(5), w(7)), "types": "(uint256)"}), format!("0x{}", w(7))),
        (json!({"input": format!("0x{three}"), "types": "(uint112,uint112)"}), format!("0x{}", w(3))),
        (json!({"input": format!("0x{}{}", w(5), w(7)), "sig": "f() returns (uint256)", "output": true}), format!("0x{}", w(7))),
    ];
    for (req, want) in cases {
        // strict default still refuses
        assert_eq!(decode_json(&req).unwrap_err(), "trailing_data", "{req}");
        let mut lr = req.clone();
        lr["allow_trailing"] = json!(false);
        assert_eq!(decode_json(&lr).unwrap_err(), "trailing_data", "{lr}");
        lr["allow_trailing"] = json!(true);
        let v = decode_json(&lr).unwrap();
        assert_eq!(v["trailing_hex"], json!(want), "{lr}");
    }
    // option set, nothing trailing: trailing_hex is "0x"; option unset: no trailing_hex key
    let ok = json!({"input": format!("0x{transfer}"), "sig": sig_t, "allow_trailing": true});
    assert_eq!(decode_json(&ok).unwrap()["trailing_hex"], json!("0x"));
    let strict = json!({"input": format!("0x{transfer}"), "sig": sig_t});
    assert!(decode_json(&strict).unwrap().get("trailing_hex").is_none());
    // values are those of the prefix
    let v = decode_json(&json!({"input": format!("0x{three}"), "types": "(uint112,uint112)", "allow_trailing": true})).unwrap();
    assert_eq!(v["args"][1]["value"], json!("2"));
    // non-bool option is refused, never coerced
    for bad in [json!("true"), json!(1), json!(null)] {
        assert_eq!(decode_json(&json!({"input": "0x", "types": "()", "allow_trailing": bad})).unwrap_err(), "allow_trailing_must_be_bool");
    }
    // lenient still rejects non-canonical / dirty input before the suffix
    let dirty = format!("0x{}{}{}", format!("01{:062x}", 0), w(1), suffix20);
    assert_eq!(decode_json(&json!({"input": dirty, "types": "(address,uint256)", "allow_trailing": true})).unwrap_err(), "dirty_address");
}

// ---- opt-in allow_gaps (abi-decode --allow-gaps, evmAbiDecode allow_gaps): a dynamic tail may start AFTER its ----
// ---- canonical position (leading gap / unconsumed head words / gaps between tails), never before it.          ----

const BRIDGE: &str = "(bytes32,string,string,address,address,address,uint256,uint256,bool,bool)";

/// Synthetic LI.FI-BridgeData-shaped tuple (canonical inside): bridge "layerswap", integrator "keyrescue-test".
fn bridge_tuple(bridge: &str) -> String {
    let s = |x: &str| { let h = hex(x.as_bytes())[2..].to_string(); format!("{}{h:0<w$}", w(x.len() as u64), w = x.len().div_ceil(32) * 64) };
    let (b, i) = (s(bridge), s("keyrescue-test"));
    let addr = |c: &str| format!("{:0>64}", c.repeat(40));
    let head = [
        "ab".repeat(32), w(0x140), w(0x140 + b.len() as u64 / 2), addr("0"), addr("1"), addr("2"),
        w(1_000_000), w(42161), w(0), w(1),
    ].concat();
    head + &b + &i
}
fn gaps(t: &str, h: &str, trailing: bool) -> Result<(Vec<serde_json::Value>, usize, usize), String> {
    let d = unhex(h).unwrap();
    let (v, end, skipped) = abi::decode_lenient(&p(t), &d, true)?;
    if !trailing && end != d.len() { return Err("trailing_data".into()); }
    Ok((v, end, skipped))
}
fn lifi_cases() -> Vec<(&'static str, String, usize)> {
    let t = bridge_tuple("layerswap");
    vec![
        // 1. offset 0x60: tuple after two unconsumed head words (other params' heads); nothing after it
        ("lifi_0x60_tuple_last", format!("0x{}{}{}{t}", w(0x60), w(7), w(8)), 64),
        // 2. offset 0x80: three unconsumed head words, tuple last
        ("lifi_0x80_tuple_last", format!("0x{}{}{}{}{t}", w(0x80), w(1), w(2), w(3)), 96),
        // 3. offset 0x60 with a 1-word hole between the head and the tuple (non-contiguous)
        ("lifi_0x60_hole", format!("0x{}{}{}{t}", w(0x60), w(9), w(0)), 64),
    ]
}

#[test]
fn allow_gaps_decodes_lifi_shaped_tuples_strict_rejects_them() {
    let ty = format!("({BRIDGE})");
    for (name, h, gap) in lifi_cases() {
        assert_eq!(dec(&ty, &h).unwrap_err(), "non_canonical_offset", "{name}: strict must reject");
        assert_eq!(abi::decode_prefix(&p(&ty), &unhex(&h).unwrap()).unwrap_err(), "non_canonical_offset", "{name}: allow_trailing alone must reject");
        let (v, end, skipped) = gaps(&ty, &h, false).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!((end, skipped), (unhex(&h).unwrap().len(), gap), "{name}");
        let tup = v[0].as_array().unwrap();
        assert_eq!(tup[1], serde_json::json!("layerswap"), "{name}");
        assert_eq!(tup[2], serde_json::json!("keyrescue-test"), "{name}");
        assert_eq!(tup[7], serde_json::json!("42161"), "{name}");
        assert_eq!((tup[8].clone(), tup[9].clone()), (serde_json::json!(false), serde_json::json!(true)), "{name}");
    }
}

#[test]
fn allow_gaps_keeps_every_other_rejection() {
    // every strict malformed case: same code (no panic); only non_canonical_offset/trailing_data may change
    for (name, t, h, want) in cases() {
        let r = std::panic::catch_unwind(|| gaps(t, &h, false));
        match r {
            Err(_) => panic!("{name}: PANIC under allow_gaps"),
            Ok(Ok(_)) => assert_eq!(want, "non_canonical_offset", "{name}: allow_gaps accepted a case that must stay {want}"),
            Ok(Err(e)) => if want != "non_canonical_offset" { assert_eq!(e, want, "{name}") },
        }
    }
    let ty = format!("({BRIDGE})");
    let t = bridge_tuple("layerswap");
    // trailing bytes after the tuple: refused unless allow_trailing too
    let h = format!("0x{}{}{}{t}{}", w(0x60), w(7), w(8), w(5));
    assert_eq!(gaps(&ty, &h, false).unwrap_err(), "trailing_data");
    let (_, end, _) = gaps(&ty, &h, true).unwrap();
    assert_eq!(unhex(&h).unwrap().len() - end, 32);
    // dirty bool / dirty address inside the gapped tuple still rejected
    let bad_bool = format!("0x{}{}{}{}", w(0x60), w(7), w(8), t.replacen(&format!("{}{}", w(0), w(1)), &format!("{}{}", w(0), w(2)), 1));
    assert_eq!(gaps(&ty, &bad_bool, false).unwrap_err(), "dirty_bool");
    let bad_addr = format!("0x{}{}{}{}", w(0x60), w(7), w(8), t.replacen(&format!("{:0>64}", "1".repeat(40)), &format!("01{:0>62}", "1".repeat(40)), 1));
    assert_eq!(gaps(&ty, &bad_addr, false).unwrap_err(), "dirty_address");
    // backward offset (into the head) and offset past the end still rejected
    assert_eq!(gaps("(bytes)", &format!("0x{}{}", w(0), w(0)), false).unwrap_err(), "non_canonical_offset");
    assert_eq!(gaps("(bytes)", &format!("0x{}", w(0x40)), false).unwrap_err(), "offset_or_length_out_of_bounds");
}

#[test]
fn allow_gaps_rejects_overlap_and_aliasing_so_work_is_bounded() {
    // two tails pointing at the same bytes (aliasing) and second tail before the first (overlap/backward)
    let one = format!("{}{}", w(1), format!("{:0<64}", "aa"));
    assert_eq!(gaps("(bytes,bytes)", &format!("0x{}{}{one}", w(0x40), w(0x40)), false).unwrap_err(), "non_canonical_offset");
    assert_eq!(gaps("(bytes,bytes)", &format!("0x{}{}{one}{one}", w(0x80), w(0x40)), false).unwrap_err(), "non_canonical_offset");
    // amplification attempt: bytes[] whose N element offsets all alias one blob -> refused at the second element
    let n = 2000u64;
    let mut h = w(32) + &w(n);
    for _ in 0..n { h += &w(n * 32); }
    h += &one;
    let t0 = std::time::Instant::now();
    assert_eq!(gaps("(bytes[])", &format!("0x{h}"), false).unwrap_err(), "non_canonical_offset");
    assert!(t0.elapsed().as_secs() < 2);
    // forward-only gaps: each tail starts at or after the previous end, so every byte is decoded at most once
    let ok = format!("0x{}{}{}{one}{}{one}", w(0x60), w(0xc0), w(0), w(0));
    let (v, _, skipped) = gaps("(bytes,bytes,uint256)", &ok, false).unwrap();
    assert_eq!((v[0].clone(), v[1].clone(), skipped), (serde_json::json!("0xaa"), serde_json::json!("0xaa"), 32));
}

#[test]
fn allow_gaps_json_option() {
    use blocktools_evm::api::decode_json;
    use serde_json::json;
    let ty = format!("({BRIDGE})");
    let (_, h, _) = &lifi_cases()[1];
    assert_eq!(decode_json(&json!({"input": h, "types": ty})).unwrap_err(), "non_canonical_offset");
    assert_eq!(decode_json(&json!({"input": h, "types": ty, "allow_trailing": true})).unwrap_err(), "non_canonical_offset");
    let v = decode_json(&json!({"input": h, "types": ty, "allow_gaps": true})).unwrap();
    assert_eq!(v["gap_bytes"], json!(96));
    assert!(v.get("trailing_hex").is_none());
    let v = decode_json(&json!({"input": format!("{h}{}", w(5)), "types": ty, "allow_gaps": true, "allow_trailing": true})).unwrap();
    assert_eq!((v["gap_bytes"].clone(), v["trailing_hex"].clone()), (json!(96), json!(format!("0x{}", w(5)))));
    assert_eq!(decode_json(&json!({"input": format!("{h}{}", w(5)), "types": ty, "allow_gaps": true})).unwrap_err(), "trailing_data");
    // canonical input under allow_gaps: gap_bytes 0; strict output has no gap_bytes key
    let c = format!("0x{}{}", w(0x20), bridge_tuple("near"));
    assert_eq!(decode_json(&json!({"input": c, "types": ty, "allow_gaps": true})).unwrap()["gap_bytes"], json!(0));
    assert!(decode_json(&json!({"input": c, "types": ty})).unwrap().get("gap_bytes").is_none());
    for bad in [json!("true"), json!(1), json!(null), json!([true])] {
        assert_eq!(decode_json(&json!({"input": "0x", "types": "()", "allow_gaps": bad})).unwrap_err(), "allow_gaps_must_be_bool");
    }
}
