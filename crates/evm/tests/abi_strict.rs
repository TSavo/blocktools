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
