//! typed-data-verify: EIP-712 typed data -> encodeType, domain separator, message hash and digest;
//! with a signature, the recovered signer (65-byte r||s||v or 64-byte EIP-2098); with --signer, a verdict. Offline.
//!   typed-data-verify mail.json
//!   typed-data-verify --sig 0x.. --signer 0x.. < typed-data.json
//!   typed-data-verify --expect-chain-id 1 --expect-verifying-contract 0x.. FILE
//! The domain's chainId and verifyingContract are printed as chain_id / verifying_contract. With an
//! --expect-* assertion, a missing or different value sets status chain_id_mismatch /
//! verifying_contract_mismatch (exit 1), whatever the signature verdict.
use blocktools_evm::eip712;
use blocktools_io::outln;
use serde_json::{json, Value};
use std::io::Read;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "typed-data-verify", "status": "bad_input", "error": e}));
    std::process::exit(2)
}

fn main() {
    blocktools_io::help("typed-data-verify [--sig HEX] [--signer ADDR] [--expect-chain-id N] [--expect-verifying-contract ADDR] [FILE]
  --sig HEX       signature: 65 bytes r||s||v (v 27/28 or 0/1) or 64 bytes EIP-2098 compact
  --signer ADDR   expected signer; status is valid (exit 0) or signer_mismatch (exit 1)
  --expect-chain-id N              domain.chainId must equal N, else status chain_id_mismatch (exit 1)
  --expect-verifying-contract ADDR domain.verifyingContract must equal ADDR, else verifying_contract_mismatch (exit 1)
FILE (or stdin): EIP-712 typed data {types, primaryType, domain, message}, an eth_signTypedData_v4
request ({\"params\": [address, typedData]}, typedData as object or JSON string: the address becomes the
expected signer), or {typed_data, signature, signer}. Without --signer, prints the recovered address only.
Prints domain_separator, message_hash and digest so you can compare them with what a wallet shows.");
    let a: Vec<String> = std::env::args().skip(1).collect();
    let (mut sig, mut signer, mut file) = (None, None, None);
    let (mut want_cid, mut want_vc): (Option<String>, Option<String>) = (None, None);
    let mut it = a.into_iter();
    while let Some(x) = it.next() {
        match x.as_str() {
            "--sig" => sig = Some(it.next().unwrap_or_else(|| die("sig_needs_value"))),
            "--signer" => signer = Some(it.next().unwrap_or_else(|| die("signer_needs_value"))),
            "--expect-chain-id" => want_cid = Some(it.next().unwrap_or_else(|| die("expect_chain_id_needs_value"))),
            "--expect-verifying-contract" => want_vc = Some(it.next().unwrap_or_else(|| die("expect_verifying_contract_needs_value"))),
            s if s.starts_with("--") => die("unknown_option"),
            _ => { if file.is_some() { die("one_file_only") } file = Some(x) }
        }
    }
    let text = match file {
        Some(p) => std::fs::read_to_string(&p).unwrap_or_else(|_| die("cannot_read_file")),
        None => { let mut s = String::new(); std::io::stdin().take(16 << 20).read_to_string(&mut s).ok(); s }
    };
    let v: Value = serde_json::from_str(text.trim()).unwrap_or_else(|_| die("bad_input_json"));
    let parse = |x: &Value| -> Value { match x { Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| die("bad_typed_data_json")), o => o.clone() } };
    let td = if let Some(p) = v.get("params").and_then(Value::as_array) {
        if signer.is_none() { signer = p.first().and_then(Value::as_str).map(str::to_string); }
        parse(p.get(1).unwrap_or_else(|| die("params_need_address_and_typed_data")))
    } else if let Some(t) = v.get("typed_data") {
        if sig.is_none() { sig = v.get("signature").and_then(Value::as_str).map(str::to_string); }
        if signer.is_none() { signer = v.get("signer").and_then(Value::as_str).map(str::to_string); }
        parse(t)
    } else { v };
    if signer.is_some() && sig.is_none() { die("signer_needs_sig"); }
    match eip712::verify(&td, sig.as_deref(), signer.as_deref()) {
        Ok(mut o) => {
            if let Some(w) = &want_cid {
                let w: u64 = w.parse().unwrap_or_else(|_| die("expect_chain_id_not_integer"));
                // EIP-712 chainId may be a JSON number or a decimal / 0x-hex string
                let got = match &o["chain_id"] { Value::Number(n) => n.as_u64(), Value::String(s) => s.strip_prefix("0x").map_or_else(|| s.parse().ok(), |h| u64::from_str_radix(h, 16).ok()), _ => None };
                if got != Some(w) { o["status"] = json!("chain_id_mismatch"); o["expected_chain_id"] = json!(w) }
            }
            if let Some(w) = &want_vc {
                let w = blocktools_evm::parse_address(w).unwrap_or_else(|_| die("expect_verifying_contract_bad_address"));
                let got = o["verifying_contract"].as_str().and_then(|s| blocktools_evm::unhex(s).ok());
                if got.as_deref() != Some(&w[..]) && o["status"] != "chain_id_mismatch" { o["status"] = json!("verifying_contract_mismatch") }
                o["expected_verifying_contract"] = json!(blocktools_evm::checksum_address(&w));
            }
            outln!("{o}");
            if ["signer_mismatch", "chain_id_mismatch", "verifying_contract_mismatch"].contains(&o["status"].as_str().unwrap_or("")) { std::process::exit(1) }
        }
        Err(e) => die(&e),
    }
}
