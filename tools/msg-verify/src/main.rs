//! msg-verify: check a message signature against an address. No keys are read.
//!   msg-verify --address ADDR (--message TEXT | --message-file FILE) [--hex] --sig SIG [--chain eth|btc]
//! The chain is detected from the address: 0x + 40 hex is Ethereum, a base58 P2PKH address starting
//! with 1 is Bitcoin (--chain, if given, must agree). Ethereum: EIP-191 personal_sign, SIG is 65 bytes hex
//! (0x optional) with v = 27/28, 0/1 (Immutable X style) or 35 + 2*chain_id + rec (EIP-155 style).
//! Bitcoin: Bitcoin Core signmessage, SIG is base64 (header 27-34, compressed or uncompressed key).
//! --message-file uses the file's exact bytes (no newline trimming); --hex reads the message as hex bytes.
//! Refused: segwit/taproot addresses and BIP137 segwit headers (35-42), BIP322, other chains' message
//! prefixes (ltc, doge, ...), EIP-712 (use typed-data-verify).
//! Output: {"status":"ok"|"signer_mismatch","chain","address","recovered"[,"v"]}; exit 0 only on ok.
//! Vectors: Trust Wallet Core EthMessageSigner (legacy, legacy_hex, eip155, immutable_x) and
//! BitcoinMessageSigner (6 verify vectors, messageToHash, negatives), crates/tx/tests/twc_message.rs.
use serde_json::json;
fn out(status: &str, extra: serde_json::Value) -> ! {
    let mut v = json!({"tool":"msg-verify","status":status}); v.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    blocktools_io::outln!("{v}"); std::process::exit(if status == "ok" { 0 } else if status == "bad_input" { 2 } else { 1 })
}
fn hexd(s: &str) -> Option<Vec<u8>> {
    let s = s.trim(); let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 { return None }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}
fn main() {
    blocktools_io::help("msg-verify --address ADDR (--message TEXT | --message-file FILE) [--hex] --sig SIG [--chain eth|btc]");
    let a: Vec<String> = blocktools_core::chain_spec::args_or_exit("msg-verify");
    let one = |k: &str| a.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).last();
    let bad = |e: &str| -> ! { out("bad_input", json!({"error":e})) };
    let addr = one("--address").unwrap_or_else(|| bad("--address ADDR required"));
    let chain = blocktools_tx::message::detect_chain(&addr).unwrap_or_else(|e| bad(e));
    if let Some(c) = one("--chain") { if c != chain { bad(if ["eth", "btc"].contains(&c.as_str()) { "chain_does_not_match_address" } else { "message_prefix_unproven_for_chain" }) } }
    let msg = match (one("--message"), one("--message-file")) {
        (Some(m), None) => m.into_bytes(),
        (None, Some(f)) => { let b = std::fs::read(f).unwrap_or_else(|_| bad("cannot read --message-file")); if b.len() > 1 << 20 { bad("message_too_large") } b }
        _ => bad("exactly one of --message / --message-file"),
    };
    let msg = if a.iter().any(|x| x == "--hex") { hexd(std::str::from_utf8(&msg).unwrap_or("")).unwrap_or_else(|| bad("bad_hex_message")) } else { msg };
    let sig = one("--sig").unwrap_or_else(|| bad("--sig SIG required"));
    let (_, same, rec, v) = blocktools_tx::message::verify(&addr, &msg, &sig).unwrap_or_else(|e| bad(e));
    let mut o = json!({"chain":chain,"address":addr,"recovered":rec}); if let Some(v) = v { o["v"] = json!(v) }
    out(if same { "ok" } else { "signer_mismatch" }, o)
}
