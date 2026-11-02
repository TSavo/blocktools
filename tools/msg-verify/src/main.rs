//! msg-verify: check a message signature against an address. No keys are read.
//!   msg-verify --address ADDR (--message TEXT | --message-file FILE) [--hex] --sig SIG [--chain eth|btc|tron|sol|cosmos]
//!              [--format raw|offchain-v0 (Solana, required)] [--pubkey B64 (Cosmos, required)]
//! The chain is detected from the address (--chain, if given, must agree):
//! - 0x + 40 hex: Ethereum EIP-191 personal_sign, SIG 65 bytes hex, v = 27/28, 0/1 or 35 + 2*chain_id + rec.
//! - base58 P2PKH starting with 1: Bitcoin Core signmessage, SIG base64 (header 27-34).
//! - base58check T... (0x41): Tron signMessageV2 (TIP-191 style "\x19TRON Signed Message:\n" + byte length),
//!   SIG 65 bytes hex, v = 27/28.
//! - base58 32-byte ed25519 key: Solana, SIG base58 64 bytes; --format is required: `raw` (the message bytes
//!   as they are, wallet signMessage) or `offchain-v0` (solana-sdk / `solana sign-offchain-message` layout).
//! - bech32 with a 20-byte payload: Cosmos ADR-036 (draft spec, Keplr signArbitrary), SIG base64 64 bytes,
//!   --pubkey (base64 33-byte compressed key) required and must hash to the address.
//! Options that do not apply to the detected chain are refused, not ignored.
//! --message-file uses the file's exact bytes (no newline trimming); --hex reads the message as hex bytes.
//! Refused: segwit/taproot addresses and BIP137 segwit headers (35-42), BIP322, other chains' message
//! prefixes (ltc, doge, ...), EIP-712 (use typed-data-verify), the Trust Wallet Core 85-byte Solana
//! off-chain layout, Ethermint-style (eth_secp256k1) Cosmos keys.
//! Output: {"status":"ok"|"signer_mismatch","chain","address","recovered"?,"v"?,"format"?,"hrp"?}; exit 0 only on ok.
//! Vectors: crates/tx/tests/twc_message.rs (eth, btc) and crates/blocktools/tests/msg_chains.rs (tron, sol,
//! cosmos round-trip only); provenance in docs/PROVENANCE-msg.md.
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
    blocktools_io::help("msg-verify --address ADDR (--message TEXT | --message-file FILE) [--hex] --sig SIG [--chain eth|btc|tron|sol|cosmos] [--format raw|offchain-v0] [--pubkey B64]");
    let a: Vec<String> = blocktools_core::chain_spec::args_or_exit("msg-verify");
    let one = |k: &str| a.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).last();
    let bad = |e: &str| -> ! { out("bad_input", json!({"error":e})) };
    let addr = one("--address").unwrap_or_else(|| bad("--address ADDR required"));
    let chain = blocktools_tx::msgchain::detect_chain(&addr).unwrap_or_else(|e| bad(e));
    if let Some(c) = one("--chain") { if c != chain { bad(if ["eth", "btc", "tron", "sol", "cosmos"].contains(&c.as_str()) { "chain_does_not_match_address" } else { "message_prefix_unproven_for_chain" }) } }
    let msg = match (one("--message"), one("--message-file")) {
        (Some(m), None) => m.into_bytes(),
        (None, Some(f)) => { let b = std::fs::read(f).unwrap_or_else(|_| bad("cannot read --message-file")); if b.len() > 1 << 20 { bad("message_too_large") } b }
        _ => bad("exactly one of --message / --message-file"),
    };
    let msg = if a.iter().any(|x| x == "--hex") { hexd(std::str::from_utf8(&msg).unwrap_or("")).unwrap_or_else(|| bad("bad_hex_message")) } else { msg };
    let sig = one("--sig").unwrap_or_else(|| bad("--sig SIG required"));
    let (format, pubkey) = (one("--format"), one("--pubkey"));
    let r = blocktools_tx::msgchain::verify(&addr, &msg, &sig, &blocktools_tx::msgchain::Opts { format: format.as_deref(), pubkey: pubkey.as_deref() }).unwrap_or_else(|e| bad(e));
    let mut o = r.clone(); let st = o.as_object_mut().unwrap().remove("status").and_then(|v| v.as_str().map(String::from)).unwrap_or_default();
    out(&st, o)
}
