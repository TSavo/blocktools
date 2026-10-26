//! msg-sign: sign ONE text message after a human reads it and types a code on /dev/tty.
//!   msg-sign --address ADDR (--message TEXT | --message-file FILE) [--chain eth|btc] [--v legacy|raw|eip155:N]  < keys
//! The chain is detected from --address (0x + 40 hex: Ethereum EIP-191 personal_sign; base58 P2PKH
//! starting with 1: Bitcoin Core signmessage); --chain, if given, must agree. The key whose address is
//! --address is used (Bitcoin: compressed or uncompressed P2PKH, whichever matches); no match is refused.
//! Ethereum --v: legacy (27/28, default), raw (0/1, Immutable X style) or eip155:N (35 + 2N + rec).
//! Refused before keys are read: a message that is a bare 32-byte hash (64 hex chars) — blind hash
//! signing; a message that decodes as a transaction or PSBT; non-UTF-8 bytes; empty or > 64 KiB
//! messages; segwit/taproot addresses (BIP137/BIP322 unsupported); other chains' message prefixes;
//! EIP-712 typed data (not signed by blocktools; typed-data-verify only verifies).
//! Keys come ONLY on stdin (WIF or 64-hex, or JSON lines with wif/private_key/key/secret).
//! Order: refusals -> read keys -> sign in memory -> verify the signature recovers --address ->
//! show the message (escaped) on the terminal -> code typed -> {"signature": ...}. Without a terminal,
//! or with the wrong code, nothing but "aborted" is printed.
//! Vectors: Trust Wallet Core EthMessageSigner and BitcoinMessageSigner, byte-exact (crates/tx/tests/twc_message.rs).
use blocktools_tx::message::{self, EthV};
use serde_json::json;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;
fn out(status: &str, extra: serde_json::Value) -> ! {
    let mut v = json!({"tool":"msg-sign","status":status}); v.as_object_mut().unwrap().extend(extra.as_object().cloned().unwrap_or_default());
    blocktools_io::outln!("{v}"); std::process::exit(if status == "ok" { 0 } else if status == "bad_input" { 2 } else { 1 })
}
fn main() {
    blocktools_io::help("msg-sign --address ADDR (--message TEXT | --message-file FILE) [--chain eth|btc] [--v legacy|raw|eip155:N] < keys   (asks for a code on the terminal)");
    let a: Vec<String> = blocktools_core::chain_spec::args_or_exit("msg-sign");
    let one = |k: &str| a.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).last();
    let bad = |e: &str| -> ! { out("bad_input", json!({"error":e})) };
    let refuse = |e: &str| -> ! { out("refused", json!({"failures":[e]})) };
    let addr = one("--address").unwrap_or_else(|| bad("--address ADDR required"));
    let chain = message::detect_chain(&addr).unwrap_or_else(|e| refuse(e));
    if let Some(c) = one("--chain") { if c != chain { refuse(if ["eth", "btc"].contains(&c.as_str()) { "chain_does_not_match_address" } else { "message_prefix_unproven_for_chain" }) } }
    if a.iter().any(|x| x == "--hex" || x == "--typed-data") { refuse("only_text_messages_signed") }
    let msg = match (one("--message"), one("--message-file")) {
        (Some(m), None) => m.into_bytes(),
        (None, Some(f)) => { let mut b = Vec::new(); std::fs::File::open(f).and_then(|f| f.take(1 << 20).read_to_end(&mut b)).unwrap_or_else(|_| bad("cannot read --message-file")); b }
        _ => bad("exactly one of --message / --message-file"),
    };
    if msg.is_empty() { refuse("empty_message") }
    if msg.len() > 64 << 10 { refuse("message_too_large") }
    let text = std::str::from_utf8(&msg).unwrap_or_else(|_| refuse("message_not_utf8"));
    if let Some(r) = message::sign_refusal(&msg, false) { refuse(r) }
    let v = match (chain, one("--v").as_deref()) {
        ("eth", None | Some("legacy")) => EthV::Legacy, ("eth", Some("raw")) => EthV::Raw,
        ("eth", Some(s)) if s.starts_with("eip155:") => EthV::Eip155(s[7..].parse().ok().filter(|c: &u64| *c <= 0x7fff_fff0).unwrap_or_else(|| bad("--v eip155:N"))),
        ("btc", None) => EthV::Legacy, _ => bad("--v legacy|raw|eip155:N (Ethereum only)"),
    };
    if let EthV::Eip155(c) = v { if 35 + 2 * c + 1 > 255 { refuse("eip155_v_exceeds_one_byte") } }

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut found = None;
    for l in std::io::stdin().lock().take(4 << 20).lines().map_while(Result::ok) {
        let l = Zeroizing::new(l);
        if l.trim().is_empty() { continue }
        if let Ok(serde_json::Value::Object(o)) = serde_json::from_str::<serde_json::Value>(&l) {
            if !["wif", "private_key", "key", "secret"].iter().any(|k| o.contains_key(*k)) { continue }
        }
        let k = blocktools_secrets::keys::parse_key_line(&l).unwrap_or_else(|| bad("unreadable key line"));
        let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &k);
        let m = if chain == "eth" { blocktools_core::eth_address(&k, &secp).eq_ignore_ascii_case(&addr).then_some(true) } else {
            let p2pkh = |b: &[u8]| bitcoin::Address::p2pkh(bitcoin::PubkeyHash::from_raw_hash(<bitcoin::hashes::hash160::Hash as bitcoin::hashes::Hash>::hash(b)), bitcoin::Network::Bitcoin).to_string();
            if p2pkh(&pk.serialize()) == addr { Some(true) } else if p2pkh(&pk.serialize_uncompressed()) == addr { Some(false) } else { None }
        };
        if let Some(c) = m { found = Some((k, c)); break }
    }
    let (mut k, compressed) = found.unwrap_or_else(|| refuse("address_does_not_match_key"));
    let sig = if chain == "eth" { format!("0x{}", blocktools_core::hex_enc(message::eth_sign(&msg, &k, v))) } else { message::btc_sign(&msg, &k, compressed) };
    k.non_secure_erase();
    let rec = if chain == "eth" { message::eth_recover(&msg, &blocktools_core::hex_dec(&sig[2..]).unwrap_or_default()).map(|x| x.0) } else { message::btc_recover(&msg, &sig) };
    if !rec.map(|r| r.eq_ignore_ascii_case(&addr)).unwrap_or(false) { out("error", json!({"error":"signature_failed_recheck"})) }
    let scheme = if chain == "eth" { "Ethereum personal_sign (EIP-191)" } else { "Bitcoin signmessage" };
    let summary = format!("Sign MESSAGE ({scheme}, {} bytes) as {addr}:\n{text:?}\nThis signs text only; it cannot move funds by itself, but whoever asked for it may use it as proof you control this address.\n", msg.len());
    if !blocktools_tty::confirm(&summary) { out("aborted", json!({})) }
    out("ok", json!({"chain":chain,"address":addr,"signature":sig}))
}
