//! xrp-tx keys   < family-seed                       -> {"chain":"xrp","algo","address","x_address","public"} (public only)
//! xrp-tx build  --account r.. --to r..|X.. (--amount DROPS | --sweep --balance DROPS [--reserve DROPS])
//!               --fee DROPS --sequence N [--last-ledger N] [--destination-tag N]   -> {"unsigned":HEX,"warnings":[..]}
//! xrp-tx decode < HEX                               -> decoded JSON
//! xrp-tx sign   --tx FILE --expect-to r..|X..  < family-seed -> {"status":"ok","tx_blob","hash"} after a typed code on /dev/tty
//! The destination tag matters: exchanges credit deposits by tag, and a payment without it is usually lost to you.
use blocktools_xrp::*;
use serde_json::{json, Value};
use std::io::Read;
use zeroize::Zeroizing;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02X}")).collect() }
fn unhex(s: &str) -> Option<Vec<u8>> { let s = s.trim(); (s.len() % 2 == 0).then(|| (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect::<Option<Vec<_>>>()).flatten() }
fn fail(e: &str) -> ! { blocktools_io::outln!("{}", json!({"status":"error","error":e})); std::process::exit(1) }
fn opt<'a>(a: &'a [String], k: &str) -> Option<&'a str> { a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).map(|s| s.as_str()) }
fn num<T: std::str::FromStr>(a: &[String], k: &str) -> Option<T> { opt(a, k).map(|v| v.parse().unwrap_or_else(|_| fail(&format!("bad_number:{k}")))) }
fn stdin_secret() -> Zeroizing<String> { let mut s = Zeroizing::new(String::new()); std::io::stdin().read_to_string(&mut s).ok(); s }

fn describe(p: &Payment) -> Value {
    let mut w = vec![];
    if p.destination_tag.is_none() { w.push("destination_tag_missing: exchanges and custodial wallets need a destination tag; without one the funds may not be credited") }
    json!({"type":"Payment","account":classic(&p.account),"destination":classic(&p.destination),"destination_tag":p.destination_tag,
        "source_tag":p.source_tag,"amount_drops":p.amount_drops,"amount_xrp":format!("{}.{:06}", p.amount_drops / 1_000_000, p.amount_drops % 1_000_000),
        "fee_drops":p.fee_drops,"sequence":p.sequence,"last_ledger_sequence":p.last_ledger_sequence,"flags":p.flags,"memos":p.memos.len(),
        "signed":p.txn_signature.is_some(),"signature_valid":p.txn_signature.is_some().then(|| verify(p)),"hash":p.txn_signature.is_some().then(|| hex(&p.hash())),"warnings":w})
}

const HELP: &str = " xrp-tx keys   < family-seed                       -> {\"chain\":\"xrp\",\"algo\",\"address\",\"x_address\",\"public\"} (public only)
 xrp-tx build  --account r.. --to r..|X.. (--amount DROPS | --sweep --balance DROPS [--reserve DROPS])
               --fee DROPS --sequence N [--last-ledger N] [--destination-tag N]   -> {\"unsigned\":HEX,\"warnings\":[..]}
 xrp-tx decode < HEX                               -> decoded JSON
 xrp-tx sign   --tx FILE --expect-to r..|X..  < family-seed -> {\"status\":\"ok\",\"tx_blob\",\"hash\"} after a typed code on /dev/tty
 The destination tag matters: exchanges credit deposits by tag, and a payment without it is usually lost to you.
";
fn main() {
    blocktools_io::help(HELP);
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(|s| s.as_str()) {
        Some("keys") => {
            let s = stdin_secret();
            let (algo, e) = decode_seed(&s).unwrap_or_else(|e| fail(e));
            let k = key_from_seed(algo, &e);
            blocktools_io::outln!("{}", json!({"tool":"xrp-tx","status":"ok","chain":"xrp","kind":"xrp","algo":format!("{algo:?}").to_lowercase(),"address":k.address(),
                "x_address":x_address(&account_id(&k.public), None, false),"public":hex(&k.public)}));
        }
        Some("build") => {
            let account = decode_classic(opt(&a, "--account").unwrap_or_else(|| fail("missing --account"))).unwrap_or_else(|| fail("bad_account"));
            let (dest, xtag) = parse_destination(opt(&a, "--to").unwrap_or_else(|| fail("missing --to"))).unwrap_or_else(|e| fail(e));
            let tag: Option<u32> = num(&a, "--destination-tag");
            if let (Some(x), Some(t)) = (xtag, tag) { if x != t { fail("destination_tag_conflicts_with_x_address") } }
            let fee: u64 = num(&a, "--fee").unwrap_or_else(|| fail("missing --fee"));
            let amount = if a.iter().any(|x| x == "--sweep") {
                let bal: u64 = num(&a, "--balance").unwrap_or_else(|| fail("--sweep needs --balance"));
                let reserve: u64 = num(&a, "--reserve").unwrap_or(1_000_000);
                bal.checked_sub(reserve + fee).filter(|&v| v > 0).unwrap_or_else(|| fail("balance_below_reserve_plus_fee"))
            } else { num(&a, "--amount").unwrap_or_else(|| fail("missing --amount or --sweep")) };
            if account == dest { fail("destination_is_source") }
            let p = Payment { account, destination: dest, amount_drops: amount, fee_drops: fee, sequence: num(&a, "--sequence").unwrap_or_else(|| fail("missing --sequence")),
                flags: 0x8000_0000, destination_tag: xtag.or(tag), last_ledger_sequence: num(&a, "--last-ledger"), ..Default::default() };
            let d = describe(&p);
            for w in d["warnings"].as_array().unwrap() { eprintln!("xrp-tx: WARNING {}", w.as_str().unwrap()) }
            blocktools_io::outln!("{}", json!({"chain":"xrp","unsigned":hex(&p.encode(false)),"warnings":d["warnings"],"summary":d}));
        }
        Some("decode") => {
            let mut s = String::new(); std::io::stdin().read_to_string(&mut s).ok();
            let s = serde_json::from_str::<Value>(&s).ok().and_then(|v| v["unsigned"].as_str().or(v["tx_blob"].as_str()).map(String::from)).unwrap_or(s);
            let p = Payment::decode(&unhex(&s).unwrap_or_else(|| fail("bad_hex"))).unwrap_or_else(|e| fail(&e));
            blocktools_io::outln!("{}", describe(&p));
        }
        Some("sign") => {
            let raw = std::fs::read_to_string(opt(&a, "--tx").unwrap_or_else(|| fail("missing --tx"))).unwrap_or_else(|_| fail("cannot_read_tx"));
            let h = serde_json::from_str::<Value>(&raw).ok().and_then(|v| v["unsigned"].as_str().map(String::from)).unwrap_or(raw);
            let mut p = Payment::decode(&unhex(&h).unwrap_or_else(|| fail("bad_hex"))).unwrap_or_else(|e| fail(&e));
            let (want, wtag) = parse_destination(opt(&a, "--expect-to").unwrap_or_else(|| fail("missing --expect-to"))).unwrap_or_else(|e| fail(e));
            if p.destination != want || (wtag.is_some() && wtag != p.destination_tag) { fail("destination_mismatch") }
            let s = stdin_secret();
            let (algo, e) = decode_seed(&s).unwrap_or_else(|e| fail(e));
            let k = key_from_seed(algo, &e);
            if account_id(&k.public) != p.account { fail("key_does_not_match_account") }
            let d = describe(&p);
            let summary = format!("XRP Payment {} XRP (+{} drops fee)\n  from {}\n  to   {}  tag {}\n{}", d["amount_xrp"].as_str().unwrap(), p.fee_drops,
                classic(&p.account), classic(&p.destination), p.destination_tag.map_or("NONE".into(), |t| t.to_string()),
                d["warnings"].as_array().unwrap().iter().map(|w| format!("  WARNING {}\n", w.as_str().unwrap())).collect::<String>());
            if !blocktools_tty::confirm(&summary) { blocktools_io::outln!("{}", json!({"status":"aborted"})); std::process::exit(1) }
            sign(&mut p, &k).unwrap_or_else(|e| fail(e));
            blocktools_io::outln!("{}", json!({"status":"ok","chain":"xrp","tx_blob":hex(&p.encode(false)),"txid":hex(&p.hash())}));
        }
        _ => { eprintln!("usage: xrp-tx keys|build|decode|sign (see source header)"); std::process::exit(2) }
    }
}
