//! acct-tx: account-model payments for xlm, algo and atom. Encoded transactions are base64 (each chain's native form).
//! Balance / sequence / rounds come from the host-side `utxo-fetch --chain xlm|algo ADDR` (this tool has no network).
//! acct-tx build   --chain xlm  --from G.. --to G.. (--amount STROOPS | --sweep) --fee STROOPS --seq N [--memo-id N|--memo-text T] [--max-time UNIX] [--testnet]
//! acct-tx build   --chain algo --from A.. --to A.. (--amount MICROALGO | --sweep) --fee MICROALGO --first-round N [--last-round N] [--note T]
//! acct-tx keys    --chain atom < hex-private-key                    -> {"address","pubkey"} (public only; build needs --pubkey)
//! acct-tx build   --chain atom --from cosmos1.. --pubkey HEX33 --to cosmos1.. (--amount UATOM | --sweep --balance UATOM) --fee UATOM
//!                 --gas N --sequence N --account-number N [--chain-id cosmoshub-4] [--memo T]   (unsigned = SignDoc, SIGN_MODE_DIRECT)
//! acct-tx decode  --chain C [--testnet] < unsigned-or-signed (JSON from build/sign, or bare base64)
//! acct-tx sign    --chain C --tx FILE --expect-to ADDR [--testnet] < secret   (xlm: S... ; algo: 25 words or base64 seed||pub)
//!   (atom: hex private key; signed JSON carries "signed" = TxRaw plus the "unsigned" SignDoc so decode can verify)
//!   shows the decoded payment on /dev/tty and signs only after the typed code. Prints {"signed":B64,"txid"}.
//! --sweep: xlm = AccountMerge (moves the whole balance incl. reserve, deletes the account; fails while trustlines/offers exist);
//!          algo = amount 0 + close-to (sends everything and closes the account; fails while ASAs are opted in).
use blocktools_acct::{algo, atom, fmt_units, xlm};
use blocktools_core::b64;
use serde_json::{json, Value};
use std::io::Read;
use zeroize::Zeroizing;

fn fail(e: &str) -> ! { println!("{}", json!({"status":"error","error":e})); std::process::exit(1) }
fn opt<'a>(a: &'a [String], k: &str) -> Option<&'a str> { a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).map(|s| s.as_str()) }
fn req<'a>(a: &'a [String], k: &str) -> &'a str { opt(a, k).unwrap_or_else(|| fail(&format!("missing {k}"))) }
fn num<T: std::str::FromStr>(a: &[String], k: &str) -> Option<T> { opt(a, k).map(|v| v.parse().unwrap_or_else(|_| fail(&format!("bad_number:{k}")))) }
fn flag(a: &[String], k: &str) -> bool { a.iter().any(|x| x == k) }
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn read_tx(s: &str) -> Vec<u8> {
    let s = serde_json::from_str::<Value>(s).ok().and_then(|v| v["unsigned"].as_str().or(v["signed"].as_str()).map(String::from)).unwrap_or(s.trim().to_string());
    b64::decode(s.trim()).unwrap_or_else(|| fail("bad_base64"))
}

fn xlm_describe(t: &xlm::Tx, net: &str) -> Value {
    let (kind, dest, amt) = match &t.op { xlm::Op::Payment { dest, amount } => ("payment", dest, Some(*amount)), xlm::Op::Merge { dest } => ("account_merge", dest, None) };
    let mut w = vec![];
    if matches!(t.memo, xlm::Memo::None) { w.push("memo_missing: exchanges credit deposits by memo; without one the funds may not be credited") }
    if kind == "account_merge" { w.push("account_merge: sends the entire balance including the reserve and deletes the source account") }
    json!({"chain":"xlm","type":kind,"from":xlm::address(&t.source),"to":xlm::address(dest),"amount_stroops":amt,"amount_str":amt.map(|v| fmt_units(v as u128, 7)),
        "fee_stroops":t.fee,"fee_str":fmt_units(t.fee as u128, 7),"seq":t.seq,"time_bounds":t.time,"memo":format!("{:?}", t.memo),
        "network":net,"txid":hex(&t.hash(net)),"signed":!t.sigs.is_empty(),"signature_valid":(!t.sigs.is_empty()).then(|| t.verify(net)),"warnings":w})
}
fn algo_describe(p: &algo::Pay) -> Value {
    let mut w = vec![];
    if p.close.is_some() { w.push("close_to: sends the entire remaining balance to the close address and closes the source account") }
    if p.gh != <[u8; 32]>::try_from(b64::decode(algo::MAINNET_GH).unwrap()).unwrap() { w.push("not_mainnet: genesis hash is not Algorand mainnet") }
    json!({"chain":"algo","type":"pay","from":algo::address(&p.snd),"to":algo::address(&p.rcv),"close_to":p.close.map(|c| algo::address(&c)),
        "amount_microalgo":p.amt,"amount_str":fmt_units(p.amt as u128, 6),"fee_microalgo":p.fee,"fee_str":fmt_units(p.fee as u128, 6),
        "first_round":p.fv,"last_round":p.lv,"genesis_id":p.gen,"note_len":p.note.len(),"txid":p.txid(),"signed":p.sig.is_some(),"signature_valid":p.sig.is_some().then(|| p.verify()),"warnings":w})
}
fn algo_secret(s: &str) -> Zeroizing<[u8; 32]> {
    if s.split_whitespace().count() == 25 { return blocktools_core::chains::algo_mnemonic_key(s).unwrap_or_else(|e| fail(e)) }
    let b = Zeroizing::new(b64::decode(s.trim()).unwrap_or_else(|| fail("secret_not_25_words_or_base64")));
    if b.len() != 64 { fail("base64_key_must_be_64_bytes") }
    Zeroizing::new(b[..32].try_into().unwrap())
}

fn atom_describe(t: &atom::Send, sig: Option<&[u8; 64]>) -> Value {
    let mut w = vec![];
    if t.memo.is_empty() { w.push("memo_missing: exchanges credit deposits by memo; without one the funds may not be credited") }
    if t.denom != "uatom" { w.push("denom_not_uatom") }
    if t.chain_id != "cosmoshub-4" { w.push("not_cosmoshub-4: chain_id differs from Cosmos Hub mainnet") }
    let raw = sig.map(|s| t.tx_raw(s));
    json!({"chain":"atom","type":"MsgSend","from":t.from,"to":t.to,"denom":t.denom,"amount_base":t.amount.to_string(),"amount_str":fmt_units(t.amount, 6),
        "fee_base":t.fee.to_string(),"fee_str":fmt_units(t.fee, 6),"gas":t.gas,"sequence":t.sequence,"account_number":t.account_number,"chain_id":t.chain_id,"memo":t.memo,
        "network":t.chain_id,"signed":sig.is_some(),"signature_valid":sig.map(|s| t.verify(s)),"txid":raw.map(|r| atom::Send::txid(&r)),"warnings":w})
}
fn hex32(s: &str) -> Zeroizing<[u8; 32]> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() != 64 { fail("private_key_must_be_64_hex") }
    let mut k = Zeroizing::new([0u8; 32]);
    for i in 0..32 { k[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_else(|_| fail("private_key_must_be_64_hex")) }
    k
}
fn unhex(s: &str) -> Vec<u8> { if s.len() % 2 != 0 { fail("bad_hex") } (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| fail("bad_hex"))).collect() }
fn atom_read(s: &str) -> (atom::Send, Option<[u8; 64]>) {
    let v: Value = serde_json::from_str(s).unwrap_or_else(|_| fail("atom input must be the JSON from build/sign"));
    let doc = b64::decode(v["unsigned"].as_str().unwrap_or_else(|| fail("missing unsigned SignDoc"))).unwrap_or_else(|| fail("bad_base64"));
    let t = atom::Send::decode_sign_doc(&doc).unwrap_or_else(|e| fail(&e));
    match v["signed"].as_str() {
        None => (t, None),
        Some(r) => { let (d, sig) = atom::Send::decode_tx_raw(&b64::decode(r).unwrap_or_else(|| fail("bad_base64")), &t.chain_id, t.account_number).unwrap_or_else(|e| fail(&e));
            if d != t { fail("signed_tx_differs_from_sign_doc") } (t, Some(sig)) }
    }
}

fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let chain = opt(&a, "--chain").unwrap_or("");
    let net = if flag(&a, "--testnet") { xlm::TESTNET } else { xlm::PUBLIC };
    match (a.first().map(|s| s.as_str()), chain) {
        (Some("build"), "xlm") => {
            let source = xlm::decode_address(req(&a, "--from")).unwrap_or_else(|e| fail(e));
            let dest = xlm::decode_address(req(&a, "--to")).unwrap_or_else(|e| fail(e));
            if source == dest { fail("destination_is_source") }
            let op = if flag(&a, "--sweep") { xlm::Op::Merge { dest } } else {
                let amount: i64 = num(&a, "--amount").unwrap_or_else(|| fail("missing --amount or --sweep"));
                if amount <= 0 { fail("amount_must_be_positive") } xlm::Op::Payment { dest, amount } };
            let memo = match (num::<u64>(&a, "--memo-id"), opt(&a, "--memo-text")) {
                (Some(i), None) => xlm::Memo::Id(i), (None, Some(t)) if t.len() <= 28 => xlm::Memo::Text(t.into()), (None, None) => xlm::Memo::None, _ => fail("bad_memo") };
            let t = xlm::Tx { source, fee: num(&a, "--fee").unwrap_or_else(|| fail("missing --fee")), seq: num(&a, "--seq").unwrap_or_else(|| fail("missing --seq")),
                time: Some((0, num(&a, "--max-time").unwrap_or(0))), memo, op, sigs: vec![] };
            let t = if t.time == Some((0, 0)) { xlm::Tx { time: None, ..t } } else { t };
            let d = xlm_describe(&t, net);
            for w in d["warnings"].as_array().unwrap() { eprintln!("acct-tx: WARNING {}", w.as_str().unwrap()) }
            println!("{}", json!({"chain":"xlm","unsigned":b64::encode(&t.envelope()),"summary":d}));
        }
        (Some("build"), "algo") => {
            let snd = algo::decode_address(req(&a, "--from")).unwrap_or_else(|e| fail(e));
            let rcv = algo::decode_address(req(&a, "--to")).unwrap_or_else(|e| fail(e));
            if snd == rcv { fail("destination_is_source") }
            let sweep = flag(&a, "--sweep");
            let amt = if sweep { 0 } else { num(&a, "--amount").unwrap_or_else(|| fail("missing --amount or --sweep")) };
            let fv: u64 = num(&a, "--first-round").unwrap_or_else(|| fail("missing --first-round"));
            let gh = b64::decode(opt(&a, "--genesis-hash").unwrap_or(algo::MAINNET_GH)).and_then(|v| v.try_into().ok()).unwrap_or_else(|| fail("bad_genesis_hash"));
            let p = algo::Pay { snd, rcv, amt, close: sweep.then_some(rcv), fee: num(&a, "--fee").unwrap_or_else(|| fail("missing --fee")), fv,
                lv: num(&a, "--last-round").unwrap_or(fv + 1000), gen: opt(&a, "--genesis-id").unwrap_or(algo::MAINNET_GEN).into(), gh,
                note: opt(&a, "--note").map(|n| n.as_bytes().to_vec()).unwrap_or_default(), sig: None };
            if p.lv < p.fv || p.lv - p.fv > 1000 { fail("last_round_must_be_within_1000_of_first") }
            let d = algo_describe(&p);
            for w in d["warnings"].as_array().unwrap() { eprintln!("acct-tx: WARNING {}", w.as_str().unwrap()) }
            println!("{}", json!({"chain":"algo","unsigned":b64::encode(&p.encode()),"summary":d}));
        }
        (Some("keys"), "atom") => {
            let mut sec = Zeroizing::new(String::new()); std::io::stdin().read_to_string(&mut sec).ok();
            let pk = atom::pubkey_of(&hex32(&sec)).unwrap_or_else(|e| fail(e));
            println!("{}", json!({"chain":"atom","address":atom::address(&pk),"pubkey":hex(&pk)}));
        }
        (Some("build"), "atom") => {
            let pubkey: [u8; 33] = unhex(req(&a, "--pubkey")).try_into().unwrap_or_else(|_| fail("pubkey_must_be_33_bytes"));
            let from = req(&a, "--from").to_string(); let to = req(&a, "--to").to_string();
            if atom::address(&pubkey) != from { fail("pubkey_does_not_match_from") }
            for x in [&from, &to] { blocktools_core::chains::cosmos_decode("cosmos", x).unwrap_or_else(|e| fail(e)); }
            if from == to { fail("destination_is_source") }
            let fee: u128 = num(&a, "--fee").unwrap_or_else(|| fail("missing --fee"));
            let amount: u128 = if flag(&a, "--sweep") { num::<u128>(&a, "--balance").unwrap_or_else(|| fail("--sweep needs --balance")).checked_sub(fee).filter(|&v| v > 0).unwrap_or_else(|| fail("balance_below_fee")) }
                else { num(&a, "--amount").unwrap_or_else(|| fail("missing --amount or --sweep")) };
            let t = atom::Send { from, to, denom: "uatom".into(), amount, memo: opt(&a, "--memo").unwrap_or("").into(), pubkey,
                sequence: num(&a, "--sequence").unwrap_or_else(|| fail("missing --sequence")), fee, gas: num(&a, "--gas").unwrap_or_else(|| fail("missing --gas")),
                chain_id: opt(&a, "--chain-id").unwrap_or("cosmoshub-4").into(), account_number: num(&a, "--account-number").unwrap_or_else(|| fail("missing --account-number")) };
            let d = atom_describe(&t, None);
            for w in d["warnings"].as_array().unwrap() { eprintln!("acct-tx: WARNING {}", w.as_str().unwrap()) }
            println!("{}", json!({"chain":"atom","unsigned":b64::encode(&t.sign_doc()),"summary":d}));
        }
        (Some("decode"), "atom") => { let mut s = String::new(); std::io::stdin().read_to_string(&mut s).ok(); let (t, sig) = atom_read(&s); println!("{}", atom_describe(&t, sig.as_ref())) }
        (Some("decode"), c) => {
            let mut s = String::new(); std::io::stdin().read_to_string(&mut s).ok();
            let b = read_tx(&s);
            match c { "xlm" => println!("{}", xlm_describe(&xlm::Tx::decode(&b).unwrap_or_else(|e| fail(&e)), net)),
                "algo" => println!("{}", algo_describe(&algo::Pay::decode(&b).unwrap_or_else(|e| fail(&e)))), _ => fail("unsupported --chain") }
        }
        (Some("sign"), c) => {
            let raw = std::fs::read_to_string(req(&a, "--tx")).unwrap_or_else(|_| fail("cannot_read_tx"));
            let b = if c == "atom" { vec![] } else { read_tx(&raw) }; let want = req(&a, "--expect-to");
            let mut secret = Zeroizing::new(String::new()); std::io::stdin().read_to_string(&mut secret).ok();
            let (d, out): (Value, Box<dyn FnOnce() -> Value>) = match c {
                "xlm" => {
                    let mut t = xlm::Tx::decode(&b).unwrap_or_else(|e| fail(&e));
                    if !t.sigs.is_empty() { fail("already_signed") }
                    let d = xlm_describe(&t, net); if d["to"] != want { fail("destination_mismatch") }
                    let k = xlm::decode_secret(&secret).unwrap_or_else(|e| fail(e));
                    (d, Box::new(move || { t.sign(&k, net).unwrap_or_else(|e| fail(e)); json!({"status":"ok","chain":"xlm","signed":b64::encode(&t.envelope()),"txid":hex(&t.hash(net))}) }))
                }
                "algo" => {
                    let mut p = algo::Pay::decode(&b).unwrap_or_else(|e| fail(&e));
                    if p.sig.is_some() { fail("already_signed") }
                    let d = algo_describe(&p); if d["to"] != want { fail("destination_mismatch") }
                    let k = algo_secret(&secret);
                    (d, Box::new(move || { p.sign(&k).unwrap_or_else(|e| fail(e)); json!({"status":"ok","chain":"algo","signed":b64::encode(&p.encode()),"txid":p.txid()}) }))
                }
                "atom" => {
                    let (t, sig) = atom_read(&raw);
                    if sig.is_some() { fail("already_signed") }
                    let d = atom_describe(&t, None); if d["to"] != want { fail("destination_mismatch") }
                    let k = hex32(&secret);
                    (d, Box::new(move || { let sg = t.sign(&k).unwrap_or_else(|e| fail(e)); let r = t.tx_raw(&sg);
                        json!({"status":"ok","chain":"atom","signed":b64::encode(&r),"unsigned":b64::encode(&t.sign_doc()),"txid":atom::Send::txid(&r)}) }))
                }
                _ => fail("unsupported --chain"),
            };
            let summary = format!("{} {} {}\n  amount {}  fee {}\n  from {}\n  to   {}{}\n{}", c.to_uppercase(), d["type"].as_str().unwrap(),
                d.get("network").and_then(|v| v.as_str()).or(d["genesis_id"].as_str()).unwrap_or(""),
                d["amount_str"].as_str().unwrap_or("ENTIRE BALANCE"), d["fee_str"].as_str().unwrap(), d["from"].as_str().unwrap(), d["to"].as_str().unwrap(),
                d["close_to"].as_str().map(|c| format!("\n  CLOSE REMAINDER TO {c}")).unwrap_or_default(),
                d["warnings"].as_array().unwrap().iter().map(|w| format!("  WARNING {}\n", w.as_str().unwrap())).collect::<String>());
            if !blocktools_tty::confirm(&summary) { println!("{}", json!({"status":"aborted"})); std::process::exit(1) }
            println!("{}", out());
        }
        _ => { eprintln!("usage: acct-tx keys|build|decode|sign --chain xlm|algo|atom (see source header)"); std::process::exit(2) }
    }
}
