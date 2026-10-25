//! acct-tx: account-model payments for xlm, algo and atom. Encoded transactions are base64 (each chain's native form).
//! Balance / sequence / rounds come from the host-side `utxo-fetch --chain xlm|algo ADDR` (this tool has no network).
//! acct-tx build   --chain xlm  --from G.. --to G.. (--amount STROOPS | --sweep) --fee STROOPS --seq N [--memo-id N|--memo-text T] [--max-time UNIX] [--testnet]
//! acct-tx build   --chain algo --from A.. --to A.. (--amount MICROALGO | --sweep) --fee MICROALGO --first-round N [--last-round N] [--note T]
//! acct-tx keys    --chain atom < hex-private-key                    -> {"address","pubkey"} (public only; build needs --pubkey)
//! acct-tx build   --chain atom --from cosmos1.. --pubkey HEX33 --to cosmos1.. (--amount UATOM | --sweep --balance UATOM) --fee UATOM
//!                 --gas N --sequence N --account-number N [--chain-id cosmoshub-4] [--memo T]   (unsigned = SignDoc, SIGN_MODE_DIRECT)
//! acct-tx build   --chain ton  --from UQ.. --to EQ..|UQ.. (--amount NANOTON | --sweep) --seqno N --valid-until UNIX [--comment T]
//!                 (wallet v4r2 external message, BOC base64; deployed wallets only: seqno >= 1; the bounce flag follows the --to form)
//! acct-tx build   --chain ada  --from addr1.. --to addr1.. --utxo TXID#IX:LOVELACE [--utxo ..] (--amount LOVELACE | --sweep) --fee LOVELACE --ttl SLOT
//!                 (ADA-only legacy outputs, change back to --from; hex CBOR like cardano-cli; UTXOs carrying native assets must not be used)
//! acct-tx build   --chain dot  --from 1.. --to 1.. (--amount PLANCK | --sweep) --nonce N --block-number N --block-hash HEX [--period 64]
//!                 [--spec V --tx-version V] [--tip PLANCK]   (Polkadot Asset Hub Balances; UNVERIFIED layout, see recipes/chain-polkadot.md)
//! acct-tx decode  --chain C [--testnet] < unsigned-or-signed (JSON from build/sign, or bare base64)
//! acct-tx sign    --chain C --tx FILE --expect-to ADDR [--testnet] < secret   (xlm: S... ; algo: 25 words or base64 seed||pub)
//!   (dot: 0x-hex mini-secret as printed by recover, or the 12/24-word mnemonic; ada: 128-hex extended payment key kL||kR as printed by recover; ton: 24 TON words or 64-hex ed25519 seed; signed JSON carries "pubkey" so decode can verify; atom: hex private key; signed JSON carries "signed" = TxRaw plus the "unsigned" SignDoc so decode can verify)
//!   shows the decoded payment on /dev/tty and signs only after the typed code. Prints {"signed":B64,"txid"}.
//! --sweep: xlm = AccountMerge (moves the whole balance incl. reserve, deletes the account; fails while trustlines/offers exist);
//!          algo = amount 0 + close-to (sends everything and closes the account; fails while ASAs are opted in).
use blocktools_acct::{ada, algo, dot, atom, fmt_units, ton, xlm};
use blocktools_core::b64;
use serde_json::{json, Value};
use std::io::Read;
use zeroize::Zeroizing;

/// Print the full decode, then one schema-clean public line (tool/status/chain/from/to/amount/fee/signed)
/// so the decoded payment survives `redact` behind sealed-run.
fn emit(v: Value) {
    println!("{v}");
    let n = |pre: &str| v.as_object().and_then(|o| o.iter().find(|(k, x)| k.starts_with(pre) && k.as_str() != "amount_str" && k.as_str() != "fee_str"
        && (x.as_u64().is_some() || x.as_str().map_or(false, |s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())))).map(|(_, x)| x.as_u64().unwrap_or_else(|| x.as_str().unwrap().parse().unwrap_or(0))));
    let mut o = serde_json::Map::new();
    o.insert("tool".into(), json!("acct-tx")); o.insert("status".into(), json!("ok"));
    for k in ["chain", "from", "to", "signed"] { if let Some(x) = v.get(k).filter(|x| !x.is_null()) { o.insert(k.into(), x.clone()); } }
    if let Some(a) = n("amount_") { o.insert("amount".into(), json!(a)); }
    if let Some(f) = n("fee_") { o.insert("fee".into(), json!(f)); }
    println!("{}", Value::Object(o));
}
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

fn ton_describe(t: &ton::Transfer, pk: Option<&[u8; 32]>) -> Value {
    let mut w = vec![];
    if t.comment.is_none() && t.mode != ton::MODE_SWEEP { w.push("comment_missing: exchanges credit deposits by comment (memo); without one the funds may not be credited") }
    if t.mode == ton::MODE_SWEEP { w.push("sweep: send mode 128 carries the entire remaining balance (fees come out of it); the wallet stays deployed with ~0 balance") }
    else if t.mode != ton::MODE_PAY { w.push("unusual_send_mode") }
    if t.bounce { w.push("bounceable: if the destination is not an active contract the funds bounce back minus fees (use the UQ.. form for a fresh wallet)") }
    if t.wallet_id != ton::WALLET_ID { w.push("subwallet_id_not_default") }
    json!({"chain":"ton","type":if t.mode == ton::MODE_SWEEP {"sweep"} else {"transfer"},"from":ton::address(&t.wallet, false),"to":ton::address(&t.to, t.bounce),
        "amount_nanoton":(t.mode != ton::MODE_SWEEP).then(|| t.amount.to_string()),"amount_str":(t.mode != ton::MODE_SWEEP).then(|| fmt_units(t.amount, 9)),
        "fee_str":"taken from the wallet balance by the network (not part of the message)","send_mode":t.mode,"seqno":t.seqno,"valid_until":t.valid_until,
        "subwallet_id":t.wallet_id,"comment":t.comment,"network":"mainnet","signed":t.signed(),"signature_valid":pk.map(|k| t.verify(k)),
        "msg_hash":t.signed().then(|| hex(&t.msg_hash())),"warnings":w})
}
fn ton_read(s: &str) -> (ton::Transfer, Option<[u8; 32]>) {
    let pk = serde_json::from_str::<Value>(s).ok().and_then(|v| v["pubkey"].as_str().map(|p| unhex(p).try_into().unwrap_or_else(|_| fail("pubkey_must_be_32_bytes"))));
    (ton::Transfer::decode(&read_tx(s)).unwrap_or_else(|e| fail(e)), pk)
}

fn dot_describe(t: &dot::Transfer) -> Value {
    let mut w = vec![];
    if t.spec != dot::SPEC || t.tx_version != dot::TX_VERSION { w.push("runtime_version_differs_from_tested (2005000/15): extension layout unchecked; the node rejects a wrong layout (BadProof), funds are not at risk") }
    if let dot::Kind::Pay(v) = t.kind { if v < dot::ED { w.push("amount_below_existential_deposit (0.01 DOT): fails if the destination account is new") } }
    if t.era.is_none() { w.push("immortal: valid until nonce is used; prefer a mortal era") }
    json!({"chain":"dot","type":match t.kind { dot::Kind::Pay(_) => "transfer_keep_alive", dot::Kind::Sweep => "sweep (transfer_all, reaps the account)" },"from":dot::address(&t.from),"to":dot::address(&t.to),
        "amount_planck":match t.kind { dot::Kind::Pay(v) => Some(v.to_string()), _ => None },"amount_str":match t.kind { dot::Kind::Pay(v) => Some(fmt_units(v, dot::DECIMALS)), _ => None },
        "fee_str":format!("runtime-computed (tip {})", fmt_units(t.tip, dot::DECIMALS)),"nonce":t.nonce,"spec":t.spec,"tx_version":t.tx_version,"network":"Polkadot Asset Hub",
        "genesis":hex(&t.genesis),"era":t.era.map(|e| json!({"period":e.0,"block_number":e.1,"block_hash":hex(&e.2)})),"signed":t.sig.is_some(),"signature_valid":t.sig.map(|_| t.verify()),
        "extrinsic_hash":t.sig.map(|_| hex(&t.hash())),"verified":false,"warnings":w})
}
fn dot_read(s: &str) -> dot::Transfer {
    let v: Value = serde_json::from_str(s).unwrap_or_else(|_| fail("dot needs the JSON from build/sign"));
    let h = v["signed"].as_str().or(v["unsigned"].as_str()).unwrap_or_else(|| fail("missing tx"));
    let n = |k: &str| v[k].as_u64().unwrap_or_else(|| fail("missing runtime fields"));
    let era = v["era"].as_object().map(|e| (e["block_number"].as_u64().unwrap_or_else(|| fail("bad era")), *hex32(e["block_hash"].as_str().unwrap_or_else(|| fail("bad era")))));
    let mut t = dot::Transfer::decode(&unhex(h.trim_start_matches("0x")), n("spec") as u32, n("tx_version") as u32, *hex32(v["genesis"].as_str().unwrap_or_else(|| fail("missing genesis"))), era).unwrap_or_else(|e| fail(e));
    if let (Some(e), Some(p)) = (&mut t.era, v["era"]["period"].as_u64()) { if e.0 != p { fail("era period mismatch") } }
    if v["signed"].is_null() { t.sig = None }
    t
}
fn dot_json(t: &dot::Transfer, key: &str) -> Value {
    json!({"chain":"dot",key:format!("0x{}", hex(&t.encode())),"spec":t.spec,"tx_version":t.tx_version,"genesis":hex(&t.genesis),
        "era":t.era.map(|e| json!({"period":e.0,"block_number":e.1,"block_hash":hex(&e.2)}))})
}

fn all<'a>(a: &'a [String], k: &str) -> Vec<&'a str> { a.windows(2).filter(|w| w[0] == k).map(|w| w[1].as_str()).collect() }
fn ada_describe(t: &ada::Tx, from: Option<&str>, input_total: Option<u128>) -> Value {
    let fb = from.map(|f| ada::decode_address(f).unwrap_or_else(|e| fail(e)));
    let pays: Vec<&(Vec<u8>, u64)> = t.outputs.iter().filter(|o| Some(&o.0) != fb.as_ref()).collect();
    let mut w = vec![];
    if t.outputs.iter().any(|o| o.1 < ada::MIN_OUTPUT) { w.push("output_below_1_ada: the ledger minimum UTxO is about 1 ADA; the node will reject it") }
    if t.fee < t.min_fee() { w.push("fee_below_size_minimum (44*bytes+155381)") }
    if let Some(i) = input_total { if i != t.input_total_needed() { w.push("inputs_do_not_balance: input total != outputs + fee; the node will reject it") } }
    if t.wit.is_some() && fb.as_ref().is_some_and(|f| ada::payment_key_hash(f).ok() != Some(&ada::key_hash(&t.wit.unwrap().0)[..])) { w.push("witness_key_not_from_address") }
    json!({"chain":"ada","type":if fb.is_some() && t.outputs.len() == 1 {"sweep"} else {"payment"},"from":from,"to":(pays.len() == 1).then(|| ada::address(&pays[0].0)),
        "amount_lovelace":(pays.len() == 1).then(|| pays[0].1),"amount_str":(pays.len() == 1).then(|| fmt_units(pays[0].1 as u128, 6)),
        "outputs":t.outputs.iter().map(|o| json!({"address":ada::address(&o.0),"lovelace":o.1,"change":Some(&o.0) == fb.as_ref()})).collect::<Vec<_>>(),
        "inputs":t.inputs.iter().map(|i| format!("{}#{}", hex(&i.0), i.1)).collect::<Vec<_>>(),"input_lovelace":input_total.map(|v| v.to_string()),
        "fee_lovelace":t.fee,"fee_str":fmt_units(t.fee as u128, 6),"min_fee":t.min_fee(),"ttl":t.ttl,"network":"mainnet","txid":hex(&t.txid()),
        "signed":t.wit.is_some(),"signature_valid":t.wit.is_some().then(|| t.verify()),"warnings":w})
}
fn ada_read(s: &str) -> (ada::Tx, Option<String>, Option<u128>) {
    let v: Value = serde_json::from_str(s).unwrap_or_else(|_| json!({"unsigned": s.trim()}));
    let h = v["signed"].as_str().or(v["unsigned"].as_str()).unwrap_or_else(|| fail("missing tx"));
    let t = ada::Tx::decode(&unhex(h.trim())).unwrap_or_else(|e| fail(e));
    (t, v["from"].as_str().map(String::from), v["input_lovelace"].as_str().and_then(|x| x.parse().ok()))
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
        (Some("build"), "ton") => {
            let (wallet, _) = ton::parse_address(req(&a, "--from")).unwrap_or_else(|e| fail(e));
            let (to, bounce) = ton::parse_address(req(&a, "--to")).unwrap_or_else(|e| fail(e));
            if wallet == to { fail("destination_is_source") }
            let sweep = flag(&a, "--sweep");
            let amount: u128 = if sweep { 0 } else { num(&a, "--amount").filter(|&v: &u128| v > 0).unwrap_or_else(|| fail("missing --amount (>0) or --sweep")) };
            let seqno: u32 = num(&a, "--seqno").unwrap_or_else(|| fail("missing --seqno"));
            if seqno == 0 { fail("seqno_0: wallet not deployed; the deploy (StateInit) message is NOT BUILT") }
            let comment = opt(&a, "--comment").map(String::from);
            if comment.as_ref().is_some_and(|c| c.is_empty() || c.len() > ton::MAX_COMMENT) { fail("comment_must_be_1_to_120_bytes") }
            let t = ton::Transfer { wallet, wallet_id: ton::WALLET_ID, valid_until: num(&a, "--valid-until").unwrap_or_else(|| fail("missing --valid-until")), seqno,
                mode: if sweep { ton::MODE_SWEEP } else { ton::MODE_PAY }, to, bounce, amount, comment, sig: [0; 64] };
            let d = ton_describe(&t, None);
            for w in d["warnings"].as_array().unwrap() { eprintln!("acct-tx: WARNING {}", w.as_str().unwrap()) }
            println!("{}", json!({"chain":"ton","unsigned":b64::encode(&t.encode()),"summary":d}));
        }
        (Some("build"), "ada") => {
            let from = req(&a, "--from"); let fb = ada::decode_address(from).unwrap_or_else(|e| fail(e));
            ada::payment_key_hash(&fb).unwrap_or_else(|e| fail(e));
            let tb = ada::decode_address(req(&a, "--to")).unwrap_or_else(|e| fail(e));
            if tb == fb { fail("destination_is_source") }
            let mut inputs = vec![]; let mut total = 0u128;
            for u in all(&a, "--utxo") {
                let (hi, v) = u.split_once(':').unwrap_or_else(|| fail("utxo_must_be_TXID#IX:LOVELACE"));
                let (h, i) = hi.split_once('#').or_else(|| hi.split_once('.')).unwrap_or_else(|| fail("utxo_must_be_TXID#IX:LOVELACE"));
                let h: [u8; 32] = unhex(h).try_into().unwrap_or_else(|_| fail("utxo_txid_must_be_32_bytes"));
                inputs.push((h, i.parse::<u32>().unwrap_or_else(|_| fail("bad_utxo_index")))); total += v.parse::<u64>().unwrap_or_else(|_| fail("bad_utxo_amount")) as u128;
            }
            if inputs.is_empty() { fail("missing --utxo") }
            inputs.sort(); if inputs.windows(2).any(|w| w[0] == w[1]) { fail("duplicate_utxo") }
            let fee: u64 = num(&a, "--fee").unwrap_or_else(|| fail("missing --fee"));
            let outputs = if flag(&a, "--sweep") {
                vec![(tb, total.checked_sub(fee as u128).and_then(|v| u64::try_from(v).ok()).unwrap_or_else(|| fail("inputs_below_fee")))]
            } else {
                let amt: u64 = num(&a, "--amount").unwrap_or_else(|| fail("missing --amount or --sweep"));
                let change = total.checked_sub(amt as u128 + fee as u128).unwrap_or_else(|| fail("inputs_below_amount_plus_fee"));
                if change > 0 && change < ada::MIN_OUTPUT as u128 { fail("change_below_1_ada: raise the fee to absorb it, add an input, or use --sweep") }
                let mut o = vec![(tb, amt)]; if change > 0 { o.push((fb, change as u64)) } o
            };
            let t = ada::Tx { inputs, outputs, fee, ttl: num(&a, "--ttl").unwrap_or_else(|| fail("missing --ttl")), wit: None };
            if fee < t.min_fee() { fail(&format!("fee_below_size_minimum: need >= {} lovelace", t.min_fee())) }
            let d = ada_describe(&t, Some(from), Some(total));
            for w in d["warnings"].as_array().unwrap() { eprintln!("acct-tx: WARNING {}", w.as_str().unwrap()) }
            println!("{}", json!({"chain":"ada","unsigned":hex(&t.encode()),"from":from,"input_lovelace":total.to_string(),"summary":d}));
        }
        (Some("build"), "dot") => {
            let from = dot::parse_address(req(&a, "--from")).unwrap_or_else(|e| fail(e)); let to = dot::parse_address(req(&a, "--to")).unwrap_or_else(|e| fail(e));
            if from == to { fail("destination_is_source") }
            let kind = if flag(&a, "--sweep") { dot::Kind::Sweep } else { dot::Kind::Pay(num(&a, "--amount").unwrap_or_else(|| fail("missing --amount or --sweep"))) };
            let era = if flag(&a, "--immortal") { None } else {
                let p: u64 = num(&a, "--period").unwrap_or(64); if !(4..=65536).contains(&p) || !p.is_power_of_two() { fail("period_must_be_power_of_two_4..65536") }
                Some((p, num(&a, "--block-number").unwrap_or_else(|| fail("missing --block-number (or --immortal)")), *hex32(req(&a, "--block-hash").trim_start_matches("0x")))) };
            let t = dot::Transfer { from, to, kind, era, nonce: num(&a, "--nonce").unwrap_or_else(|| fail("missing --nonce")), tip: num(&a, "--tip").unwrap_or(0),
                spec: num(&a, "--spec").unwrap_or(dot::SPEC), tx_version: num(&a, "--tx-version").unwrap_or(dot::TX_VERSION), genesis: dot::GENESIS, sig: None };
            let d = dot_describe(&t);
            for w in d["warnings"].as_array().unwrap() { eprintln!("acct-tx: WARNING {}", w.as_str().unwrap()) }
            let mut o = dot_json(&t, "unsigned"); o["summary"] = d; println!("{o}");
        }
        (Some("decode"), "dot") => { let mut s = String::new(); std::io::stdin().read_to_string(&mut s).ok(); emit(dot_describe(&dot_read(&s))) }
        (Some("decode"), "ada") => { let mut s = String::new(); std::io::stdin().read_to_string(&mut s).ok(); let (t, f, i) = ada_read(&s); emit(ada_describe(&t, f.as_deref(), i)) }
        (Some("decode"), "ton") => { let mut s = String::new(); std::io::stdin().read_to_string(&mut s).ok(); let (t, pk) = ton_read(&s); emit(ton_describe(&t, pk.as_ref())) }
        (Some("keys"), "atom") => {
            let mut sec = Zeroizing::new(String::new()); std::io::stdin().read_to_string(&mut sec).ok();
            let pk = atom::pubkey_of(&hex32(&sec)).unwrap_or_else(|e| fail(e));
            println!("{}", json!({"tool":"acct-tx","status":"ok","chain":"atom","address":atom::address(&pk),"pubkey":hex(&pk)}));
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
        (Some("decode"), "atom") => { let mut s = String::new(); std::io::stdin().read_to_string(&mut s).ok(); let (t, sig) = atom_read(&s); emit(atom_describe(&t, sig.as_ref())) }
        (Some("decode"), c) => {
            let mut s = String::new(); std::io::stdin().read_to_string(&mut s).ok();
            let b = read_tx(&s);
            match c { "xlm" => emit(xlm_describe(&xlm::Tx::decode(&b).unwrap_or_else(|e| fail(&e)), net)),
                "algo" => emit(algo_describe(&algo::Pay::decode(&b).unwrap_or_else(|e| fail(&e)))), _ => fail("unsupported --chain") }
        }
        (Some("sign"), c) => {
            let raw = std::fs::read_to_string(req(&a, "--tx")).unwrap_or_else(|_| fail("cannot_read_tx"));
            let b = if c == "atom" || c == "ton" || c == "ada" || c == "dot" { vec![] } else { read_tx(&raw) }; let want = req(&a, "--expect-to");
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
                "dot" => {
                    let mut t = dot_read(&raw);
                    let d = dot_describe(&t);
                    if dot::parse_address(want).ok() != Some(t.to) { fail("destination_mismatch") }
                    let k = if secret.split_whitespace().count() >= 12 { blocktools_core::chains::substrate_mini_secret(secret.trim(), "").unwrap_or_else(|e| fail(e)) } else { hex32(secret.trim().trim_start_matches("0x")) };
                    (d, Box::new(move || { t.sign(&k).unwrap_or_else(|e| fail(e)); let mut o = dot_json(&t, "signed"); o["status"] = json!("ok"); o["extrinsic_hash"] = json!(hex(&t.hash())); o }))
                }
                "ada" => {
                    let (mut t, from, total) = ada_read(&raw);
                    if t.wit.is_some() { fail("already_signed") }
                    let from = from.unwrap_or_else(|| fail("ada sign needs the JSON from build (it carries --from)"));
                    let d = ada_describe(&t, Some(&from), total);
                    if d["to"] != want { fail("destination_mismatch") }
                    if !d["warnings"].as_array().unwrap().is_empty() { fail("refusing_to_sign_with_warnings") }
                    let sk = Zeroizing::new(unhex(secret.trim())); let xk: Zeroizing<[u8; 64]> = Zeroizing::new(sk[..].try_into().unwrap_or_else(|_| fail("ada_key_must_be_128_hex (kL||kR)")));
                    if ada::payment_key_hash(&ada::decode_address(&from).unwrap()).ok() != Some(&ada::key_hash(&ada::ext_pub(&xk))[..]) { fail("key_does_not_match_from") }
                    (d, Box::new(move || { t.sign(&xk); json!({"status":"ok","chain":"ada","signed":hex(&t.encode()),"from":from,"txid":hex(&t.txid())}) }))
                }
                "ton" => {
                    let (mut t, _) = ton_read(&raw);
                    if t.signed() { fail("already_signed") }
                    let d = ton_describe(&t, None);
                    if ton::parse_address(want).map(|x| x.0) != Ok(t.to) { fail("destination_mismatch") }
                    let k = if secret.split_whitespace().count() == 24 { blocktools_core::chains::ton_mnemonic_key(&secret).unwrap_or_else(|e| fail(e)) } else { hex32(&secret) };
                    (d, Box::new(move || { let pk = t.sign(&k).unwrap_or_else(|e| fail(e));
                        json!({"status":"ok","chain":"ton","signed":b64::encode(&t.encode()),"pubkey":hex(&pk),"msg_hash":hex(&t.msg_hash())}) }))
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
        _ => { eprintln!("usage: acct-tx keys|build|decode|sign --chain xlm|algo|atom|ton|ada|dot (see source header)"); std::process::exit(2) }
    }
}
