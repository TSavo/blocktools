//! tx-combine: merge the partial-signature PSBTs of an m-of-n multisig (each produced by
//! `tx-sign --partial` by a different cosigner) and finalize the inputs once the threshold is met.
//!   tx-combine --psbt p1.json --psbt p2.json --psbt p3.json
//! stdout: one JSON line {signed_tx: hex, psbt: finalized base64}. Refuses (not_enough_signatures)
//! if any multisig input is below its threshold. Offline, reads only public PSBTs, holds no key.
use bitcoin::psbt::Psbt;
use blocktools_io::outln;
use serde_json::json;
use std::io::Read;

fn die(status: &str, e: &str) -> ! {
    eprintln!("{}", json!({"tool": "tx-combine", "status": status, "error": e}));
    std::process::exit(if status == "bad_input" { 2 } else { 1 })
}

fn read_psbt(f: &str) -> Psbt {
    let txt = if f == "-" {
        let mut s = String::new();
        std::io::stdin().take(8 << 20).read_to_string(&mut s).ok();
        s
    } else {
        std::fs::read_to_string(f).unwrap_or_else(|_| die("bad_input", "cannot read --psbt file"))
    };
    let raw = blocktools_tx::input_bytes(&txt).unwrap_or_else(|e| die("bad_input", e));
    Psbt::deserialize(&raw).unwrap_or_else(|_| die("bad_input", "not a PSBT"))
}

fn main() {
    blocktools_io::help(
        "tx-combine --psbt FILE [--psbt FILE ...]   (FILE may be - for stdin)
  Merge partial-signature PSBTs from an m-of-n multisig (tx-sign --partial outputs from each cosigner)
  and finalize once the threshold is met. stdout: {signed_tx, psbt}. Offline, public PSBTs, no keys.",
    );
    let a: Vec<String> = std::env::args().skip(1).collect();
    let mut files = Vec::new();
    let mut i = 0;
    while i < a.len() {
        match a[i].as_str() {
            "--psbt" => {
                i += 1;
                files.push(a.get(i).cloned().unwrap_or_else(|| die("bad_input", "--psbt needs a FILE")));
            }
            _ => die("bad_input", "unexpected argument"),
        }
        i += 1;
    }
    if files.is_empty() {
        die("bad_input", "at least one --psbt FILE is required")
    }
    // The same library path the wasm `combinePsbts` export calls (blocktools_tx::multisig::combine_psbts).
    let raws: Vec<Vec<u8>> = files.iter().map(|f| read_psbt(f).serialize()).collect();
    let (signed, psbt) = blocktools_tx::multisig::combine_psbts(&raws).unwrap_or_else(|e| match e {
        "psbts_do_not_combine" => die("bad_input", "PSBTs do not combine (different unsigned tx?)"),
        e => die("refused", e),
    });
    outln!(
        "{}",
        json!({"tool":"tx-combine","status":"ok","signed_tx":blocktools_core::hex_enc(&signed),"psbt":blocktools_core::b64::encode(&psbt)})
    );
}
