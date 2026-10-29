//! safe-tx: Gnosis Safe (>= 1.3.0) m-of-n execTransaction, offline, no keys.
//!   safe-tx hash   --safe ADDR --chain-id N --nonce N --to ADDR --value WEI [--data HEX] [--operation 0|1]
//!                  [--safe-tx-gas N] [--base-gas N] [--gas-price N] [--gas-token ADDR] [--refund-receiver ADDR]
//!       -> {safe_tx_hash, domain_separator, struct_hash}   (what each owner signs in their own wallet)
//!   safe-tx exec   <same tx flags> --owner-sig HEX [--owner-sig HEX ...]
//!       -> {calldata, to, ordered_owners}   (orders the owner sigs ascending, builds the execTransaction call)
//!   safe-tx verify --safe ADDR --chain-id N --nonce N --calldata HEX --owner ADDR [--owner ADDR ...] --threshold M
//!       -> {status, owners}   (recompute the hash, recover each packed sig, require ascending+owned+>=threshold)
//! Owner signatures are ordinary ECDSA (65-byte r||s||v, v in {27,28}) over the Safe tx hash; this tool
//! never holds a key. The pubkeys/owners are public; nothing secret is read or printed.
use blocktools_evm::{parse_address, safe};
use blocktools_io::outln;
use serde_json::json;

fn die(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "safe-tx", "status": "bad_input", "error": e}));
    std::process::exit(2)
}
fn refuse(e: &str) -> ! {
    eprintln!("{}", json!({"tool": "safe-tx", "status": "refused", "error": e}));
    std::process::exit(1)
}

struct Args(Vec<String>);
impl Args {
    fn get(&self, k: &str) -> Option<String> {
        let i = self.0.iter().position(|x| x == k)?;
        self.0.get(i + 1).cloned()
    }
    fn req(&self, k: &str) -> String { self.get(k).unwrap_or_else(|| die(&format!("missing {k}"))) }
    fn all(&self, k: &str) -> Vec<String> {
        let mut v = Vec::new();
        for (i, x) in self.0.iter().enumerate() {
            if x == k { if let Some(val) = self.0.get(i + 1) { v.push(val.clone()); } }
        }
        v
    }
    fn opt(&self, k: &str, d: &str) -> String { self.get(k).unwrap_or_else(|| d.to_string()) }
}

fn tx_from(a: &Args) -> safe::SafeTx {
    safe::SafeTx {
        to: a.req("--to"),
        value: a.opt("--value", "0"),
        data: a.opt("--data", "0x"),
        operation: a.opt("--operation", "0"),
        safe_tx_gas: a.opt("--safe-tx-gas", "0"),
        base_gas: a.opt("--base-gas", "0"),
        gas_price: a.opt("--gas-price", "0"),
        gas_token: a.opt("--gas-token", safe::ZERO_ADDR),
        refund_receiver: a.opt("--refund-receiver", safe::ZERO_ADDR),
        nonce: a.req("--nonce"),
    }
}

fn hex32(b: &[u8; 32]) -> String { blocktools_evm::hex(b) }

fn main() {
    blocktools_io::help(
        "safe-tx hash|exec|verify ...   Gnosis Safe (>=1.3.0) m-of-n execTransaction, offline, no keys.
  hash   --safe --chain-id --nonce --to --value [--data --operation --safe-tx-gas --base-gas --gas-price --gas-token --refund-receiver]
  exec   <hash flags> --owner-sig HEX [--owner-sig HEX ...]        order owner sigs ascending, build the execTransaction calldata
  verify --safe --chain-id --nonce --calldata --owner ADDR [...] --threshold M   recompute the hash and check the packed signatures",
    );
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let cmd = argv.first().cloned().unwrap_or_default();
    let a = Args(argv);
    match cmd.as_str() {
        "hash" => {
            let t = tx_from(&a);
            match safe::safe_tx_hashes(&a.req("--chain-id"), &a.req("--safe"), &t) {
                Ok((ds, sh, h)) => outln!("{}", json!({"tool":"safe-tx","status":"ok",
                    "safe_tx_hash":hex32(&h),"domain_separator":hex32(&ds),"struct_hash":hex32(&sh)})),
                Err(e) => die(&e),
            }
        }
        "exec" => {
            let t = tx_from(&a);
            let sigs: Vec<Vec<u8>> = a.all("--owner-sig").iter()
                .map(|s| blocktools_evm::unhex(s).unwrap_or_else(|_| die("bad --owner-sig hex")))
                .collect();
            if sigs.is_empty() { die("at least one --owner-sig is required"); }
            match safe::exec_calldata(&a.req("--chain-id"), &a.req("--safe"), &t, &sigs) {
                Ok((calldata, owners)) => outln!("{}", json!({"tool":"safe-tx","status":"ok",
                    "to":a.req("--safe"),"calldata":calldata,
                    "ordered_owners":owners.iter().map(|o| blocktools_evm::checksum_address(o)).collect::<Vec<_>>()})),
                Err(e) => refuse(&e),
            }
        }
        "verify" => {
            let owners: Vec<[u8; 20]> = a.all("--owner").iter()
                .map(|s| parse_address(s).unwrap_or_else(|_| die("bad --owner address")))
                .collect();
            if owners.is_empty() { die("at least one --owner is required"); }
            let threshold: usize = a.req("--threshold").parse().unwrap_or_else(|_| die("--threshold must be a number"));
            match safe::verify_exec(&a.req("--chain-id"), &a.req("--safe"), &a.req("--nonce"),
                &a.req("--calldata"), &owners, threshold) {
                Ok(got) => outln!("{}", json!({"tool":"safe-tx","status":"ok",
                    "owners":got.iter().map(|o| blocktools_evm::checksum_address(o)).collect::<Vec<_>>()})),
                Err(e) => refuse(&e),
            }
        }
        "" => die("a subcommand is required: hash | exec | verify"),
        _ => die("unknown subcommand (hash | exec | verify)"),
    }
}
