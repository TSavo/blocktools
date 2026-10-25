//! xmr-keys [--net main|stage|test] [--scan-out FILE [--restore-height N]] < seed
//! stdout: one JSON line of PUBLIC data (address, public spend/view keys).
//! --scan-out writes a monero-wallet-rpc `generate_from_keys` request for a VIEW-ONLY wallet
//! (address + private view key, no spend key) to FILE, created new with mode 0600. The view key
//! is secret (it reveals incoming funds), so it never goes to stdout or stderr.
use std::io::Read;
use blocktools_monero::*;
use zeroize::Zeroizing;
fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
fn main() {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let net = match a.iter().position(|x| x == "--net").and_then(|i| a.get(i + 1)).map(|s| s.as_str()) {
        None | Some("main") => Net::Main, Some("stage") => Net::Stage, Some("test") => Net::Test,
        _ => { eprintln!("{{\"error\":\"bad_net\"}}"); std::process::exit(2) } };
    let mut s = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut s).ok();
    match seed_to_spend(&s) {
        Ok(sp) => { let k = keys_from_spend(&sp);
            println!("{{\"tool\":\"xmr-keys\",\"status\":\"ok\",\"chain\":\"xmr\",\"kind\":\"xmr\",\"address\":\"{}\",\"spend_public\":\"{}\",\"view_public\":\"{}\"}}",
                address(net, &k.spend_public, &k.view_public), hex(&k.spend_public), hex(&k.view_public));
            if let Some(path) = arg(&a, "--scan-out") {
                let height: u64 = match arg(&a, "--restore-height").map(|h| h.parse()) {
                    None => 0, Some(Ok(h)) => h,
                    Some(Err(_)) => { eprintln!("{{\"error\":\"bad_restore_height\"}}"); std::process::exit(2) } };
                let body = Zeroizing::new(format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"generate_from_keys\",\"params\":{{\"restore_height\":{height},\"filename\":\"blocktools-viewonly\",\"address\":\"{}\",\"viewkey\":\"{}\",\"password\":\"\"}}}}\n",
                    address(net, &k.spend_public, &k.view_public), Zeroizing::new(hex(&k.view_secret[..])).as_str()));
                if let Err(e) = write_private(path, body.as_bytes()) { eprintln!("{{\"error\":\"scan_out: {}\"}}", e.kind()); std::process::exit(1) }
                eprintln!("{{\"scan_out\":\"written\",\"mode\":\"0600\",\"contains\":\"private view key\"}}");
            } }
        Err(e) => { eprintln!("{{\"error\":\"{e}\"}}"); std::process::exit(1) }
    }
}
fn arg<'a>(a: &'a [String], k: &str) -> Option<&'a str> { a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).map(|s| s.as_str()) }
fn write_private(path: &str, b: &[u8]) -> std::io::Result<()> {
    use std::io::Write; use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(b)?; f.sync_all()
}
