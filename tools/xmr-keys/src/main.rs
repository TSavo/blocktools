//! xmr-keys [--net main|stage|test] < seed : one JSON line of PUBLIC data (address, public spend/view keys).
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
            println!("{{\"chain\":\"xmr\",\"kind\":\"standard\",\"address\":\"{}\",\"spend_public\":\"{}\",\"view_public\":\"{}\"}}",
                address(net, &k.spend_public, &k.view_public), hex(&k.spend_public), hex(&k.view_public)); }
        Err(e) => { eprintln!("{{\"error\":\"{e}\"}}"); std::process::exit(1) }
    }
}
