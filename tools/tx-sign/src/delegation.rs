use blocktools_core::{eth_address, hex_enc, validate};
use blocktools_tx::delegation::Authorization;
use serde_json::json;
use std::io::{BufRead, Read};
use zeroize::Zeroizing;

pub(super) fn run() -> ! {
    let args: Vec<_> = std::env::args().skip(2).collect();
    let bad = |reason: &str| -> ! { super::out("bad_input", json!({"error":reason})) };
    let [chain, nonce, sender, delegate] = args.as_slice() else {
        bad("usage: tx-sign authorize-delegate CHAIN_ID NONCE SENDER DELEGATE < key")
    };
    let auth = Authorization {
        chain_id: chain.parse().unwrap_or_else(|_| bad("invalid chain id")),
        nonce: nonce.parse().unwrap_or_else(|_| bad("invalid nonce")),
        delegate: validate::eth(delegate).unwrap_or_else(|_| bad("invalid delegate address")),
    };
    let expected = validate::eth(sender).unwrap_or_else(|_| bad("invalid sender address"));
    auth.digest().unwrap_or_else(|e| bad(e));
    let key = read_key(expected).unwrap_or_else(|| bad("sender key missing"));
    let action = if auth.delegate == [0; 20] {
        "Clear delegation"
    } else {
        "Authorize persistent delegation of this account"
    };
    let summary=format!("{action}\nSender: {sender}\nDelegate: {delegate}\nChain ID: {}\nAccount nonce: {}\nThis authorization is independent of any specific payment.",auth.chain_id,auth.nonce);
    if !blocktools_tty::confirm(&summary) {
        super::out("aborted", json!({}));
    }
    let (parity, sig) = auth.sign(&key).unwrap_or_else(|e| bad(e));
    super::out(
        "ok",
        json!({"authorization":{"chainId":format!("{:#x}",auth.chain_id),"address":delegate,"nonce":format!("{:#x}",auth.nonce),"yParity":format!("{parity:#x}"),"r":format!("0x{}",hex_enc(&sig[..32])),"s":format!("0x{}",hex_enc(&sig[32..]))}}),
    )
}

pub(super) fn read_key(expected: [u8; 20]) -> Option<bitcoin::secp256k1::SecretKey> {
    let mut stream = std::io::stdin().lock().take(4 << 20);
    let mut line = Zeroizing::new(String::new());
    loop {
        line.clear();
        if stream.read_line(&mut line).ok()? == 0 {
            return None;
        }
        if let Some(key) = blocktools_secrets::keys::parse_key_line(&line) {
            if validate::eth(&eth_address(&key, &bitcoin::secp256k1::Secp256k1::new())).ok()
                == Some(expected)
            {
                return Some(key);
            }
        }
    }
}
