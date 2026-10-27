//! THORChain MsgDeposit known-answer tests against the REAL mainnet `swapchan` THORName transactions
//! (register seq 0, alias seq 1), built by this code, signed by the owner key, and ACCEPTED by thorchain-1
//! on 2026-10-27. Signer/owner thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu. The pubkey and the signatures
//! are public (read back from the chain), so the whole signed TxRaw is a golden vector: this crate's
//! encoder must reproduce it byte for byte, and `verify` must accept the on-chain signature.
use blocktools_acct::thor::Deposit;

const PUBKEY: &str = "02db731fc490a4107583546391517f26d0196a1e8ac777560cccda03c702c86023";
const OWNER: &str = "thor174jsu5agtgztcmcly96ac9mrtf5n2k98dhmunu";

fn pk() -> [u8; 33] { unhex(PUBKEY).try_into().unwrap() }
fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
fn b64(b: &[u8]) -> String { blocktools_core::b64::encode(b) }

// register: ~:swapchan:THOR:owner:owner:ETH.ETH for 1 year (10 RUNE + per-block), 11.0512 RUNE, seq 0
const REG_TXRAW: &str = "CsIBCr8BChEvdHlwZXMuTXNnRGVwb3NpdBKpAQogChIKBFRIT1ISBFJVTkUaBFJVTkUSCjExMDUxMjAwMDASb346c3dhcGNoYW46VEhPUjp0aG9yMTc0anN1NWFndGd6dGNtY2x5OTZhYzltcnRmNW4yazk4ZGhtdW51OnRob3IxNzRqc3U1YWd0Z3p0Y21jbHk5NmFjOW1ydGY1bjJrOThkaG11bnU6RVRILkVUSBoU9WUOU6haBLxvHyF13BdjWmk1WKcSVwpOCkYKHy9jb3Ntb3MuY3J5cHRvLnNlY3AyNTZrMS5QdWJLZXkSIwohAttzH8SQpBB1g1RjkVF/JtAZah6Kx3dWDMzaA8cCyGAjEgQKAggBEgUQgNrECRpAYSbi35ahc3/tzKCMWKhHg78s1GUXQsqEt+zRrtTqeAdnkmmox8b5dv9wF2C6kHUkqm6cgrwWnsQflSMnuvm2sg==";
const REG_SIG: &str = "6126e2df96a1737fedcca08c58a84783bf2cd4651742ca84b7ecd1aed4ea7807679269a8c7c6f976ff701760ba907524aa6e9c82bc169ec41f952327baf9b6b2";
// alias: ~:swapchan:ETH:0xeb0eC7a28E4B6B175806E21D9D3afE45792C5c7B, 0.01 RUNE, seq 1
const ALIAS_TXRAW: &str = "CogBCoUBChEvdHlwZXMuTXNnRGVwb3NpdBJwCh0KEgoEVEhPUhIEUlVORRoEUlVORRIHMTAwMDAwMBI5fjpzd2FwY2hhbjpFVEg6MHhlYjBlQzdhMjhFNEI2QjE3NTgwNkUyMUQ5RDNhZkU0NTc5MkM1YzdCGhT1ZQ5TqFoEvG8fIXXcF2NaaTVYpxJZClAKRgofL2Nvc21vcy5jcnlwdG8uc2VjcDI1NmsxLlB1YktleRIjCiEC23MfxJCkEHWDVGORUX8m0BlqHorHd1YMzNoDxwLIYCMSBAoCCAEYARIFEIDaxAkaQLmE09FG9Gu5OBo4ldFzG2AZis++bynVbBrgFEdVXd7gDVpABbbDFb8/QicT8JNaCQxXzVTBNNaKfMicpd/Lx6E=";
const ALIAS_SIG: &str = "b984d3d146f46bb9381a3895d1731b60198acfbe6f29d56c1ae01447555ddee00d5a4005b6c315bf3f422713f0935a090c57cd54c134d68a7cc89ca5dfcbc7a1";

fn check(d: &Deposit, txraw_b64: &str, sig_hex: &str) {
    assert_eq!(d.thor_address(), OWNER, "address from pubkey");
    let sig: [u8; 64] = unhex(sig_hex).try_into().unwrap();
    // The signed TxRaw this crate builds must equal the bytes thorchain-1 accepted.
    assert_eq!(b64(&d.tx_raw(&sig)), txraw_b64, "TxRaw byte-for-byte vs mainnet");
    // The on-chain signature must verify against our SignDoc digest.
    assert!(d.verify(&sig), "on-chain signature verifies");
    // Round-trips: SignDoc and TxRaw decode back to the same Deposit (canonical re-encode check inside).
    assert_eq!(&Deposit::decode_sign_doc(&d.sign_doc()).unwrap(), d, "SignDoc round-trip");
    assert_eq!(&Deposit::decode_tx_raw(&d.tx_raw(&sig), &d.chain_id, d.account_number).unwrap().0, d, "TxRaw round-trip");
}

#[test]
fn register_golden() {
    let d = Deposit { asset_chain: "THOR".into(), asset_symbol: "RUNE".into(), asset_ticker: "RUNE".into(),
        amount: 1105120000,
        memo: format!("~:swapchan:THOR:{OWNER}:{OWNER}:ETH.ETH"),
        pubkey: pk(), sequence: 0, gas: 20000000, chain_id: "thorchain-1".into(), account_number: 157891 };
    check(&d, REG_TXRAW, REG_SIG);
}

#[test]
fn alias_golden() {
    let d = Deposit { asset_chain: "THOR".into(), asset_symbol: "RUNE".into(), asset_ticker: "RUNE".into(),
        amount: 1000000,
        memo: "~:swapchan:ETH:0xeb0eC7a28E4B6B175806E21D9D3afE45792C5c7B".into(),
        pubkey: pk(), sequence: 1, gas: 20000000, chain_id: "thorchain-1".into(), account_number: 157891 };
    check(&d, ALIAS_TXRAW, ALIAS_SIG);
}

#[test]
fn sign_verify_roundtrip_public_key() {
    // Public throwaway key 1 (private 0x..01): sign a deposit, our own signature must verify, and
    // a tampered memo must break the digest. No secrets; this exercises the sign path end to end.
    use secp256k1::{Secp256k1, SecretKey, PublicKey};
    let mut sk = [0u8; 32]; sk[31] = 1;
    let pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&sk).unwrap()).serialize();
    let d = Deposit { asset_chain: "THOR".into(), asset_symbol: "RUNE".into(), asset_ticker: "RUNE".into(),
        amount: 100000000, memo: "=:ETH.ETH:0x0000000000000000000000000000000000000001".into(),
        pubkey, sequence: 3, gas: 20000000, chain_id: "thorchain-1".into(), account_number: 1 };
    let sig = d.sign(&sk).unwrap();
    assert!(d.verify(&sig));
    let mut tampered = d.clone(); tampered.memo.push('X');
    assert!(!tampered.verify(&sig), "signature must not verify after the memo changes");
    assert_eq!(Deposit::decode_tx_raw(&d.tx_raw(&sig), &d.chain_id, d.account_number).unwrap().0, d);
}
