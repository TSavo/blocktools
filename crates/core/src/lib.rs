//! Shared, dependency-light helpers for the blocktools tools that touch Bitcoin /
//! Ethereum keys. One crypto family (rust-bitcoin + secp256k1) plus sha3 for
//! Keccak. No hand-rolled primitives.
//! Default build: public inputs only (addresses, plans, xpub derivation). Anything that
//! takes or emits a private key is behind the `secrets` feature.
#[cfg(feature = "secrets")]
use bitcoin::bip32::{DerivationPath, Xpriv};
#[cfg(feature = "secrets")]
use bitcoin::secp256k1::{All, PublicKey, Secp256k1, SecretKey};
#[cfg(feature = "secrets")]
use bitcoin::{Address, CompressedPublicKey, Network, PrivateKey};
use sha3::{Digest, Keccak256};
pub mod blake2b;
pub mod chains;
pub mod chain_spec;
pub mod plan;
pub mod validate;
pub mod b64;
pub mod xpub;
pub mod classify;
#[cfg(feature = "secrets")]
use std::str::FromStr;

pub fn hex_enc(b: impl AsRef<[u8]>) -> String {
    b.as_ref().iter().map(|x| format!("{x:02x}")).collect()
}
pub fn hex_dec(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

#[cfg(feature = "secrets")]
/// EIP-55 checksummed Ethereum address from a secp256k1 secret key.
pub fn eth_address(sk: &SecretKey, secp: &Secp256k1<All>) -> String {
    let pk = PublicKey::from_secret_key(secp, sk).serialize_uncompressed();
    eth_address_from_pubkey(&pk)
}
pub fn eth_address_from_pubkey(uncompressed_pk: &[u8]) -> String {
    let h = Keccak256::digest(&uncompressed_pk[1..]);
    let a = hex_enc(&h[12..]);
    let ch = hex_enc(Keccak256::digest(a.as_bytes()));
    let s: String = a.chars().zip(ch.chars())
        .map(|(c, k)| if k.to_digit(16).unwrap() >= 8 { c.to_ascii_uppercase() } else { c })
        .collect();
    format!("0x{s}")
}

#[cfg(feature = "secrets")]
pub struct Row { pub kind: &'static str, pub path: String, pub address: String, pub secret: String }

pub const ACCOUNT_KINDS: [(&str, u32, u32); 5] =
    [("p2pkh", 44, 0), ("p2sh-p2wpkh", 49, 0), ("p2wpkh", 84, 0), ("p2tr", 86, 0), ("eth", 44, 60)];

#[cfg(feature = "secrets")]
/// Given a BIP32 master key, derive the standard external-chain addresses.
pub fn derive_from_master(master: &Xpriv, count: u32) -> Vec<Row> {
    let secp = Secp256k1::new();
    let mut rows = Vec::new();
    for (kind, purpose, coin) in ACCOUNT_KINDS {
        for i in 0..count {
            let path = format!("m/{purpose}'/{coin}'/0'/0/{i}");
            let xk = master.derive_priv(&secp, &DerivationPath::from_str(&path).unwrap()).unwrap();
            rows.push(row_for(kind, path, &xk.private_key, &secp));
        }
    }
    rows
}

#[cfg(feature = "secrets")]
pub fn row_for(kind: &'static str, path: String, sk: &SecretKey, secp: &Secp256k1<All>) -> Row {
    let (address, secret) = if kind == "eth" {
        (eth_address(sk, secp), hex_enc(sk.secret_bytes()))
    } else {
        let cpk = CompressedPublicKey::from_private_key(secp, &PrivateKey::new(*sk, Network::Bitcoin)).unwrap();
        let a = match kind {
            "p2pkh" => Address::p2pkh(cpk, Network::Bitcoin),
            "p2sh-p2wpkh" => Address::p2shwpkh(&cpk, Network::Bitcoin),
            "p2wpkh" => Address::p2wpkh(&cpk, Network::Bitcoin),
            _ => Address::p2tr(secp, cpk.0.x_only_public_key().0, None, Network::Bitcoin),
        };
        (a.to_string(), PrivateKey::new(*sk, Network::Bitcoin).to_wif())
    };
    Row { kind, path, address, secret }
}

#[cfg(feature = "secrets")]
/// Address rows for a bare key (legacy wallets): compressed keys get
/// p2pkh, p2sh-p2wpkh and p2wpkh; uncompressed keys only p2pkh (uncompressed WIF).
pub fn key_rows(sk: &SecretKey, compressed: bool) -> Vec<Row> {
    let secp = Secp256k1::new();
    if !compressed {
        let pk = PrivateKey { compressed: false, network: Network::Bitcoin.into(), inner: *sk };
        let a = Address::p2pkh(pk.public_key(&secp), Network::Bitcoin);
        return vec![Row { kind: "p2pkh", path: String::new(), address: a.to_string(), secret: pk.to_wif() }];
    }
    ["p2pkh", "p2sh-p2wpkh", "p2wpkh"].iter().map(|k| row_for(k, String::new(), sk, &secp)).collect()
}

pub fn kind_name(k: &str) -> Option<&'static str> {
    ACCOUNT_KINDS.iter().map(|x| x.0).find(|x| *x == k)
}

#[cfg(feature = "secrets")]
/// Derive from an account-level key that sits at `path` (e.g. m/84'/0'/0'):
/// rows for `path/branch/i`, i < count, of one address kind.
pub fn derive_account(acct: &Xpriv, kind: &'static str, path: &str, branch: u32, count: u32) -> Vec<Row> {
    let secp = Secp256k1::new();
    (0..count).map(|i| {
        let rel = DerivationPath::from_str(&format!("m/{branch}/{i}")).unwrap();
        let xk = acct.derive_priv(&secp, &rel).unwrap();
        row_for(kind, format!("{path}/{branch}/{i}"), &xk.private_key, &secp)
    }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn hexroundtrip() { assert_eq!(hex_dec(&hex_enc([1u8, 255])).unwrap(), vec![1, 255]); assert_eq!(hex_dec("0xff"), Some(vec![255])); }
}
