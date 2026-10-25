//! Public-key derivation: account-level xpub -> addresses. No private key is ever
//! involved, so this is in the default (secrets-off) build.
use crate::chains::{self, AddrRow, Chain};
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::Secp256k1;
use std::str::FromStr;

/// Upper bound on rows from one call (keeps WASM/JS callers from asking for millions).
pub const MAX_ROWS: usize = 100_000;

/// Derive `xpub/branch/i` for each branch and index, encoded for `chain`; `kinds` filters
/// script types (empty = all the chain supports). Paths in the rows are relative to the
/// xpub ("m/0/3"). Only non-hardened steps are possible from an xpub.
pub fn from_xpub(xpub: &str, chain: &Chain, kinds: &[&str], branches: &[u32], indices: &[u32]) -> Result<Vec<AddrRow>, &'static str> {
    let x = Xpub::from_str(xpub.trim()).map_err(|_| "bad_xpub")?;
    if branches.len().saturating_mul(indices.len()) > MAX_ROWS { return Err("too_many_candidates") }
    if chain.enc == chains::Enc::Sol { return Err("unsupported") } // ed25519 has no public derivation
    let secp = Secp256k1::verification_only();
    let mut out = Vec::new();
    for &b in branches {
        let bk = x.derive_pub(&secp, &[ChildNumber::from_normal_idx(b).map_err(|_| "bad_input")?]).map_err(|_| "bad_input")?;
        for &i in indices {
            let k = bk.derive_pub(&secp, &[ChildNumber::from_normal_idx(i).map_err(|_| "bad_input")?]).map_err(|_| "bad_input")?;
            out.extend(chains::pub_rows(chain, &format!("m/{b}/{i}"), &k.public_key, false).into_iter()
                .filter(|r| kinds.is_empty() || kinds.contains(&r.kind)));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    // BIP84 test vector (public): zpub of "abandon x11 about", given here as the xpub form.
    // Account m/84'/0'/0' of the BIP39 root; first receive address from BIP84.
    const ACCT84: &str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
    #[test] fn bip84_first_address() {
        let r = from_xpub(ACCT84, chains::chain("btc").unwrap(), &["p2wpkh"], &[0], &[0, 1]).unwrap();
        assert_eq!(r[0].address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(r[1].address, "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
        assert_eq!(r[0].path, "m/0/0");
    }
    #[test] fn rejects() {
        assert_eq!(from_xpub("nope", chains::chain("btc").unwrap(), &[], &[0], &[0]).unwrap_err(), "bad_xpub");
        assert_eq!(from_xpub(ACCT84, chains::chain("btc").unwrap(), &[], &[1 << 31], &[0]).unwrap_err(), "bad_input");
    }
}
