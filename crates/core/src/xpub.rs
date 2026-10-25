//! Public-key derivation: account-level xpub -> addresses. No private key is ever
//! involved, so this is in the default (secrets-off) build.
use crate::chains::{self, AddrRow, Chain};
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::secp256k1::Secp256k1;
use std::str::FromStr;

/// Upper bound on rows from one call (keeps WASM/JS callers from asking for millions).
pub const MAX_ROWS: usize = 100_000;

/// SLIP-132: ypub/zpub (and testnet upub/vpub) carry the same key as an xpub/tpub with other
/// version bytes. Returns the xpub/tpub form and the script kind the prefix implies, if any.
pub fn normalize(s: &str) -> Result<(String, Option<&'static str>), &'static str> {
    let s = s.trim();
    let (ver, kind): ([u8; 4], Option<&str>) = match s.get(..4) {
        Some("xpub") => return Ok((s.to_string(), None)), Some("tpub") => return Ok((s.to_string(), None)),
        Some("ypub") => ([0x04, 0x88, 0xB2, 0x1E], Some("p2sh-p2wpkh")), Some("zpub") => ([0x04, 0x88, 0xB2, 0x1E], Some("p2wpkh")),
        Some("upub") => ([0x04, 0x35, 0x87, 0xCF], Some("p2sh-p2wpkh")), Some("vpub") => ([0x04, 0x35, 0x87, 0xCF], Some("p2wpkh")),
        _ => return Err("bad_xpub"),
    };
    let mut b = bitcoin::base58::decode_check(s).map_err(|_| "bad_xpub")?;
    if b.len() != 78 { return Err("bad_xpub") }
    b[..4].copy_from_slice(&ver);
    Ok((bitcoin::base58::encode_check(&b), kind))
}

/// Derive `xpub/branch/i` for each branch and index, encoded for `chain`; `kinds` filters
/// script types (empty = all the chain supports). Paths in the rows are relative to the
/// xpub ("m/0/3"). Only non-hardened steps are possible from an xpub.
pub fn from_xpub(xpub: &str, chain: &Chain, kinds: &[&str], branches: &[u32], indices: &[u32]) -> Result<Vec<AddrRow>, &'static str> {
    let (norm, implied) = normalize(xpub)?;
    let x = Xpub::from_str(&norm).map_err(|_| "bad_xpub")?;
    let implied_k; let kinds = if kinds.is_empty() { implied_k = implied.into_iter().collect::<Vec<_>>(); &implied_k[..] } else { kinds };
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

/// Addresses at `xpub / steps...` (all non-hardened), every script kind the chain supports.
/// Row paths are relative to the xpub ("m/0/5").
pub fn at_path(xpub: &str, chain: &Chain, steps: &[u32]) -> Result<Vec<AddrRow>, &'static str> {
    let x = Xpub::from_str(&normalize(xpub)?.0).map_err(|_| "bad_xpub")?;
    if chain.enc == chains::Enc::Sol { return Err("unsupported") }
    if steps.len() > 16 { return Err("bad_path") }
    let p: Vec<ChildNumber> = steps.iter().map(|&n| ChildNumber::from_normal_idx(n).map_err(|_| "bad_path")).collect::<Result<_, _>>()?;
    let k = x.derive_pub(&Secp256k1::verification_only(), &p).map_err(|_| "bad_path")?;
    let path = std::iter::once("m".to_string()).chain(steps.iter().map(|n| n.to_string())).collect::<Vec<_>>().join("/");
    Ok(chains::pub_rows(chain, &path, &k.public_key, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    // BIP84 test vector (public): zpub of "abandon x11 about", given here as the xpub form.
    // Account m/84'/0'/0' of the BIP39 root; first receive address from BIP84.
    const ACCT84: &str = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
    #[test] fn at_path_matches_from_xpub() {
        let r = at_path(ACCT84, chains::chain("btc").unwrap(), &[0, 1]).unwrap();
        assert!(r.iter().any(|r| r.kind == "p2wpkh" && r.address == "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g" && r.path == "m/0/1"));
    }
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

#[cfg(test)]
mod slip132 {
    // BIP84 spec: account 0 zpub of "abandon x11 about"; first receive bc1qcr8te4..., first change bc1q8c6fshw2...
    #[test] fn zpub_gives_bip84_addresses() {
        let z = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
        let r = super::from_xpub(z, crate::chains::chain("btc").unwrap(), &[], &[0, 1], &[0]).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].address, "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(r[1].address, "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
        assert!(super::normalize("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYt").is_err());
    }
}
