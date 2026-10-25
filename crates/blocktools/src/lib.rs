//! blocktools: offline crypto-recovery building blocks as a library.
//!
//! Default features are public-data only: addresses from public keys, watch-only
//! derivation from an xpub (`xpub`), derivation-path plans (`plan`), address
//! validation (`validate`), and transaction decode / build / verify (`tx`). Nothing in
//! the default build takes a private key, reads a file, or opens a socket.
//!
//! * `secrets` — seed phrases, wallet.dat, keystores, private-key rows, signing.
//! * `ed25519` — Solana addresses.  * `schema` — CLI output schema.  * `net` — HTTPS.
//!
//! The CLIs in `tools/` are thin wrappers over these APIs; the library never depends on them.
#![forbid(unsafe_code)]
pub use blocktools_core::{b64, chains, eth_address_from_pubkey, hex_dec, hex_enc, kind_name, plan, validate, xpub, ACCOUNT_KINDS};
/// Transactions: `build` (unsigned PSBT / EVM), `evm`, `policy` (verify), `rlp`; `sign` with `secrets`.
pub use blocktools_tx as tx;
#[cfg(feature = "secrets")]
pub use blocktools_secrets as secrets;
#[cfg(feature = "schema")]
pub use blocktools_schema as schema;
#[cfg(feature = "net")]
pub use blocktools_net as net;

/// Library version (same as the crate / npm package version).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Address validation against the chain table. Unverified rows are refused (`unverified_chain`).
pub mod address {
    pub use blocktools_core::validate::AddrKind;
    pub fn validate(chain: &str, addr: &str) -> Result<AddrKind, &'static str> {
        let c = blocktools_core::chains::chain(chain).ok_or("unknown_chain")?;
        if !c.verified { return Err("unverified_chain") }
        blocktools_core::validate::validate(chain, addr)
    }
}

/// Watch-only derivation.
pub mod derive {
    use blocktools_core::chains::{self, AddrRow};
    /// Addresses at `xpub / path / index` on `chain`. `path` is relative to the xpub and
    /// non-hardened ("", "m", "0", "m/1", "0/7"...); `index` is appended. All script kinds the
    /// chain supports are returned. Unverified chains are refused.
    pub fn from_xpub(chain: &str, xpub: &str, path: &str, index: u32) -> Result<Vec<AddrRow>, &'static str> {
        let c = chains::supported(chain).ok_or("unknown_or_unverified_chain")?;
        let p = path.trim().trim_start_matches('m').trim_start_matches('/');
        let mut steps: Vec<u32> = if p.is_empty() { vec![] } else {
            p.split('/').map(|s| s.parse::<u32>().ok().filter(|n| *n < 1 << 31)).collect::<Option<_>>().ok_or("bad_path")?
        };
        if steps.len() > 8 { return Err("bad_path") }
        steps.push(index);
        blocktools_core::xpub::at_path(xpub, c, &steps)
    }
}

/// Fail-closed transaction check for wallets / swap front-ends: JSON in, JSON out, public data only.
pub mod check;
