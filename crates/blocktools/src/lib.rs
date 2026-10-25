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
