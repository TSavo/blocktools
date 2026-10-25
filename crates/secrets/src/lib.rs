//! Secret-handling half of blocktools: seed phrases, wallet files, keystores, private keys.
//! Everything here takes or returns private key material. Nothing here prints, logs, reads
//! files or touches the network; the CLIs do I/O. Not part of the `blocktools` facade's
//! default features.
#![forbid(unsafe_code)]
#[cfg(feature = "dat")]
pub mod dat;
#[cfg(feature = "multibit")]
pub mod multibit;
#[cfg(feature = "electrum")]
pub mod electrum;
#[cfg(feature = "keys")]
pub mod keys;
#[cfg(feature = "keystore")]
pub mod keystore;
#[cfg(feature = "repair")]
pub mod repair;
#[cfg(feature = "seed")]
pub mod seed;
#[cfg(feature = "walk")]
pub mod walk;
