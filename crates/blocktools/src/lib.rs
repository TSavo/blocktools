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

/// Addresses: validate, detect (all candidates, never a guess), convert, and the parameter table.
pub mod address {
    pub use blocktools_core::validate::AddrKind;
    use blocktools_core::chains::{self, Enc, Sign};
    use bitcoin::base58;

    /// Zcash transparent addresses (zcash/zcash src/chainparams.cpp): 2-byte prefixes, sha256d
    /// checksum. Transparent only: unsigned v5 sweeps (P2PKH, ZIP-244) via `sweep`; no derive, no shielded.
    pub const ZEC_P2PKH: [u8; 2] = [0x1c, 0xb8];
    pub const ZEC_P2SH: [u8; 2] = [0x1c, 0xbd];

    pub fn validate(chain: &str, addr: &str) -> Result<AddrKind, &'static str> {
        if chain == "zec" { return zec(addr).map(|(k, _)| k) }
        let c = chains::chain(chain).ok_or("unknown_chain")?;
        if !c.verified { return Err("unverified_chain") }
        blocktools_core::validate::validate(chain, addr)
    }
    fn zec(addr: &str) -> Result<(AddrKind, [u8; 20]), &'static str> {
        if addr.len() > 60 { return Err("bad length") }
        let b = base58::decode_check(addr).map_err(|_| "bad base58check")?;
        if b.len() != 22 { return Err("bad length") }
        let h: [u8; 20] = b[2..].try_into().unwrap();
        match [b[0], b[1]] { ZEC_P2PKH => Ok((AddrKind::P2pkh, h)), ZEC_P2SH => Ok((AddrKind::P2sh, h)), _ => Err("wrong network") }
    }

    /// Every verified chain (plus `zec`) on which `addr` is valid, with its kind. Version-byte
    /// collisions (DGB/DOGE 30, VIA/VTC 71, LTC p2sh 50 = MONA p2pkh 50, BTC/BCH/BSV/TRC 0, ...)
    /// return ALL matching chains; the caller must not pick one silently.
    pub fn detect(addr: &str) -> Vec<(&'static str, AddrKind)> {
        let mut v: Vec<(&'static str, AddrKind)> = chains::CHAINS.iter().filter(|c| c.verified)
            .filter_map(|c| blocktools_core::validate::validate(c.name, addr).ok().map(|k| (c.name, k))).collect();
        if let Ok((k, _)) = zec(addr) { v.push(("zec", k)) }
        v
    }

    /// Re-encode the same hash (same script) for another chain. `addr` must be valid on at least
    /// one verified chain, and every candidate must read it as the same script; otherwise
    /// `ambiguous_address` (use `convert_from`). Errors: `unrecognised_address`, `ambiguous_address`, `unknown_or_unverified_chain`,
    /// `no_equivalent` (e.g. segwit to a chain without segwit, taproot to a chain without taproot).
    pub fn convert(addr: &str, to: &str) -> Result<String, &'static str> {
        if detect(addr).is_empty() { return Err("unrecognised_address") }
        let script = script_of(addr).ok_or("ambiguous_address")?;
        convert_script(&script, to)
    }
    /// As `convert`, with the source chain stated (needed when `detect` gives candidates that
    /// read the bytes as different script types, e.g. version 50 = MONA p2pkh = LTC p2sh).
    pub fn convert_from(from: &str, addr: &str, to: &str) -> Result<String, &'static str> {
        validate(from, addr)?;
        let script = if from == "zec" { script_of(addr) } else { chains::address_to_script(chains::chain(from).ok_or("unknown_chain")?, addr) };
        convert_script(&script.ok_or("unrecognised_address")?, to)
    }
    fn convert_script(script: &[u8], to: &str) -> Result<String, &'static str> {
        let script = script.to_vec();
        if to == "zec" {
            let (pre, h) = match script.as_slice() {
                [0x76, 0xa9, 0x14, h @ .., 0x88, 0xac] if h.len() == 20 => (ZEC_P2PKH, h),
                [0xa9, 0x14, h @ .., 0x87] if h.len() == 20 => (ZEC_P2SH, h),
                _ => return Err("no_equivalent"),
            };
            let mut b = pre.to_vec(); b.extend(h); return Ok(base58::encode_check(&b));
        }
        let c = chains::supported(to).ok_or("unknown_or_unverified_chain")?;
        if !matches!(c.enc, Enc::Utxo { .. }) { return Err("no_equivalent") }
        chains::script_to_address(c, &script).map(|x| x.1).ok_or("no_equivalent")
    }
    fn script_of(addr: &str) -> Option<Vec<u8>> {
        if let Ok((k, h)) = zec(addr) {
            let mut s = if k == AddrKind::P2pkh { vec![0x76, 0xa9, 0x14] } else { vec![0xa9, 0x14] };
            s.extend(h); s.extend(if k == AddrKind::P2pkh { &[0x88, 0xac][..] } else { &[0x87][..] }); return Some(s);
        }
        let mut it = detect(addr).into_iter().filter_map(|(n, _)| chains::chain(n).and_then(|c| chains::address_to_script(c, addr)));
        let first = it.next()?;
        if it.any(|s| s != first) { return None }
        Some(first)
    }

    /// Base units per coin (PPC and NVC: COIN = 1000000 in their source; QRK 5: only value x 1e5 reproduces mainnet txids; ETH 18, SOL 9, XLM 7 (stroops), TRX/XRP 6).
    pub fn decimals(chain: &str) -> Option<u8> {
        Some(match chain { "ppc" | "nvc" | "tron" | "xrp" | "atom" | "algo" => 6, "dot" => 10, "ton" => 9, "ada" => 6, "eth" => 18, "sol" => 9, "xlm" => 7, "zec" => 8, "qrk" => 5, c => { chains::chain(c)?; 8 } })
    }
    /// Unsigned transaction format a row uses, and whether `tx::build_unsigned_sweep` supports it.
    pub fn tx_format(chain: &str) -> (&'static str, bool) {
        match chains::chain(chain) {
            Some(c) => match (c.enc, c.sign) {
                (Enc::Utxo { .. }, Sign::Standard) => ("legacy", c.verified),
                (Enc::Utxo { .. }, Sign::ForkId(_)) => ("forkid", c.verified),
                (Enc::Utxo { .. }, Sign::PosTime) => ("pos-ntime", c.verified && blocktools_tx::pos::layout(c.name).is_some()),
                (Enc::Utxo { .. }, Sign::Unknown) => ("unknown", false),
                (Enc::Utxo { .. }, Sign::Sha256Single) => ("legacy-sha256", c.verified),
                (Enc::Eth, _) => ("evm", false), // EVM builds go through tx::build::build_evm, not the sweep
                _ => ("account", false),
            },
            None if chain == "zec" => ("zcash-v5", true),
            None => ("unknown", false),
        }
    }

    /// The parameter table as JSON rows (what SwapChan imports instead of its own literals).
    fn fee_warn_json(n: &str) -> serde_json::Value { let f = chains::fee_warn(n); serde_json::json!({"fee": f.fee, "rate": f.rate, "basis": f.basis}) }
    pub fn params_json() -> serde_json::Value {
        use serde_json::json;
        let mut rows: Vec<serde_json::Value> = chains::CHAINS.iter().map(|c| {
            let (fmt, sweep) = tx_format(c.name);
            let (p2pkh, p2sh, hrp, wif) = match c.enc { Enc::Utxo { p2pkh, p2sh, hrp, wif, .. } => (json!([p2pkh]), json!([p2sh]), json!(hrp), json!(wif)), _ => (json!(null), json!(null), json!(null), json!(null)) };
            let forkid = match c.sign { Sign::ForkId(f) => json!(f), _ => json!(null) };
            json!({"name": c.name, "ticker": c.ticker, "title": c.title, "slip44": c.coin, "verified": c.verified,
                   "p2pkh": p2pkh, "p2sh": p2sh, "hrp": hrp, "wif": wif, "checksum": if matches!(c.enc, Enc::Utxo{..}) { json!(if c.ck() == chains::Ck::Groestl { "groestl512d" } else { "sha256d" }) } else { json!(null) },
                   "decimals": decimals(c.name), "forkid": forkid, "tx_format": fmt, "sweep_build": sweep,
                   "fee_warn": fee_warn_json(c.name),
                   "sources": c.sources.iter().map(|s| json!({"name": s.name, "url": s.url, "api": s.api, "checked": s.checked})).collect::<Vec<_>>()})
        }).collect();
        rows.push(json!({"name": "zec", "ticker": "ZEC", "title": "Zcash (transparent)", "slip44": 133, "verified": true, "scope": "transparent",
            "p2pkh": ZEC_P2PKH, "p2sh": ZEC_P2SH, "hrp": null, "wif": 128, "checksum": "sha256d", "decimals": 8, "forkid": null,
            "tx_format": "zcash-v5", "sweep_build": true, "fee_warn": fee_warn_json("zec"), "sources": []}));
        json!(rows)
    }
}

/// Unsigned sweep build per tx format. Only `legacy` (Bitcoin-format, incl. segwit where the
/// chain has it) and `forkid` (BCH/BSV/BTG: same unsigned bytes; the signer must use
/// SIGHASH_FORKID with input amounts, which the PSBT carries) are built. `pos-ntime` (PPC/NVC/CLAM/RDD,
/// layouts confirmed on mainnet txs) and `zcash-v5` (transparent, ZIP-244) build a raw tx +
/// prevouts instead of a PSBT. Unknown formats are refused, never approximated.
pub mod sweep {
    use serde_json::{json, Value};
    /// In: chain, UTXO JSON lines ({"txid","vout","amount","address"[,"prev_tx"]}), destination,
    /// fee rate (sat/vB). Out: {"psbt" base64, "unsigned_tx" hex, "fee", "amount", "inputs", "tx_format"}.
    pub fn build_unsigned_sweep(chain: &str, utxos: &str, to: &str, fee_rate: u64) -> Result<Value, String> {
        let (fmt, ok) = crate::address::tx_format(chain);
        if !ok { return Err(format!("unsupported_tx_format:{fmt}")) }
        if chain == "zec" { return build_unsigned_zec_sweep(utxos, to, fee_rate, blocktools_tx::zcash::MAINNET_BRANCH_ID, 0) }
        let c = blocktools_core::chains::supported(chain).ok_or("unknown_or_unverified_chain")?;
        let u = blocktools_tx::build::parse_utxos(c, utxos)?;
        if fmt == "pos-ntime" {
            #[cfg(not(target_arch = "wasm32"))]
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0);
            #[cfg(target_arch = "wasm32")]
            let now = 0u32;
            return build_unsigned_sweep_at(chain, utxos, to, fee_rate, now);
        }
        let total = blocktools_tx::sum_amounts(u.iter().map(|x| x.amount)).ok_or("amount_overflow")?;
        let n = u.len();
        let plan = blocktools_tx::build::BtcPlan { to: to.into(), send: None, change: None, fee_rate, rbf: false, dust: 546, locktime: 0 };
        let p = blocktools_tx::build::build_btc(c, u, &plan)?;
        let amount: u64 = p.unsigned_tx.output.iter().map(|o| o.value.to_sat()).sum();
        Ok(json!({"chain": chain, "tx_format": fmt, "psbt": blocktools_core::b64::encode(&p.serialize()),
                  "unsigned_tx": blocktools_core::hex_enc(bitcoin::consensus::serialize(&p.unsigned_tx)),
                  "inputs": n, "amount": amount.to_string(), "fee": (total - amount).to_string()}))
    }
    /// Zcash transparent v5 sweep (P2PKH inputs). `branch_id` is the consensus branch id the tx
    /// commits to (must be the network's current one; `MAINNET_BRANCH_ID` was measured 2026-10-25),
    /// `expiry` 0 = none. Fee = max(ZIP-317, size × fee_rate). Out: {"unsigned_tx", "zec_prevouts",
    /// "branch_id", "expiry_height", "fee", "amount", "inputs", "tx_format":"zcash-v5"}; no PSBT exists.
    pub fn build_unsigned_zec_sweep(utxos: &str, to: &str, fee_rate: u64, branch_id: u32, expiry: u32) -> Result<Value, String> {
        let (tx, prev) = blocktools_tx::zcash::build_sweep(utxos, to, fee_rate, branch_id, expiry, 546)?;
        let total: u64 = prev.iter().map(|p| p.0).sum();
        let amount = tx.outputs[0].0;
        let mut o = blocktools_tx::zcash::envelope(&tx, &prev);
        o["inputs"] = json!(prev.len()); o["amount"] = json!(amount.to_string()); o["fee"] = json!((total - amount).to_string());
        Ok(o)
    }
    /// As `build_unsigned_sweep` for PoS-nTime chains (PPC/NVC/CLAM/RDD) with an explicit tx
    /// timestamp (unix seconds; 0 = refuse). Out: {"unsigned_tx" hex, "pos_prevouts", "time", "fee", "amount", "inputs", "tx_format"}.
    /// No PSBT exists for this format: the signer needs `pos_prevouts`.
    pub fn build_unsigned_sweep_at(chain: &str, utxos: &str, to: &str, fee_rate: u64, time: u32) -> Result<Value, String> {
        let (fmt, ok) = crate::address::tx_format(chain);
        if fmt != "pos-ntime" || !ok { return build_unsigned_sweep(chain, utxos, to, fee_rate) }
        if time == 0 { return Err("pos_ntime_needs_time".into()) }
        let c = blocktools_core::chains::supported(chain).ok_or("unknown_or_unverified_chain")?;
        let u = blocktools_tx::build::parse_utxos(c, utxos)?;
        let (tx, prev) = blocktools_tx::build::build_pos_sweep(c, &u, to, fee_rate, time, 546)?;
        let total: u64 = prev.iter().map(|p| p.0).sum();
        let amount = tx.outputs[0].0;
        let mut o = blocktools_tx::pos::envelope(chain, &tx, &prev);
        o["inputs"] = json!(u.len()); o["amount"] = json!(amount.to_string()); o["fee"] = json!((total - amount).to_string());
        Ok(o)
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
