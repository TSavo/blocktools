//! JS/TS surface. Inputs are strings / arrays; outputs are JSON strings (callers `JSON.parse`).
//! Errors are thrown as short strings. Nothing here accepts private key material.
#![forbid(unsafe_code)]
use blocktools::tx::policy::{check, Policy};
use blocktools::{chains, plan, tx, validate as v, xpub};
use serde_json::json;
use wasm_bindgen::prelude::*;

fn err(e: impl AsRef<str>) -> JsError { JsError::new(e.as_ref()) }

/// Additive string twins: every integer `amount` / `fee` field (at any depth) gets an
/// `amount_str` / `fee_str` decimal string beside it, because `JSON.parse` rounds integers
/// above 2^53. The numeric fields are unchanged; use the `_str` twins for exact values.
fn twins(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(m) => {
            for k in ["amount", "fee"] {
                let n = m.get(k).and_then(|x| x.as_u64().map(|n| n.to_string()).or_else(|| x.as_str().filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())).map(String::from)));
                if let Some(n) = n { m.entry(format!("{k}_str")).or_insert_with(|| n.into()); }
            }
            m.values_mut().for_each(twins);
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(twins),
        _ => {}
    }
}
fn twin_str(s: &str) -> String {
    match serde_json::from_str::<serde_json::Value>(s) { Ok(mut v) => { twins(&mut v); v.to_string() } Err(_) => s.to_string() }
}

/// Address kind ("P2pkh", "SegwitV0", "Eth", ...) if `address` is valid for `chain`; throws otherwise.
#[wasm_bindgen(js_name = validateAddress)]
pub fn validate_address(chain: &str, address: &str) -> Result<String, JsError> {
    v::validate(chain, address).map(|k| format!("{k:?}")).map_err(err)
}

/// Chains this build knows: JSON array of names.
#[wasm_bindgen(js_name = listChains)]
pub fn list_chains() -> String { let mut v: Vec<&str> = chains::CHAINS.iter().map(|c| c.name).collect(); v.push("zec"); json!(v).to_string() }

/// Watch-only addresses from an account-level xpub: JSON [{chain,kind,path,address}].
#[wasm_bindgen(js_name = addressesFromXpub)]
pub fn addresses_from_xpub(xpub_str: &str, chain: &str, kinds: Vec<String>, branches: Vec<u32>, indices: Vec<u32>) -> Result<String, JsError> {
    let c = chains::chain(chain).ok_or_else(|| err("unknown chain"))?;
    let k: Vec<&str> = kinds.iter().map(|s| s.as_str()).collect();
    let rows = xpub::from_xpub(xpub_str, c, &k, &branches, &indices).map_err(err)?;
    Ok(json!(rows.iter().map(|r| json!({"chain": r.chain, "kind": r.kind, "path": r.path, "address": r.address})).collect::<Vec<_>>()).to_string())
}

/// `derive --explain` for the given derive flags: JSON [{chain,kind,template,path,count}]. No keys.
#[wasm_bindgen(js_name = explainPlan)]
pub fn explain_plan(args: Vec<String>) -> Result<String, JsError> {
    let o = plan::from_args(&args).map_err(err)?;
    Ok(json!(plan::explain(&o).iter().map(|e| json!({"chain": e.chain, "kind": e.kind, "template": e.template, "path": e.path, "count": e.count})).collect::<Vec<_>>()).to_string())
}

/// Decode a transaction (hex/base64 raw, PSBT, EVM RLP, or a JSON line): JSON array of the tx-decode lines.
#[wasm_bindgen(js_name = decodeTx)]
pub fn decode_tx(input: &str, chain: &str) -> Result<String, JsError> {
    let mut v = json!(tx::decode(input, chain).map_err(err)?.json_lines()); twins(&mut v); Ok(v.to_string())
}

/// Novacoin: raw tx hex from api.novaco.in `/gettransaction/<txid>` decoded JSON (nTime layout).
/// Throws unless reverse(sha256d(raw)) equals `expected_txid` and the JSON `txid`.
#[wasm_bindgen(js_name = serializeNvcTxFromJson)]
pub fn serialize_nvc_tx_from_json(json: &str, expected_txid: &str) -> Result<String, JsError> {
    tx::nvc_json::serialize_nvc_tx_from_json(json, expected_txid).map_err(err)
}

/// Plain-text summary of a transaction (what tx-decode --text prints).
#[wasm_bindgen(js_name = describeTx)]
pub fn describe_tx(input: &str, chain: &str) -> Result<String, JsError> { Ok(tx::decode(input, chain).map_err(err)?.text()) }

/// tx-verify: JSON {ok, failures, warnings}. `max_fee` is a decimal string (sats or wei) or "" (EVM: the
/// tx-sign default 0.01 ETH; UTXO: no cap). `allow_value_with_token` (default false) accepts ETH value
/// alongside ERC-20 transfer calldata.
#[wasm_bindgen(js_name = verifyTx)]
#[allow(clippy::too_many_arguments)]
pub fn verify_tx(input: &str, chain: &str, expect_to: Vec<String>, change: Vec<String>, chain_id: Option<u32>, max_fee: &str, allow_warnings: bool, allow_value_with_token: Option<bool>) -> Result<String, JsError> {
    let d = tx::decode(input, chain).map_err(err)?;
    let max_fee = if max_fee.is_empty() { d.evm.as_ref().map(|_| blocktools::tx::policy::default_max_fee(&d)) } else { Some(max_fee.parse::<u128>().map_err(|_| err("max_fee"))?) };
    let p = Policy { expect_to, change, chain_id: chain_id.map(u64::from), max_fee, allow_warnings, allow_value_with_token: allow_value_with_token.unwrap_or(false) };
    let f = check(&d, &p);
    Ok(json!({"ok": f.is_empty(), "failures": f, "warnings": d.warnings}).to_string())
}

// ---- Stable API (EXPORTS.md). Everything below refuses unverified chains. ----

/// Library version (semver string, same as the `blocktools` crate).
#[wasm_bindgen]
pub fn version() -> String { blocktools::VERSION.to_string() }

fn row(c: &chains::Chain) -> serde_json::Value {
    json!({"name": c.name, "ticker": c.ticker, "title": c.title, "slip44": c.coin, "verified": c.verified,
           "sources": c.sources.iter().map(|s| json!({"name": s.name, "url": s.url, "api": s.api, "checked": s.checked})).collect::<Vec<_>>()})
}
/// Verified (supported) chains: JSON [{name,ticker,title,slip44,verified:true,sources:[{name,url,api,checked}]}].
#[wasm_bindgen(js_name = supportedChains)]
pub fn supported_chains() -> String {
    let mut v: Vec<serde_json::Value> = chains::CHAINS.iter().filter(|c| c.verified).map(row).collect();
    // Zcash transparent lives outside the table (two-byte prefixes). Verified: ZIP-243/244 official
    // txid+sighash vectors, 7 mainnet txs, 21 mainnet script->address pairs from blockchair.
    v.push(json!({"name": "zec", "ticker": "ZEC", "title": "Zcash (transparent)", "slip44": 133, "verified": true, "scope": "transparent", "sources": []}));
    json!(v).to_string()
}
/// Known but unverified chains (NOT supported by the other calls): same shape, verified:false.
#[wasm_bindgen(js_name = unverifiedChains)]
pub fn unverified_chains() -> String { json!(chains::CHAINS.iter().filter(|c| !c.verified).map(row).collect::<Vec<_>>()).to_string() }

/// `derive::from_xpub(chain, xpub, path, index)`: JSON [{chain,kind,path,address}] for every script kind.
#[wasm_bindgen(js_name = deriveFromXpub)]
pub fn derive_from_xpub(chain: &str, xpub_str: &str, path: &str, index: u32) -> Result<String, JsError> {
    let rows = blocktools::derive::from_xpub(chain, xpub_str, path, index).map_err(err)?;
    Ok(json!(rows.iter().map(|r| json!({"chain": r.chain, "kind": r.kind, "path": r.path, "address": r.address})).collect::<Vec<_>>()).to_string())
}
/// `address::validate(chain, addr)`: address kind string; throws on invalid / unverified chain.
#[wasm_bindgen(js_name = addressValidate)]
pub fn address_validate(chain: &str, addr: &str) -> Result<String, JsError> {
    blocktools::address::validate(chain, addr).map(|k| format!("{k:?}")).map_err(err)
}
/// Fail-closed tx check, JSON in / JSON out; never throws. See EXPORTS.md for the schema.
#[wasm_bindgen(js_name = checkTx)]
pub fn check_tx(input_json: &str) -> String { twin_str(&blocktools::check::tx_json(input_json)) }

/// Every verified chain (and `zec`) on which `addr` is valid: JSON [{chain,kind}]. Collisions
/// (DGB/DOGE, VIA/VTC, version 50/0 ...) return all candidates; an empty list = unrecognised.
#[wasm_bindgen(js_name = detectAddress)]
pub fn detect_address(addr: &str) -> String {
    json!(blocktools::address::detect(addr).iter().map(|(c, k)| json!({"chain": c, "kind": format!("{k:?}")})).collect::<Vec<_>>()).to_string()
}
/// Additive to detectAddress (whose shape is unchanged): JSON {candidates:[{chain,kind}], ambiguous, kinds_agree}.
/// `ambiguous` = more than one chain; `kinds_agree` = every candidate has the same script kind.
#[wasm_bindgen(js_name = detectAddressInfo)]
pub fn detect_address_info(addr: &str) -> String {
    let d = blocktools::address::detect(addr);
    // XRP X-addresses (XLS-5d) validate as kind Xrp; report them as "xaddress" so callers know a tag may be embedded.
    let kinds: Vec<String> = d.iter().map(|(c, k)| if *c == "xrp" && addr.starts_with('X') { "xaddress".into() } else { format!("{k:?}") }).collect();
    json!({"candidates": d.iter().zip(&kinds).map(|((c, _), k)| json!({"chain": c, "kind": k})).collect::<Vec<_>>(),
           "ambiguous": d.len() > 1, "kinds_agree": kinds.windows(2).all(|w| w[0] == w[1])}).to_string()
}
/// Same hash, re-encoded for `to`; throws `ambiguous_address` when candidates disagree on the script type.
#[wasm_bindgen(js_name = convertAddress)]
pub fn convert_address(addr: &str, to: &str) -> Result<String, JsError> { blocktools::address::convert(addr, to).map_err(err) }
/// As convertAddress with the source chain stated.
#[wasm_bindgen(js_name = convertAddressFrom)]
pub fn convert_address_from(from: &str, addr: &str, to: &str) -> Result<String, JsError> { blocktools::address::convert_from(from, addr, to).map_err(err) }
/// Full parameter table: JSON [{name,ticker,title,slip44,verified,p2pkh[],p2sh[],hrp,wif,checksum,decimals,forkid,tx_format,sweep_build,sources}].
#[wasm_bindgen(js_name = chainParams)]
pub fn chain_params() -> String { blocktools::address::params_json().to_string() }
/// Unsigned sweep of all `utxos` (JSON lines {txid,vout,amount,address[,prev_tx]}) to `to`:
/// JSON {chain,tx_format,psbt,unsigned_tx,inputs,amount,fee}. Legacy, legacy-sha256 and forkid
/// formats; pos-ntime chains need `buildUnsignedSweepAt` (a tx timestamp).
#[wasm_bindgen(js_name = buildUnsignedSweep)]
pub fn build_unsigned_sweep(chain: &str, utxos: &str, to: &str, fee_rate: u32) -> Result<String, JsError> {
    blocktools::sweep::build_unsigned_sweep(chain, utxos, to, fee_rate as u64).map(|mut v| { twins(&mut v); v.to_string() }).map_err(err)
}
/// As `buildUnsignedSweep` with tx timestamp `time` (unix seconds). For pos-ntime chains
/// (ppc/nvc/clam/rdd) returns {chain,tx_format:"pos-ntime",unsigned_tx,time,pos_prevouts,inputs,amount,fee}
/// (no PSBT exists for that format); other chains ignore `time`.
#[wasm_bindgen(js_name = buildUnsignedSweepAt)]
pub fn build_unsigned_sweep_at(chain: &str, utxos: &str, to: &str, fee_rate: u32, time: u32) -> Result<String, JsError> {
    blocktools::sweep::build_unsigned_sweep_at(chain, utxos, to, fee_rate as u64, time).map(|mut v| { twins(&mut v); v.to_string() }).map_err(err)
}

// ---- Substrate / BLAKE2b (public data) ----
fn hx(s: &str) -> Result<Vec<u8>, JsError> { blocktools::hex_dec(s.trim_start_matches("0x")).ok_or_else(|| err("bad_hex")) }
fn acct32(s: &str) -> Result<[u8; 32], JsError> {
    if let Ok((_, a)) = blocktools::substrate::ss58_decode(s) { return Ok(a) }
    hx(s)?.try_into().map_err(|_| err("bad_account"))
}
/// BLAKE2b of hex `data_hex` with `out_len` bytes (1..64) and a UTF-8 personalization (<= 16 bytes, "" for none). Returns hex.
#[wasm_bindgen(js_name = blake2b)]
pub fn blake2b_hex(data_hex: &str, out_len: u32, personal: &str) -> Result<String, JsError> {
    Ok(blocktools::hex_enc(blocktools::substrate::blake2b_hash(&hx(data_hex)?, out_len as usize, personal.as_bytes()).map_err(err)?))
}
/// Substrate twox_128 of UTF-8 `text`. Returns hex.
#[wasm_bindgen(js_name = twox128)]
pub fn twox128_hex(text: &str) -> String { blocktools::hex_enc(blocktools::substrate::twox128(text.as_bytes())) }
/// SS58 address from a 32-byte account id (hex) and prefix (0 Polkadot, 2 Kusama, 42 generic; up to 16383).
#[wasm_bindgen(js_name = ss58Encode)]
pub fn ss58_encode(account_hex: &str, prefix: u32) -> Result<String, JsError> {
    let a: [u8; 32] = hx(account_hex)?.try_into().map_err(|_| err("bad_account"))?;
    blocktools::substrate::ss58_encode(u16::try_from(prefix).map_err(|_| err("bad_prefix"))?, &a).map_err(err)
}
/// JSON {prefix, account} (account id hex) for an SS58 address; throws bad_base58/bad_prefix/bad_length/bad_checksum.
#[wasm_bindgen(js_name = ss58Decode)]
pub fn ss58_decode(addr: &str) -> Result<String, JsError> {
    let (p, a) = blocktools::substrate::ss58_decode(addr).map_err(err)?;
    Ok(json!({"prefix": p, "account": blocktools::hex_enc(a)}).to_string())
}
/// System.Account storage key (hex, no 0x) for an SS58 address or a 32-byte account id hex.
#[wasm_bindgen(js_name = polkadotAccountStorageKey)]
pub fn polkadot_account_storage_key(account: &str) -> Result<String, JsError> { Ok(blocktools::hex_enc(blocktools::substrate::system_account_key(&acct32(account)?))) }
/// SCALE AccountInfo (80 bytes hex, as returned by state_getStorage) -> JSON {nonce,consumers,providers,sufficients,data:{free,reserved,frozen,flags}}; u128 as decimal strings.
#[wasm_bindgen(js_name = decodeAccountInfo)]
pub fn decode_account_info(hex: &str) -> Result<String, JsError> { Ok(blocktools::substrate::decode_account_info(&hx(hex)?).map_err(err)?.to_string()) }

// ---- Solana (public data) ----
use blocktools::sol;
/// Raw tx bytes from hex (optional 0x) or base64 (the RPC/wallet wire form).
fn sol_raw(s: &str) -> Result<Vec<u8>, JsError> {
    let t = s.trim(); let h = t.trim_start_matches("0x");
    if h.len() % 2 == 0 && h.bytes().all(|b| b.is_ascii_hexdigit()) { return hx(h) }
    blocktools_core_b64(t).ok_or_else(|| err("bad_encoding"))
}
fn blocktools_core_b64(s: &str) -> Option<Vec<u8>> { blocktools::b64::decode(s) }
/// Base58 (Bitcoin alphabet, no checksum) of hex bytes.
#[wasm_bindgen(js_name = base58Encode)]
pub fn base58_encode(hex: &str) -> Result<String, JsError> { Ok(sol::b58enc(&hx(hex)?)) }
/// Hex bytes of a base58 string; throws bad_base58.
#[wasm_bindgen(js_name = base58Decode)]
pub fn base58_decode(s: &str) -> Result<String, JsError> { Ok(blocktools::hex_enc(sol::b58dec(s).map_err(err)?)) }
/// true if a base58 Solana pubkey is an ed25519 curve point (wallet), false if off-curve (PDA); throws on bad input.
#[wasm_bindgen(js_name = solIsOnCurve)]
pub fn sol_is_on_curve(addr: &str) -> Result<bool, JsError> { Ok(sol::is_on_curve(&sol::pubkey(addr).map_err(err)?)) }
/// findProgramAddress. `seeds_json` = JSON array of hex strings (each <= 32 bytes, <= 15 seeds). Returns {address, bump}.
#[wasm_bindgen(js_name = solFindProgramAddress)]
pub fn sol_find_program_address(seeds_json: &str, program: &str) -> Result<String, JsError> {
    let v: Vec<String> = serde_json::from_str(seeds_json).map_err(|_| err("bad_seeds"))?;
    let seeds: Vec<Vec<u8>> = v.iter().map(|s| hx(s)).collect::<Result<_, _>>()?;
    let r: Vec<&[u8]> = seeds.iter().map(|s| s.as_slice()).collect();
    let (a, b) = sol::find_program_address(&r, &sol::pubkey(program).map_err(err)?).map_err(err)?;
    Ok(json!({"address": sol::b58enc(&a), "bump": b}).to_string())
}
/// Associated token account. `token_program` "" = classic SPL Token. Returns {address, bump}.
#[wasm_bindgen(js_name = solAssociatedTokenAddress)]
pub fn sol_associated_token_address(owner: &str, mint: &str, token_program: &str) -> Result<String, JsError> {
    let tp = if token_program.is_empty() { sol::TOKEN } else { token_program };
    let (a, b) = sol::associated_token_address(&sol::pubkey(owner).map_err(err)?, &sol::pubkey(mint).map_err(err)?, &sol::pubkey(tp).map_err(err)?).map_err(err)?;
    Ok(json!({"address": sol::b58enc(&a), "bump": b}).to_string())
}
/// Anchor discriminator sha256("global:"+name)[..8] as hex.
#[wasm_bindgen(js_name = solAnchorDiscriminator)]
pub fn sol_anchor_discriminator(name: &str) -> String { blocktools::hex_enc(sol::anchor_discriminator(name)) }
/// Decode a wire transaction (hex or base64; legacy or v0). JSON: see EXPORTS.md.
#[wasm_bindgen(js_name = solDecodeTx)]
pub fn sol_decode_tx(raw: &str) -> Result<String, JsError> { Ok(sol::decode_tx(&sol_raw(raw)?).map_err(err)?.to_string()) }
/// Verify a wire transaction against `expect_json` {owner?, to?, lamports?, mint?, amount?, allow_programs?}. Returns {ok, failures, warnings, txid, lamports, token_amount}; fails closed.
#[wasm_bindgen(js_name = solVerifyTx)]
pub fn sol_verify_tx(raw: &str, expect_json: &str) -> Result<String, JsError> {
    let e: serde_json::Value = if expect_json.trim().is_empty() { json!({}) } else { serde_json::from_str(expect_json).map_err(|_| err("bad_expect"))? };
    Ok(sol::verify_tx(&sol_raw(raw)?, &e).map_err(err)?.to_string())
}

// ---- CashAddr / address <-> script (public data) ----
use blocktools::cashaddr;
fn ca_type(t: u8) -> serde_json::Value { match t { 0 => json!("p2pkh"), 1 => json!("p2sh"), n => json!(n) } }
/// Decode a CashAddr (prefix optional, default "bitcoincash"). Returns {prefix, type:"p2pkh"|"p2sh"|<n>, hash}.
#[wasm_bindgen(js_name = cashAddrDecode)]
pub fn cash_addr_decode(addr: &str) -> Result<String, JsError> {
    let (p, t, h) = cashaddr::decode(addr, "bitcoincash").map_err(err)?;
    Ok(json!({"prefix": p, "type": ca_type(t), "hash": blocktools::hex_enc(h)}).to_string())
}
/// Encode a CashAddr. `kind` "p2pkh" | "p2sh"; `hash_hex` 20 (or 24..64 spec sizes) bytes.
#[wasm_bindgen(js_name = cashAddrEncode)]
pub fn cash_addr_encode(prefix: &str, kind: &str, hash_hex: &str) -> Result<String, JsError> {
    let t = match kind { "p2pkh" => 0, "p2sh" => 1, _ => return Err(err("bad_type")) };
    cashaddr::encode(prefix, t, &hx(hash_hex)?).map_err(err)
}
/// CashAddr -> legacy base58 address.
#[wasm_bindgen(js_name = cashAddrToLegacy)]
pub fn cash_addr_to_legacy(addr: &str) -> Result<String, JsError> { cashaddr::to_legacy(addr).map_err(err) }
/// Legacy base58 BCH address -> CashAddr with `prefix` ("" = bitcoincash).
#[wasm_bindgen(js_name = legacyToCashAddr)]
pub fn legacy_to_cash_addr(addr: &str, prefix: &str) -> Result<String, JsError> { cashaddr::from_legacy(addr, if prefix.is_empty() { "bitcoincash" } else { prefix }).map_err(err) }
/// Output script (hex) paying `addr` on UTXO `chain` (bch also takes CashAddr). Throws unknown_chain / bad_address.
#[wasm_bindgen(js_name = addressToScript)]
pub fn address_to_script(chain: &str, addr: &str) -> Result<String, JsError> { Ok(blocktools::hex_enc(cashaddr::address_to_script(chain, addr).map_err(err)?)) }
/// Standard output script -> {kind, address}, or null for non-standard scripts.
#[wasm_bindgen(js_name = scriptToAddress)]
pub fn script_to_address(chain: &str, script_hex: &str) -> Result<String, JsError> {
    Ok(match cashaddr::script_to_address(chain, &hx(script_hex)?).map_err(err)? { Some((k, a)) => json!({"kind": k, "address": a}), None => json!(null) }.to_string())
}

// ---- PSBT with OP_RETURN memo; Tron tx id / decode (public data) ----
/// Unsigned PSBT paying `to` with an OP_RETURN `memo_hex` (1..80 bytes) and change.
/// `amount` "" = sweep all UTXOs to `to` (no change). `utxos` = JSON lines {txid,vout,amount,address}.
/// Optional trailing `rbf` (default false): false = nSequence 0xffffffff on every input (non-RBF, required for
/// THORChain inbound txs); true = 0xfffffffd (BIP-125).
/// Returns {psbt (base64), fee, vsize, rbf, outputs:[{address|null, script, value}]}; amounts are decimal strings.
#[wasm_bindgen(js_name = buildPsbtWithMemo)]
pub fn build_psbt_with_memo(chain: &str, utxos: &str, to: &str, amount: &str, change: &str, fee_rate: u32, memo_hex: &str, rbf: Option<bool>) -> Result<String, JsError> {
    let send = if amount.is_empty() { None } else { Some(amount.parse::<u64>().map_err(|_| err("bad_amount"))?) };
    let ch = if change.is_empty() { None } else { Some(change) };
    Ok(blocktools::psbtmemo::build_with(chain, utxos, to, send, ch, fee_rate as u64, &hx(memo_hex)?, rbf.unwrap_or(false)).map_err(err)?.to_string())
}
/// Tron txID (hex) = sha256(raw_data). Input is raw_data hex (tronweb raw_data_hex).
#[wasm_bindgen(js_name = tronTxId)]
pub fn tron_tx_id(raw_data_hex: &str) -> Result<String, JsError> { Ok(blocktools::tron::txid(&hx(raw_data_hex)?)) }
/// Decode Tron raw_data hex or a full signed Transaction hex. JSON: see EXPORTS.md.
#[wasm_bindgen(js_name = tronDecodeTx)]
pub fn tron_decode_tx(hex: &str) -> Result<String, JsError> { Ok(blocktools::tron::decode(&hx(hex)?).map_err(err)?.to_string()) }

fn js_u64(x: f64, what: &str) -> Result<u64, JsError> {
    if x.is_finite() && x >= 0.0 && x.fract() == 0.0 && x <= 9007199254740991.0 { Ok(x as u64) } else { Err(err(format!("bad_{what}"))) }
}
fn tx_json(s: &str) -> Result<serde_json::Value, JsError> { serde_json::from_str(s).map_err(|_| err("bad_json")) }
fn now_or_clock(now_s: f64) -> Result<u64, JsError> {
    if now_s == 0.0 { return Err(err("bad_now")) } // explicit clock: pass Math.floor(Date.now()/1000)
    js_u64(now_s, "now")
}
/// SwapChan verifyRecovery twin. `tx_json` = {"to","data","value"}; `now_s` = unix seconds (required; 0 = bad_now).
/// Returns {"verified":true,"call"} or {"verified":false,"reason"}.
#[wasm_bindgen(js_name = verifyRecovery)]
pub fn verify_recovery(tx_json_s: &str, owner: &str, now_s: f64) -> Result<String, JsError> {
    Ok(blocktools::verifier::verify_recovery_json(&tx_json(tx_json_s)?, owner, now_or_clock(now_s)?).to_json().to_string())
}
/// verifyRecovery on a raw (signed or unsigned) EVM tx hex. Adds "tx":{kind,chainId,signed,from,to,value,data,txid}.
#[wasm_bindgen(js_name = verifyRecoveryRaw)]
pub fn verify_recovery_raw(raw_hex: &str, owner: &str, chain_id: f64, now_s: f64) -> Result<String, JsError> {
    Ok(blocktools::verifier::verify_recovery_raw(&hx(raw_hex)?, owner, js_u64(chain_id, "chain_id")?, now_or_clock(now_s)?).to_string())
}
/// SwapChan verifySweepTx twin. `tx_json` = {from,to,value,data?,chainId}; `token` = "" for a native sweep.
#[wasm_bindgen(js_name = verifySweepTx)]
pub fn verify_sweep_tx(tx_json_s: &str, owner: &str, chain_id: f64, token: &str) -> Result<String, JsError> {
    let t = (!token.is_empty()).then_some(token);
    Ok(blocktools::verifier::verify_sweep(&tx_json(tx_json_s)?, owner, js_u64(chain_id, "chain_id")?, t).to_json().to_string())
}
/// verifySweepTx on a raw EVM tx hex; the sender is recovered from the signature (unsigned fails closed).
#[wasm_bindgen(js_name = verifySweepRaw)]
pub fn verify_sweep_raw(raw_hex: &str, owner: &str, chain_id: f64, token: &str) -> Result<String, JsError> {
    let t = (!token.is_empty()).then_some(token);
    Ok(blocktools::verifier::verify_sweep_raw(&hx(raw_hex)?, owner, js_u64(chain_id, "chain_id")?, t).to_string())
}
/// The verifier's allowlists: standard sigs/owner slots, pinned contracts, MultiSend, deadline cap.
#[wasm_bindgen(js_name = recoveryTables)]
pub fn recovery_tables() -> String { blocktools::verifier::tables().to_string() }
/// Unsigned EIP-155 transfer (ETH forks / extra EVM chains, native or ERC-20). Request JSON:
/// {chainId, nonce, gas, gasPrice, to, value | balance, token?, maxPriorityFeePerGas?, from?}.
/// Returns {unsigned, sighash, kind, chainId, nonce, gas, gasPrice, to, value, data, fee, ...}.
#[wasm_bindgen(js_name = buildEvmTransfer)]
pub fn build_evm_transfer(req_json: &str) -> Result<String, JsError> {
    blocktools::build::build_evm_transfer(&tx_json(req_json)?).map(|v| v.to_string()).map_err(err)
}
/// SwapChan coin selection: own script only, drop value < rate×148×20 (fee > 5%), largest first, max 200 inputs.
#[wasm_bindgen(js_name = selectUtxos)]
pub fn select_utxos(utxos_json: &str, script_hex: &str, fee_rate: f64) -> Result<String, JsError> {
    let r = js_u64(fee_rate, "rate")? as u128;
    blocktools::build::select_utxos(&tx_json(utxos_json)?, script_hex, r).map(|v| v.to_string()).map_err(err)
}
