//! rpc library: pure parts of the `rpc` tool (no network). Protocol detection, the secret-method
//! deny-list (ONE source of truth: DENY), request checks, wallet-sign summaries, redaction.
use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto { Evm, Btc, Sol, Tron, Cosmos, Esplora, Blockbook }
impl Proto {
    pub fn name(self) -> &'static str {
        match self { Proto::Evm => "evm", Proto::Btc => "btc", Proto::Sol => "sol", Proto::Tron => "tron", Proto::Cosmos => "cosmos", Proto::Esplora => "esplora", Proto::Blockbook => "blockbook" }
    }
    pub fn parse(s: &str) -> Option<Proto> {
        Some(match s { "evm" | "eth" => Proto::Evm, "btc" | "bitcoin" | "bitcoind" => Proto::Btc, "sol" | "solana" => Proto::Sol, "tron" | "trx" => Proto::Tron,
            "cosmos" | "lcd" | "atom" => Proto::Cosmos, "esplora" => Proto::Esplora, "blockbook" => Proto::Blockbook, _ => return None })
    }
    pub fn is_rest(self) -> bool { matches!(self, Proto::Tron | Proto::Cosmos | Proto::Esplora | Proto::Blockbook) }
}

/// URL hints, checked in order on the lowercased URL. First match wins.
pub const URL_RULES: &[(&str, Proto)] = &[
    ("solana", Proto::Sol), (":8899", Proto::Sol), ("helius", Proto::Sol),
    ("tron", Proto::Tron), (":8090", Proto::Tron),
    ("blockbook", Proto::Blockbook), ("/api/v2", Proto::Blockbook),
    ("esplora", Proto::Esplora), ("blockstream.info", Proto::Esplora), ("mempool.space", Proto::Esplora), ("litecoinspace", Proto::Esplora),
    ("cosmos-rest", Proto::Cosmos), ("lcd", Proto::Cosmos), (":1317", Proto::Cosmos), ("cosmos.directory", Proto::Cosmos), ("polkachu", Proto::Cosmos),
    (":8332", Proto::Btc), (":18332", Proto::Btc), (":18443", Proto::Btc), (":38332", Proto::Btc), (":9332", Proto::Btc), (":19332", Proto::Btc), (":22555", Proto::Btc), (":44555", Proto::Btc),
    (":8545", Proto::Evm), ("infura", Proto::Evm), ("alchemy", Proto::Evm), ("-rpc.publicnode.com", Proto::Evm), ("flashbots", Proto::Evm), ("drpc", Proto::Evm), ("llamarpc", Proto::Evm),
];
pub fn detect_url(url: &str) -> Option<Proto> { let u = url.to_ascii_lowercase(); URL_RULES.iter().find(|r| u.contains(r.0)).map(|r| r.1) }

const SOL_METHODS: &[&str] = &["getAccountInfo", "getBalance", "getBlock", "getBlockHeight", "getBlockTime", "getEpochInfo", "getFeeForMessage", "getGenesisHash",
    "getHealth", "getLatestBlockhash", "getMinimumBalanceForRentExemption", "getMultipleAccounts", "getProgramAccounts", "getRecentPrioritizationFees",
    "getSignatureStatuses", "getSignaturesForAddress", "getSlot", "getTokenAccountBalance", "getTokenAccountsByOwner", "getTransaction", "getVersion",
    "isBlockhashValid", "sendTransaction", "simulateTransaction", "requestAirdrop"];
/// Protocol from a JSON-RPC method name: eth_/net_/web3_ -> evm; known Solana camelCase -> sol; all-lowercase -> bitcoind.
pub fn detect_method(m: &str) -> Option<Proto> {
    if ["eth_", "net_", "web3_", "personal_", "wallet_", "debug_", "txpool_"].iter().any(|p| m.starts_with(p)) { return Some(Proto::Evm) }
    if SOL_METHODS.contains(&m) { return Some(Proto::Sol) }
    if !m.is_empty() && m.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()) { return Some(Proto::Btc) }
    None
}

/// One deny-list row. `pat` is matched case-insensitively against the JSON-RPC method or the REST path
/// (leading '/' stripped). `prefix`: pat matches any method starting with it. `flag`: the only rows
/// `--allow-wallet-sign` can open (and then only after a decoded summary and chain-id check).
pub struct Deny { pub pat: &'static str, pub prefix: bool, pub code: &'static str, pub family: &'static str, pub flag: bool }
const fn d(pat: &'static str, prefix: bool, code: &'static str, family: &'static str) -> Deny { Deny { pat, prefix, code, family, flag: false } }
pub const EXPORTS: &str = "method_exports_secrets";
pub const IMPORTS: &str = "method_imports_secrets";
pub const UNLOCKS: &str = "method_unlocks_wallet";
pub const SIGNS: &str = "method_wallet_signs";
pub const SPENDS: &str = "method_wallet_spends";
pub const NEEDS_FLAG: &str = "wallet_sign_needs_flag";
/// THE deny-list. Everything that refuses a method reads this table (and docs/RPC.md is checked against it).
pub const DENY: &[Deny] = &[
    // bitcoind and forks (litecoind, dogecoind, ...)
    d("dumpprivkey", false, EXPORTS, "bitcoind"), d("dumpwallet", false, EXPORTS, "bitcoind"), d("backupwallet", false, EXPORTS, "bitcoind"),
    d("dumpmasterprivkey", false, EXPORTS, "bitcoind fork"), d("dumphdinfo", false, EXPORTS, "dashd"),
    d("importprivkey", false, IMPORTS, "bitcoind"), d("importwallet", false, IMPORTS, "bitcoind"), d("importmulti", false, IMPORTS, "bitcoind"),
    d("importdescriptors", false, IMPORTS, "bitcoind"), d("sethdseed", false, IMPORTS, "bitcoind"), d("upgradetohd", false, IMPORTS, "dashd"),
    d("signrawtransactionwithkey", false, IMPORTS, "bitcoind"), d("signmessagewithprivkey", false, IMPORTS, "bitcoind"),
    d("walletpassphrase", false, UNLOCKS, "bitcoind"), d("walletpassphrasechange", false, UNLOCKS, "bitcoind"), d("encryptwallet", false, UNLOCKS, "bitcoind"),
    d("signrawtransactionwithwallet", false, SIGNS, "bitcoind"), d("signrawtransaction", false, SIGNS, "bitcoind (old)"), d("walletprocesspsbt", false, SIGNS, "bitcoind"),
    d("signmessage", false, SIGNS, "bitcoind"),
    d("sendtoaddress", false, SPENDS, "bitcoind"), d("sendmany", false, SPENDS, "bitcoind"), d("send", false, SPENDS, "bitcoind"), d("sendall", false, SPENDS, "bitcoind"),
    d("sendfrom", false, SPENDS, "bitcoind (old)"), d("bumpfee", false, SPENDS, "bitcoind"),
    // geth / clef / EIP-1193
    d("personal_unlockaccount", false, UNLOCKS, "geth"), d("personal_importrawkey", false, IMPORTS, "geth"),
    d("personal_exportrawkey", false, EXPORTS, "geth"), d("personal_", true, SIGNS, "geth"), d("eth_sign", false, SIGNS, "geth"), d("eth_signtransaction", false, SIGNS, "geth"),
    d("eth_signtypeddata", false, SIGNS, "geth"), d("eth_signtypeddata_v1", false, SIGNS, "wallet"), d("eth_signtypeddata_v3", false, SIGNS, "wallet"),
    Deny { pat: "eth_sendtransaction", prefix: false, code: NEEDS_FLAG, family: "geth / wallet", flag: true },
    Deny { pat: "eth_signtypeddata_v4", prefix: false, code: NEEDS_FLAG, family: "wallet", flag: true },
    d("account_", true, SIGNS, "clef"), d("parity_exportaccount", false, EXPORTS, "openethereum"), d("parity_", true, SIGNS, "openethereum"),
    // Electrum daemon
    d("getprivatekeys", false, EXPORTS, "electrum"), d("getseed", false, EXPORTS, "electrum"), d("getmasterprivate", false, EXPORTS, "electrum"),
    d("export_privkeys", false, EXPORTS, "electrum"), d("importprivkey", false, IMPORTS, "electrum"), d("signtransaction", false, SIGNS, "electrum"),
    d("password", false, UNLOCKS, "electrum"), d("payto", false, SPENDS, "electrum"), d("paytomany", false, SPENDS, "electrum"),
    // monero-wallet-rpc
    d("query_key", false, EXPORTS, "monero-wallet-rpc"), d("restore_deterministic_wallet", false, IMPORTS, "monero-wallet-rpc"),
    d("generate_from_keys", false, IMPORTS, "monero-wallet-rpc"), d("open_wallet", false, UNLOCKS, "monero-wallet-rpc"),
    d("transfer", false, SPENDS, "monero-wallet-rpc"), d("sweep_all", false, SPENDS, "monero-wallet-rpc"),
    // Tron full-node HTTP API: endpoints that take or return private keys / shielded spending keys
    d("wallet/easytransfer", true, IMPORTS, "tron"), d("wallet/gettransactionsign", false, IMPORTS, "tron"), d("wallet/addtransactionsign", false, IMPORTS, "tron"),
    d("wallet/createaddress", false, EXPORTS, "tron"), d("wallet/generateaddress", false, EXPORTS, "tron"), d("wallet/getaddressbyprivatekey", false, IMPORTS, "tron"),
    d("wallet/getspendingkey", false, EXPORTS, "tron"), d("wallet/getexpandedspendingkey", false, EXPORTS, "tron"), d("wallet/getakfromask", false, EXPORTS, "tron"),
    d("wallet/getnkfromnsk", false, EXPORTS, "tron"), d("wallet/getnewshieldedaddress", false, EXPORTS, "tron"), d("wallet/createshieldedtransaction", false, IMPORTS, "tron"),
    d("wallet/createshieldedcontractparameters", false, IMPORTS, "tron"), d("wallet/createspendauthsig", false, IMPORTS, "tron"),
    // Cosmos legacy LCD key endpoints
    d("keys", true, EXPORTS, "cosmos lcd (legacy)"),
];

/// One read-allowlist row: `pat` (lowercased, leading '/' stripped) is a method or REST path a read may use.
/// `prefix`: matches any method/path starting with it. Fail closed: a call not listed here (and not a
/// flag-opened wallet-sign row) is refused with `method_not_allowlisted` unless `--allow-unlisted` is given.
pub struct Allow { pub proto: Proto, pub pat: &'static str, pub prefix: bool }
const fn a(proto: Proto, pat: &'static str) -> Allow { Allow { proto, pat, prefix: false } }
const fn ap(proto: Proto, pat: &'static str) -> Allow { Allow { proto, pat, prefix: true } }
/// THE read allowlist (docs/RPC.md "The read allowlist" is checked against it by `allow_table_documented`).
pub const ALLOW: &[Allow] = &[
    // EVM (eth_/net_/web3_ reads)
    a(Proto::Evm, "eth_blocknumber"), a(Proto::Evm, "eth_chainid"), a(Proto::Evm, "eth_getbalance"), a(Proto::Evm, "eth_gettransactioncount"),
    a(Proto::Evm, "eth_getcode"), a(Proto::Evm, "eth_getstorageat"), a(Proto::Evm, "eth_call"), a(Proto::Evm, "eth_estimategas"),
    a(Proto::Evm, "eth_gasprice"), a(Proto::Evm, "eth_maxpriorityfeepergas"), a(Proto::Evm, "eth_feehistory"), a(Proto::Evm, "eth_blobbaseprice"),
    a(Proto::Evm, "eth_getblockbynumber"), a(Proto::Evm, "eth_getblockbyhash"), a(Proto::Evm, "eth_getblockreceipts"),
    a(Proto::Evm, "eth_getblocktransactioncountbynumber"), a(Proto::Evm, "eth_getblocktransactioncountbyhash"),
    a(Proto::Evm, "eth_gettransactionbyhash"), a(Proto::Evm, "eth_gettransactionreceipt"), a(Proto::Evm, "eth_gettransactionbyblocknumberandindex"),
    a(Proto::Evm, "eth_gettransactionbyblockhashandindex"), a(Proto::Evm, "eth_getlogs"), a(Proto::Evm, "eth_getproof"), a(Proto::Evm, "eth_syncing"),
    a(Proto::Evm, "eth_protocolversion"), a(Proto::Evm, "eth_createaccesslist"), a(Proto::Evm, "net_version"), a(Proto::Evm, "net_listening"),
    a(Proto::Evm, "net_peercount"), a(Proto::Evm, "web3_clientversion"), a(Proto::Evm, "web3_sha3"),
    // Bitcoin Core-style (bitcoind and forks): chain, mempool, utxo and fee reads; no wallet RPCs
    a(Proto::Btc, "getblockchaininfo"), a(Proto::Btc, "getblockcount"), a(Proto::Btc, "getbestblockhash"), a(Proto::Btc, "getblockhash"),
    a(Proto::Btc, "getblock"), a(Proto::Btc, "getblockheader"), a(Proto::Btc, "getblockstats"), a(Proto::Btc, "getchaintips"),
    a(Proto::Btc, "getdifficulty"), a(Proto::Btc, "getrawtransaction"), a(Proto::Btc, "decoderawtransaction"), a(Proto::Btc, "decodescript"),
    a(Proto::Btc, "decodepsbt"), a(Proto::Btc, "gettxout"), a(Proto::Btc, "gettxoutsetinfo"), a(Proto::Btc, "gettxoutproof"),
    a(Proto::Btc, "scantxoutset"), a(Proto::Btc, "getmempoolinfo"), a(Proto::Btc, "getrawmempool"), a(Proto::Btc, "getmempoolentry"),
    a(Proto::Btc, "testmempoolaccept"), a(Proto::Btc, "estimatesmartfee"), a(Proto::Btc, "getnetworkinfo"), a(Proto::Btc, "getconnectioncount"),
    a(Proto::Btc, "getindexinfo"), a(Proto::Btc, "validateaddress"), a(Proto::Btc, "getdescriptorinfo"), a(Proto::Btc, "uptime"),
    // Solana
    a(Proto::Sol, "getaccountinfo"), a(Proto::Sol, "getbalance"), a(Proto::Sol, "getblock"), a(Proto::Sol, "getblockheight"),
    a(Proto::Sol, "getblocktime"), a(Proto::Sol, "getepochinfo"), a(Proto::Sol, "getfeeformessage"), a(Proto::Sol, "getgenesishash"),
    a(Proto::Sol, "gethealth"), a(Proto::Sol, "getlatestblockhash"), a(Proto::Sol, "getminimumbalanceforrentexemption"),
    a(Proto::Sol, "getmultipleaccounts"), a(Proto::Sol, "getprogramaccounts"), a(Proto::Sol, "getrecentprioritizationfees"),
    a(Proto::Sol, "getsignaturestatuses"), a(Proto::Sol, "getsignaturesforaddress"), a(Proto::Sol, "getslot"),
    a(Proto::Sol, "gettokenaccountbalance"), a(Proto::Sol, "gettokenaccountsbyowner"), a(Proto::Sol, "gettransaction"),
    a(Proto::Sol, "getversion"), a(Proto::Sol, "isblockhashvalid"), a(Proto::Sol, "simulatetransaction"),
    // Tron HTTP API reads
    a(Proto::Tron, "wallet/getnowblock"), a(Proto::Tron, "wallet/getblockbynum"), a(Proto::Tron, "wallet/getblockbyid"), a(Proto::Tron, "wallet/getaccount"),
    a(Proto::Tron, "wallet/getaccountresource"), a(Proto::Tron, "wallet/gettransactionbyid"), a(Proto::Tron, "wallet/gettransactioninfobyid"),
    a(Proto::Tron, "wallet/triggerconstantcontract"), a(Proto::Tron, "wallet/getchainparameters"), a(Proto::Tron, "wallet/getnodeinfo"),
    a(Proto::Tron, "wallet/validateaddress"), a(Proto::Tron, "walletsolidity/getaccount"), a(Proto::Tron, "walletsolidity/gettransactioninfobyid"),
    // Cosmos REST / LCD query routes
    ap(Proto::Cosmos, "cosmos/base/tendermint/v1beta1/"), ap(Proto::Cosmos, "cosmos/bank/v1beta1/"), ap(Proto::Cosmos, "cosmos/auth/v1beta1/accounts/"),
    ap(Proto::Cosmos, "cosmos/staking/v1beta1/"), ap(Proto::Cosmos, "cosmos/distribution/v1beta1/"), ap(Proto::Cosmos, "cosmos/tx/v1beta1/txs/"),
    a(Proto::Cosmos, "cosmos/tx/v1beta1/txs"), a(Proto::Cosmos, "cosmos/tx/v1beta1/simulate"), ap(Proto::Cosmos, "cosmos/gov/v1beta1/"), ap(Proto::Cosmos, "cosmos/gov/v1/"),
    // Esplora
    ap(Proto::Esplora, "blocks/"), ap(Proto::Esplora, "block/"), ap(Proto::Esplora, "block-height/"), ap(Proto::Esplora, "tx/"),
    ap(Proto::Esplora, "address/"), ap(Proto::Esplora, "scripthash/"), a(Proto::Esplora, "fee-estimates"), ap(Proto::Esplora, "mempool"),
    // Blockbook
    a(Proto::Blockbook, "api/v2"), ap(Proto::Blockbook, "api/v2/tx/"), ap(Proto::Blockbook, "api/v2/tx-specific/"), ap(Proto::Blockbook, "api/v2/address/"),
    ap(Proto::Blockbook, "api/v2/xpub/"), ap(Proto::Blockbook, "api/v2/utxo/"), ap(Proto::Blockbook, "api/v2/block/"), ap(Proto::Blockbook, "api/v2/block-index/"),
    ap(Proto::Blockbook, "api/v2/estimatefee/"),
];
/// Row that lists this call. `proto` None (not detected): any protocol's row counts. Query strings are ignored (norm).
pub fn allow_row(proto: Option<Proto>, m: &str) -> Option<&'static Allow> {
    let n = norm(m);
    ALLOW.iter().find(|r| proto.map_or(true, |p| p == r.proto) && if r.prefix { n.starts_with(r.pat) } else { n == r.pat })
}
pub const NOT_LISTED: &str = "method_not_allowlisted";

/// Request fields whose presence means a secret is being sent (any depth, case-insensitive key match).
pub const SECRET_FIELDS: &[&str] = &["privatekey", "private_key", "privkey", "privkeys", "passphrase", "password", "mnemonic", "seed", "secret", "secretkey", "secret_key", "wif", "xprv", "spendingkey", "ask", "nsk", "esk"];

pub const BROADCAST_METHODS: &[&str] = &["eth_sendrawtransaction", "eth_sendrawtransactionconditional", "eth_sendbundle", "sendrawtransaction", "submitpackage", "sendtransaction",
    "wallet/broadcasttransaction", "wallet/broadcasthex", "tx", "api/tx", "cosmos/tx/v1beta1/txs", "txs", "blockchain.transaction.broadcast", "submit"];

#[derive(Debug, PartialEq)]
pub struct Refusal { pub code: &'static str, pub detail: String }
fn refuse(code: &'static str, detail: impl Into<String>) -> Refusal { Refusal { code, detail: detail.into() } }

pub fn norm(m: &str) -> String { m.trim().trim_start_matches('/').split('?').next().unwrap_or("").to_ascii_lowercase() }
pub fn deny_row(m: &str) -> Option<&'static Deny> {
    let n = norm(m);
    // exact rows first so eth_signTypedData_v4 is not swallowed by a shorter prefix
    DENY.iter().find(|r| !r.prefix && n == r.pat).or_else(|| DENY.iter().find(|r| r.prefix && n.starts_with(r.pat)))
}
fn has_secret_field(v: &Value, depth: usize) -> Option<String> {
    if depth > 32 { return Some("(nesting too deep)".into()) }
    match v {
        Value::Object(o) => o.iter().find_map(|(k, x)| if SECRET_FIELDS.contains(&k.to_ascii_lowercase().as_str()) { Some(k.clone()) } else { has_secret_field(x, depth + 1) }),
        Value::Array(a) => a.iter().find_map(|x| has_secret_field(x, depth + 1)),
        _ => None,
    }
}
fn truthy(v: &Value) -> bool { v == &json!(true) || v.get("private") == Some(&json!(true)) }

/// What the caller must do after a call passes the checks.
#[derive(Debug, PartialEq)]
pub enum Pass { Plain, WalletSign }
/// Check one call. `extra` = refusals added by the policy file (exact, or prefix ending in '*').
/// `rest_post`: method is a REST path sent as POST (esplora POST /tx is a broadcast, GET /tx/ID is a read).
pub fn check_call(method: &str, params: &Value, extra: &[String], allow_wallet_sign: bool, rest_post: bool) -> Result<Pass, Refusal> {
    check_call_in(None, true, method, params, extra, allow_wallet_sign, rest_post)
}
/// The full check: `proto` the endpoint protocol (None = undetected), `allow_unlisted` the `--allow-unlisted` opt-in.
pub fn check_call_in(proto: Option<Proto>, allow_unlisted: bool, method: &str, params: &Value, extra: &[String], allow_wallet_sign: bool, rest_post: bool) -> Result<Pass, Refusal> {
    let n = norm(method);
    if n.is_empty() { return Err(refuse("bad_input", "empty method")) }
    for p in extra {
        let p = p.to_ascii_lowercase(); let p = p.trim_start_matches('/');
        if p.strip_suffix('*').map_or(n == p, |q| n.starts_with(q)) { return Err(refuse("method_denied_by_policy", method)) }
    }
    if let Some(r) = deny_row(method) {
        if !(r.flag && allow_wallet_sign) {
            let hint = if r.flag { " (only --allow-wallet-sign opens it; the wallet's own UI then confirms)" } else { "" };
            return Err(refuse(r.code, format!("{method}{hint}")))
        }
    }
    // bitcoind: private-key listings behind a boolean argument
    if (n == "listdescriptors" || n == "gethdkeys") && (params.get(0).is_some_and(truthy) || params.get("private") == Some(&json!(true))) {
        return Err(refuse(EXPORTS, format!("{method} with private=true")))
    }
    if n == "createwallet" && params.get(3).and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty()) { return Err(refuse(UNLOCKS, "createwallet with a passphrase")) }
    if let Some(k) = has_secret_field(params, 0) { return Err(refuse("request_contains_secret_field", k)) }
    let rest_only = matches!(n.as_str(), "tx" | "api/tx" | "txs" | "cosmos/tx/v1beta1/txs" | "wallet/broadcasttransaction" | "wallet/broadcasthex");
    let sendtx = n.starts_with("api/v2/sendtx") || n.starts_with("api/sendtx");
    if sendtx || (BROADCAST_METHODS.contains(&n.as_str()) && (if rest_only { rest_post } else { !method.contains('/') })) {
        return Err(refuse("broadcast_needs_sendraw", format!("{method}: use `rpc URL sendraw` (decodes the tx and asks for a code on the terminal)")))
    }
    if deny_row(method).is_some_and(|r| r.flag) { return Ok(Pass::WalletSign) }
    if !allow_unlisted && allow_row(proto, method).is_none() {
        let on = proto.map_or("any protocol".to_string(), |p| p.name().to_string());
        return Err(refuse(NOT_LISTED, format!("{method}: not in the {on} read allowlist (docs/RPC.md); --allow-unlisted sends it anyway")))
    }
    Ok(Pass::Plain)
}

fn hexq(v: &Value) -> Option<u128> {
    let s = v.as_str()?.strip_prefix("0x")?;
    if s.is_empty() || s.len() > 32 { return None }
    u128::from_str_radix(s, 16).ok()
}
/// chain id given as JSON number, 0x-hex or decimal string
pub fn chain_id_of(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| hexq(v).and_then(|x| u64::try_from(x).ok())).or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}
fn is_hex(s: &str) -> bool { s.strip_prefix("0x").is_some_and(|h| h.len() % 2 == 0 && h.bytes().all(|b| b.is_ascii_hexdigit())) }
fn is_addr(v: &Value) -> bool { v.as_str().is_some_and(|s| s.len() == 42 && is_hex(s)) }

/// Decoded summary of a flag-allowed wallet-sign request, plus the chain id it pins (None = not pinned by the request).
pub fn wallet_sign_summary(method: &str, params: &Value) -> Result<(String, Option<u64>), Refusal> {
    let bad = |w: &str| refuse("wallet_sign_undecodable", w.to_string());
    match norm(method).as_str() {
        "eth_sendtransaction" => {
            let tx = params.get(0).and_then(|t| t.as_object()).ok_or_else(|| bad("params[0] must be a transaction object"))?;
            const KNOWN: &[&str] = &["from", "to", "value", "data", "input", "gas", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "nonce", "chainId", "type", "accessList"];
            if let Some(k) = tx.keys().find(|k| !KNOWN.contains(&k.as_str())) { return Err(bad(&format!("unknown field {k}"))) }
            if params.as_array().map_or(0, |a| a.len()) != 1 { return Err(bad("expected exactly one params entry")) }
            let from = tx.get("from").filter(|v| is_addr(v)).ok_or_else(|| bad("from must be a 20-byte hex address"))?;
            let to = match tx.get("to") { None | Some(Value::Null) => return Err(bad("contract creation (no to) is not summarized; refused")), Some(v) if is_addr(v) => v.as_str().unwrap_or(""), _ => return Err(bad("to is not an address")) };
            let value = match tx.get("value") { None => 0, Some(v) => hexq(v).ok_or_else(|| bad("value is not a 0x quantity"))? };
            let data = match (tx.get("data"), tx.get("input")) { (Some(a), Some(b)) if a != b => return Err(bad("data and input differ")), (Some(v), _) | (None, Some(v)) => v.as_str().filter(|s| is_hex(s)).ok_or_else(|| bad("data is not hex"))?, _ => "0x" };
            for k in ["gas", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "nonce", "chainId"] { if let Some(v) = tx.get(k) { hexq(v).ok_or_else(|| bad(&format!("{k} is not a 0x quantity")))?; } }
            let cid = tx.get("chainId").and_then(chain_id_of);
            let nbytes = (data.len() - 2) / 2;
            let sel = if nbytes >= 4 { &data[..10] } else if nbytes == 0 { "(none: plain transfer)" } else { return Err(bad("data shorter than a 4-byte selector")) };
            let mut s = format!("wallet-sign eth_sendTransaction (the wallet will ask you to approve)\n  from:     {}\n  to:       {to}\n  value:    {value} wei\n  data:     selector {sel}, {nbytes} bytes\n", from.as_str().unwrap_or(""));
            if let Some(c) = cid { s += &format!("  chain id: {c}\n") }
            for k in ["gas", "maxFeePerGas", "maxPriorityFeePerGas", "gasPrice", "nonce"] { if let Some(v) = tx.get(k).and_then(hexq) { s += &format!("  {k}: {v}\n") } }
            Ok((s, cid))
        }
        "eth_signtypeddata_v4" => {
            let a = params.as_array().filter(|a| a.len() == 2).ok_or_else(|| bad("params must be [address, typedData]"))?;
            if !is_addr(&a[0]) { return Err(bad("params[0] must be an address")) }
            let td: Value = match &a[1] { Value::String(s) => serde_json::from_str(s).map_err(|_| bad("typedData string is not JSON"))?, v @ Value::Object(_) => v.clone(), _ => return Err(bad("typedData must be an object or JSON string")) };
            let types = td.get("types").and_then(|t| t.as_object()).ok_or_else(|| bad("missing types"))?;
            let primary = td.get("primaryType").and_then(|p| p.as_str()).ok_or_else(|| bad("missing primaryType"))?;
            let ptype = types.get(primary).and_then(|t| t.as_array()).ok_or_else(|| bad("primaryType not defined in types"))?;
            let domain = td.get("domain").and_then(|d| d.as_object()).ok_or_else(|| bad("missing domain"))?;
            let msg = td.get("message").and_then(|m| m.as_object()).ok_or_else(|| bad("missing message"))?;
            let names: Vec<&str> = ptype.iter().filter_map(|f| f.get("name").and_then(|n| n.as_str())).collect();
            if names.len() != ptype.len() { return Err(bad("type field without a name")) }
            if let Some(k) = msg.keys().find(|k| !names.contains(&k.as_str())) { return Err(bad(&format!("message field {k} is not in type {primary}"))) }
            if let Some(k) = names.iter().find(|k| !msg.contains_key(**k)) { return Err(bad(&format!("message lacks field {k}"))) }
            let cid = domain.get("chainId").map(|v| chain_id_of(v).ok_or_else(|| bad("domain.chainId unreadable"))).transpose()?;
            let show = |v: &Value| { let s = match v { Value::String(s) => s.clone(), o => o.to_string() }; let s: String = s.chars().filter(|c| !c.is_control()).collect(); if s.chars().count() > 200 { s.chars().take(200).collect::<String>() + "..." } else { s } };
            let mut s = format!("wallet-sign eth_signTypedData_v4 (the wallet will ask you to approve)\n  signer:      {}\n  domain:\n", a[0].as_str().unwrap_or(""));
            for k in ["name", "version", "chainId", "verifyingContract", "salt"] { if let Some(v) = domain.get(k) { s += &format!("    {k}: {}\n", show(v)) } }
            s += &format!("  primaryType: {primary}\n  message:\n");
            for k in &names { s += &format!("    {k}: {}\n", show(&msg[*k])) }
            Ok((s, cid))
        }
        _ => Err(refuse(SIGNS, method.to_string())),
    }
}

/// Field names that mean a response is carrying a secret.
pub const RESPONSE_SECRET_FIELDS: &[&str] = &["privkey", "privatekey", "private_key", "hdseed", "mnemonic", "seed_phrase", "spend_key", "spendingkey", "secret_key", "wif", "xprv"];
const XPRV: &[&str] = &["xprv", "tprv", "yprv", "zprv", "uprv", "vprv", "Yprv", "Zprv", "Ltpv"];
/// Defense in depth for methods the deny-list does not know: a response that carries a key is withheld.
pub fn response_secret(v: &Value, depth: usize) -> Option<String> {
    if depth > 64 { return None }
    match v {
        Value::Object(o) => o.iter().find_map(|(k, x)| {
            let lk = k.to_ascii_lowercase();
            if RESPONSE_SECRET_FIELDS.contains(&lk.as_str()) && !x.is_null() && x != &json!("") { Some(format!("field {k}")) } else { response_secret(x, depth + 1) } }),
        Value::Array(a) => a.iter().find_map(|x| response_secret(x, depth + 1)),
        Value::String(s) => XPRV.iter().find(|p| s.match_indices(*p).any(|(i, _)| s[i..].chars().take(111).filter(|c| c.is_ascii_alphanumeric()).count() >= 100)).map(|_| "extended private key string".into()),
        _ => None,
    }
}

/// Replace every occurrence of each secret (len >= 4) with [REDACTED].
pub fn redact(s: &str, secrets: &[String]) -> String {
    let mut o = s.to_string();
    for x in secrets { if x.len() >= 4 { o = o.replace(x.as_str(), "[REDACTED]") } }
    o
}

/// Parse an auth file / env value into an HTTP header and the strings that must never be printed.
/// "user:pass" (also a bitcoind .cookie) -> Basic; "Bearer TOKEN" or a bare token -> Bearer;
/// "Header-Name: value" lines (e.g. TRON-PRO-API-KEY: ...) -> those headers.
pub fn parse_auth(content: &str) -> Result<(Vec<(String, String)>, Vec<String>), &'static str> {
    let t = content.trim_matches(|c| c == '\n' || c == '\r' || c == ' ');
    if t.is_empty() { return Err("auth_empty") }
    let mut secrets = vec![t.to_string()];
    let lines: Vec<&str> = t.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
    let header_line = |l: &str| l.split_once(": ").is_some_and(|(k, _)| !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    let mut h = vec![];
    if lines.len() > 1 || (header_line(lines[0]) && !lines[0].to_ascii_lowercase().starts_with("bearer")) {
        for l in &lines {
            let (k, v) = l.split_once(": ").filter(|_| header_line(l)).ok_or("auth_file_bad_header_line")?;
            secrets.push(v.trim().to_string()); h.push((k.to_string(), v.trim().to_string()));
        }
    } else if let Some(tok) = t.strip_prefix("Bearer ").or_else(|| t.strip_prefix("bearer ")) {
        secrets.push(tok.trim().to_string()); h.push(("Authorization".into(), format!("Bearer {}", tok.trim())));
    } else if let Some((u, p)) = t.split_once(':').filter(|_| !t.contains(char::is_whitespace)) {
        let b = blocktools_core::b64::encode(t.as_bytes());
        secrets.push(p.to_string()); secrets.push(b.clone()); let _ = u;
        h.push(("Authorization".into(), format!("Basic {b}")));
    } else if !t.contains(char::is_whitespace) {
        h.push(("Authorization".into(), format!("Bearer {t}")));
    } else { return Err("auth_file_unrecognized") }
    secrets.retain(|s| s.len() >= 4);
    Ok((h, secrets))
}

/// Policy file: {"version":1,"rpc":{"deny":["method","prefix_*"]}} ("chains" is the tx policy and is ignored here).
pub fn parse_policy(s: &str) -> Result<Vec<String>, String> {
    let v: Value = serde_json::from_str(s).map_err(|_| "policy_bad_json")?;
    let o = v.as_object().ok_or("policy_bad_json")?;
    if let Some(k) = o.keys().find(|k| !["version", "rpc", "chains"].contains(&k.as_str())) { return Err(format!("policy_unknown_key: {k}")) }
    if v["version"] != json!(1) { return Err("policy_version".into()) }
    let Some(r) = o.get("rpc") else { return Ok(vec![]) };
    let r = r.as_object().ok_or("policy_bad_json")?;
    if let Some(k) = r.keys().find(|k| k.as_str() != "deny") { return Err(format!("policy_unknown_key: rpc.{k}")) }
    r.get("deny").map(|d| d.as_array().ok_or("policy_bad_json".to_string())?.iter().map(|x| x.as_str().map(String::from).ok_or("policy_bad_json".to_string())).collect()).unwrap_or(Ok(vec![]))
}

/// Decimal coin amount from a JSON number (bitcoind BTC floats) to base units, exact for 8 decimals.
pub fn coins_to_units(v: &Value) -> Option<u64> {
    let s = v.to_string();
    let (i, f) = s.split_once('.').unwrap_or((&s, ""));
    if f.len() > 8 || i.starts_with('-') || f.contains(['e', 'E']) || i.contains(['e', 'E']) { return None }
    let i: u64 = i.parse().ok()?;
    let f: u64 = format!("{f:0<8}").parse().ok()?;
    i.checked_mul(100_000_000)?.checked_add(f)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn refused(m: &str, p: Value) -> Option<&'static str> { check_call(m, &p, &[], false, false).err().map(|r| r.code) }
    #[test]
    fn swapchan_key_export_list_is_a_subset() {
        // /workspace/handoff/rpc-knife-requirements.md: every method there must be refused here
        for m in ["dumpprivkey", "dumpwallet", "importprivkey", "backupwallet", "sethdseed", "personal_importRawKey", "personal_unlockAccount", "getprivatekeys", "getseed"] {
            assert!(refused(m, json!([])).is_some(), "{m}")
        }
        assert_eq!(refused("listdescriptors", json!([true])), Some("method_exports_secrets"));
        assert_eq!(refused("listdescriptors", json!({"private":true})), Some("method_exports_secrets"));
        assert_eq!(refused("listdescriptors", json!([])), None);
    }
    #[test]
    fn case_and_reads() {
        assert!(refused("DumpPrivKey", json!([])).is_some());
        for m in ["eth_getBalance", "eth_call", "getblockcount", "getBalance", "eth_getLogs"] { assert_eq!(refused(m, json!([])), None, "{m}") }
        assert_eq!(check_call("eth_sendTransaction", &json!([]), &[], true, false).ok(), Some(Pass::WalletSign));
        assert!(check_call("eth_sign", &json!([]), &[], true, false).is_err());
        assert!(check_call("x", &json!([]), &["x".into()], true, false).is_err());
    }
    #[test]
    fn rest_broadcast_only_on_post() {
        assert!(check_call("/tx", &json!("00"), &[], false, true).is_err());
        assert!(check_call("/tx/abcd", &Value::Null, &[], false, false).is_ok());
        assert!(check_call("tx", &json!([]), &[], false, false).is_ok()); // xrpl-style tx lookup over JSON-RPC
        assert!(check_call("/cosmos/tx/v1beta1/txs", &Value::Null, &[], false, false).is_ok());
        assert!(check_call("/wallet/broadcasttransaction", &json!({}), &[], false, true).is_err());
        assert!(check_call("/wallet/getaccount", &json!({"address":"T"}), &[], false, true).is_ok());
    }
    #[test]
    fn secret_fields_refused() {
        assert_eq!(refused("anything", json!([{"privateKey":"aa"}])), Some("request_contains_secret_field"));
        assert_eq!(refused("anything", json!({"mnemonic":"a b"})), Some("request_contains_secret_field"));
    }
    #[test]
    fn detection() {
        assert_eq!(detect_url("https://ethereum-rpc.publicnode.com"), Some(Proto::Evm));
        assert_eq!(detect_url("http://127.0.0.1:8332"), Some(Proto::Btc));
        assert_eq!(detect_url("https://blockstream.info/api"), Some(Proto::Esplora));
        assert_eq!(detect_method("eth_chainId"), Some(Proto::Evm));
        assert_eq!(detect_method("getblockcount"), Some(Proto::Btc));
        assert_eq!(detect_method("getSlot"), Some(Proto::Sol));
    }
    #[test]
    fn coins_exact() {
        assert_eq!(coins_to_units(&json!(0.29)), Some(29_000_000));
        assert_eq!(coins_to_units(&json!(21000000.0)), Some(2_100_000_000_000_000));
        assert_eq!(coins_to_units(&json!(0.000000001)), None);
    }
    #[test]
    fn auth_forms() {
        let (h, s) = parse_auth("u:pass\n").unwrap();
        assert_eq!(h[0].1, "Basic dTpwYXNz"); assert!(s.contains(&"pass".to_string()) && s.contains(&"dTpwYXNz".to_string()));
        assert_eq!(parse_auth("Bearer abc").unwrap().0[0].1, "Bearer abc");
        assert_eq!(parse_auth("X-Api-Key: k1").unwrap().0[0], ("X-Api-Key".into(), "k1".into()));
    }
}
#[cfg(test)]
mod doc_tests {
    #[test]
    fn summary_capture() {
        // the summary shown in docs/RPC.md
        let p = serde_json::json!([{"from":"0x1111111111111111111111111111111111111111","to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","value":"0x0","data":"0xa9059cbb0000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000003b9aca00","chainId":"0x1"}]);
        let (s, c) = super::wallet_sign_summary("eth_sendTransaction", &p).unwrap();
        assert!(s.contains("selector 0xa9059cbb, 68 bytes") && c == Some(1), "{s}");
        assert!(include_str!("../../../docs/RPC.md").contains(s.trim_end()), "docs summary differs from code:\n{s}");
    }
    #[test]
    fn deny_table_documented() {
        let doc = include_str!("../../../docs/RPC.md");
        for d in super::DENY { assert!(doc.contains(&format!("| `{}` |", d.pat)), "docs/RPC.md deny table lacks {}", d.pat); assert!(doc.contains(d.code), "{}", d.code) }
    }
}
#[cfg(test)]
mod allow_tests {
    use super::*;
    #[test]
    fn allow_table_documented() {
        let doc = include_str!("../../../docs/RPC.md");
        for r in ALLOW { let cell = format!("`{}`{}", r.pat, if r.prefix { "…" } else { "" }); assert!(doc.contains(&cell), "docs/RPC.md allowlist lacks {cell}") }
        assert!(doc.contains(NOT_LISTED));
    }
    #[test]
    fn allowlist_and_denylist_disjoint() {
        for r in ALLOW { if !r.prefix { assert!(deny_row(r.pat).is_none(), "{} is allowed and denied", r.pat); assert!(!BROADCAST_METHODS.contains(&r.pat) || r.pat.contains('/'), "{}", r.pat) } }
    }
    #[test]
    fn fail_closed_by_protocol() {
        let c = |p, m: &str| check_call_in(Some(p), false, m, &Value::Null, &[], false, false).err().map(|r| r.code);
        assert_eq!(c(Proto::Evm, "eth_getBalance"), None);
        assert_eq!(c(Proto::Evm, "getblockcount"), Some(NOT_LISTED));
        assert_eq!(c(Proto::Btc, "getwalletinfo"), Some(NOT_LISTED));
        assert_eq!(c(Proto::Cosmos, "/cosmos/bank/v1beta1/balances/x?y=1"), None);
        assert_eq!(c(Proto::Esplora, "/tx/ab"), None);
        assert_eq!(c(Proto::Btc, "dumpprivkey"), Some(EXPORTS));
    }
}
