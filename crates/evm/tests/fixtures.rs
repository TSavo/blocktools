//! Real Ethereum mainnet JSON-RPC responses (recipes/fixtures/evm-mainnet, provenance in PROVENANCE.md).
use blocktools_evm::api;
use serde_json::{json, Value};

macro_rules! fx { ($f:literal) => { include_str!(concat!("../../../recipes/fixtures/evm-mainnet/", $f)) } }
fn j(s: &str) -> Value { serde_json::from_str(s).unwrap() }
fn dec(req: Value) -> Value { api::decode_json(&req).unwrap() }

#[test]
fn usdc_transfer_calldata_receipt_and_logs() {
    let tx = j(fx!("01a-erc20-transfer-tx.json"));
    let r = dec(json!({"input": tx, "sig": "transfer(address,uint256)"}));
    assert_eq!(r["status"], "ok");
    assert_eq!(r["selector"], "0xa9059cbb");
    let to = r["args"][0]["value"].as_str().unwrap().to_string();
    let amt = r["args"][1]["value"].as_str().unwrap().to_string();
    // same transfer appears as a Transfer log in the receipt and in getLogs, with matching to/value
    let ev = "event Transfer(address indexed from, address indexed to, uint256 value)";
    let rc = j(fx!("01b-erc20-transfer-receipt.json"));
    let logs = rc["result"]["logs"].as_array().unwrap();
    let hit = logs.iter().map(|l| dec(json!({"input": l, "sig": ev}))).find(|d| d["status"] == "ok" && d["args"][1]["value"] == to).unwrap();
    assert_eq!(hit["args"][2]["value"], amt);
    assert_eq!(hit["args"][0]["value"].as_str().unwrap().to_lowercase(), tx["result"]["from"].as_str().unwrap());
    let gl = j(fx!("01c-usdc-transfer-getLogs.json"));
    let all = gl["result"].as_array().unwrap();
    assert!(!all.is_empty());
    for l in all { assert_eq!(dec(json!({"input": l, "sig": ev}))["status"], "ok"); }
}

#[test]
fn eth_call_returndata() {
    let r = dec(json!({"input": fx!("03a-usdc-decimals.json"), "sig": "decimals() returns (uint8)", "output": true}));
    assert_eq!(r["args"][0]["value"], "6");
    let r = dec(json!({"input": fx!("03b-usdc-symbol.json"), "types": "(string)"}));
    assert_eq!(r["args"][0]["value"], "USDC");
    let r = dec(json!({"input": fx!("03c-usdc-balanceOf.json"), "sig": "balanceOf(address) returns (uint256)", "output": true}));
    let raw = j(fx!("03c-usdc-balanceOf.json"))["result"].as_str().unwrap().to_string();
    assert_eq!(r["args"][0]["value"], u128::from_str_radix(&raw[2..].trim_start_matches('0'), 16).unwrap().to_string());
}

#[test]
fn reverts() {
    let r = dec(json!({"input": fx!("04d-error-string-eth_call.json")}));
    assert_eq!(r["signature"], "Error(string)");
    assert_eq!(r["args"][0]["value"], "ERC20: transfer amount exceeds allowance");
    // custom error without an ABI: no_match + selector; with the Universal Router error signature it decodes
    let r = dec(json!({"input": fx!("04e-custom-error-eth_call.json")}));
    assert_eq!(r, json!({"status": "no_match", "selector": "0x5bf6f916"}));
    let r = dec(json!({"input": fx!("04e-custom-error-eth_call.json"), "sig": "error TransactionDeadlinePassed()"}));
    assert_eq!(r["status"], "ok");
    assert_eq!(r["kind"], "error");
}

#[test]
fn universal_router_execute_calldata() {
    let r = dec(json!({"input": fx!("02a-swap-tx.json"), "sig": "execute(bytes commands, bytes[] inputs, uint256 deadline)"}));
    assert_eq!(r["selector"], "0x3593564c");
    assert!(r["args"][1]["value"].as_array().unwrap().len() >= 1);
}

#[test]
fn create_tx_matches_receipt_contract_address() {
    let r = api::create_json(&j(fx!("05a-create-tx.json"))).unwrap();
    let want = j(fx!("05b-create-receipt.json"))["result"]["contractAddress"].as_str().unwrap().to_string();
    assert_eq!(r["address"].as_str().unwrap().to_lowercase(), want);
    assert_eq!(want, "0x0a0e5274d286a72614a4e4015370395ef9e42eed");
}

#[test]
fn uniswap_v3_pool_create2_from_pool_created_log() {
    // PoolCreated(token0, token1, fee, tickSpacing, pool) from the receipt; salt = keccak256(abi.encode(token0, token1, fee));
    // init-code hash = POOL_INIT_CODE_HASH published in Uniswap v3-periphery PoolAddress.sol.
    let rc = j(fx!("05d-create2-pool-receipt.json"));
    let l = rc["result"]["logs"].as_array().unwrap().iter().find(|l| l["address"] == "0x1f98431c8ad98523631ae4a59f267346ea31f984").unwrap();
    let d = dec(json!({"input": l, "sig": "event PoolCreated(address indexed token0, address indexed token1, uint24 indexed fee, int24 tickSpacing, address pool)"}));
    let (t0, t1, fee, pool) = (&d["args"][0]["value"], &d["args"][1]["value"], &d["args"][2]["value"], &d["args"][4]["value"]);
    let enc = api::encode_call("(address,address,uint24)", &[t0.clone(), t1.clone(), fee.clone()]).unwrap();
    let salt = api::keccak256_hex(enc["data"].as_str().unwrap()).unwrap();
    let r = api::create_json(&json!({"deployer": "0x1F98431c8aD98523631AE4a59f267346ea31F984", "salt": salt,
        "init_code_hash": "0xe34f199b19b2b4f47f68442619d555527d244f78a3297ea89325f843f87b8b54"})).unwrap();
    assert_eq!(&r["address"], pool);
    assert_eq!(pool, "0x7fF72b3aab6db0398e7fbCaB8efcd37159323EcF");
}
