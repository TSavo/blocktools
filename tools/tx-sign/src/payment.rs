//! Narrow signer for the Base Sepolia WETH-to-USDC payment experiment.
use blocktools_core::{hex_dec, hex_enc, validate};
use blocktools_tx::user_operation::UserOperation;
use serde_json::{json, Value};
use std::io::Read;

const WETH: &str = "0x4200000000000000000000000000000000000006";
const USDC: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const ROUTER: &str = "0x94cC0AaC535CCDB3C01d6787D6413C739ae12bc4";
const PM: &str = "0x888888888888Ec68A58AB8094Cc1AD20Ba3D2402";
const DELEGATE: &str = "0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9";
fn call(sig: &str, args: Value) -> Result<String, &'static str> {
    let data = blocktools_evm::api::encode_call(sig, args.as_array().ok_or("invalid args")?)
        .map_err(|_| "invalid call")?;
    Ok(data["data"].as_str().ok_or("invalid encoding")?.to_owned())
}
fn quantity(op: &Value, key: &str) -> Result<u128, &'static str> {
    let s = op[key]
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or("missing quantity")?;
    u128::from_str_radix(s, 16).map_err(|_| "invalid quantity")
}
fn word(n: u128) -> [u8; 32] {
    let mut w = [0; 32];
    w[16..].copy_from_slice(&n.to_be_bytes());
    w
}
fn verify_delegation(auth: &Value, quote: &Value, sender: [u8; 20]) -> Result<(), &'static str> {
    use bitcoin::secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId},
        Message, Secp256k1,
    };
    use blocktools_tx::delegation::Authorization;
    let nonce = u64::try_from(quantity(auth, "nonce")?).map_err(|_| "invalid delegation nonce")?;
    let delegate = validate::eth(auth["address"].as_str().ok_or("missing delegate")?)?;
    if delegate != validate::eth(DELEGATE)?
        || quantity(auth, "chainId")? != 84532
        || quote["authorizationNonce"] != nonce.to_string()
    {
        return Err("delegation differs from quote");
    }
    let parity = quantity(auth, "yParity")?;
    if parity > 1 {
        return Err("invalid delegation parity");
    }
    let mut compact = [0u8; 64];
    for (name, chunk) in ["r", "s"].into_iter().zip(compact.chunks_exact_mut(32)) {
        let hex = auth[name]
            .as_str()
            .and_then(|v| v.strip_prefix("0x"))
            .ok_or("missing delegation signature")?;
        if hex.len() != 64 {
            return Err("invalid delegation signature");
        }
        chunk.copy_from_slice(&hex_dec(hex).ok_or("invalid delegation signature")?);
    }
    let id = RecoveryId::from_i32(parity as i32).map_err(|_| "invalid delegation parity")?;
    let sig = RecoverableSignature::from_compact(&compact, id)
        .map_err(|_| "invalid delegation signature")?;
    let digest = Authorization {
        chain_id: 84532.try_into().unwrap(),
        delegate,
        nonce,
    }
    .digest()?;
    let key = Secp256k1::verification_only()
        .recover_ecdsa(&Message::from_digest(digest), &sig)
        .map_err(|_| "invalid delegation signature")?;
    if validate::eth(&blocktools_core::eth_address_from_pubkey(
        &key.serialize_uncompressed(),
    ))? != sender
    {
        return Err("wrong delegation signer");
    }
    Ok(())
}
const MESSENGER: &str = "0x8745D906D67C346E5eb1aEEED38Eb87F34DF0C0A";
const BURN: &str = "depositForBurnWithFees(uint256,uint32,bytes32,address,bytes32,(bytes,address))";

fn checked_burn(
    circle: &Value,
    sender: &str,
    recipient: &str,
    payout: u128,
    cap: u128,
    expected_hash: &str,
) -> Result<String, &'static str> {
    use blocktools_evm::{abi, api, sig::Sig};
    let burn = circle["burnData"].as_str().ok_or("missing Circle burn")?;
    if cap < payout
        || circle["maxInputMicroUsdc"] != cap.to_string()
        || circle["destinationChainId"] != 11155420
        || circle["burnDataHash"] != expected_hash
        || api::keccak256_hex(burn).map_err(|_| "invalid Circle data")? != expected_hash
    {
        return Err("Circle terms differ from review");
    }
    let signature = Sig::parse(BURN).map_err(|_| "invalid burn signature")?;
    let bytes = blocktools_evm::unhex(burn).map_err(|_| "invalid Circle burn")?;
    let args = abi::decode(&signature.inputs, bytes.get(4..).ok_or("short burn")?)
        .map_err(|_| "invalid Circle fields")?;
    let signed_quote = args[5][0]
        .as_str()
        .filter(|v| v.len() > 2)
        .ok_or("missing forwarding quote")?;
    let mint_recipient = format!("0x{:024}{}", 0, hex_enc(validate::eth(recipient)?));
    let expected = call(
        BURN,
        json!([
            payout.to_string(),
            "2",
            mint_recipient,
            USDC,
            format!("0x{:064}", 0),
            [signed_quote, sender]
        ]),
    )?;
    if !expected.eq_ignore_ascii_case(burn) {
        return Err("Circle burn differs from intended payment");
    }
    Ok(expected)
}

pub(super) fn run() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args().skip(2).collect();
    let inspect = args.last().is_some_and(|s| s == "--inspect");
    let args = &args[..args.len() - usize::from(inspect)];
    let [path, sender, recipient, payout, spend, reserve, options @ ..] = args else {
        return Err("usage: base-sepolia-payment BUILD.json SENDER RECIPIENT PAYOUT_MICRO_USDC MAX_WETH_WEI MAX_GAS_MICRO_USDC [--circle MAX_BRIDGE_MICRO_USDC REVIEWED_BURN_HASH] [--wrap NATIVE_WEI] [--inspect]");
    };
    let (bridge, options) = match options {
        [flag, cap, hash, rest @ ..] if flag == "--circle" => (
            Some((
                cap.parse::<u128>().map_err(|_| "invalid bridge cap")?,
                hash.as_str(),
            )),
            rest,
        ),
        _ => (None, options),
    };
    let wrap = match options {
        [] => 0,
        [flag, amount] if flag == "--wrap" => {
            amount.parse::<u128>().map_err(|_| "invalid native wrap")?
        }
        _ => return Err("unexpected payment options"),
    };
    let account = validate::eth(sender)?;
    validate::eth(recipient)?;
    let spend: u128 = spend.parse().map_err(|_| "invalid spend")?;
    let reserve: u128 = reserve.parse().map_err(|_| "invalid reserve")?;
    let payout: u128 = payout.parse().map_err(|_| "invalid payout")?;
    if payout == 0 || reserve == 0 {
        return Err("payment amount and gas cap must be positive");
    }
    let mut file = String::new();
    std::fs::File::open(path)
        .map_err(|_| "open operation")?
        .take(65537)
        .read_to_string(&mut file)
        .map_err(|_| "read operation")?;
    if file.len() > 65536 {
        return Err("operation too large");
    }
    let build: Value = serde_json::from_str(&file).map_err(|_| "invalid build")?;
    let q = &build["quote"];
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(u64::MAX)
    };
    let expiry = q["expiresAt"].as_u64().ok_or("missing quote expiry")?;
    if expiry <= now() {
        return Err("expired payment");
    }
    if q["chainId"] != 84532
        || !q["sender"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(sender))
        || !q["recipient"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(recipient))
        || q["amountMicroUsdc"] != payout.to_string()
        || q["maxGasMicroUsdc"] != reserve.to_string()
        || q["maxWethWei"] != spend.to_string()
        || !build["entryPoint"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case("0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108"))
    {
        return Err("reviewed payment differs from quote");
    }
    let output = q["swapOutputMicroUsdc"]
        .as_str()
        .and_then(|s| s.parse::<u128>().ok())
        .ok_or("invalid swap output")?;
    let burn = match (bridge, q.get("circle")) {
        (Some((cap, hash)), Some(circle)) => {
            Some(checked_burn(circle, sender, recipient, payout, cap, hash)?)
        }
        (None, None) => None,
        _ => return Err("unexpected payment destination"),
    };
    if wrap > spend
        || q.get("wrapNativeWei").map_or(Some("0"), Value::as_str)
            != Some(wrap.to_string().as_str())
    {
        return Err("native wrap differs from review");
    }
    let bridge_cap = bridge.map_or(payout, |(cap, _)| cap);
    if (spend == 0) != (output == 0)
        || output > bridge_cap.checked_add(reserve).ok_or("payment overflow")?
    {
        return Err("invalid swap bounds");
    }
    let op = &build["userOperation"];
    let direct = bridge.is_none() && q["requiresDelegation"] == false && spend == 0;
    for (field, limit) in [
        (
            "callGasLimit",
            if bridge.is_some() {
                700000
            } else if direct {
                80000
            } else {
                450000
            },
        ),
        ("verificationGasLimit", if direct { 70000 } else { 140000 }),
        (
            "preVerificationGas",
            if bridge.is_some() {
                2400000
            } else if direct {
                90000
            } else {
                145000
            },
        ),
        (
            "paymasterVerificationGasLimit",
            if direct { 85000 } else { 120000 },
        ),
        (
            "paymasterPostOpGasLimit",
            if direct { 90000 } else { 100000 },
        ),
    ] {
        if quantity(op, field)? > limit {
            return Err("operation exceeds the reviewed gas limits");
        }
    }
    if validate::eth(op["sender"].as_str().ok_or("missing sender")?)? != account
        || !op["paymaster"]
            .as_str()
            .is_some_and(|s| s.eq_ignore_ascii_case(PM))
    {
        return Err("unexpected sender or paymaster");
    }
    let approve =
        |who: &str, n: u128| call("approve(address,uint256)", json!([who, n.to_string()]));
    let mut calls = Vec::new();
    if wrap > 0 {
        calls.push(json!([
            WETH,
            wrap.to_string(),
            call("deposit()", json!([]))?
        ]));
    }
    if spend > 0 {
        let swap = call(
            "exactOutputSingle((address,address,uint24,address,uint256,uint256,uint160))",
            json!([[
                WETH,
                USDC,
                "3000",
                sender,
                output.to_string(),
                spend.to_string(),
                "0"
            ]]),
        )?;
        calls.extend([
            json!([WETH, "0", approve(ROUTER, spend)?]),
            json!([ROUTER, "0", swap]),
            json!([WETH, "0", approve(ROUTER, 0)?]),
        ]);
    }
    if let Some(data) = burn {
        calls.push(json!([USDC, "0", approve(MESSENGER, bridge_cap)?]));
        calls.push(json!([MESSENGER, "0", data]));
    } else {
        calls.push(json!([
            USDC,
            "0",
            call(
                "transfer(address,uint256)",
                json!([recipient, payout.to_string()])
            )?
        ]));
    }
    calls.push(json!([USDC, "0", approve(PM, reserve)?]));
    let batch = call("executeBatch((address,uint256,bytes)[])", json!([calls]))?;
    if !op["callData"]
        .as_str()
        .is_some_and(|s| s.eq_ignore_ascii_case(&batch))
    {
        return Err("batch differs from the reviewed payment");
    }
    let calldata = hex_dec(&batch[2..]).ok_or("invalid calldata")?;
    let mut pm = validate::eth(PM)?.to_vec();
    for k in ["paymasterVerificationGasLimit", "paymasterPostOpGasLimit"] {
        pm.extend(quantity(&op, k)?.to_be_bytes());
    }
    pm.extend(
        hex_dec(
            op["paymasterData"]
                .as_str()
                .and_then(|s| s.strip_prefix("0x"))
                .ok_or("missing paymaster data")?,
        )
        .ok_or("bad paymaster data")?,
    );
    let delegate = match op.get("factory").and_then(Value::as_str) {
        None if op.get("eip7702Auth").is_none() && op.get("factoryData").is_none() => None,
        Some("0x7702") if op["factoryData"] == "0x" => {
            verify_delegation(&op["eip7702Auth"], q, account)?;
            Some(validate::eth(DELEGATE)?)
        }
        _ => return Err("unsupported factory"),
    };
    if q["requiresDelegation"] != delegate.is_some()
        || op["maxFeePerGas"] != q["maxFeePerGas"]
        || op["maxPriorityFeePerGas"] != q["maxPriorityFeePerGas"]
    {
        return Err("delegation or fee terms changed");
    }
    let u = UserOperation {
        chain_id: 84532u64.try_into().unwrap(),
        sender: account,
        nonce: word(quantity(&op, "nonce")?),
        marker_delegate: delegate,
        call_data: &calldata,
        verification_gas: quantity(&op, "verificationGasLimit")?,
        call_gas: quantity(&op, "callGasLimit")?,
        pre_verification_gas: word(quantity(&op, "preVerificationGas")?),
        priority_fee: quantity(&op, "maxPriorityFeePerGas")?,
        max_fee: quantity(&op, "maxFeePerGas")?,
        paymaster_and_data: &pm,
    };
    let digest = format!("0x{}", hex_enc(u.digest()));
    if build["userOpHash"] != digest {
        return Err("hash differs from simulated operation");
    }
    let destination = if bridge.is_some() {
        format!(
            "Optimism Sepolia (11155420) via Circle. Maximum bridge spend {bridge_cap} micro-USDC"
        )
    } else {
        "Base Sepolia (84532)".to_owned()
    };
    let summary=format!("Base Sepolia (84532), Simple7702Account payment\nSender: {sender}\nRecipient: {recipient}\nDestination: {destination}\nNative ETH to wrap: {wrap} wei\nExact payout: {payout} micro-USDC\nMaximum WETH spend: {spend} wei\nPimlico gas approval: {reserve} micro-USDC\nUserOperation hash: {digest}");
    if inspect {
        super::out("ok", json!({"userOpHash":digest,"summary":summary}));
    }
    let key = super::delegation::read_key(account).ok_or("sender key missing")?;
    if !blocktools_tty::confirm(&summary) {
        super::out("aborted", json!({}));
    }
    if expiry <= now() {
        return Err("expired payment");
    }
    super::out(
        "ok",
        json!({"signature":format!("0x{}",hex_enc(u.sign(&key)?))}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn circle_burn_binds_destination_recipient_and_bridge_cap() {
        let recipient = USDC;
        let padded = format!("0x{:024}{}", 0, hex_enc(validate::eth(recipient).unwrap()));
        let data = call(
            BURN,
            json!([
                "1",
                "2",
                padded,
                USDC,
                format!("0x{:064}", 0),
                ["0x1234", WETH]
            ]),
        )
        .unwrap();
        let hash = blocktools_evm::api::keccak256_hex(&data).unwrap();
        let mut quote = json!({"burnData":data, "burnDataHash":hash, "destinationChainId":11155420, "maxInputMicroUsdc":"9"});
        assert!(checked_burn(&quote, WETH, recipient, 1, 9, &hash).is_ok());
        assert!(checked_burn(&quote, WETH, recipient, 1, 10, &hash).is_err());
        assert!(checked_burn(&quote, WETH, ROUTER, 1, 9, &hash).is_err());
        quote["destinationChainId"] = json!(10);
        assert!(checked_burn(&quote, WETH, recipient, 1, 9, &hash).is_err());
    }
    #[test]
    fn checks_the_settled_sepolia_delegation_against_the_reviewed_sender() {
        let sender = validate::eth("0x18eE1D19Ab2030e5dd6f52c6be152ffeA0d08c0D").unwrap();
        let quote = json!({"authorizationNonce":"0"});
        let auth = json!({
            "address":DELEGATE,"chainId":"0x14a34","nonce":"0x0","yParity":"0x1",
            "r":"0xe8064703a36cfb1fe5e70ddcd66e051dfaaea10e1673e63a2e12f523a7f55972",
            "s":"0x5891822a135f294de01e40168136ef5a0834a7029c06078bed98628d0e0b2ece"
        });
        assert!(verify_delegation(&auth, &quote, sender).is_ok());
        for (field, replacement) in [
            ("address", WETH),
            ("nonce", "0x1"),
            ("chainId", "0x1"),
            ("yParity", "0x0"),
        ] {
            let mut changed = auth.clone();
            changed[field] = json!(replacement);
            assert!(verify_delegation(&changed, &quote, sender).is_err());
        }
        assert!(verify_delegation(&auth, &quote, [0x11; 20]).is_err());
    }
}
