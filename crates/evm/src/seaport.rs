//! Seaport order-signature checks for EIP-712 typed data (typed-data-verify, the wasm `evmTypedDataVerify`, and
//! rpc --allow-wallet-sign). A Seaport order has no approve and no spender: an order that lists the signer's NFTs or
//! tokens for (almost) nothing is filled by a drainer through the conduit approval the signer already gave. What
//! matters is what comes back to the offerer, so that is what is checked.
//!
//! Source of the shapes and deployments (github.com/ProjectOpenSea/seaport, main at 7f966fe, tags 1.5 and 1.6):
//!   eip-712-types/order.js, bulkOrder.js, domain.js       the typed-data definitions used here
//!   reference/lib/ReferenceConsiderationBase.sol           the same type strings (OfferItem, ConsiderationItem,
//!                                                          OrderComponents, BulkOrder(OrderComponents[2]x7 tree))
//!   seaport-js src/utils/eip712/bulk-orders.ts (main e635c29): BulkOrder `tree` type is `OrderComponents` + `[2]`
//!   repeated `height` times, height = max(ceil(log2(order count)), 1); seaport-core src/lib/Verifiers.sol (main)
//!   accepts bulk proofs of 1..=24 siblings ("(1 <= y <= 24)"), and seaport-types TypehashDirectory.sol holds the 24
//!   BulkOrder typehashes. So heights 1..=24 are recognised, each as its exact type string; any other is not checkable.
//!   contracts/Seaport.sol `_nameString` = "Seaport"; ConsiderationConstants.sol information_versionWithLength
//!   0x03312e35 ("1.5", tag 1.5) and 0x03312e36 ("1.6", seaport-types main)
//!   README.md deployments: Seaport 1.5 0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC,
//!                          Seaport 1.6 0x0000000000000068F116a894984e2DB1123eB395 (same address on every listed chain)
//!   seaport-types ConsiderationEnums.sol: ItemType NATIVE 0, ERC20 1, ERC721 2, ERC1155 3, ERC721_WITH_CRITERIA 4,
//!   ERC1155_WITH_CRITERIA 5; OrderType FULL_OPEN 0, PARTIAL_OPEN 1, FULL_RESTRICTED 2, PARTIAL_RESTRICTED 3, CONTRACT 4
//!
//! Recognised: primaryType OrderComponents or BulkOrder (every leaf of the tree is checked) with exactly those
//! field sets. Typed data is treated as Seaport when primaryType is OrderComponents / BulkOrder or domain.name is
//! "Seaport". Statuses (fail closed, whatever the signature verdict; signer/chain/verifying-contract mismatches and
//! permit findings win):
//!   seaport_not_checkable        Seaport-looking, but not the exact shape, a value does not parse, or an item type > 5
//!   seaport_unknown_deployment   domain name/version/verifyingContract is not Seaport 1.5 / 1.6 at its canonical address
//!   seaport_no_consideration     an order offers something and the offerer receives nothing (no item to the offerer
//!                                with a nonzero conservative amount, NFT items included)
//!   seaport_dust_consideration   with expect_min_consideration: no listed currency reaches its floor
//! Amounts are conservative: what the offerer receives is min(startAmount, endAmount), what it gives is max.
//! `expect_min_consideration` ("SPEC"): comma-separated floors in smallest units, `N` or `native:N` for the native
//! currency (itemType 0), `0xTOKEN:N` for an ERC20 (itemType 1) token. Per currency, the offerer's received amounts
//! are summed; the order passes when at least one listed currency reaches its floor. Currencies not listed, and
//! NFTs, do not count toward a floor (an NFT-for-NFT swap passes only without a floor). Errors:
//! expect_min_consideration_must_be_string, _empty, _bad_amount, _bad_token, _duplicate_token.
//! Advisory `seaport_findings` (no status change): zone_set, zone_hash_set, conduit_key_set, restricted_order_type,
//! contract_order_type, criteria_item, nft_consideration, far_future_end_time (endTime - startTime > 366 days or
//! endTime >= 2^40), consideration_to_others (fees/royalties, shown in consideration_to_others).
use crate::{checksum_address, hex, parse_address, unhex};
use serde_json::{json, Map, Value};

pub const SEAPORT_1_5: &str = "0x00000000000000adc04c56bf30ac9d3c0aaf14dc";
pub const SEAPORT_1_6: &str = "0x0000000000000068f116a894984e2db1123eb395";
const OFFER_ITEM: &[(&str, &str)] = &[("itemType", "uint8"), ("token", "address"), ("identifierOrCriteria", "uint256"), ("startAmount", "uint256"), ("endAmount", "uint256")];
const CONS_ITEM: &[(&str, &str)] = &[("itemType", "uint8"), ("token", "address"), ("identifierOrCriteria", "uint256"), ("startAmount", "uint256"), ("endAmount", "uint256"), ("recipient", "address")];
const ORDER: &[(&str, &str)] = &[("offerer", "address"), ("zone", "address"), ("offer", "OfferItem[]"), ("consideration", "ConsiderationItem[]"), ("orderType", "uint8"),
    ("startTime", "uint256"), ("endTime", "uint256"), ("zoneHash", "bytes32"), ("salt", "uint256"), ("conduitKey", "bytes32"), ("counter", "uint256")];
/// Official BulkOrder tree heights (seaport-core Verifiers.sol: 1 <= height <= 24).
pub const BULK_MIN_HEIGHT: usize = 1;
pub const BULK_MAX_HEIGHT: usize = 24;
/// The exact `tree` type string for a BulkOrder of height `h`.
pub fn bulk_tree_type(h: usize) -> String { format!("OrderComponents{}", "[2]".repeat(h)) }
/// The BulkOrder height declared by `types`, when BulkOrder is exactly {tree: OrderComponents[2]^h} for an official h.
fn bulk_height(types: &serde_json::Map<String, Value>) -> Option<usize> {
    (BULK_MIN_HEIGHT..=BULK_MAX_HEIGHT).find(|&h| is_shape(types, "BulkOrder", &[("tree", bulk_tree_type(h).as_str())]))
}
const ITEM: &[&str] = &["native", "erc20", "erc721", "erc1155", "erc721_with_criteria", "erc1155_with_criteria"];
const ORDER_TYPE: &[&str] = &["full_open", "partial_open", "full_restricted", "partial_restricted", "contract"];
const YEAR_PLUS: u128 = 366 * 86400;
const FAR_END: u128 = 1 << 40;

/// Statuses this module sets; all are exit-1 / refusal statuses.
pub const FAIL_STATUSES: &[&str] = &["seaport_not_checkable", "seaport_unknown_deployment", "seaport_no_consideration", "seaport_dust_consideration"];

/// Floors from expect_min_consideration: (None = native | Some(lowercase 0x token), decimal amount).
#[derive(Default, Debug, Clone, PartialEq)]
pub struct SeaportExpect { pub floors: Vec<(Option<String>, String)> }

fn dec_norm(s: &str) -> Option<String> {
    if s.is_empty() || s.len() > 100 || !s.bytes().all(|b| b.is_ascii_digit()) { return None }
    let t = s.trim_start_matches('0');
    Some(if t.is_empty() { "0".into() } else { t.into() })
}
fn dec_ge(a: &str, b: &str) -> bool { a.len() > b.len() || (a.len() == b.len() && a >= b) }
fn dec_min(a: String, b: String) -> String { if dec_ge(&a, &b) { b } else { a } }
fn dec_max(a: String, b: String) -> String { if dec_ge(&a, &b) { a } else { b } }
fn dec_add(a: &str, b: &str) -> String {
    let (x, y): (Vec<u8>, Vec<u8>) = (a.bytes().rev().collect(), b.bytes().rev().collect());
    let (mut out, mut c) = (vec![], 0u8);
    for i in 0..x.len().max(y.len()) {
        let s = x.get(i).map_or(0, |d| d - b'0') + y.get(i).map_or(0, |d| d - b'0') + c;
        out.push(b'0' + s % 10); c = s / 10;
    }
    if c > 0 { out.push(b'0' + c) }
    out.reverse();
    String::from_utf8(out).ok().and_then(|s| dec_norm(&s)).unwrap_or_else(|| "0".into())
}

impl SeaportExpect {
    pub fn asserted(&self) -> bool { !self.floors.is_empty() }
    /// Parses SPEC (see the module doc).
    pub fn new(spec: Option<&str>) -> Result<Self, String> {
        let Some(spec) = spec else { return Ok(Self::default()) };
        if spec.trim().is_empty() { return Err("expect_min_consideration_empty".into()) }
        let mut floors: Vec<(Option<String>, String)> = vec![];
        for part in spec.split(',') {
            let part = part.trim();
            let (tok, amt) = match part.rsplit_once(':') { Some((t, a)) => (Some(t.trim()), a.trim()), None => (None, part) };
            let tok = match tok {
                None | Some("native") => None,
                Some(t) => Some(parse_address(t).map(|a| hex(&a)).map_err(|_| "expect_min_consideration_bad_token".to_string())?),
            };
            let amt = dec_norm(amt).ok_or_else(|| "expect_min_consideration_bad_amount".to_string())?;
            if floors.iter().any(|(t, _)| *t == tok) { return Err("expect_min_consideration_duplicate_token".into()) }
            floors.push((tok, amt));
        }
        Ok(Self { floors })
    }
    /// From the wasm options object (`expect_min_consideration`: string).
    pub fn from_json(opt: &Value) -> Result<Self, String> {
        match opt.get("expect_min_consideration") { None => Ok(Self::default()), Some(Value::String(s)) => Self::new(Some(s)), _ => Err("expect_min_consideration_must_be_string".into()) }
    }
}

fn field_set<'a>(types: &'a Map<String, Value>, t: &str) -> Option<Vec<(&'a str, &'a str)>> {
    let mut v: Vec<(&str, &str)> = types.get(t)?.as_array()?.iter().map(|f| Some((f.get("name")?.as_str()?, f.get("type")?.as_str()?))).collect::<Option<_>>()?;
    v.sort(); Some(v)
}
fn is_shape(types: &Map<String, Value>, t: &str, want: &[(&str, &str)]) -> bool { let mut w = want.to_vec(); w.sort(); field_set(types, t).is_some_and(|f| f == w) }
fn uint(v: &Value, ty: &str) -> Option<String> {
    let e = crate::abi::encode(&[crate::abi::Param::new(crate::abi::Ty::parse(ty).ok()?)], std::slice::from_ref(v)).ok()?;
    let mut w = [0u8; 32]; w.copy_from_slice(&e[..32]); Some(crate::u256::to_dec(&w))
}
fn addr(v: &Value) -> Option<[u8; 20]> { let b = unhex(v.as_str()?.trim()).ok()?; (b.len() == 20).then(|| { let mut a = [0u8; 20]; a.copy_from_slice(&b); a }) }
fn b32_nonzero(v: &Value) -> Option<bool> { let b = unhex(v.as_str()?.trim()).ok()?; (b.len() == 32).then(|| b.iter().any(|x| *x != 0)) }

/// True when `td` claims to be a Seaport order (primaryType OrderComponents / BulkOrder, or domain.name "Seaport").
pub fn looks_like(td: &Value) -> bool {
    matches!(td.get("primaryType").and_then(Value::as_str), Some("OrderComponents" | "BulkOrder"))
        || td.get("domain").and_then(|d| d.get("name")).and_then(Value::as_str) == Some("Seaport")
}

struct Item { kind: u8, token: [u8; 20], id: String, give: String, get: String, recipient: Option<[u8; 20]> }
fn item(v: &Value, cons: bool) -> Option<Item> {
    let kind: u8 = uint(v.get("itemType")?, "uint8")?.parse().ok()?;
    let (s, e) = (uint(v.get("startAmount")?, "uint256")?, uint(v.get("endAmount")?, "uint256")?);
    Some(Item { kind, token: addr(v.get("token")?)?, id: uint(v.get("identifierOrCriteria")?, "uint256")?, give: dec_max(s.clone(), e.clone()), get: dec_min(s, e),
        recipient: if cons { Some(addr(v.get("recipient")?)?) } else { None } })
}
fn item_json(i: &Item, amount: &str, with_recipient: bool) -> Value {
    let mut o = json!({"item_type": ITEM.get(i.kind as usize).copied().unwrap_or("unknown"), "token": checksum_address(&i.token), "identifier_or_criteria": i.id, "amount": amount});
    if with_recipient { if let Some(r) = i.recipient { o["recipient"] = json!(checksum_address(&r)) } }
    o
}

type OrderResult = (Value, Option<&'static str>, Vec<&'static str>);
/// One OrderComponents value -> (summary, fail status or None, findings); None when a value does not parse.
fn order(m: &Value, e: &SeaportExpect) -> Option<OrderResult> {
    let offerer = addr(m.get("offerer")?)?;
    let zone = addr(m.get("zone")?)?;
    let ot: u8 = uint(m.get("orderType")?, "uint8")?.parse().ok()?;
    let (st, et) = (uint(m.get("startTime")?, "uint256")?, uint(m.get("endTime")?, "uint256")?);
    let (zh, ck) = (b32_nonzero(m.get("zoneHash")?)?, b32_nonzero(m.get("conduitKey")?)?);
    uint(m.get("salt")?, "uint256")?; uint(m.get("counter")?, "uint256")?;
    let offer: Vec<Item> = m.get("offer")?.as_array()?.iter().map(|v| item(v, false)).collect::<Option<_>>()?;
    let cons: Vec<Item> = m.get("consideration")?.as_array()?.iter().map(|v| item(v, true)).collect::<Option<_>>()?;
    if offer.iter().chain(&cons).any(|i| i.kind > 5) || ot > 4 { return None }
    let (to_me, to_others): (Vec<&Item>, Vec<&Item>) = cons.iter().partition(|i| i.recipient == Some(offerer));
    let got: Vec<&Item> = to_me.iter().copied().filter(|i| i.get != "0").collect();
    let mut f: Vec<&'static str> = vec![];
    if zone != [0; 20] { f.push("zone_set") }
    if zh { f.push("zone_hash_set") }
    if ck { f.push("conduit_key_set") }
    if ot == 2 || ot == 3 { f.push("restricted_order_type") }
    if ot == 4 { f.push("contract_order_type") }
    if offer.iter().chain(&cons).any(|i| i.kind >= 4) { f.push("criteria_item") }
    if got.iter().any(|i| i.kind >= 2) { f.push("nft_consideration") }
    let (s128, e128) = (st.parse::<u128>().unwrap_or(u128::MAX), et.parse::<u128>().unwrap_or(u128::MAX));
    if e128 >= FAR_END || e128.saturating_sub(s128) > YEAR_PLUS { f.push("far_future_end_time") }
    if !to_others.is_empty() { f.push("consideration_to_others") }
    // per-currency sums of what the offerer receives (native / ERC20 only)
    let mut sums: Vec<(Option<String>, String)> = vec![];
    for i in got.iter().filter(|i| i.kind <= 1) {
        let k = if i.kind == 0 { None } else { Some(hex(&i.token)) };
        match sums.iter_mut().find(|(t, _)| *t == k) { Some((_, s)) => *s = dec_add(s, &i.get), None => sums.push((k, i.get.clone())) }
    }
    let gives = offer.iter().any(|i| i.give != "0");
    let status = if !gives { None } else if got.is_empty() { Some("seaport_no_consideration") }
        else if e.asserted() && !e.floors.iter().any(|(t, min)| sums.iter().any(|(k, s)| k == t && dec_ge(s, min))) { Some("seaport_dust_consideration") }
        else { None };
    let cur = |t: &Option<String>| t.as_deref().and_then(|t| addr(&json!(t))).map_or("native".to_string(), |a| checksum_address(&a));
    let s = json!({
        "offerer": checksum_address(&offerer), "zone": checksum_address(&zone), "zone_hash_set": zh, "conduit_key": m["conduitKey"], "conduit_key_set": ck,
        "order_type": ORDER_TYPE[ot as usize], "start_time": st, "end_time": et,
        "offer": offer.iter().map(|i| item_json(i, &i.give, false)).collect::<Vec<_>>(),
        "consideration_to_offerer": to_me.iter().map(|i| item_json(i, &i.get, false)).collect::<Vec<_>>(),
        "consideration_to_others": to_others.iter().map(|i| item_json(i, &i.give, true)).collect::<Vec<_>>(),
        "received_by_currency": sums.iter().map(|(t, s)| json!({"currency": cur(t), "amount": s})).collect::<Vec<_>>(),
    });
    Some((s, status, f))
}

fn leaves<'a>(v: &'a Value, depth: usize, h: usize, out: &mut Vec<&'a Value>) -> Option<()> {
    if depth == h { out.push(v); return Some(()) }
    let a = v.as_array()?;
    if a.len() != 2 { return None }
    for x in a { leaves(x, depth + 1, h, out)? }
    Some(())
}

/// The Seaport check on its own: None when `td` does not look like Seaport; else {status (null = pass), seaport, findings}.
pub fn check(td: &Value, e: &SeaportExpect) -> Option<Value> {
    if !looks_like(td) { return None }
    let nc = |why: &str| Some(json!({"status": "seaport_not_checkable", "seaport": {"reason": why}, "findings": []}));
    let (Some(types), Some(p)) = (td.get("types").and_then(Value::as_object), td.get("primaryType").and_then(Value::as_str)) else { return nc("no_types") };
    let shapes = is_shape(types, "OrderComponents", ORDER) && is_shape(types, "OfferItem", OFFER_ITEM) && is_shape(types, "ConsiderationItem", CONS_ITEM);
    let Some(m) = td.get("message") else { return nc("no_message") };
    let orders: Vec<&Value> = match p {
        "OrderComponents" if shapes => vec![m],
        "BulkOrder" if shapes && bulk_height(types).is_some() => {
            let h = bulk_height(types).unwrap_or(0);
            let mut o = vec![];
            if m.get("tree").and_then(|t| leaves(t, 0, h, &mut o)).is_none() { return nc("bad_bulk_tree") }
            o
        }
        _ => return nc("not_a_seaport_order_shape"),
    };
    let d = td.get("domain").cloned().unwrap_or(Value::Null);
    let ver = d.get("version").and_then(Value::as_str);
    let vc = d.get("verifyingContract").and_then(addr).map(|a| hex(&a));
    let canon = match ver { Some("1.5") => Some(SEAPORT_1_5), Some("1.6") => Some(SEAPORT_1_6), _ => None };
    let deployment_ok = d.get("name").and_then(Value::as_str) == Some("Seaport") && canon.is_some() && vc.as_deref() == canon;
    let (mut sums, mut status, mut findings): (Vec<Value>, Option<&str>, Vec<&str>) = (vec![], None, vec![]);
    for o in orders {
        let Some((s, st, f)) = order(o, e) else { return nc("unparseable_order_value") };
        if status.is_none() { status = st }
        for x in f { if !findings.contains(&x) { findings.push(x) } }
        sums.push(s);
    }
    if !deployment_ok { status = Some("seaport_unknown_deployment") }
    let mut sp = json!({"kind": if p == "BulkOrder" { "bulk_order" } else { "order" }, "version": ver, "verifying_contract": d.get("verifyingContract"), "canonical_deployment": deployment_ok});
    if p == "BulkOrder" { sp["orders"] = json!(sums) } else if let Some(Value::Object(o)) = sums.pop() { for (k, v) in o { sp[k] = v } }
    if e.asserted() { sp["expect_min_consideration"] = json!(e.floors.iter().map(|(t, m)| json!({"currency": t.as_deref().unwrap_or("native"), "min": m})).collect::<Vec<_>>()) }
    Some(json!({"status": status, "seaport": sp, "findings": findings}))
}

/// Adds `seaport` / `seaport_findings` to a verify result and sets a fail status (unless a signer / chain /
/// verifying-contract mismatch or a permit finding already set one). With expect_min_consideration on typed data
/// that is not a Seaport order: seaport_not_checkable.
pub fn apply(o: &mut Value, td: &Value, e: &SeaportExpect) {
    let keep = crate::permit::FAIL_STATUSES.contains(&o["status"].as_str().unwrap_or(""));
    match check(td, e) {
        Some(c) => {
            o["seaport"] = c["seaport"].clone();
            if c["findings"].as_array().is_some_and(|a| !a.is_empty()) { o["seaport_findings"] = c["findings"].clone() }
            if let Some(s) = c["status"].as_str() { if !keep { o["status"] = json!(s) } }
        }
        None => if e.asserted() && !keep { o["status"] = json!("seaport_not_checkable"); o["seaport"] = json!({"reason": "not_a_seaport_order"}) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eip712;
    const ME: &str = "0x2222222222222222222222222222222222222222";
    const OS_FEE: &str = "0x0000a26b00c1f0df003000390027140000faa719";
    const NFT: &str = "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d";
    const WETH: &str = "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2";
    const DRAINER: &str = "0x1111111111111111111111111111111111111111";
    const Z32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
    const OS_CONDUIT: &str = "0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000";
    fn types() -> Value {
        let f = |v: &[(&str, &str)]| json!(v.iter().map(|(n, t)| json!({"name": n, "type": t})).collect::<Vec<_>>());
        json!({"EIP712Domain": f(&[("name","string"),("version","string"),("chainId","uint256"),("verifyingContract","address")]),
            "OrderComponents": f(ORDER), "OfferItem": f(OFFER_ITEM), "ConsiderationItem": f(CONS_ITEM)})
    }
    fn nft_offer() -> Value { json!([{"itemType":2,"token":NFT,"identifierOrCriteria":"1234","startAmount":"1","endAmount":"1"}]) }
    fn eth(amount: &str, to: &str) -> Value { json!({"itemType":0,"token":"0x0000000000000000000000000000000000000000","identifierOrCriteria":"0","startAmount":amount,"endAmount":amount,"recipient":to}) }
    fn msg(offer: Value, cons: Value) -> Value {
        json!({"offerer":ME,"zone":"0x0000000000000000000000000000000000000000","offer":offer,"consideration":cons,"orderType":0,"startTime":"1730000000","endTime":"1732600000",
            "zoneHash":Z32,"salt":"24446860302761739304752683030156737591518664810215442929818227897836383814680","conduitKey":OS_CONDUIT,"counter":"0"})
    }
    fn td(ver: &str, vc: &str, m: Value) -> Value {
        json!({"types":types(),"primaryType":"OrderComponents","domain":{"name":"Seaport","version":ver,"chainId":1,"verifyingContract":vc},"message":m})
    }
    fn run(t: &Value, spec: Option<&str>) -> Value { let mut o = eip712::verify(t, None, None).unwrap(); apply(&mut o, t, &SeaportExpect::new(spec).unwrap()); o }
    fn listing() -> Value { msg(nft_offer(), json!([eth("975000000000000000", ME), eth("25000000000000000", OS_FEE)])) }

    #[test]
    fn legit_listing_passes_and_is_summarized() {
        for (v, a) in [("1.6", SEAPORT_1_6), ("1.5", SEAPORT_1_5)] {
            let o = run(&td(v, a, listing()), None);
            assert_eq!(o["status"], "ok", "{o}");
            let s = &o["seaport"];
            assert_eq!(s["kind"], "order"); assert_eq!(s["canonical_deployment"], true); assert_eq!(s["version"], v);
            assert_eq!(s["offer"][0]["item_type"], "erc721"); assert_eq!(s["consideration_to_offerer"][0]["amount"], "975000000000000000");
            assert_eq!(s["consideration_to_others"][0]["amount"], "25000000000000000");
            assert_eq!(s["received_by_currency"][0], json!({"currency":"native","amount":"975000000000000000"}));
            assert_eq!(o["seaport_findings"], json!(["conduit_key_set", "consideration_to_others"]));
        }
        assert_eq!(run(&td("1.6", SEAPORT_1_6, listing()), Some("native:900000000000000000"))["status"], "ok");
    }
    #[test]
    fn zero_consideration_drainer_fails_closed() {
        // the drainer order: the signer's NFT for nothing, the only consideration goes to the drainer
        let o = run(&td("1.6", SEAPORT_1_6, msg(nft_offer(), json!([eth("1", DRAINER)]))), None);
        assert_eq!(o["status"], "seaport_no_consideration", "{o}");
        assert_eq!(o["seaport"]["consideration_to_offerer"], json!([]));
        assert_eq!(run(&td("1.6", SEAPORT_1_6, msg(nft_offer(), json!([]))), None)["status"], "seaport_no_consideration");
        assert_eq!(run(&td("1.6", SEAPORT_1_6, msg(nft_offer(), json!([eth("0", ME)]))), None)["status"], "seaport_no_consideration");
        // descending amounts: the conservative (min) amount is 0
        let mut c = eth("1000", ME); c["endAmount"] = json!("0");
        assert_eq!(run(&td("1.6", SEAPORT_1_6, msg(nft_offer(), json!([c]))), None)["status"], "seaport_no_consideration");
    }
    #[test]
    fn signed_drainer_order_valid_signature_still_fails() {
        use secp256k1::{Message, Secp256k1, SecretKey};
        let t = td("1.6", SEAPORT_1_6, msg(nft_offer(), json!([eth("1", DRAINER)])));
        let (_, _, d) = eip712::digest(&t).unwrap();
        let sk = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let (rid, rs) = Secp256k1::new().sign_ecdsa_recoverable(&Message::from_digest(d), &sk).serialize_compact();
        let mut sig = rs.to_vec(); sig.push(27 + rid.to_i32() as u8);
        let rec = eip712::verify(&t, Some(&hex(&sig)), None).unwrap()["recovered"].as_str().unwrap().to_string();
        let mut o = eip712::verify(&t, Some(&hex(&sig)), Some(&rec)).unwrap();
        assert_eq!(o["status"], "valid");
        apply(&mut o, &t, &SeaportExpect::default());
        assert_eq!(o["status"], "seaport_no_consideration");
        let mut o = eip712::verify(&t, Some(&hex(&sig)), Some(DRAINER)).unwrap();
        apply(&mut o, &t, &SeaportExpect::default());
        assert_eq!(o["status"], "signer_mismatch"); assert!(o.get("seaport").is_some());
    }
    #[test]
    fn dust_floor_native_and_erc20() {
        let t = td("1.6", SEAPORT_1_6, msg(nft_offer(), json!([eth("1000", ME), eth("1000", ME)])));
        assert_eq!(run(&t, None)["status"], "ok"); // nonzero passes without a floor
        assert_eq!(run(&t, Some("2000"))["status"], "ok"); // summed per currency
        assert_eq!(run(&t, Some("2001"))["status"], "seaport_dust_consideration");
        let weth = json!({"itemType":1,"token":WETH,"identifierOrCriteria":"0","startAmount":"5000000000000000000","endAmount":"5000000000000000000","recipient":ME});
        let t = td("1.5", SEAPORT_1_5, msg(nft_offer(), json!([weth])));
        let o = run(&t, Some(&format!("{}:1000000000000000000", WETH.to_uppercase().replace("0X", "0x"))));
        assert_eq!(o["status"], "ok", "{o}");
        assert_eq!(run(&t, Some("native:1"))["status"], "seaport_dust_consideration"); // WETH does not count for native
        assert_eq!(run(&t, Some(&format!("native:1,{WETH}:5000000000000000000")))["status"], "ok"); // any listed currency
    }
    #[test]
    fn nft_for_nft_swap() {
        let c = json!([{"itemType":2,"token":NFT,"identifierOrCriteria":"99","startAmount":"1","endAmount":"1","recipient":ME}]);
        let o = run(&td("1.6", SEAPORT_1_6, msg(nft_offer(), c.clone())), None);
        assert_eq!(o["status"], "ok", "{o}"); assert!(o["seaport_findings"].as_array().unwrap().contains(&json!("nft_consideration")));
        assert_eq!(run(&td("1.6", SEAPORT_1_6, msg(nft_offer(), c)), Some("1"))["status"], "seaport_dust_consideration");
        let z = json!([{"itemType":3,"token":NFT,"identifierOrCriteria":"99","startAmount":"0","endAmount":"0","recipient":ME}]);
        assert_eq!(run(&td("1.6", SEAPORT_1_6, msg(nft_offer(), z)), None)["status"], "seaport_no_consideration");
    }
    #[test]
    fn deployments() {
        assert_eq!(run(&td("1.4", SEAPORT_1_6, listing()), None)["status"], "seaport_unknown_deployment");
        assert_eq!(run(&td("1.6", SEAPORT_1_5, listing()), None)["status"], "seaport_unknown_deployment");
        assert_eq!(run(&td("1.6", DRAINER, listing()), None)["status"], "seaport_unknown_deployment");
        let mut t = td("1.6", SEAPORT_1_6, listing()); t["domain"]["name"] = json!("Seaport Clone");
        assert_eq!(run(&t, None)["status"], "seaport_unknown_deployment");
    }
    #[test]
    fn findings_and_bulk() {
        let mut m = listing(); m["zone"] = json!(DRAINER); m["orderType"] = json!(2); m["endTime"] = json!("99999999999999");
        m["offer"][0]["itemType"] = json!(4);
        let o = run(&td("1.6", SEAPORT_1_6, m), None);
        assert_eq!(o["status"], "ok");
        for f in ["zone_set", "restricted_order_type", "criteria_item", "far_future_end_time"] { assert!(o["seaport_findings"].as_array().unwrap().contains(&json!(f)), "{f}") }
    }
    fn bulk(h: usize, at: usize, x: &Value) -> Value {
        let mut ty = types(); ty["BulkOrder"] = json!([{"name":"tree","type":bulk_tree_type(h)}]);
        let pad = msg(json!([]), json!([]));
        fn tree(d: usize, h: usize, n: &mut usize, at: usize, x: &Value, pad: &Value) -> Value {
            if d == h { *n += 1; return if *n == at { x.clone() } else { pad.clone() } }
            json!([tree(d + 1, h, n, at, x, pad), tree(d + 1, h, n, at, x, pad)])
        }
        json!({"types":ty,"primaryType":"BulkOrder","domain":{"name":"Seaport","version":"1.6","chainId":1,"verifyingContract":SEAPORT_1_6},"message":{"tree":tree(0, h, &mut 0, at, x, &pad)}})
    }
    #[test]
    fn bulk_every_official_height() {
        // heights 1, 2, 3, 7, 10 built in full: one real leaf + padding passes, one drainer leaf fails the whole signature
        let drainer = msg(nft_offer(), json!([eth("1", DRAINER)]));
        for h in [1usize, 2, 3, 7, 10] {
            let n = 1usize << h;
            let o = run(&bulk(h, n, &listing()), None);
            assert_eq!(o["status"], "ok", "h={h} {}", o["status"]); assert_eq!(o["seaport"]["orders"].as_array().unwrap().len(), n);
            assert_eq!(o["seaport"]["kind"], "bulk_order");
            assert_eq!(run(&bulk(h, 1, &drainer), None)["status"], "seaport_no_consideration", "h={h}");
            // padding-only tree: nothing is offered, so nothing to fail on (padding leaves are skipped)
            assert_eq!(run(&bulk(h, 0, &listing()), None)["status"], "ok", "h={h}");
            // tree depth must match the declared height exactly
            let mut t = bulk(h, 1, &listing()); t["message"]["tree"] = json!([t["message"]["tree"].clone(), t["message"]["tree"].clone()]);
            assert_eq!(check(&t, &SeaportExpect::default()).unwrap()["status"], "seaport_not_checkable", "h={h}");
            let mut t = bulk(h, 1, &listing()); t["message"]["tree"] = json!([t["message"]["tree"][0].clone()]);
            assert_eq!(check(&t, &SeaportExpect::default()).unwrap()["seaport"]["reason"], "bad_bulk_tree", "h={h}");
        }
        // every official height 1..=24 is recognised by its exact type string (24 = 2^24 leaves: a full tree is far too
        // large to build in a test, so the max is checked at the type level and with a wrong-depth tree)
        let mut ty = types();
        for h in BULK_MIN_HEIGHT..=BULK_MAX_HEIGHT { ty["BulkOrder"] = json!([{"name":"tree","type":bulk_tree_type(h)}]); assert_eq!(bulk_height(ty.as_object().unwrap()), Some(h)) }
        let mut t = bulk(1, 1, &listing()); t["types"]["BulkOrder"][0]["type"] = json!(bulk_tree_type(24));
        assert_eq!(check(&t, &SeaportExpect::default()).unwrap()["seaport"]["reason"], "bad_bulk_tree");
        // unofficial heights and odd shapes stay fail-closed
        for bad in [bulk_tree_type(0), bulk_tree_type(25), "OrderComponents[3]".into(), "OrderComponents[2][]".into(), "OrderComponents[]".into()] {
            let mut t = bulk(1, 1, &listing()); t["types"]["BulkOrder"][0]["type"] = json!(bad);
            assert_eq!(check(&t, &SeaportExpect::default()).unwrap()["status"], "seaport_not_checkable", "{bad}");
        }
    }
    #[test]
    fn malformed_and_not_seaport() {
        let mut t = td("1.6", SEAPORT_1_6, listing());
        t["types"]["OfferItem"].as_array_mut().unwrap().pop();
        assert_eq!(check(&t, &SeaportExpect::default()).unwrap()["status"], "seaport_not_checkable");
        let mut t = td("1.6", SEAPORT_1_6, listing()); t["message"]["offer"][0]["itemType"] = json!(6);
        assert_eq!(check(&t, &SeaportExpect::default()).unwrap()["seaport"]["reason"], "unparseable_order_value");
        let mut t = td("1.6", SEAPORT_1_6, listing()); t["primaryType"] = json!("OfferItem");
        assert_eq!(check(&t, &SeaportExpect::default()).unwrap()["status"], "seaport_not_checkable");
        let mail = json!({"types":{"EIP712Domain":[{"name":"name","type":"string"}],"Mail":[{"name":"to","type":"address"}]},"primaryType":"Mail","domain":{"name":"x"},"message":{"to":ME}});
        assert!(check(&mail, &SeaportExpect::default()).is_none());
        assert_eq!(run(&mail, None)["status"], "ok");
        assert_eq!(run(&mail, Some("1"))["status"], "seaport_not_checkable");
    }
    #[test]
    fn bad_options() {
        for (s, err) in [("", "expect_min_consideration_empty"), ("1e18", "expect_min_consideration_bad_amount"), ("native:-1", "expect_min_consideration_bad_amount"),
            ("0x12:5", "expect_min_consideration_bad_token"), ("1,native:2", "expect_min_consideration_duplicate_token"), ("weth:5", "expect_min_consideration_bad_token")] {
            assert_eq!(SeaportExpect::new(Some(s)).unwrap_err(), err, "{s}");
        }
        assert_eq!(SeaportExpect::from_json(&json!({"expect_min_consideration": 5})).unwrap_err(), "expect_min_consideration_must_be_string");
        assert!(!SeaportExpect::from_json(&json!({})).unwrap().asserted());
        assert_eq!(dec_add("999", "1"), "1000");
    }
}
