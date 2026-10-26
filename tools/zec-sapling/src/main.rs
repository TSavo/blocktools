//! zec-sapling [--count N] [--unified] [--viewkey-out FILE] < BIP39 mnemonic
//! --unified also emits, per account, the ZIP-316 unified address (orchard + sapling + p2pkh, all
//! at the account's first valid Sapling diversifier index j, as zcashd/librustzcash do) and the
//! transparent t1 address at m/44'/133'/i'/0/j. Orchard keys: ZIP-32 m/32'/133'/i' (orchard crate).
//! Zcash Sapling (ZIP-32): seed = BIP39(mnemonic, ""), account i = m/32'/133'/i', default
//! (first valid diversifier) payment address, encoded bech32 "zs". stdout: PUBLIC rows only.
//! --viewkey-out writes the accounts' extended full viewing keys (bech32 "zxviews", secret:
//! they reveal all incoming and outgoing funds, but cannot spend) to FILE, new, mode 0600.
//! The spending key is never output.
use std::io::Read;
use sapling_crypto::zip32::ExtendedSpendingKey;
use zeroize::Zeroizing;
use zip32::ChildIndex;

pub fn account(seed: &[u8], i: u32) -> ExtendedSpendingKey {
    let m = ExtendedSpendingKey::master(seed);
    ExtendedSpendingKey::from_path(&m, &[ChildIndex::hardened(32), ChildIndex::hardened(133), ChildIndex::hardened(i)])
}
pub fn zs(addr: &sapling_crypto::PaymentAddress) -> String {
    bech32::encode::<bech32::Bech32>(bech32::Hrp::parse("zs").unwrap(), &addr.to_bytes()).unwrap()
}
/// ZIP-316 unified address for account i: (j, ua, t1 address, receivers).
pub fn unified(seed: &[u8], i: u32) -> (u128, String, String) {
    let (j, sap) = account(seed, i).default_address();
    let (orch, p2pkh) = receivers(seed, i, j);
    let r = vec![Receiver::Orchard(orch), Receiver::Sapling(sap.to_bytes()), Receiver::P2pkh(p2pkh)];
    let ua = zcash_address::unified::Address::try_from_items(r).unwrap().encode(&NetworkType::Main);
    (u128::from(j), ua, t1(&p2pkh))
}
use zcash_address::unified::{Encoding, Receiver};
use zcash_protocol::consensus::NetworkType;
pub fn receivers(seed: &[u8], i: u32, j: zip32::DiversifierIndex) -> ([u8; 43], [u8; 20]) {
    let sk = orchard::keys::SpendingKey::from_zip32_seed(seed, 133, zip32::AccountId::try_from(i).unwrap()).unwrap();
    let o = orchard::keys::FullViewingKey::from(&sk).address_at(j, orchard::keys::Scope::External).to_raw_address_bytes();
    use bitcoin::bip32::{ChildNumber as C, Xpriv};
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let ji = u32::try_from(u128::from(j)).expect("j < 2^31");
    let path = [C::from_hardened_idx(44).unwrap(), C::from_hardened_idx(133).unwrap(), C::from_hardened_idx(i).unwrap(), C::from_normal_idx(0).unwrap(), C::from_normal_idx(ji).unwrap()];
    let x = Xpriv::new_master(bitcoin::Network::Bitcoin, seed).unwrap().derive_priv(&secp, &path).unwrap();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &x.private_key).serialize();
    use bitcoin::hashes::Hash;
    (o, bitcoin::hashes::hash160::Hash::hash(&pk).to_byte_array())
}
pub fn t1(h: &[u8; 20]) -> String { let mut v = vec![0x1c, 0xb8]; v.extend_from_slice(h); bitcoin::base58::encode_check(&v) }
fn arg<'a>(a: &'a [String], k: &str) -> Option<&'a str> { a.iter().position(|x| x == k).and_then(|i| a.get(i + 1)).map(|s| s.as_str()) }
const HELP: &str = " zec-sapling [--count N] [--unified] [--viewkey-out FILE] < BIP39 mnemonic
 --unified also emits, per account, the ZIP-316 unified address (orchard + sapling + p2pkh, all
 at the account's first valid Sapling diversifier index j, as zcashd/librustzcash do) and the
 transparent t1 address at m/44'/133'/i'/0/j. Orchard keys: ZIP-32 m/32'/133'/i' (orchard crate).
 Zcash Sapling (ZIP-32): seed = BIP39(mnemonic, \"\"), account i = m/32'/133'/i', default
 (first valid diversifier) payment address, encoded bech32 \"zs\". stdout: PUBLIC rows only.
 --viewkey-out writes the accounts' extended full viewing keys (bech32 \"zxviews\", secret:
 they reveal all incoming and outgoing funds, but cannot spend) to FILE, new, mode 0600.
 The spending key is never output.
";
fn main() {
    blocktools_io::help(HELP);
    let a: Vec<String> = std::env::args().skip(1).collect();
    let count: u32 = match arg(&a, "--count").map(|c| c.parse()) { None => 1, Some(Ok(n)) if (1..=100).contains(&n) => n,
        _ => { eprintln!("{{\"error\":\"bad_count\"}}"); std::process::exit(2) } };
    let mut s = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut s).ok();
    let m = match bip39::Mnemonic::parse_in_normalized(bip39::Language::English, s.trim()) { Ok(m) => m,
        Err(_) => { eprintln!("{{\"error\":\"bad_mnemonic\"}}"); std::process::exit(1) } };
    let seed = Zeroizing::new(m.to_seed(""));
    let mut views = Zeroizing::new(String::new());
    for i in 0..count {
        let xsk = account(&seed[..], i);
        let (_, addr) = xsk.default_address();
        blocktools_io::outln!("{{\"tool\":\"zec-sapling\",\"status\":\"ok\",\"chain\":\"zec\",\"kind\":\"sapling\",\"path\":\"m/32'/133'/{i}'\",\"address\":\"{}\"}}", zs(&addr));
        if a.iter().any(|x| x == "--unified") {
            let (j, ua, t) = unified(&seed[..], i);
            blocktools_io::outln!("{{\"tool\":\"zec-sapling\",\"status\":\"ok\",\"chain\":\"zec\",\"kind\":\"unified\",\"path\":\"m/32'/133'/{i}'\",\"diversifier_index\":{j},\"receivers\":\"orchard,sapling,p2pkh\",\"address\":\"{ua}\"}}");
            blocktools_io::outln!("{{\"tool\":\"zec-sapling\",\"status\":\"ok\",\"chain\":\"zec\",\"kind\":\"p2pkh\",\"path\":\"m/44'/133'/{i}'/0/{j}\",\"address\":\"{t}\"}}");
        }
        #[allow(deprecated)]
        let fvk = xsk.to_extended_full_viewing_key();
        let mut b = Zeroizing::new(Vec::new()); fvk.write(&mut *b).unwrap();
        let hrp = bech32::Hrp::parse("zxviews").unwrap();
        views.push_str(&format!("{{\"path\":\"m/32'/133'/{i}'\",\"viewing_key\":\"{}\"}}\n", Zeroizing::new(bech32::encode::<bech32::Bech32>(hrp, &b).unwrap()).as_str()));
    }
    if let Some(p) = arg(&a, "--viewkey-out") {
        if let Err(e) = write_private(p, views.as_bytes()) { eprintln!("{{\"error\":\"viewkey_out: {}\"}}", e.kind()); std::process::exit(1) }
        eprintln!("{{\"viewkey_out\":\"written\",\"mode\":\"0600\",\"contains\":\"sapling extended full viewing keys\"}}");
    }
}
fn write_private(path: &str, b: &[u8]) -> std::io::Result<()> {
    use std::io::Write; use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(b)?; f.sync_all()
}
#[cfg(test)]
mod tests {
    use super::*;
    // zcash-test-vectors sapling_zip32_hard.json (seed = 0..31; m, m/1', m/1'/2', m/1'/2'/3'): xfvk serialisation.
    const XFVK: [&str; 4] = ["000000000000000000d0947c4b03bf72a37ab44f72276d1cf3fdcd7ebf3e73348b7e550d752018668e93442e5feffbff16e7217202dc7306729ffffe85af5683bce2642e3eeb5d3871dce8e7edece04b8950417f85ba57691b783c45b1a27422db1693dceb67b10106395884890323b9d4933c021db89bcf767df21977b2ff0683848321a4df4afb2177c17cb75b7796afb39f0f3e91c924607da56fa9a20e283509bc8a3ef996a172", "0114c2713a010000806fccaa45a8206b063ebb68c610e05927aa94d61be93ec25eb4f82efd68caaedbcfca79d337bc689813e409a54e3e72ad8e2f703ae6f8223c9becbde9a8a35f53513de64085d35a3adf23d89d5a21cdee4db4c625bd6a3c3c624bef4344141deb2530761933348c1fcf14355433a8d291167fbb37b2ce37ca97160a47ec331c69f288400fd65f9adfe3a7c3720aceee0dae050d0a819d619f92e9e2cb4434d526", "02768423cb020000804479086c75d080796020f500c1e30a54cfe29dda36f2144fb33a50806fbef7da9a853f9544713797e0851764da392e68534b1d948dae4742ee765c727572ab4ef166a28a4f88cec12141a82d2120bd6d8caf879c9a1b3ad2118501364f5d4fbed9fc7101bf907f41886a7330a5d6a7bd23535e305eb7679bc23d7605936185ace4699e9a86e031c54b21cdd0960ac18ddd61ec9f7ae98d5582a6faf65f3248d1", "030bdc2d2b0300008033dc012d7690ced2cd2bcb2cc3e463e28d8c29ef3b01be59b2bdfc385bbdc74b9c6d859a752c305d6263de95f2fcf734b126df2456c7d31bc601c8ddec409112d3ee41f84b5a9508b61d29b2fb45636d19aa10d782cd978cfe6715492fcd224e1e36ea0cf2be2e9d6ce380a8af18e75da9225551fbef8b98311b5c9c1b4b9ee357fc6c59a4f3ad5a6f609db671d28cbf703f0d14dc363aaaed70729c107bbb6a"];
    #[test] fn zip32_hard_vectors() {
        let seed: Vec<u8> = (0..32).collect();
        let m = ExtendedSpendingKey::master(&seed);
        let k = ExtendedSpendingKey::from_path(&m, &[]);
        #[allow(deprecated)] let f = k.to_extended_full_viewing_key(); let mut b = Vec::new(); f.write(&mut b).unwrap();
        assert_eq!(hex(&b), XFVK[0]);
        let k = ExtendedSpendingKey::from_path(&m, &[ChildIndex::hardened(1)]);
        #[allow(deprecated)] let f = k.to_extended_full_viewing_key(); let mut b = Vec::new(); f.write(&mut b).unwrap();
        assert_eq!(hex(&b), XFVK[1]);
        let k = ExtendedSpendingKey::from_path(&m, &[ChildIndex::hardened(1), ChildIndex::hardened(2)]);
        #[allow(deprecated)] let f = k.to_extended_full_viewing_key(); let mut b = Vec::new(); f.write(&mut b).unwrap();
        assert_eq!(hex(&b), XFVK[2]);
        let k = ExtendedSpendingKey::from_path(&m, &[ChildIndex::hardened(1), ChildIndex::hardened(2), ChildIndex::hardened(3)]);
        #[allow(deprecated)] let f = k.to_extended_full_viewing_key(); let mut b = Vec::new(); f.write(&mut b).unwrap();
        assert_eq!(hex(&b), XFVK[3]);
        let (j, _) = m.default_address(); assert_eq!(u128::from(j), 0);
        assert_eq!(hex(&m.default_address().1.to_bytes()[..11]), "d8621b981cf300e9d4cc89");
    }
    // sapling_key_components.json row 0: sk -> default address d || pk_d, and zs encoding round trip.
    #[test] fn key_components() {
        let sk: [u8; 32] = unhex("0000000000000000000000000000000000000000000000000000000000000000").try_into().unwrap();
        let fvk = sapling_crypto::keys::FullViewingKey::from_expanded_spending_key(&sapling_crypto::keys::ExpandedSpendingKey::from_spending_key(&sk));
        let d = sapling_crypto::Diversifier(unhex("f19d9b797e39f337445839").try_into().unwrap());
        let a = fvk.vk.to_payment_address(d).unwrap();
        assert_eq!(hex(&a.to_bytes()[11..]), "db4cd2b0aac4f7eb8ca131f16567c445a9555126d3c29f14e3d776e841ae7415");
        let s = zs(&a); assert!(s.starts_with("zs1") && s.len() == 78);
    }
    // orchard_key_components.json row 0: sk -> default (j=0) address d || pk_d.
    #[test] fn orchard_key_components() {
        let sk = orchard::keys::SpendingKey::from_bytes(unhex("5d7a8f739a2d9e945b0ce152a8049e294c4d6e66b164939daffa2ef6ee692148").try_into().unwrap()).unwrap();
        let a = orchard::keys::FullViewingKey::from(&sk).address_at(0u32, orchard::keys::Scope::External).to_raw_address_bytes();
        assert_eq!(hex(&a), "8ff3386971cb64b8e7789908dd8ebd7de92a68e586a34db8fea999efd2016fae76750afae7ee941646bcb9");
    }
    // unified_address.json (zcash-test-vectors Python reference): all rows. From root_seed/account/j we
    // derive each present orchard/sapling/p2pkh receiver and the UA string; p2sh/unknown bytes are taken
    // from the row (random in the generator). Sapling: j must be valid (find_address(j) returns j).
    #[test] fn unified_address_vectors() {
        let mut n = 0;
        for l in include_str!("ua_vectors.tsv").lines() {
            let f: Vec<&str> = l.split('\t').collect();
            let seed = unhex(f[0]); let i: u32 = f[1].parse().unwrap(); let j: u128 = f[2].parse().unwrap();
            let jj = zip32::DiversifierIndex::try_from(j).unwrap();
            let (dj, sap) = { #[allow(deprecated)] let f = account(&seed, i).to_extended_full_viewing_key(); f.find_address(jj).unwrap() };
            let (o, p) = receivers(&seed, i, jj);
            let mut r = vec![];
            if f[3] == "1" { assert_eq!(hex(&p), f[4]); r.push(Receiver::P2pkh(p)); }
            if f[5] != "-" { r.push(Receiver::P2sh(unhex(f[5]).try_into().unwrap())); }
            if f[6] == "1" { assert_eq!(u128::from(dj), j); assert_eq!(hex(&sap.to_bytes()), f[7]); r.push(Receiver::Sapling(sap.to_bytes())); }
            if f[8] == "1" { assert_eq!(hex(&o), f[9]); r.push(Receiver::Orchard(o)); }
            if f[10] != "-" { r.push(Receiver::Unknown { typecode: f[10].parse().unwrap(), data: unhex(f[11]) }); }
            let ua = zcash_address::unified::Address::try_from_items(r).unwrap().encode(&NetworkType::Main);
            assert_eq!(ua, f[12]); n += 1;
        }
        assert_eq!(n, 60);
    }
    fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{x:02x}")).collect() }
    fn unhex(s: &str) -> Vec<u8> { (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect() }
}
