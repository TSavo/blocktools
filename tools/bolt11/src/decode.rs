//! BOLT11 Lightning invoice decode + byte-identical re-encode. Pure: bech32 (BIP173, NOT bech32m),
//! tagged-field parse, and secp256k1 recovery of the payee pubkey from the signature. No channel
//! protocol, no signing of invoices, no keys. The 5-bit (fe32) words are handled directly because
//! BOLT11 fields are sub-byte aligned.
use bitcoin::hashes::{sha256, Hash};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{Message, Secp256k1};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn char_to_u5(c: u8) -> Option<u8> {
    CHARSET.iter().position(|&x| x == c).map(|p| p as u8)
}

// BIP173 checksum (Bech32, constant 1), used for both verify (decode) and create (encode).
fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= *g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let b = hrp.as_bytes();
    let mut v: Vec<u8> = b.iter().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(b.iter().map(|c| c & 0x1f));
    v
}

/// The 6 checksum words for hrp + data words (BIP173 Bech32).
fn create_checksum(hrp: &str, data: &[u8]) -> [u8; 6] {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data);
    values.extend_from_slice(&[0u8; 6]);
    let m = polymod(&values) ^ 1;
    let mut out = [0u8; 6];
    for (i, o) in out.iter_mut().enumerate() {
        *o = ((m >> (5 * (5 - i))) & 0x1f) as u8;
    }
    out
}

/// Re-encode an hrp + 5-bit data words (no checksum) into the lowercase bech32 string, checksum appended.
pub fn encode(hrp: &str, data: &[u8]) -> String {
    let chk = create_checksum(hrp, data);
    let mut s = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for &w in data.iter().chain(chk.iter()) {
        s.push(CHARSET[w as usize] as char);
    }
    s
}

/// Re-encode an invoice byte-identically: parse its 5-bit words, drop the 6 checksum words, and
/// re-emit hrp + data + a freshly computed checksum. Returns the lowercase canonical string.
pub fn reencode(invoice: &str) -> Result<String, &'static str> {
    let s = invoice.trim().to_ascii_lowercase();
    let sep = s.rfind('1').ok_or("no_separator")?;
    let (hrp, data_part) = (&s[..sep], &s[sep + 1..]);
    if data_part.len() < 6 {
        return Err("too_short");
    }
    let mut words = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        words.push(char_to_u5(c).ok_or("bad_bech32_char")?);
    }
    Ok(encode(hrp, &words[..words.len() - 6]))
}

/// 5-bit words -> a big-endian bit vector (0/1 per entry, MSB of each word first).
fn words_to_bits(words: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(words.len() * 5);
    for &w in words {
        for i in (0..5).rev() {
            bits.push((w >> i) & 1);
        }
    }
    bits
}

/// The leading `n_bytes` bytes (n_bytes*8 bits, MSB first) of a 5-bit word slice; None if too short.
fn field_bytes(words: &[u8], n_bytes: usize) -> Option<Vec<u8>> {
    let bits = words_to_bits(words);
    if bits.len() < n_bytes * 8 {
        return None;
    }
    Some(bits[..n_bytes * 8].chunks(8).map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b)).collect())
}

/// A big-endian unsigned integer from all the bits of a 5-bit word slice (for expiry / cltv).
fn field_uint(words: &[u8]) -> u64 {
    words.iter().fold(0u64, |a, &w| (a << 5) | w as u64)
}

/// Pack 5-bit words into bytes MSB-first, zero-padding the final partial byte (BOLT11 signing payload).
fn words_to_bytes_padded(words: &[u8]) -> Vec<u8> {
    let mut bits = words_to_bits(words);
    while bits.len() % 8 != 0 {
        bits.push(0);
    }
    bits.chunks(8).map(|c| c.iter().fold(0u8, |a, &b| (a << 1) | b)).collect()
}

#[derive(Debug, Default, PartialEq)]
pub struct Invoice {
    pub hrp: String,
    pub currency: String,
    pub network: String,
    pub amount_msat: Option<u128>,
    pub amount_raw: String, // the amount part of the hrp verbatim (e.g. "2500u"), "" if none
    pub timestamp: u64,
    pub payment_hash: Option<String>,
    pub payment_secret: Option<String>,
    pub description: Option<String>,
    pub description_hash: Option<String>,
    pub payee_pubkey_field: Option<String>, // from an `n` tag, if present
    pub expiry: Option<u64>,
    pub min_final_cltv_expiry: Option<u64>,
    pub features_hex: Option<String>,
    pub fallback_hex: Option<String>,
    pub routing_hint_count: usize,
    pub signature: String,     // 64-byte r||s, hex
    pub recovery_id: u8,       // 0..3
    pub recovered_payee: String, // compressed pubkey recovered from the signature, hex
}

fn parse_amount(currency_and_amount: &str) -> (String, String, Option<u128>) {
    // currency = leading chars before the first digit; amount = the rest (digits + optional multiplier).
    let split = currency_and_amount.find(|c: char| c.is_ascii_digit()).unwrap_or(currency_and_amount.len());
    let (cur, amt) = currency_and_amount.split_at(split);
    if amt.is_empty() {
        return (cur.to_string(), String::new(), None);
    }
    let bytes = amt.as_bytes();
    let (digits, mult) = match bytes.last() {
        Some(m @ (b'm' | b'u' | b'n' | b'p')) => (&amt[..amt.len() - 1], Some(*m)),
        _ => (amt, None),
    };
    let msat = digits.parse::<u128>().ok().and_then(|d| match mult {
        None => Some(d * 100_000_000_000),
        Some(b'm') => Some(d * 100_000_000),
        Some(b'u') => Some(d * 100_000),
        Some(b'n') => Some(d * 100),
        Some(b'p') => {
            if d % 10 == 0 {
                Some(d / 10)
            } else {
                None // sub-msat precision: report amount_raw only
            }
        }
        _ => None,
    });
    (cur.to_string(), amt.to_string(), msat)
}

fn network_of(currency: &str) -> String {
    match currency {
        "bc" => "mainnet",
        "tb" => "testnet",
        "bcrt" => "regtest",
        "tbs" | "sb" => "signet",
        _ => "unknown",
    }
    .to_string()
}

/// Decode a BOLT11 invoice. Errors are stable snake_case codes.
pub fn decode(invoice: &str) -> Result<Invoice, &'static str> {
    let s = invoice.trim();
    if s.len() > 7071 {
        return Err("invoice_too_long");
    }
    // Reject mixed case (BIP173): the whole string is one case.
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err("mixed_case");
    }
    let s = s.to_ascii_lowercase();
    let sep = s.rfind('1').ok_or("no_separator")?;
    if sep == 0 {
        return Err("empty_hrp");
    }
    let hrp = &s[..sep];
    let data_part = &s[sep + 1..];
    if !hrp.starts_with("ln") {
        return Err("not_a_lightning_invoice");
    }
    if data_part.len() < 6 {
        return Err("too_short");
    }
    // charset -> 5-bit words (incl. the 6 checksum words)
    let mut words = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        words.push(char_to_u5(c).ok_or("bad_bech32_char")?);
    }
    // BIP173 checksum over hrp + all data words must be 1.
    let mut chk_in = hrp_expand(hrp);
    chk_in.extend_from_slice(&words);
    if polymod(&chk_in) != 1 {
        return Err("bad_checksum");
    }
    let payload = &words[..words.len() - 6]; // drop checksum words
    if payload.len() < 7 + 104 {
        return Err("too_short_for_timestamp_and_signature");
    }
    let sig_start = payload.len() - 104;
    let timestamp = field_uint(&payload[..7]);
    let tagged = &payload[7..sig_start];
    let sig_words = &payload[sig_start..];

    // Signature: 104 words = 520 bits = 65 bytes (64-byte r||s + 1 recovery id).
    let sig_bytes = field_bytes(sig_words, 65).ok_or("bad_signature_length")?;
    let recid = sig_bytes[64];
    if recid > 3 {
        return Err("bad_recovery_id");
    }
    // Signed message = sha256(hrp_ascii || padded-bytes(timestamp+tagged words)).
    let mut msg = hrp.as_bytes().to_vec();
    msg.extend_from_slice(&words_to_bytes_padded(&payload[..sig_start]));
    let digest = sha256::Hash::hash(&msg).to_byte_array();
    let secp = Secp256k1::verification_only();
    let rsig = RecoverableSignature::from_compact(
        &sig_bytes[..64],
        RecoveryId::from_i32(recid as i32).map_err(|_| "bad_recovery_id")?,
    )
    .map_err(|_| "bad_signature")?;
    let pk = secp
        .recover_ecdsa(&Message::from_digest(digest), &rsig)
        .map_err(|_| "signature_does_not_recover")?;
    let recovered_payee = blocktools_core::hex_enc(pk.serialize());

    let (currency, amount_raw, amount_msat) = parse_amount(&hrp[2..]);
    let mut inv = Invoice {
        hrp: hrp.to_string(),
        network: network_of(&currency),
        currency,
        amount_msat,
        amount_raw,
        timestamp,
        signature: blocktools_core::hex_enc(&sig_bytes[..64]),
        recovery_id: recid,
        recovered_payee,
        ..Default::default()
    };

    // Tagged fields: type (1 word) + length (2 words, big-endian 10 bits) + data (length words).
    let mut i = 0usize;
    while i + 3 <= tagged.len() {
        let typ = tagged[i];
        let len = (tagged[i + 1] as usize) * 32 + tagged[i + 2] as usize;
        let start = i + 3;
        if start + len > tagged.len() {
            return Err("tagged_field_overruns");
        }
        let d = &tagged[start..start + len];
        match typ {
            1 => inv.payment_hash = field_bytes(d, 32).map(|b| blocktools_core::hex_enc(b)), // p
            16 => inv.payment_secret = field_bytes(d, 32).map(|b| blocktools_core::hex_enc(b)), // s
            23 => inv.description_hash = field_bytes(d, 32).map(|b| blocktools_core::hex_enc(b)), // h
            13 => {
                // d: description, 5-bit -> bytes -> UTF-8
                let nbytes = (d.len() * 5) / 8;
                if let Some(b) = field_bytes(d, nbytes) {
                    inv.description = Some(String::from_utf8_lossy(&b).into_owned());
                }
            }
            19 => inv.payee_pubkey_field = field_bytes(d, 33).map(|b| blocktools_core::hex_enc(b)), // n
            6 => inv.expiry = Some(field_uint(d)),               // x
            24 => inv.min_final_cltv_expiry = Some(field_uint(d)), // c
            5 => {
                let nbytes = (d.len() * 5 + 7) / 8;
                inv.features_hex = field_bytes(d, nbytes.min((d.len() * 5) / 8)).map(|b| blocktools_core::hex_enc(b)); // 9
            }
            9 => {
                // f: fallback address — first word is the version, rest the program; report raw hex
                inv.fallback_hex = Some(blocktools_core::hex_enc(words_to_bytes_padded(d)));
            }
            3 => inv.routing_hint_count += 1, // r: one hop-set; count them (each 51 bytes per hop)
            _ => {}                           // unknown tag: ignored (BOLT11 allows this)
        }
        i = start + len;
    }

    Ok(inv)
}

#[cfg(test)]
mod tests {
    use super::*;

    // BOLT11 spec test vector: "Please consider supporting this project" on mainnet, no amount.
    // Public test vector from the BOLT11 specification (BOLT #11).
    const INV: &str = "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql";
    // Amount vector (2500 micro-BTC) from the same spec appendix.
    const INV_2500U: &str = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";

    #[test]
    fn decodes_the_spec_vector_and_recovers_the_payee() {
        let inv = decode(INV).expect("decode");
        assert_eq!(inv.hrp, "lnbc");
        assert_eq!(inv.network, "mainnet");
        assert_eq!(inv.amount_msat, None); // no amount in the hrp
        assert_eq!(inv.timestamp, 1_496_314_658);
        assert_eq!(
            inv.payment_hash.as_deref(),
            Some("0001020304050607080900010203040506070809000102030405060708090102")
        );
        assert_eq!(
            inv.description.as_deref(),
            Some("Please consider supporting this project")
        );
        assert_eq!(inv.payment_secret.as_deref().map(|s| s.len()), Some(64));
        // The payee pubkey recovered from the signature is the spec's node id.
        assert_eq!(
            inv.recovered_payee,
            "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"
        );
    }

    #[test]
    fn decodes_the_amount_and_recovers_the_same_payee() {
        let inv = decode(INV_2500U).expect("decode");
        assert_eq!(inv.amount_msat, Some(250_000_000)); // 2500u BTC = 2500 * 100_000 msat
        assert_eq!(inv.network, "mainnet");
        assert_eq!(
            inv.recovered_payee,
            "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad"
        );
    }

    #[test]
    fn re_encodes_byte_identical() {
        // Rebuild the full 5-bit payload we parsed and re-encode; must equal the (lowercased) input.
        let s = INV;
        let sep = s.rfind('1').unwrap();
        let (hrp, data_part) = (&s[..sep], &s[sep + 1..]);
        let words: Vec<u8> = data_part.bytes().map(|c| char_to_u5(c).unwrap()).collect();
        let payload = &words[..words.len() - 6];
        assert_eq!(encode(hrp, payload), s);
    }

    #[test]
    fn rejects_a_tampered_checksum() {
        let mut s = INV.to_string();
        s.pop();
        s.push(if INV.ends_with('w') { 'x' } else { 'w' });
        assert_eq!(decode(&s), Err("bad_checksum"));
    }

    #[test]
    fn rejects_a_tampered_signature() {
        // Flip one data char well before the checksum: the signature no longer recovers (or checksum fails).
        let s = INV;
        let sep = s.rfind('1').unwrap();
        // corrupt a char in the signature region (near the end, before the 6 checksum chars)
        let pos = s.len() - 10;
        let mut v: Vec<char> = s.chars().collect();
        v[pos] = if v[pos] == 'q' { 'p' } else { 'q' };
        let bad: String = v.into_iter().collect();
        let _ = sep;
        // Either the checksum catches it or the recovery fails — both are a rejection.
        assert!(decode(&bad).is_err());
    }

    #[test]
    fn rejects_mixed_case_and_non_ln() {
        assert_eq!(decode("lnBC1pvjl"), Err("mixed_case"));
        assert_eq!(decode("bc1qxyz"), Err("not_a_lightning_invoice"));
    }
}
