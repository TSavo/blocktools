//! Seed-phrase typo repair: nearest BIP39 words, checksum-valid combinations. Public
//! wordlist only; the phrase itself is the secret and is never stored.
//! Validity: BIP39 checksum, Electrum 2.x HMAC version prefix, or either (`Scheme::Any`).
use bip39::{Language, Mnemonic};
use bitcoin::hashes::{hmac::{Hmac, HmacEngine}, sha512, Hash, HashEngine};

pub const MAX_COMBOS: u64 = 200_000;

/// Which checksum / version check a candidate must pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme { Bip39, Electrum, Any }

impl Scheme {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "bip39" => Some(Self::Bip39),
            "electrum" => Some(Self::Electrum),
            "any" => Some(Self::Any),
            _ => None,
        }
    }
}

pub fn lev(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            cur.push((prev[j] + (ca != *cb) as usize).min(prev[j + 1] + 1).min(cur[j] + 1));
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Candidate words for one token, best first. Known words map to themselves.
pub fn word_candidates(tok: &str) -> Vec<&'static str> {
    let wl = Language::English.word_list();
    if tok == "?" { return wl.to_vec(); }
    if let Some(i) = Language::English.find_word(tok) { return vec![wl[i as usize]]; }
    let mut c: Vec<(usize, &'static str)> = wl.iter()
        .filter_map(|w| {
            let d = lev(tok, w);
            let prefix = tok.len() >= 4 && w.starts_with(&tok[..4]);
            if d <= 2 || prefix { Some((if prefix { 0 } else { d }, *w)) } else { None }
        }).collect();
    c.sort();
    c.into_iter().map(|x| x.1).collect()
}

fn electrum_ok(phrase: &str) -> bool {
    let mut e = HmacEngine::<sha512::Hash>::new(b"Seed version");
    e.input(phrase.as_bytes());
    let h = Hmac::<sha512::Hash>::from_engine(e).to_byte_array();
    matches!((h[0], h[1] >> 4), (0x01, _) | (0x10, 0x0..=0x2))
}

fn valid(words: &[&str], scheme: Scheme) -> bool {
    let s = words.join(" ");
    match scheme {
        Scheme::Bip39 => Mnemonic::parse_in_normalized(Language::English, &s).is_ok(),
        Scheme::Electrum => electrum_ok(&s),
        Scheme::Any => Mnemonic::parse_in_normalized(Language::English, &s).is_ok() || electrum_ok(&s),
    }
}

/// Like `repair`, plus missing words: a `?` token is an unknown word (all 2048 tried), and a phrase one
/// word short (11, 14, 17, 20, 23) is retried with `?` at every position. Two `?` tokens are streamed
/// up to `MAX_COMBOS` iterations (non-exhaustive when the budget is hit). Two words short is not attempted.
pub fn repair_missing(tokens: &[String], max_out: usize) -> Result<Vec<(Vec<&'static str>, usize)>, &'static str> {
    repair_missing_scheme(tokens, max_out, Scheme::Bip39)
}

pub fn repair_missing_scheme(tokens: &[String], max_out: usize, scheme: Scheme) -> Result<Vec<(Vec<&'static str>, usize)>, &'static str> {
    let n_q = tokens.iter().filter(|t| t.as_str() == "?").count();
    if n_q >= 3 { return Err("too_many_missing"); }
    if ![11, 14, 17, 20, 23].contains(&tokens.len()) { return repair_scheme(tokens, max_out, scheme); }
    let mut out: Vec<(Vec<&'static str>, usize)> = Vec::new();
    for pos in 0..=tokens.len() {
        let mut t = tokens.to_vec(); t.insert(pos, "?".into());
        for r in repair_scheme(&t, max_out, scheme)? {
            if !out.iter().any(|o| o.0 == r.0) { out.push(r) }
            if out.len() >= max_out { return Ok(out) }
        }
    }
    Ok(out)
}

/// Returns checksum/version-valid phrases (as word vectors) and how many words changed.
pub fn repair(tokens: &[String], max_out: usize) -> Result<Vec<(Vec<&'static str>, usize)>, &'static str> {
    repair_scheme(tokens, max_out, Scheme::Bip39)
}

pub fn repair_scheme(tokens: &[String], max_out: usize, scheme: Scheme) -> Result<Vec<(Vec<&'static str>, usize)>, &'static str> {
    if ![12, 15, 18, 21, 24].contains(&tokens.len()) { return Err("bad_input"); }
    let cands: Vec<Vec<&'static str>> = tokens.iter().map(|t| word_candidates(t)).collect();
    if cands.iter().any(|c| c.is_empty()) { return Err("no_candidates"); }
    let n_wild = cands.iter().filter(|c| c.len() > 1).count();
    let combos = cands.iter().try_fold(1u64, |a, c| a.checked_mul(c.len() as u64)).unwrap_or(u64::MAX);
    // Two wildcards (typically two `?`): stream with an iteration budget instead of refusing.
    let stream_two = n_wild == 2 && combos > MAX_COMBOS;
    if combos > MAX_COMBOS && !stream_two { return Err("too_many_candidates"); }
    let orig: Vec<&str> = tokens.iter().map(|s| s.as_str()).collect();
    let changed = |w: &[&str]| w.iter().zip(&orig).filter(|(a, b)| **a != **b).count();
    let mut out = Vec::new();
    let mut idx = vec![0usize; cands.len()];
    let mut iters = 0u64;
    let budget = if stream_two { MAX_COMBOS } else { u64::MAX };
    'outer: loop {
        let w: Vec<&'static str> = idx.iter().enumerate().map(|(i, &j)| cands[i][j]).collect();
        if valid(&w, scheme) { let c = changed(&w); out.push((w, c)); if out.len() >= max_out { break; } }
        iters += 1;
        if iters >= budget { break; }
        let mut p = 0;
        loop {
            if p == idx.len() { break 'outer; }
            idx[p] += 1;
            if idx[p] < cands[p].len() { break; }
            idx[p] = 0; p += 1;
        }
    }
    if out.is_empty() {
        // All words known but check fails: try all pairwise swaps, then one wrong word.
        let base: Vec<&'static str> = cands.iter().map(|c| c[0]).collect();
        for i in 0..base.len() {
            for j in (i + 1)..base.len() {
                let mut w = base.clone(); w.swap(i, j);
                if w != base && valid(&w, scheme) { out.push((w, 2)); if out.len() >= max_out { return Ok(out); } }
            }
        }
        for i in 0..base.len() {
            for nw in Language::English.word_list() {
                if *nw == base[i] { continue; }
                let mut w = base.clone(); w[i] = nw;
                if valid(&w, scheme) { out.push((w, 1)); if out.len() >= max_out { return Ok(out); } }
            }
        }
    }
    Ok(out)
}


#[cfg(test)]
mod repair_tests {
    use super::*;
    fn t(s: &str) -> Vec<String> { s.split(' ').map(String::from).collect() }
    const V: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    // Electrum public vector (electrum/tests/test_mnemonic.py): standard seed
    const EL: &str = "wild father tree among universe such mobile favorite target dynamic credit identify";
    #[test] fn valid_passthrough() {
        let r = repair(&t(V), 10).unwrap();
        assert_eq!(r[0].0.join(" "), V); assert_eq!(r[0].1, 0);
    }
    #[test] fn typo_fixed() {
        let r = repair(&t("abandon abandon abandn abandon abandon abandon abandon abandon abandon abandon abandon abuot"), 100).unwrap();
        assert!(r.iter().any(|(w, c)| w.join(" ") == V && *c == 2));
    }
    #[test] fn wrong_known_word() {
        let r = repair(&t("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"), 5000).unwrap();
        assert!(r.iter().any(|(w, _)| w.join(" ") == V));
    }
    #[test] fn missing_word_any_position() {
        let w: Vec<String> = V.split(' ').map(String::from).collect();
        let mut short = w.clone(); short.remove(4);
        let r = repair_missing(&short, 5000).unwrap();
        assert!(r.iter().any(|(x, _)| x.join(" ") == V));
        let mut q = w.clone(); q[11] = "?".into();
        let r = repair_missing(&q, 5000).unwrap();
        assert!(r.iter().any(|(x, _)| x.join(" ") == V));
    }
    #[test] fn pairwise_swap_not_just_adjacent() {
        // BIP39 Trezor vector; swap word 0 ("legal") with word 3 ("year") — not adjacent.
        const P: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let mut w: Vec<String> = P.split(' ').map(String::from).collect();
        w.swap(0, 3);
        assert_ne!(w.join(" "), P);
        let r = repair(&w, 100).unwrap();
        assert!(r.iter().any(|(x, c)| x.join(" ") == P && *c == 2), "{r:?}");
    }
    #[test] fn electrum_passthrough() {
        assert!(Mnemonic::parse_in_normalized(Language::English, EL).is_err());
        let r = repair_scheme(&t(EL), 10, Scheme::Electrum).unwrap();
        assert_eq!(r[0].0.join(" "), EL);
        // BIP39 scheme must not accept the Electrum phrase as-is.
        let bip = repair_scheme(&t(EL), 10, Scheme::Bip39).unwrap();
        assert!(bip.iter().all(|(w, _)| w.join(" ") != EL));
        let r = repair_scheme(&t(EL), 10, Scheme::Any).unwrap();
        assert!(r.iter().any(|(w, _)| w.join(" ") == EL));
    }
    #[test] fn electrum_adjacent_swap() {
        let mut w: Vec<String> = EL.split(' ').map(String::from).collect();
        w.swap(3, 4);
        let r = repair_scheme(&w, 50, Scheme::Electrum).unwrap();
        assert!(r.iter().any(|(x, _)| x.join(" ") == EL));
    }
    #[test] fn two_question_marks_budgeted() {
        // Two `?` at end: may or may not find V within budget; must not Err(too_many_candidates).
        let mut w: Vec<String> = V.split(' ').map(String::from).collect();
        w[10] = "?".into(); w[11] = "?".into();
        let r = repair_scheme(&w, 5, Scheme::Bip39).unwrap();
        // Budgeted search; assert it returns without panic. Prefer finding V when early in order.
        let _ = r;
    }
    #[test] fn bad_len() { assert_eq!(repair(&t("abandon about"), 1).unwrap_err(), "bad_input"); }
}
