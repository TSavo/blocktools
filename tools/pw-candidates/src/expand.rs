use std::collections::BTreeSet;
const QWERTY: &[&str] = &["1234567890","qwertyuiop","asdfghjkl","zxcvbnm","QWERTYUIOP","ASDFGHJKL","ZXCVBNM"];
fn neighbors(c: char) -> Vec<char> {
    let mut o = Vec::new();
    for row in QWERTY {
        if let Some(i) = row.find(c) {
            if i > 0 { o.push(row.as_bytes()[i - 1] as char); }
            if i + 1 < row.len() { o.push(row.as_bytes()[i + 1] as char); }
        }
    }
    o
}
pub fn case_variants(s: &str) -> Vec<String> {
    let mut v = vec![s.to_string(), s.to_lowercase(), s.to_uppercase()];
    if !s.is_empty() {
        let mut t: Vec<char> = s.chars().collect();
        t[0] = t[0].to_ascii_uppercase();
        for c in t.iter_mut().skip(1) { *c = c.to_ascii_lowercase(); }
        v.push(t.into_iter().collect());
    }
    v
}
pub fn swaps(s: &str) -> Vec<String> {
    let mut b: Vec<u8> = s.bytes().collect();
    let mut o = Vec::new();
    for i in 0..b.len().saturating_sub(1) {
        b.swap(i, i + 1); o.push(String::from_utf8_lossy(&b).into_owned()); b.swap(i, i + 1);
    }
    o
}
pub fn key_typos(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut o = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        for n in neighbors(c) {
            let mut t = chars.clone(); t[i] = n; o.push(t.into_iter().collect());
        }
    }
    o
}
pub fn digits(s: &str) -> Vec<String> {
    let mut o = Vec::new();
    for d in b'0'..=b'9' { let c = d as char; o.push(format!("{s}{c}")); o.push(format!("{c}{s}")); }
    o
}
pub fn expand(tokens: &[String], rules: &[&str], max: usize) -> Vec<String> {
    let base: Vec<String> = if tokens.is_empty() { vec![] }
        else if tokens.len() == 1 { vec![tokens[0].clone()] }
        else {
            let mut v = vec![tokens.join(""), tokens.join(" ")];
            v.extend(tokens.iter().cloned());
            v
        };
    let mut out: BTreeSet<String> = BTreeSet::new();
    for b in &base {
        if !b.is_empty() { out.insert(b.clone()); }
        if out.len() >= max { return out.into_iter().collect(); }
    }
    let mut frontier: Vec<String> = out.iter().cloned().collect();
    for rule in rules {
        let mut next = Vec::new();
        for s in &frontier {
            let news: Vec<String> = match *rule {
                "case" => case_variants(s),
                "swap" => swaps(s),
                "typo" => key_typos(s),
                "digit" => digits(s),
                _ => continue,
            };
            for n in news {
                if out.len() >= max { return out.into_iter().collect(); }
                if out.insert(n.clone()) { next.push(n); }
            }
        }
        frontier.extend(next);
    }
    out.into_iter().take(max).collect()
}
