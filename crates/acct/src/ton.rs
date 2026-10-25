//! TON wallet v4r2: external message carrying one internal transfer (tonsdk WalletV4ContractR2 layout, BOC without index, crc32c).
//! Only deployed wallets (seqno >= 1): the seqno-0 deploy message (StateInit with the wallet code) is NOT BUILT.
use bitcoin::hashes::{sha256, Hash};
pub const WALLET_ID: u32 = 698983191;
pub const MODE_PAY: u8 = 3; // pay fees separately + ignore errors
pub const MODE_SWEEP: u8 = 128; // carry the whole remaining balance (wallet stays deployed)
pub const MAX_COMMENT: usize = 120;

#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Cell { pub bits: Vec<bool>, pub refs: Vec<Cell> }
impl Cell {
    fn uint(&mut self, v: u128, n: usize) { for i in (0..n).rev() { self.bits.push((v >> i) & 1 == 1) } }
    fn bytes(&mut self, b: &[u8]) { for x in b { self.uint(*x as u128, 8) } }
    fn grams(&mut self, v: u128) { let l = (128 - v.leading_zeros() as usize).div_ceil(8); self.uint(l as u128, 4); self.uint(v, l * 8) }
    fn addr(&mut self, a: Option<&[u8; 32]>) { match a { None => self.uint(0, 2), Some(a) => { self.uint(0b100, 3); self.uint(0, 8); self.bytes(a) } } }
    fn append(&mut self, c: &Cell) { self.bits.extend_from_slice(&c.bits); self.refs.extend(c.refs.iter().cloned()) }
    /// tonsdk create_common_msg_info: no StateInit; body inline when it fits, else as a ref.
    fn body(&mut self, b: &Cell) {
        self.bits.push(false);
        if b.bits.is_empty() && b.refs.is_empty() { self.bits.push(false); return }
        if 1023 - self.bits.len() >= b.bits.len() { self.bits.push(false); self.append(b) } else { self.bits.push(true); self.refs.push(b.clone()) }
    }
    fn data(&self) -> Vec<u8> {
        let n = self.bits.len();
        let mut d = vec![self.refs.len() as u8, (n / 8 + n.div_ceil(8)) as u8];
        let mut b = vec![0u8; n.div_ceil(8)];
        for (i, x) in self.bits.iter().enumerate() { if *x { b[i / 8] |= 0x80 >> (i % 8) } }
        if n % 8 != 0 { b[n / 8] |= 0x80 >> (n % 8) }
        d.extend(b); d
    }
    pub fn depth(&self) -> u16 { self.refs.iter().map(|r| r.depth() + 1).max().unwrap_or(0) }
    pub fn hash(&self) -> [u8; 32] {
        let mut d = self.data();
        for r in &self.refs { d.extend(r.depth().to_be_bytes()) }
        for r in &self.refs { d.extend(r.hash()) }
        sha256::Hash::hash(&d).to_byte_array()
    }
}

fn crc32c(d: &[u8]) -> u32 {
    let mut c = !0u32;
    for b in d { c ^= *b as u32; for _ in 0..8 { c = if c & 1 == 1 { (c >> 1) ^ 0x82F6_3B78 } else { c >> 1 } } }
    !c
}
/// BOC with crc32c, no index, one root (tonsdk to_boc(False)). Cells in pre-order; trees only (no shared subcells here).
pub fn boc(root: &Cell) -> Vec<u8> {
    fn walk<'a>(c: &'a Cell, o: &mut Vec<(&'a Cell, Vec<usize>)>) -> usize {
        let me = o.len(); o.push((c, vec![]));
        for r in &c.refs { let k = walk(r, o); o[me].1.push(k) }
        me
    }
    let mut order = vec![]; walk(root, &mut order);
    let n = order.len();
    let sb = ((usize::BITS - n.leading_zeros()) as usize).div_ceil(8).max(1);
    let mut body = vec![];
    for (c, kids) in &order { body.extend(c.data()); for k in kids { body.extend(&k.to_be_bytes()[8 - sb..]) } }
    let ob = ((usize::BITS - body.len().leading_zeros()) as usize).div_ceil(8).max(1);
    let mut o = vec![0xB5, 0xEE, 0x9C, 0x72, 0b0100_0000 | sb as u8, ob as u8];
    for v in [n, 1, 0] { o.extend(&v.to_be_bytes()[8 - sb..]) }
    o.extend(&body.len().to_be_bytes()[8 - ob..]);
    o.extend(&0usize.to_be_bytes()[8 - sb..]);
    o.extend(body);
    o.extend(crc32c(&o).to_le_bytes());
    o
}
/// Strict inverse of `boc` for small trees: checks magic, flags, crc, root 0, refs pointing forward.
pub fn parse_boc(b: &[u8]) -> Result<Cell, &'static str> {
    if b.len() < 10 || b[..4] != [0xB5, 0xEE, 0x9C, 0x72] { return Err("not_a_boc") }
    if b[4] & 0xf8 != 0x40 { return Err("boc_flags_unsupported (need crc32c, no index, no cache)") }
    let (body, crc) = b.split_at(b.len() - 4);
    if crc32c(body) != u32::from_le_bytes(crc.try_into().unwrap()) { return Err("boc_bad_crc") }
    let sb = (b[4] & 7) as usize; let ob = b[5] as usize;
    if sb == 0 || sb > 4 || ob == 0 || ob > 8 { return Err("boc_bad_sizes") }
    let mut p = 6;
    let mut rd = |k: usize| -> Result<usize, &'static str> { let s = body.get(p..p + k).ok_or("boc_truncated")?; p += k; Ok(s.iter().fold(0usize, |a, x| a << 8 | *x as usize)) };
    let (n, roots, absent, tot, root) = (rd(sb)?, rd(sb)?, rd(sb)?, rd(ob)?, rd(sb)?);
    if roots != 1 || absent != 0 || root != 0 || n == 0 || n > 16 { return Err("boc_unsupported_shape") }
    let cells = body.get(p..).ok_or("boc_truncated")?;
    if cells.len() != tot { return Err("boc_size_mismatch") }
    let mut raw = vec![]; let mut q = 0;
    for _ in 0..n {
        let g = |i: usize| cells.get(i).copied().ok_or("boc_truncated");
        let (d1, d2) = (g(q)?, g(q + 1)?); q += 2;
        if d1 & 0xf8 != 0 || d1 > 4 { return Err("boc_exotic_or_level_cell") }
        let nb = d2.div_ceil(2) as usize; let data = cells.get(q..q + nb).ok_or("boc_truncated")?; q += nb;
        let mut bits = vec![];
        for (i, x) in data.iter().enumerate() { for j in 0..8 { bits.push(x & (0x80 >> j) != 0); let _ = i; } }
        if d2 % 2 == 1 { while bits.pop() == Some(false) {} } // remove completion tag
        let mut kids = vec![];
        for _ in 0..d1 { let s = cells.get(q..q + sb).ok_or("boc_truncated")?; q += sb; kids.push(s.iter().fold(0usize, |a, x| a << 8 | *x as usize)) }
        raw.push((bits, kids));
    }
    if q != cells.len() { return Err("boc_trailing_bytes") }
    fn build(i: usize, raw: &[(Vec<bool>, Vec<usize>)]) -> Result<Cell, &'static str> {
        let mut c = Cell { bits: raw[i].0.clone(), refs: vec![] };
        for &k in &raw[i].1 { if k <= i || k >= raw.len() { return Err("boc_bad_ref") } c.refs.push(build(k, raw)?) }
        Ok(c)
    }
    let c = build(0, &raw)?;
    if boc(&c) != b { return Err("boc_not_canonical") }
    Ok(c)
}

struct Rd<'a> { c: &'a Cell, p: usize }
impl Rd<'_> {
    fn u(&mut self, n: usize) -> Result<u128, &'static str> {
        let s = self.c.bits.get(self.p..self.p + n).ok_or("cell_underflow")?; self.p += n;
        Ok(s.iter().fold(0u128, |a, b| a << 1 | *b as u128))
    }
    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], &'static str> { let mut o = [0u8; N]; for x in o.iter_mut() { *x = self.u(8)? as u8 } Ok(o) }
    fn addr(&mut self) -> Result<[u8; 32], &'static str> {
        if self.u(3)? != 0b100 { return Err("address_not_std") }
        if self.u(8)? != 0 { return Err("workchain_not_0") }
        self.bytes::<32>()
    }
    fn grams(&mut self) -> Result<u128, &'static str> { let l = self.u(4)? as usize; self.u(l * 8) }
    fn left(&self) -> usize { self.c.bits.len() - self.p }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer { pub wallet: [u8; 32], pub wallet_id: u32, pub valid_until: u32, pub seqno: u32, pub mode: u8,
    pub to: [u8; 32], pub bounce: bool, pub amount: u128, pub comment: Option<String>, pub sig: [u8; 64] }

impl Transfer {
    fn order(&self) -> Cell {
        let mut h = Cell::default();
        h.bits.extend([false, true, self.bounce, false]);
        h.addr(None); h.addr(Some(&self.to)); h.grams(self.amount);
        h.bits.push(false); h.grams(0); h.grams(0); h.uint(0, 64); h.uint(0, 32);
        let mut p = Cell::default();
        if let Some(t) = &self.comment { p.uint(0, 32); p.bytes(t.as_bytes()) }
        h.body(&p); h
    }
    pub fn signing_cell(&self) -> Cell {
        let mut c = Cell::default();
        c.uint(self.wallet_id as u128, 32); c.uint(self.valid_until as u128, 32); c.uint(self.seqno as u128, 32); c.uint(0, 8); c.uint(self.mode as u128, 8);
        c.refs.push(self.order()); c
    }
    pub fn signing_hash(&self) -> [u8; 32] { self.signing_cell().hash() }
    pub fn message(&self) -> Cell {
        let mut b = Cell::default(); b.bytes(&self.sig); b.append(&self.signing_cell());
        let mut m = Cell::default(); m.uint(0b10, 2); m.addr(None); m.addr(Some(&self.wallet)); m.grams(0);
        m.body(&b); m
    }
    /// External-in message hash (what TON explorers index the message by; the transaction hash differs).
    pub fn msg_hash(&self) -> [u8; 32] { self.message().hash() }
    pub fn encode(&self) -> Vec<u8> { boc(&self.message()) }
    pub fn signed(&self) -> bool { self.sig != [0; 64] }
    pub fn sign(&mut self, seed: &[u8; 32]) -> Result<[u8; 32], &'static str> {
        let (pk, _) = crate::ed_sign(seed, b"");
        if blocktools_core::chains::ton_v4r2_account(&pk) != self.wallet { return Err("key_does_not_match_wallet (v4r2, subwallet 698983191)") }
        self.sig = crate::ed_sign(seed, &self.signing_hash()).1; Ok(pk)
    }
    pub fn verify(&self, pk: &[u8; 32]) -> bool { blocktools_core::chains::ton_v4r2_account(pk) == self.wallet && crate::ed_verify(pk, &self.signing_hash(), &self.sig) }
    /// Strict decode: exactly the layout `encode` writes (re-encoded and compared).
    pub fn decode(b: &[u8]) -> Result<Self, &'static str> {
        let m = parse_boc(b)?;
        let mut r = Rd { c: &m, p: 0 };
        if r.u(2)? != 0b10 || r.u(2)? != 0 { return Err("not_external_in_message") }
        let wallet = r.addr()?;
        if r.grams()? != 0 { return Err("import_fee_nonzero") }
        if r.u(1)? != 0 { return Err("state_init_present (deploy message NOT BUILT)") }
        if r.u(1)? != 0 { return Err("body_as_ref_unsupported") }
        let sig = r.bytes::<64>()?;
        let (wallet_id, valid_until, seqno) = (r.u(32)? as u32, r.u(32)? as u32, r.u(32)? as u32);
        if r.u(8)? != 0 { return Err("wallet_op_not_simple_send") }
        let mode = r.u(8)? as u8;
        if r.left() != 0 || m.refs.len() != 1 { return Err("not_exactly_one_transfer") }
        let o = &m.refs[0]; let mut r = Rd { c: o, p: 0 };
        if r.u(1)? != 0 || r.u(1)? != 1 { return Err("not_internal_or_ihr_enabled") }
        let bounce = r.u(1)? == 1;
        if r.u(1)? != 0 || r.u(2)? != 0 { return Err("bad_internal_header") }
        let to = r.addr()?; let amount = r.grams()?;
        if r.u(1)? != 0 { return Err("extra_currencies_unsupported") }
        r.grams()?; r.grams()?; r.u(64)?; r.u(32)?;
        if r.u(1)? != 0 { return Err("state_init_in_transfer_unsupported") }
        let comment = {
            let either = r.u(1)?;
            let (c, start) = if either == 1 { if o.refs.len() != 1 || r.left() != 0 { return Err("bad_payload_ref") } (&o.refs[0], 0) } else { (o, r.p) };
            let mut q = Rd { c, p: start };
            if q.left() == 0 && c.refs.is_empty() { None } else {
                if q.u(32)? != 0 || q.left() % 8 != 0 || !c.refs.is_empty() { return Err("payload_not_plain_comment") }
                let mut v = vec![]; while q.left() > 0 { v.push(q.u(8)? as u8) }
                Some(String::from_utf8(v).map_err(|_| "comment_not_utf8")?)
            }
        };
        let t = Transfer { wallet, wallet_id, valid_until, seqno, mode, to, bounce, amount, comment, sig };
        if t.encode() != b { return Err("non_canonical_layout") }
        Ok(t)
    }
}
/// Friendly address (EQ.. bounceable / UQ.. non-bounceable, mainnet, workchain 0) -> (account, bounce).
pub fn parse_address(a: &str) -> Result<([u8; 32], bool), &'static str> {
    if a.starts_with("0:") { return Err("raw_address: pass the EQ.. or UQ.. form so the bounce flag is explicit") }
    let acct = blocktools_core::chains::ton_decode(a)?;
    let d = blocktools_core::b64::decode(&a.replace('-', "+").replace('_', "/")).ok_or("bad base64")?;
    Ok((acct, d[0] == 0x11))
}
pub fn address(acct: &[u8; 32], bounce: bool) -> String { blocktools_core::chains::ton_address(acct, bounce) }
