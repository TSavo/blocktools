// Solana unsigned transfer corpus for blocktools::sol::build_transfer, compiled by @solana/kit 8.5
// (independent oracle). Random public addresses from a fixed PRNG; no keys. Run from a directory
// with @solana/kit installed:  node sol-build-gen.mjs > crates/blocktools/tests/data/sol-build-corpus.json
import * as k from "@solana/kit";
let seed = 0x5eed1234; const rnd = () => { seed = (Math.imul(seed, 1103515245) + 12345) >>> 0; return seed >>> 8; };
const bytes = (n) => Uint8Array.from({ length: n }, () => rnd() & 0xff);
const dec = k.getAddressDecoder();
const addr = () => dec.decode(bytes(32));
const SYS = k.address("11111111111111111111111111111111"), CB = k.address("ComputeBudget111111111111111111111111111111");
const ATA = k.address("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const TOK = [k.address("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"), k.address("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")];
const R = k.AccountRole, enc = k.getAddressEncoder();
const le = (n, v) => { const b = new Uint8Array(n); let x = BigInt(v); for (let i = 0; i < n; i++) { b[i] = Number(x & 0xffn); x >>= 8n } return b };
const cat = (...a) => Uint8Array.from(a.flatMap((x) => [...x]));
const ataOf = async (owner, mint, tp) => (await k.getProgramDerivedAddress({ programAddress: ATA, seeds: [enc.encode(owner), enc.encode(tp), enc.encode(mint)] }))[0];
const out = [];
for (let i = 0; i < 120; i++) {
  const from = addr(), to = addr(), blockhash = addr();
  const kind = ["send", "sweep", "token"][i % 3];
  const priority = i % 4 >= 2 ? [BigInt(rnd() % 50000), (rnd() % 400000) + 1000] : null;
  const ixs = [];
  if (priority) {
    ixs.push({ programAddress: CB, accounts: [], data: cat([2], le(4, priority[1])) });
    ixs.push({ programAddress: CB, accounts: [], data: cat([3], le(8, priority[0])) });
  }
  const c = { from, to, blockhash, kind, priority: priority && [priority[0].toString(), priority[1]] };
  if (kind !== "token") {
    let lam = BigInt(rnd()) * 1000n + 1n;
    if (kind === "sweep") {
      const fee = 5000n + (priority ? (priority[0] * BigInt(priority[1]) + 999999n) / 1000000n : 0n);
      c.balance = (lam + fee).toString();
    } else c.lamports = lam.toString();
    c.expect_lamports = lam.toString();
    ixs.push({ programAddress: SYS, accounts: [{ address: from, role: R.WRITABLE_SIGNER }, { address: to, role: R.WRITABLE }], data: cat(le(4, 2), le(8, lam)) });
  } else {
    const mint = addr(), tp = TOK[i % 2], amount = BigInt(rnd()) * 7n + 1n, decimals = rnd() % 10, create = (i % 6) < 3;
    Object.assign(c, { mint, token_program: tp, amount: amount.toString(), decimals, create_ata: create });
    const src = await ataOf(from, mint, tp), dst = await ataOf(to, mint, tp);
    if (create) ixs.push({ programAddress: ATA, accounts: [{ address: from, role: R.WRITABLE_SIGNER }, { address: dst, role: R.WRITABLE }, { address: to, role: R.READONLY }, { address: mint, role: R.READONLY }, { address: SYS, role: R.READONLY }, { address: tp, role: R.READONLY }], data: Uint8Array.of(1) });
    ixs.push({ programAddress: tp, accounts: [{ address: src, role: R.WRITABLE }, { address: mint, role: R.READONLY }, { address: dst, role: R.WRITABLE }, { address: from, role: R.READONLY_SIGNER }], data: cat([12], le(8, amount), [decimals]) });
  }
  const msg = k.pipe(k.createTransactionMessage({ version: "legacy" }), (m) => k.setTransactionMessageFeePayer(from, m),
    (m) => k.setTransactionMessageLifetimeUsingBlockhash({ blockhash, lastValidBlockHeight: 1n }, m), (m) => k.appendTransactionMessageInstructions(ixs, m));
  c.tx = Buffer.from(k.getTransactionEncoder().encode(k.compileTransaction(msg))).toString("hex");
  out.push(c);
}
console.log(JSON.stringify(out, null, 0).replace(/\},\{/g, "},\n{"));
