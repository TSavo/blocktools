// Solana v1 (SIMD-0385) wire transactions built and signed with @solana/kit 8.5 using throwaway
// deterministic keys (bytes 1..32 style; public test vectors only). Output: hex wire tx + kit's own decode.
import * as k from "@solana/kit";
const enc = k.getTransactionEncoder(), hex = (b) => Buffer.from(b).toString("hex");
const kp = (n) => k.createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(n)); // throwaway
const SYS = k.address("11111111111111111111111111111111");
const MEMO = k.address("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const bh = { blockhash: k.address("EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N"), lastValidBlockHeight: 100n };
const transfer = (from, to, lamports) => { const d = new Uint8Array(12); new DataView(d.buffer).setUint32(0, 2, true); new DataView(d.buffer).setBigUint64(4, lamports, true);
  return { programAddress: SYS, accounts: [{ address: from.address, role: k.AccountRole.WRITABLE_SIGNER, signer: from }, { address: to, role: k.AccountRole.WRITABLE }], data: d }; };
const memo = (signer, text) => ({ programAddress: MEMO, accounts: [{ address: signer.address, role: k.AccountRole.READONLY_SIGNER, signer }], data: new TextEncoder().encode(text) });
const a = await kp(7), b = await kp(9), dest = (await kp(11)).address;
const base = (payer) => k.pipe(k.createTransactionMessage({ version: 1 }), (m) => k.setTransactionMessageFeePayerSigner(payer, m), (m) => k.setTransactionMessageLifetimeUsingBlockhash(bh, m));
const out = [];
const add = async (name, msg, opt = {}) => {
  let tx = opt.partial ? await k.partiallySignTransactionMessageWithSigners(msg) : await k.signTransactionMessageWithSigners(msg);
  const bytes = new Uint8Array(enc.encode(tx));
  out.push({ name, hex: hex(bytes), fee_payer: a.address, signers: Object.keys(tx.signatures), message_hex: hex(tx.messageBytes) });
};
await add("v1 transfer", k.appendTransactionMessageInstruction(transfer(a, dest, 12345n), base(a)));
let m = k.appendTransactionMessageInstruction(transfer(a, dest, 5000n), base(a));
m = k.setTransactionMessageComputeUnitLimit(200000, m); m = k.setTransactionMessagePriorityFeeLamports(7777n, m); m = k.setTransactionMessageHeapSize(64 * 1024, m); m = k.setTransactionMessageLoadedAccountsDataSizeLimit(65536, m);
await add("v1 transfer all config", m);
m = k.appendTransactionMessageInstructions([transfer(a, dest, 1n), memo(b, "hello v1")], base(a));
m = k.setTransactionMessageComputeUnitLimit(1400, m);
await add("v1 two signers memo cu", m);
console.log(JSON.stringify(out, null, 1));
