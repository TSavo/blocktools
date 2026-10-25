// Regenerates SwapChan's buildBtcPsbt fixtures (btc.ts, verbatim) for blocktools buildPsbtWithMemo parity.
import { Psbt } from "bitcoinjs-lib";
import { buildBtcPsbt, type Utxo } from "./btc.ts";
const FROM = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"; // BIP-173 public vector
const TO = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";
const memos = ["", "=:ETH.ETH:0x0000000000000000000000000000000000000001", "x".repeat(75), "y".repeat(76), "z".repeat(80)];
const out: any[] = [];
let seed = 3; const rnd = () => ((seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32);
for (let n = 1; n <= 5; n++) for (const rate of [1, 2, 5, 8, 13, 22]) for (const memo of memos) {
  const utxos: Utxo[] = Array.from({ length: 6 }, (_, i) => ({ txid: (n * 1000 + rate * 10 + i).toString(16).padStart(64, "a"), vout: i % 2, value: 20000 + Math.floor(rnd() * 5000) }));
  const sorted = [...utxos].sort((a, b) => b.value - a.value);
  // amount needing exactly n inputs: just above the sum of n-1 inputs (minus fee), below n
  const sumN = sorted.slice(0, n).reduce((s, u) => s + u.value, 0);
  const amount = BigInt(sumN - 3000 - rate * 400);
  const name = `n${n} r${rate} m${memo.length}`;
  try {
    const psbt = await buildBtcPsbt(async () => utxos, { from: FROM, to: TO, amount, memo: memo || undefined, feeRate: rate });
    out.push({ name, from: FROM, to: TO, amount: amount.toString(), memo, feeRate: rate, utxos, psbt });
  } catch (e: any) { out.push({ name, from: FROM, to: TO, amount: amount.toString(), memo, feeRate: rate, utxos, error: e.message }); }
}
// Regressions reported by SwapChan (exact inputs). 2026-10-25: 76-byte memo, rate 22, 5 UTXOs = 89494, send 44747:
// btc.ts folds the sub-dust change into the fee; blocktools refused with "memo fee leaves dust".
const regress: { name: string; vals: number[]; amount: bigint; memo: string; feeRate: number }[] = [
  { name: "swapchan fold r22 m76", vals: [21259, 30300, 7443, 18169, 12323], amount: 44747n, memo: "y".repeat(76), feeRate: 22 },
];
for (const r of regress) {
  const utxos: Utxo[] = r.vals.map((value, i) => ({ txid: (0xc0de00 + i).toString(16).padStart(64, "b"), vout: i % 2, value }));
  const psbt = await buildBtcPsbt(async () => utxos, { from: FROM, to: TO, amount: r.amount, memo: r.memo, feeRate: r.feeRate });
  out.push({ name: r.name, from: FROM, to: TO, amount: r.amount.toString(), memo: r.memo, feeRate: r.feeRate, utxos, psbt });
}
// btc.ts never sets nSequence, so every input is 0xffffffff (final, non-RBF): THORChain inbound txs must not be RBF.
// Recorded per vector so the Rust parity test checks buildPsbtWithMemo's default (rbf=false) against it.
for (const o of out) if (o.psbt) o.sequences = Psbt.fromBase64(o.psbt).txInputs.map(i => (i.sequence ?? 0xffffffff).toString(16));
console.log(JSON.stringify(out));
