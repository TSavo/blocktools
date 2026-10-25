// Regenerates SwapChan's buildBtcPsbt fixtures (btc.ts, verbatim) for blocktools buildPsbtWithMemo parity.
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
console.log(JSON.stringify(out));
