// Independent oracle for blocktools::build: viem serializeTransaction/keccak256 for buildEvmTransfer,
// and a direct TS transcription of SwapChan utxochains.ts selection policy (own-script filter,
// value < rate*148*20 dropped, largest-first stable, 200 cap) for selectUtxos.
import { serializeTransaction, keccak256, encodeFunctionData, parseAbi } from "viem";
const R = (n: number) => { let s = n >>> 0; return () => ((s = (s * 1103515245 + 12345) >>> 0) / 2 ** 32); };
const rnd = R(7);
const A = (i: number) => ("0x" + i.toString(16).padStart(2, "0").repeat(20)) as `0x${string}`;
const evm: any[] = [];
const chains = [1, 10, 56, 61, 137, 250, 8453, 42161, 43114, 2020, 1284, 11155111];
for (let i = 0; i < 120; i++) {
  const chainId = chains[i % chains.length];
  const gas = BigInt([21000, 65000, 100000][i % 3]);
  const gasPrice = BigInt(Math.floor(rnd() * 1e12)) + 1n;
  const nonce = BigInt(Math.floor(rnd() * 5000));
  const to = A(1 + (i % 200));
  const tokenMode = i % 4 === 1;
  const sweep = i % 3 === 2;
  const tip = i % 5 === 3 ? gasPrice / 2n : undefined;
  const balance = gas * gasPrice + BigInt(Math.floor(rnd() * 1e15)) + 1n;
  const amount = BigInt(Math.floor(rnd() * 1e18)) + 1n;
  const token = tokenMode ? A(0xee) : undefined;
  const value = tokenMode ? 0n : sweep ? balance - gas * gasPrice : amount;
  const data = tokenMode ? encodeFunctionData({ abi: parseAbi(["function transfer(address,uint256)"]), args: [to, sweep ? balance : amount] }) : "0x";
  const base: any = { chainId, nonce: Number(nonce), gas, to: token ?? to, value, data };
  const tx = tip !== undefined ? { ...base, type: "eip1559", maxFeePerGas: gasPrice, maxPriorityFeePerGas: tip } : { ...base, type: "legacy", gasPrice };
  const unsigned = serializeTransaction(tx);
  const req: any = { chainId, nonce: nonce.toString(), gas: i % 2 ? gas.toString() : Number(gas), gasPrice: i % 7 === 0 ? "0x" + gasPrice.toString(16) : gasPrice.toString(), to };
  if (sweep) req.balance = balance.toString(); else req.value = amount.toString();
  if (token) req.token = token;
  if (tip !== undefined) req.maxPriorityFeePerGas = tip.toString();
  evm.push({ name: `evm ${i}`, req, expect: { unsigned, sighash: keccak256(unsigned), value: value.toString(), fee: (gas * gasPrice).toString() } });
}
const errs: [string, any, string][] = [
  ["no chain", { nonce: 0, gas: 21000, gasPrice: "1", to: A(1), value: "1" }, "missing_chainId"],
  ["low gas", { chainId: 1, nonce: 0, gas: 20999, gasPrice: "1", to: A(1), value: "1" }, "bad_gas"],
  ["bad to", { chainId: 1, nonce: 0, gas: 21000, gasPrice: "1", to: "0x12", value: "1" }, "bad_to"],
  ["both", { chainId: 1, nonce: 0, gas: 21000, gasPrice: "1", to: A(1), value: "1", balance: "5" }, "value_and_balance"],
  ["poor", { chainId: 1, nonce: 0, gas: 21000, gasPrice: "1", to: A(1), balance: "21000" }, "insufficient_balance"],
  ["zero", { chainId: 1, nonce: 0, gas: 21000, gasPrice: "1", to: A(1), value: "0" }, "zero_value"],
  ["neg", { chainId: 1, nonce: 0, gas: 21000, gasPrice: "1", to: A(1), value: "-1" }, "bad_value"],
  ["tip", { chainId: 1, nonce: 0, gas: 21000, gasPrice: "1", to: A(1), value: "1", maxPriorityFeePerGas: "2" }, "tip_above_max_fee"],
  ["float", { chainId: 1, nonce: 0, gas: 21000, gasPrice: 1.5, to: A(1), value: "1" }, "bad_gasPrice"],
];
for (const [name, req, e] of errs) evm.push({ name, req, error: e });

// selectUtxos reference (transcribed policy)
function select(utxos: any[], script: string, rate: bigint) {
  const min = rate * 148n * 20n; const own = script.toLowerCase();
  let foreign = 0, unecon = 0;
  const keep = utxos.filter(u => { if (String(u.script).toLowerCase() !== own) { foreign++; return false }
    if (BigInt(u.value) < min) { unecon++; return false } return true; });
  keep.sort((a, b) => (BigInt(b.value) > BigInt(a.value) ? 1 : BigInt(b.value) < BigInt(a.value) ? -1 : 0));
  const cap = Math.max(0, keep.length - 200); const sel = keep.slice(0, 200);
  return { selected: sel, total: sel.reduce((s, u) => s + BigInt(u.value), 0n).toString(), count: sel.length,
    dropped_foreign: foreign, dropped_uneconomic: unecon, dropped_cap: cap, min_value: min.toString() };
}
const sel: any[] = [];
const OWN = "76a914" + "ab".repeat(20) + "88ac", OTH = "0014" + "cd".repeat(20);
for (let i = 0; i < 40; i++) {
  const n = [0, 1, 5, 50, 199, 200, 201, 450][i % 8];
  const rate = BigInt([0, 1, 2, 10, 50][i % 5]);
  const utxos = Array.from({ length: n }, (_, k) => ({ txid: k.toString(16).padStart(64, "0"), vout: k % 3,
    value: rnd() < 0.3 ? Math.floor(rnd() * 3000) : rnd() < 0.5 ? 5000 : Math.floor(rnd() * 2e8),
    script: rnd() < 0.15 ? OTH : (rnd() < 0.2 ? OWN.toUpperCase() : OWN) }));
  sel.push({ name: `sel ${i}`, utxos, script: OWN, rate: Number(rate), expect: select(utxos, OWN, rate) });
}
console.log(JSON.stringify({ evm, select: sel }));
