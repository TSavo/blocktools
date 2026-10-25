import { verifyRecovery, verifySweepTx, STANDARD_RECOVERY, setNow, MULTISEND_CALL_ONLY, ownerSig } from "./verifier.ts";
import { encodeFunctionData, encodeAbiParameters, encodePacked, concat, size, parseAbiItem, type Hex } from "viem";
const NOW_S = 1761400000; setNow(NOW_S * 1000);
const OWNER = "0x1111111111111111111111111111111111111111", OTHER = "0x2222222222222222222222222222222222222222";
const cases: any[] = [];
const rec = (name: string, tx: any, owner = OWNER) => { const v = verifyRecovery(tx, owner); cases.push({ kind: "recovery", name, tx, owner, expect: v }); };
const sw = (name: string, tx: any, owner: string, chainId: number, token?: string) => { const v = verifySweepTx(tx, owner, chainId, token); cases.push({ kind: "sweep", name, tx, owner, chainId, ...(token ? { token } : {}), expect: v }); };
const fnA = (s: string) => parseAbiItem(`function ${s}`) as any;
function val(p: any, addr: string, big: bigint): any {
  const t: string = p.type;
  if (t.endsWith("[]")) return [val({ ...p, type: t.slice(0, -2) }, addr, big)];
  if (t === "tuple") return p.components.map((c: any) => val(c, addr, big));
  if (t === "address") return addr; if (t === "bool") return true; if (t === "bytes") return "0x";
  if (t.startsWith("bytes")) return "0x" + "ab".repeat(Number(t.slice(5)));
  if (t.startsWith("uint")) return big; if (t.startsWith("int")) return 5; return 0;
}
const D_OK = BigInt(NOW_S + 1200), D_FAR = BigInt(NOW_S + 7200);
for (const s of STANDARD_RECOVERY) {
  const a = fnA(s.sig);
  for (const [lbl, addr] of [["owner", OWNER], ["other", OTHER]] as const) {
    for (const big of [0n, 7n, D_OK, D_FAR]) {
      const args = a.inputs.map((p: any) => val(p, addr, big));
      // mixed: owner args to owner, others to OTHER
      const mixed = a.inputs.map((p: any, i: number) => s.owners.includes(i) ? val(p, OWNER, big) : val(p, OTHER, big));
      if (s.owners.includes(-1)) mixed[0][1] = OWNER; if (s.owners.includes(-2)) mixed[0][2] = OWNER;
      for (const [k, ar] of [[lbl, args], ["mixed", mixed]] as const) {
        try { const data = encodeFunctionData({ abi: [a], args: ar }); rec(`${s.sig} ${k} ${big}`, { to: OTHER, data, value: "0" });
          if (big === 7n && k === "mixed") { rec(`${s.sig} value`, { to: OTHER, data, value: "1" }); rec(`${s.sig} trunc`, { to: OTHER, data: data.slice(0, data.length - 8), value: "0" }); rec(`${s.sig} extra`, { to: OTHER, data: data + "00".repeat(32), value: "0" }); } } catch (e) { }
      }
    }
  }
}
// multicall
const MC = fnA("multicall(bytes[])"), W = encodeFunctionData({ abi: [fnA("withdraw()")] }), GR = (a: string) => encodeFunctionData({ abi: [fnA("getReward(address)")], args: [a] });
rec("multicall ok", { to: OTHER, data: encodeFunctionData({ abi: [MC], args: [[W, GR(OWNER)]] }), value: "0" });
rec("multicall bad", { to: OTHER, data: encodeFunctionData({ abi: [MC], args: [[W, GR(OTHER)]] }), value: "0" });
rec("multicall empty", { to: OTHER, data: encodeFunctionData({ abi: [MC], args: [[]] }), value: "0" });
rec("multicall nested", { to: OTHER, data: encodeFunctionData({ abi: [MC], args: [[encodeFunctionData({ abi: [MC], args: [[W]] })]] }), value: "0" });
// pinned
const AP = (sp: string) => encodeFunctionData({ abi: [fnA("approve(address,uint256)")], args: [sp, 5n] });
rec("approve pendle", { to: OTHER, data: AP("0x888888888889758F76e7103c6CbF23ABbF58F946"), value: "0" });
rec("approve other", { to: OTHER, data: AP(OTHER), value: "0" });
rec("thedao approve", { to: "0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413", data: AP("0xbf4ed7b27f1d666546e30d74d50d173d20bca754"), value: "0" });
rec("thedao approve wrong token", { to: OTHER, data: AP("0xbf4ed7b27f1d666546e30d74d50d173d20bca754"), value: "0" });
rec("withdrawdao", { to: "0xbf4ed7b27f1d666546e30d74d50d173d20bca754", data: "0x3ccfd60b", value: "0" });
rec("withdrawdao elsewhere", { to: OTHER, data: "0x3ccfd60b", value: "0" });
rec("arb outbox", { to: "0x0B9857ae2D4A3DBe74ffE1d7DF045bb7F96E4840", data: "0x08635a95" + "00".repeat(64), value: "0" });
rec("arb outbox wrong", { to: OTHER, data: "0x08635a95" + "00".repeat(64), value: "0" });
for (const sel of ["4870496f", "43ca1c50", "4870496F"]) rec("op portal " + sel, { to: "0xbEb5Fc579115071764c7423A4f75eDeDa441Ec71", data: "0x" + sel + "00".repeat(32), value: "0" });
rec("ironhands", { to: "0xE58b65d1c0C8e8b2a0e3A3AcEC633271531084ED", data: "0x63bd1d4a", value: "0" });
rec("ironhands wrong to", { to: OTHER, data: "0x63bd1d4a", value: "0" });
rec("garbage", { to: OTHER, data: "0xdeadbeef", value: "0" });
rec("empty", { to: OTHER, data: "0x", value: "0" });
rec("value hex", { to: OTHER, data: W, value: "0x0" });
// safe
const EXEC = fnA("execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures)");
const MS = fnA("multiSend(bytes transactions)"), XF = fnA("transfer(address to, uint256 amount)"), Z = "0x0000000000000000000000000000000000000000";
const xf = (to: string, a = 9n) => encodeFunctionData({ abi: [XF], args: [to, a] });
const ex = (to: string, v: bigint, d: Hex, op: number, gp = 0n, gt = Z, rr = Z) => encodeFunctionData({ abi: [EXEC], args: [to, v, d, op, 0n, 0n, gp, gt, rr, ownerSig(OWNER)] });
const pk = (legs: [number, string, bigint, Hex][]) => encodeFunctionData({ abi: [MS], args: [concat(legs.map(([o, t, v, d]) => encodePacked(["uint8", "address", "uint256", "uint256", "bytes"], [o, t as Hex, v, BigInt(size(d)), d])))] });
const TOK = "0x3333333333333333333333333333333333333333";
rec("safe native", { to: OTHER, data: ex(OWNER, 5n, "0x", 0), value: "0" });
rec("safe native calldata", { to: OTHER, data: ex(OWNER, 5n, "0x1234", 0), value: "0" });
rec("safe token", { to: OTHER, data: ex(TOK, 0n, xf(OWNER), 0), value: "0" });
rec("safe token other", { to: OTHER, data: ex(TOK, 0n, xf(OTHER), 0), value: "0" });
rec("safe token value", { to: OTHER, data: ex(TOK, 1n, xf(OWNER), 0), value: "0" });
rec("safe gasprice", { to: OTHER, data: ex(OWNER, 5n, "0x", 0, 1n), value: "0" });
rec("safe refund", { to: OTHER, data: ex(OWNER, 5n, "0x", 0, 0n, Z, OTHER), value: "0" });
for (const m of MULTISEND_CALL_ONLY) rec("safe multisend " + m, { to: OTHER, data: ex(m, 0n, pk([[0, OWNER, 3n, "0x"], [0, TOK, 0n, xf(OWNER)]]), 1), value: "0" });
rec("safe multisend bad leg", { to: OTHER, data: ex(MULTISEND_CALL_ONLY[0]!, 0n, pk([[0, OWNER, 3n, "0x"], [0, TOK, 0n, xf(OTHER)]]), 1), value: "0" });
rec("safe multisend delegate leg", { to: OTHER, data: ex(MULTISEND_CALL_ONLY[0]!, 0n, pk([[1, OWNER, 3n, "0x"]]), 1), value: "0" });
rec("safe multisend wrong contract", { to: OTHER, data: ex(OTHER, 0n, pk([[0, OWNER, 3n, "0x"]]), 1), value: "0" });
rec("safe op2", { to: OTHER, data: ex(OWNER, 0n, "0x", 2), value: "0" });
rec("safe multisend empty", { to: OTHER, data: ex(MULTISEND_CALL_ONLY[0]!, 0n, encodeFunctionData({ abi: [MS], args: ["0x"] }), 1), value: "0" });
rec("safe truncated", { to: OTHER, data: ex(OWNER, 5n, "0x", 0).slice(0, 100), value: "0" });
// v4
const MOD = fnA("modifyLiquidities(bytes unlockData, uint256 deadline)");
const dec = (L: bigint, m0: bigint, m1: bigint) => encodeAbiParameters([{ type: "uint256" }, { type: "uint256" }, { type: "uint128" }, { type: "uint128" }, { type: "bytes" }], [1n, L, m0, m1, "0x"]);
const take = (to: string) => encodeAbiParameters([{ type: "address" }, { type: "address" }, { type: "address" }], [Z, TOK, to as Hex]);
const v4 = (acts: Hex, ps: Hex[], dl = D_OK) => encodeFunctionData({ abi: [MOD], args: [encodeAbiParameters([{ type: "bytes" }, { type: "bytes[]" }], [acts, ps]), dl] });
rec("v4 ok", { to: OTHER, data: v4("0x0111", [dec(5n, 1n, 1n), take(OWNER)]), value: "0" });
rec("v4 zero min", { to: OTHER, data: v4("0x0111", [dec(5n, 0n, 0n), take(OWNER)]), value: "0" });
rec("v4 zero liq zero min", { to: OTHER, data: v4("0x0111", [dec(0n, 0n, 0n), take(OWNER)]), value: "0" });
rec("v4 take other", { to: OTHER, data: v4("0x0111", [dec(5n, 1n, 1n), take(OTHER)]), value: "0" });
rec("v4 far deadline", { to: OTHER, data: v4("0x0111", [dec(5n, 1n, 1n), take(OWNER)], D_FAR), value: "0" });
rec("v4 no take", { to: OTHER, data: v4("0x01", [dec(5n, 1n, 1n)]), value: "0" });
rec("v4 other action", { to: OTHER, data: v4("0x0211", [dec(5n, 1n, 1n), take(OWNER)]), value: "0" });
rec("v4 count mismatch", { to: OTHER, data: v4("0x0111", [dec(5n, 1n, 1n)]), value: "0" });
rec("v4 take only", { to: OTHER, data: v4("0x11", [take(OWNER)]), value: "0" });

// adversarial decoding cases (viem semantics)
const GRo = GR(OWNER);
rec("dirty address word", { to: OTHER, data: GRo.slice(0, 10) + "ff".repeat(12) + GRo.slice(34), value: "0" });
rec("uppercase arg hex", { to: OTHER, data: GR("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").toUpperCase().replace("0X", "0x").replace(GR(OWNER).slice(2, 10).toUpperCase(), GR(OWNER).slice(2, 10)) , value: "0" }, "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd");
rec("uppercase selector", { to: OTHER, data: "0x3CCFD60B", value: "0" });
rec("uppercase safe selector", { to: OTHER, data: ex(OWNER, 5n, "0x", 0).replace("6a761202", "6A761202"), value: "0" });
const WU = encodeFunctionData({ abi: [fnA("withdrawAndUnwrap(uint256,bool)")], args: [5n, true] });
rec("bool 2", { to: OTHER, data: WU.slice(0, WU.length - 2) + "02", value: "0" });
rec("bool dirty high", { to: OTHER, data: WU.slice(0, 74) + "01" + WU.slice(76), value: "0" });
for (const v of [" 0 ", "0x00", "-0", "00", "", "0b0", "+0", "-1"]) rec("value " + JSON.stringify(v), { to: OTHER, data: W, value: v });
// offsets
const mc1 = encodeFunctionData({ abi: [MC], args: [[W]] });
rec("offset to end", { to: OTHER, data: mc1.slice(0, 10) + (BigInt((mc1.length - 10) / 2)).toString(16).padStart(64, "0") + mc1.slice(74), value: "0" });
rec("offset huge", { to: OTHER, data: mc1.slice(0, 10) + "f".repeat(64) + mc1.slice(74), value: "0" });
// recursive read limit: many elements sharing one data offset
const shared = (n: number) => { const w = (x: bigint) => x.toString(16).padStart(64, "0");
  const off = BigInt(n * 32); let h = "0xac9650d8" + w(32n) + w(BigInt(n)); for (let i = 0; i < n; i++) h += w(off);
  return h + w(4n) + "3ccfd60b".padEnd(64, "0"); };
rec("shared offsets 4000", { to: OTHER, data: shared(4000), value: "0" });
rec("shared offsets 4200", { to: OTHER, data: shared(4200), value: "0" });
let nest: Hex = W; for (let i = 0; i < 32; i++) nest = encodeFunctionData({ abi: [MC], args: [[nest]] });
rec("multicall depth 32", { to: OTHER, data: nest, value: "0" });
// multisend blob edge cases
const exb = (blob: string) => ex(MULTISEND_CALL_ONLY[0]!, 0n, encodeFunctionData({ abi: [MS], args: [("0x" + blob) as Hex] }), 1);
const hdr = (to: string, v: bigint, len: bigint) => "00" + to.slice(2) + v.toString(16).padStart(64, "0") + len.toString(16).padStart(64, "0");
rec("multisend short data to owner", { to: OTHER, data: exb(hdr(OWNER, 1n, 5n)), value: "0" });
rec("multisend short data to token", { to: OTHER, data: exb(hdr(TOK, 0n, 68n) + xf(OWNER).slice(2, 20)), value: "0" });
rec("multisend header only to", { to: OTHER, data: exb("00" + OWNER.slice(2)), value: "0" });
rec("multisend huge len", { to: OTHER, data: exb("00" + OWNER.slice(2) + "00".repeat(32) + "ff".repeat(32)), value: "0" });
rec("multisend trailing junk", { to: OTHER, data: exb(hdr(OWNER, 1n, 0n) + "01"), value: "0" });
rec("multisend uppercase owner leg", { to: OTHER, data: exb(hdr(OWNER, 1n, 0n)), value: "0" }, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
rec("safe invalid owner", { to: OTHER, data: ex(OWNER, 5n, "0x", 0), value: "0" }, "0x1111");
rec("v4 invalid owner", { to: OTHER, data: v4("0x0111", [dec(5n, 1n, 1n), take(OWNER)]), value: "0" }, "0xnotanaddress");
rec("std owner case-insensitive", { to: OTHER, data: GR("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"), value: "0" }, "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED");
// mutation fuzz over valid recovery cases
let seed = 12345; const rnd = (n: number) => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % n; };
const valid = cases.filter((c) => c.kind === "recovery").slice();
for (let i = 0; i < 400; i++) {
  const c = valid[rnd(valid.length)]; const d: string = c.tx.data; if (d.length < 12) continue;
  const pos = 2 + rnd(d.length - 2); const nib = "0123456789abcdef"[rnd(16)];
  rec(`mut ${i}`, { ...c.tx, data: d.slice(0, pos) + nib + d.slice(pos + 1) });
}
// sweep
const ERC = (to: string, a: bigint) => xf(to, a);
sw("native ok", { from: OWNER, to: OWNER, value: "100", chainId: 1 }, OWNER, 1);
sw("native zero", { from: OWNER, to: OWNER, value: "0", chainId: 1 }, OWNER, 1);
sw("native to other", { from: OWNER, to: OTHER, value: "100", chainId: 1 }, OWNER, 1);
sw("native calldata", { from: OWNER, to: OWNER, value: "100", data: "0x12", chainId: 1 }, OWNER, 1);
sw("native data 0x", { from: OWNER, to: OWNER, value: "100", data: "0x", chainId: 1 }, OWNER, 1);
sw("wrong chain", { from: OWNER, to: OWNER, value: "100", chainId: 2 }, OWNER, 1);
sw("no chain", { from: OWNER, to: OWNER, value: "100" }, OWNER, 1);
sw("chain string", { from: OWNER, to: OWNER, value: "100", chainId: "1" }, OWNER, 1);
sw("from other", { from: OTHER, to: OWNER, value: "100", chainId: 1 }, OWNER, 1);
sw("bad owner", { from: OWNER, to: OWNER, value: "100", chainId: 1 }, "0x12", 1);
sw("bad to", { from: OWNER, to: "0x12", value: "100", chainId: 1 }, OWNER, 1);
sw("checksum mixed ok", { from: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", to: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", value: "1", chainId: 1 }, "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED", 1);
sw("bad checksum", { from: "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD", to: "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", value: "1", chainId: 1 }, "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed", 1);
sw("token ok", { from: OWNER, to: TOK, value: "0", data: ERC(OWNER, 5n), chainId: 56 }, OWNER, 56, TOK);
sw("token zero amt", { from: OWNER, to: TOK, value: "0", data: ERC(OWNER, 0n), chainId: 56 }, OWNER, 56, TOK);
sw("token other", { from: OWNER, to: TOK, value: "0", data: ERC(OTHER, 5n), chainId: 56 }, OWNER, 56, TOK);
sw("token value", { from: OWNER, to: TOK, value: "1", data: ERC(OWNER, 5n), chainId: 56 }, OWNER, 56, TOK);
sw("token wrong contract", { from: OWNER, to: OTHER, value: "0", data: ERC(OWNER, 5n), chainId: 56 }, OWNER, 56, TOK);
sw("token approve", { from: OWNER, to: TOK, value: "0", data: AP(OWNER), chainId: 56 }, OWNER, 56, TOK);
sw("token garbage", { from: OWNER, to: TOK, value: "0", data: "0xdeadbeef", chainId: 56 }, OWNER, 56, TOK);
sw("token no data", { from: OWNER, to: TOK, value: "0", chainId: 56 }, OWNER, 56, TOK);
sw("value hex", { from: OWNER, to: OWNER, value: "0x10", chainId: 1 }, OWNER, 1);
sw("value array", { from: OWNER, to: OWNER, value: [10], chainId: 1 }, OWNER, 1);
sw("value bool", { from: OWNER, to: OWNER, value: true, chainId: 1 }, OWNER, 1);
sw("value float", { from: OWNER, to: OWNER, value: 1.5, chainId: 1 }, OWNER, 1);
sw("value negative", { from: OWNER, to: OWNER, value: "-5", chainId: 1 }, OWNER, 1);
sw("value null", { from: OWNER, to: OWNER, value: null, chainId: 1 }, OWNER, 1);
sw("chain float", { from: OWNER, to: OWNER, value: "1", chainId: 1.0 }, OWNER, 1);
sw("token uppercase selector", { from: OWNER, to: TOK, value: "0", data: ERC(OWNER, 5n).replace("a9059cbb", "A9059CBB"), chainId: 56 }, OWNER, 56, TOK);
sw("token transferFrom", { from: OWNER, to: TOK, value: "0", data: encodeFunctionData({ abi: [fnA("transferFrom(address,address,uint256)")], args: [OWNER, OWNER, 5n] }), chainId: 56 }, OWNER, 56, TOK);
sw("token truncated", { from: OWNER, to: TOK, value: "0", data: ERC(OWNER, 5n).slice(0, 40), chainId: 56 }, OWNER, 56, TOK);
sw("token short sel", { from: OWNER, to: TOK, value: "0", data: "0xa905", chainId: 56 }, OWNER, 56, TOK);
sw("bad token addr", { from: OWNER, to: TOK, value: "0", data: ERC(OWNER, 5n), chainId: 56 }, OWNER, 56, "0x33");
sw("value number", { from: OWNER, to: OWNER, value: 10, chainId: 1 }, OWNER, 1);
console.log(JSON.stringify({ now_s: NOW_S, pendle_router: "0x888888888889758f76e7103c6cbf23abbf58f946", cases }, null, 0));
