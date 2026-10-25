import { decodeAbiParameters, encodeAbiParameters, encodeFunctionData, formatUnits, getAddress, keccak256, parseAbiItem } from "viem";
import { evmClient, prices, pxOf } from "./onchain.js";
import type { NewFound } from "./recover.js";
import { deadlineOk, exitDeadline, minOut, PRIVATE_SUBMISSION_NOTE } from "./exitguard.js";

/** Uniswap v4 positions (Ethereum, Base, Arbitrum, Optimism). Ids from Blockscout ERC-721 transfers + ownerOf.
 *  Principal is exact (bigint TickMath at the current sqrtPrice), fees exact from fee-growth accounting.
 *  Exit tx: modifyLiquidities([DECREASE_LIQUIDITY(all), TAKE_PAIR(to owner)]). */
type F = typeof fetch;
export const V4 = [
  { chainId: 1, pm: "0xbd216513d74c8cf14cf4747e6aaa6420ff64ee9e", sv: "0x7ffe42c4a5deea5b0fec41c94c136cf115597227", bs: "https://eth.blockscout.com" },
  { chainId: 8453, pm: "0x7c5f5a4bbd8fd63184577525326123b519429bdc", sv: "0xa3c0c9b65bad0b08107aa264b0f3db444b867a71", bs: "https://base.blockscout.com" },
  { chainId: 42161, pm: "0xd88f38f930b7952f2db2432cb002e7abbf3dd869", sv: "0x76fd297e2d437cd7f76d50f01afe6160f86e9990", bs: "https://arbitrum.blockscout.com" },
  { chainId: 10, pm: "0x3c3ea4b57a46241e54610e5f022e5c45859a1017", sv: "0xc18a3169788f4f75a170290584eca6395c75ecdb", bs: "https://optimism.blockscout.com" },
] as const;
const Q96 = 2n ** 96n, Q128 = 2n ** 128n, M256 = 2n ** 256n;
export function sqrtAtTick(tick: number): bigint {
  const a = BigInt(Math.abs(tick));
  let r = a & 1n ? 0xfffcb933bd6fad37aa2d162d1a594001n : 0x100000000000000000000000000000000n;
  const k: [bigint, bigint][] = [[2n, 0xfff97272373d413259a46990580e213an], [4n, 0xfff2e50f5f656932ef12357cf3c7fdccn], [8n, 0xffe5caca7e10e4e61c3624eaa0941cd0n], [16n, 0xffcb9843d60f6159c9db58835c926644n], [32n, 0xff973b41fa98c081472e6896dfb254c0n], [64n, 0xff2ea16466c96a3843ec78b326b52861n], [128n, 0xfe5dee046a99a2a811c461f1969c3053n], [256n, 0xfcbe86c7900a88aedcffc83b479aa3a4n], [512n, 0xf987a7253ac413176f2b074cf7815e54n], [1024n, 0xf3392b0822b70005940c7a398e4b70f3n], [2048n, 0xe7159475a2c29b7443b29c7fa6e889d9n], [4096n, 0xd097f3bdfd2022b8845ad8f792aa5825n], [8192n, 0xa9f746462d870fdf8a65dc1f90e061e5n], [16384n, 0x70d869a156d2a1b890bb3df62baf32f7n], [32768n, 0x31be135f97d08fd981231505542fcfa6n], [65536n, 0x9aa508b5b7a84e1c677de54f3e99bc9n], [131072n, 0x5d6af8dedb81196699c329225ee604n], [262144n, 0x2216e584f5fa1ea926041bedfe98n], [524288n, 0x48a170391f7dc42444e8fa2n]];
  for (const [b, m] of k) if (a & b) r = (r * m) >> 128n;
  if (tick > 0) r = (M256 - 1n) / r;
  return (r >> 32n) + (r % (1n << 32n) === 0n ? 0n : 1n);
}
export function amountsFor(L: bigint, sp: bigint, sa: bigint, sb: bigint): [bigint, bigint] {
  if (sa > sb) [sa, sb] = [sb, sa];
  const a0 = (lo: bigint, hi: bigint) => (L * Q96 * (hi - lo)) / hi / lo;
  const a1 = (lo: bigint, hi: bigint) => (L * (hi - lo)) / Q96;
  if (sp <= sa) return [a0(sa, sb), 0n];
  if (sp >= sb) return [0n, a1(sa, sb)];
  return [a0(sp, sb), a1(sa, sp)];
}
const s24 = (x: bigint) => { const v = Number(x & 0xffffffn); return v >= 0x800000 ? v - 0x1000000 : v; };
export const unpackInfo = (info: bigint) => ({ tickLower: s24(info >> 8n), tickUpper: s24(info >> 32n) });

const MOD = parseAbiItem("function modifyLiquidities(bytes unlockData, uint256 deadline) payable");
/** principal = quoted principal out (from pool state, fees excluded: v4 checks mins against principal only). */
export function v4ExitTx(chainId: number, pm: string, id: bigint, L: bigint, c0: string, c1: string, owner: `0x${string}`, principal: readonly [bigint, bigint], nowMs = Date.now()) {
  const dec = encodeAbiParameters([{ type: "uint256" }, { type: "uint256" }, { type: "uint128" }, { type: "uint128" }, { type: "bytes" }], [id, L, minOut(principal[0]), minOut(principal[1]), "0x"]);
  const take = encodeAbiParameters([{ type: "address" }, { type: "address" }, { type: "address" }], [c0 as `0x${string}`, c1 as `0x${string}`, owner]);
  const unlock = encodeAbiParameters([{ type: "bytes" }, { type: "bytes[]" }], ["0x0111", [dec, take]]);
  return { chainId, to: pm, value: "0", data: encodeFunctionData({ abi: [MOD], args: [unlock, exitDeadline(nowMs)] }), description: `Remove all liquidity from v4 position #${id} and take both tokens to your wallet` };
}
/** Only DECREASE_LIQUIDITY (0x01) and TAKE_PAIR (0x11) with recipient == owner are allowed. */
export function verifyV4(data: string, owner: string): boolean | null {
  if (!data.startsWith("0xdd46508f")) return null;
  try {
    const [unlock, deadline] = decodeAbiParameters([{ type: "bytes" }, { type: "uint256" }], `0x${data.slice(10)}`);
    if (!deadlineOk(deadline)) return false;
    const [acts, params] = decodeAbiParameters([{ type: "bytes" }, { type: "bytes[]" }], unlock);
    const a = acts.slice(2).match(/../g) ?? [];
    if (a.length !== params.length || !a.length) return false;
    let took = false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] === "01") {
        const [, liq, m0, m1] = decodeAbiParameters([{ type: "uint256" }, { type: "uint256" }, { type: "uint128" }, { type: "uint128" }, { type: "bytes" }], params[i]!);
        if (liq > 0n && m0 === 0n && m1 === 0n) return false; // zero-minimum decrease is sandwichable
        continue;
      }
      if (a[i] !== "11") return false;
      const [, , to] = decodeAbiParameters([{ type: "address" }, { type: "address" }, { type: "address" }], params[i]!);
      if (getAddress(to) !== getAddress(owner)) return false;
      took = true;
    }
    return took;
  } catch { return false; }
}

const KEY = "(address currency0,address currency1,uint24 fee,int24 tickSpacing,address hooks)";
export async function v4Positions(f: F, env: NodeJS.ProcessEnv, owner: `0x${string}`): Promise<NewFound[]> {
  const meta = new Map<string, { symbol: string; decimals: number }>();
  const per = await Promise.all(V4.map(async (v) => {
    const cand = new Set<string>();
    let q = "";
    for (let page = 0; page < 3; page++) {
      const r = await f(`${v.bs}/api/v2/addresses/${owner}/token-transfers?type=ERC-721&filter=to&token=${v.pm}${q}`, { signal: AbortSignal.timeout(6000) }).catch(() => null);
      if (!r?.ok) break;
      const d = (await r.json()) as { items: { total?: { token_id?: string } }[]; next_page_params: Record<string, unknown> | null };
      for (const it of d.items) if (it.total?.token_id) cand.add(it.total.token_id);
      if (!d.next_page_params) break;
      q = "&" + new URLSearchParams(Object.entries(d.next_page_params).map(([k, x]) => [k, String(x)])).toString();
    }
    if (!cand.size) return [];
    const c = evmClient(v.chainId, env);
    const ids = [...cand].slice(0, 60).map(BigInt);
    const pm = v.pm as `0x${string}`, sv = v.sv as `0x${string}`;
    const r = await c.multicall({ allowFailure: true, contracts: ids.flatMap((id) => [
      { address: pm, abi: [parseAbiItem("function ownerOf(uint256) view returns (address)")], functionName: "ownerOf", args: [id] },
      { address: pm, abi: [parseAbiItem(`function getPoolAndPositionInfo(uint256) view returns (${KEY}, uint256)`)], functionName: "getPoolAndPositionInfo", args: [id] },
      { address: pm, abi: [parseAbiItem("function getPositionLiquidity(uint256) view returns (uint128)")], functionName: "getPositionLiquidity", args: [id] },
    ]) as never[] });
    const out = (await Promise.all(ids.map(async (_, i) => {
      const o = r[3 * i]?.result as string | undefined;
      if (!o || getAddress(o) !== getAddress(owner)) return null;
      const pi = r[3 * i + 1]?.result as unknown as [{ currency0: string; currency1: string; fee: number; tickSpacing: number; hooks: string }, bigint] | undefined;
      const L = (r[3 * i + 2]?.result as unknown as bigint) ?? 0n;
      if (!pi) return null;
      const [key, info] = pi;
      const { tickLower, tickUpper } = unpackInfo(info);
      const poolId = keccak256(encodeAbiParameters([{ type: "address" }, { type: "address" }, { type: "uint24" }, { type: "int24" }, { type: "address" }], [key.currency0 as `0x${string}`, key.currency1 as `0x${string}`, key.fee, key.tickSpacing, key.hooks as `0x${string}`]));
      const salt = `0x${ids[i]!.toString(16).padStart(64, "0")}` as `0x${string}`;
      const [s0, fg, pinfo] = await Promise.all([
        c.readContract({ address: sv, abi: [parseAbiItem("function getSlot0(bytes32) view returns (uint160,int24,uint24,uint24)")], functionName: "getSlot0", args: [poolId] }),
        c.readContract({ address: sv, abi: [parseAbiItem("function getFeeGrowthInside(bytes32,int24,int24) view returns (uint256,uint256)")], functionName: "getFeeGrowthInside", args: [poolId, tickLower, tickUpper] }),
        c.readContract({ address: sv, abi: [parseAbiItem("function getPositionInfo(bytes32,address,int24,int24,bytes32) view returns (uint128,uint256,uint256)")], functionName: "getPositionInfo", args: [poolId, pm, tickLower, tickUpper, salt] }),
      ]).catch(() => [null, null, null] as const);
      if (!s0 || !fg || !pinfo) return null;
      const [p0, p1] = amountsFor(L, s0[0], sqrtAtTick(tickLower), sqrtAtTick(tickUpper));
      const f0 = ((((fg[0] - pinfo[1]) % M256) + M256) % M256) * L / Q128;
      const f1 = ((((fg[1] - pinfo[2]) % M256) + M256) % M256) * L / Q128;
      const a0 = p0 + f0, a1 = p1 + f1;
      if (a0 === 0n && a1 === 0n) return null;
      return ({ v, id: ids[i]!, L, key, a0, a1, tx: v4ExitTx(v.chainId, v.pm, ids[i]!, L, key.currency0, key.currency1, owner, [p0, p1]) });
    }))).filter((x) => x !== null);
    const toks = [...new Set(out.flatMap((x) => [x.key.currency0, x.key.currency1]).filter((t) => !/^0x0+$/.test(t)))] as `0x${string}`[];
    const md = await c.multicall({ allowFailure: true, contracts: toks.flatMap((t) => [
      { address: t, abi: [parseAbiItem("function symbol() view returns (string)")], functionName: "symbol" },
      { address: t, abi: [parseAbiItem("function decimals() view returns (uint8)")], functionName: "decimals" },
    ]) as never[] }).catch(() => []);
    toks.forEach((t, j) => { const sy = md[2 * j]?.result, de = md[2 * j + 1]?.result; if (typeof sy === "string" && de !== undefined) meta.set(`${v.chainId}:${t.toLowerCase()}`, { symbol: sy, decimals: Number(de) }); });
    return out;
  }));
  const all = per.flat();
  if (!all.length) return [];
  const NATIVE = "0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE";
  const tok = (a: string) => (/^0x0+$/.test(a) ? NATIVE : a);
  const px = await prices(f, all.flatMap((x) => [{ chainId: x.v.chainId, address: tok(x.key.currency0) }, { chainId: x.v.chainId, address: tok(x.key.currency1) }])).catch(() => new Map());
  return all.map((x) => {
    const leg = (t: string, a: bigint) => {
      const m = meta.get(`${x.v.chainId}:${t.toLowerCase()}`);
      const p = pxOf(px, x.v.chainId, tok(t)) ?? (/^0x0+$/.test(t) ? { decimals: 18, symbol: "ETH", price: 0 } : m ? { ...m, price: 0 } : undefined);
      const amt = p?.decimals !== undefined ? Number(formatUnits(a, p.decimals)) : null;
      return { unp: !p?.price, s: `${amt === null ? a + " raw" : amt.toPrecision(6)} ${p?.symbol ?? t.slice(0, 8)}`, usd: amt !== null && p?.price ? amt * p.price : null };
    };
    const l0 = leg(x.key.currency0, x.a0), l1 = leg(x.key.currency1, x.a1);
    const usd = l0.usd === null && l1.usd === null ? null : Math.round(((l0.usd ?? 0) + (l1.usd ?? 0)) * 100) / 100;
    return {
      kind: "claimable", protocol: "Uniswap v4 LP", chainId: x.v.chainId,
      what: `Position #${x.id}: ${l0.s} + ${l1.s} incl. fees (exact from pool state${l0.unp || l1.unp ? "; USD counts priced legs only" : ""})`,
      valueUsd: usd, claimTx: x.tx,
      action: `Sign one transaction to remove the liquidity and take both tokens to your wallet, then swap on SwapChan. ${PRIVATE_SUBMISSION_NOTE}`,
      confidence: "high",
      evidence: [{ chainId: x.v.chainId, address: x.v.pm, call: "getPoolAndPositionInfo, getPositionLiquidity; StateView getSlot0/getFeeGrowthInside/getPositionInfo", args: [x.id.toString()], raw: [x.a0.toString(), x.a1.toString()] }],
    } as NewFound;
  });
}
