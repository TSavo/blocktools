import { concat, decodeFunctionData, encodeFunctionData, encodePacked, getAddress, pad, parseAbiItem, size, type Hex } from "viem";
import { evmClient, walletBalances } from "./onchain.js";
import type { NewFound } from "./recover.js";

/** Safes the wallet owns (Safe Transaction Service). For 1-of-N Safes we build a single execTransaction that the
 *  owner can submit directly (pre-validated "msg.sender is owner" signature, v=1), moving native + every priced token
 *  to the owner via MultiSendCallOnly. Multi-sig Safes are reported with what they hold and the threshold. */
type F = typeof fetch;
export const MULTISEND_CALL_ONLY = ["0x40a2accbd92bca938b02010e17a5b8929b49130d", "0x9641d764fc13c8b624c04430c7356c1c7c8102e2"];
const SAFE_NET: Record<number, string> = { 1: "eth", 8453: "base", 42161: "arb1", 10: "oeth", 137: "pol", 56: "bnb", 43114: "avax" };
const EXEC = parseAbiItem("function execTransaction(address to, uint256 value, bytes data, uint8 operation, uint256 safeTxGas, uint256 baseGas, uint256 gasPrice, address gasToken, address refundReceiver, bytes signatures) payable returns (bool)");
const MS = parseAbiItem("function multiSend(bytes transactions) payable");
const XFER = parseAbiItem("function transfer(address to, uint256 amount) returns (bool)");
const Z = "0x0000000000000000000000000000000000000000";
type Leg = { to: string; value: bigint; data: Hex };
export const ownerSig = (owner: string): Hex => concat([pad(owner as Hex, { size: 32 }), pad("0x0", { size: 32 }), "0x01"]);
export function safeSweepTx(chainId: number, safe: string, owner: `0x${string}`, legs: Leg[]) {
  const [to, value, data, op] = legs.length === 1
    ? [legs[0]!.to, legs[0]!.value, legs[0]!.data, 0]
    : [MULTISEND_CALL_ONLY[0]!, 0n, encodeFunctionData({ abi: [MS], args: [concat(legs.map((l) => encodePacked(["uint8", "address", "uint256", "uint256", "bytes"], [0, l.to as Hex, l.value, BigInt(size(l.data)), l.data])))] }), 1];
  return {
    chainId, to: safe, value: "0",
    data: encodeFunctionData({ abi: [EXEC], args: [to as Hex, value, data, op, 0n, 0n, 0n, Z, Z, ownerSig(owner)] }),
    description: `Move everything this Safe holds (${legs.length} asset${legs.length > 1 ? "s" : ""}) to your wallet`,
  };
}
function legOk(l: Leg, owner: string) {
  if (getAddress(l.to) === getAddress(owner)) return l.data === "0x";
  if (l.value !== 0n) return false;
  try { const d = decodeFunctionData({ abi: [XFER], data: l.data }); return getAddress(d.args[0]) === getAddress(owner); } catch { return false; }
}
/** Accept only execTransaction whose every leg pays the owner (native to owner, or ERC-20 transfer(owner)). */
export function verifySafe(data: string, owner: string): boolean | null {
  if (!data.startsWith("0x6a761202")) return null;
  try {
    const { args: [to, value, inner, op, , , gasPrice, gasToken, refund] } = decodeFunctionData({ abi: [EXEC], data: data as Hex });
    if (gasPrice !== 0n || gasToken !== Z || refund !== Z) return false;
    if (op === 0) return legOk({ to, value, data: inner }, owner);
    if (op !== 1 || !MULTISEND_CALL_ONLY.includes(to.toLowerCase())) return false;
    const blob = decodeFunctionData({ abi: [MS], data: inner }).args[0].slice(2);
    let i = 0, n = 0;
    while (i < blob.length) {
      if (blob.slice(i, i + 2) !== "00") return false;
      const t = "0x" + blob.slice(i + 2, i + 42), v = BigInt("0x" + blob.slice(i + 42, i + 106)), len = Number(BigInt("0x" + blob.slice(i + 106, i + 170)));
      const d = ("0x" + blob.slice(i + 170, i + 170 + 2 * len)) as Hex;
      if (!legOk({ to: t, value: v, data: d }, owner)) return false;
      i += 170 + 2 * len; n++;
    }
    return n > 0;
  } catch { return false; }
}

const R = (n: number) => Math.round(n * 100) / 100;
export async function ownedSafes(f: F, env: NodeJS.ProcessEnv, owner: `0x${string}`): Promise<NewFound[]> {
  const out: NewFound[] = [];
  let anyOk = false;
  await Promise.all(Object.entries(SAFE_NET).map(async ([id, net]) => {
    const chainId = Number(id);
    const r = await f(`https://api.safe.global/tx-service/${net}/api/v1/owners/${getAddress(owner)}/safes/`, { signal: AbortSignal.timeout(8000) }).catch(() => null);
    if (!r?.ok) return;
    anyOk = true;
    const safes = (((await r.json()) as { safes?: string[] }).safes ?? []).slice(0, 5);
    const c = evmClient(chainId, env);
    await Promise.all(safes.map(async (s) => {
      const safe = getAddress(s);
      const [thr, owners] = await Promise.all([
        c.readContract({ address: safe, abi: [parseAbiItem("function getThreshold() view returns (uint256)")], functionName: "getThreshold" }),
        c.readContract({ address: safe, abi: [parseAbiItem("function getOwners() view returns (address[])")], functionName: "getOwners" }),
      ]).catch(() => [0n, [] as readonly string[]] as const);
      if (!owners.some((o) => getAddress(o) === getAddress(owner))) return;
      const wb = await walletBalances(f, env, safe, [chainId]).catch(() => null);
      const hold = (wb?.holdings ?? []).filter((h) => (h.valueUsd ?? 0) >= 0.01);
      if (!hold.length) return;
      const raws = await Promise.all(hold.map((h) => /^0xe{40}$/i.test(h.address) || /^0x0{40}$/.test(h.address)
        ? c.getBalance({ address: safe })
        : c.readContract({ address: h.address as Hex, abi: [parseAbiItem("function balanceOf(address) view returns (uint256)")], functionName: "balanceOf", args: [safe] }).catch(() => 0n)));
      const legs: Leg[] = hold.flatMap((h, i) => (raws[i]! > 0n ? [/^0xe{40}$/i.test(h.address) || /^0x0{40}$/.test(h.address)
        ? { to: owner, value: raws[i]!, data: "0x" as Hex }
        : { to: h.address, value: 0n, data: encodeFunctionData({ abi: [XFER], args: [owner, raws[i]!] }) }] : []));
      if (!legs.length) return;
      const usd = R(hold.reduce((a, h) => a + (h.valueUsd ?? 0), 0));
      const list = hold.slice(0, 5).map((h) => `${Number(h.balance).toPrecision(4)} ${h.symbol}`).join(", ") + (hold.length > 5 ? ` +${hold.length - 5} more` : "");
      const solo = thr === 1n;
      out.push({
        kind: "claimable", protocol: `Safe ${safe.slice(0, 6)}…${safe.slice(-4)}`, chainId,
        what: `You own this Safe (${thr}-of-${owners.length}); it holds ${list} (live balances, priced)`,
        valueUsd: usd,
        ...(solo ? { claimTx: safeSweepTx(chainId, safe, owner, legs) } : {}),
        action: solo ? "Sign one transaction from your wallet (you are the sole required signer) to move everything to your wallet, then swap on SwapChan"
          : `This Safe needs ${thr} of ${owners.length} owners to sign, so one wallet can't move it alone. Ask your co-owners to sign a transfer to your wallet`,
        confidence: "high",
        evidence: [{ chainId, address: safe, call: "getThreshold/getOwners", args: [], raw: [thr.toString(), String(owners.length)] }],
      });
    }));
  }));
  if (!anyOk) throw new Error("Safe Transaction Service unavailable");
  return out;
}
