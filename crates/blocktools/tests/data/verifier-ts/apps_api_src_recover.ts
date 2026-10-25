import { checkSolSpec, encodeSol, type SolIx, type SolSpec } from "./solrecover.js";
import { tronSpec, verifyTronSpec, encodeSpec } from "./tronrecover.js";
import { verifySafe } from "./safe.js";
import { PENDLE_ROUTER } from "./pendle.js";
import { verifyV4 } from "./lpv4.js";
import { deadlineOk } from "./exitguard.js";
import type { DatabaseSync } from "node:sqlite";
import { NATIVE_TOKEN, SOLANA, SUPPORTED_CHAINS } from "@swapchan/shared";
import {
  decodeFunctionData,
  encodeFunctionData,
  formatUnits,
  getAddress,
  parseAbiItem,
  toFunctionSelector,
  toHex,
} from "viem";
import {
  chainName,
  evmClient,
  json,
  prices,
  pxOf,
  SITE,
  solRpc,
  swapUrl,
  usdcOf,
} from "./onchain.js";

/**
 * Guided recovery: every stuck-money finding becomes
 *   step 1: sign the recovery tx (claim / withdraw / unstake / unwrap) on swapchan.com/recover
 *   step 2: swap what came out to USDC (prefilled swap link + permanent short link)
 */
type F = typeof fetch;
export type RecoveryTx = {
  chainId: number;
  to: string;
  data: string;
  value: string;
  description: string;
};
const fn = (s: string) => [parseAbiItem(`function ${s}`)] as const;
const r2 = (n: number) => Math.round(n * 100) / 100;

/**
 * Standard recovery calls SwapChan will build for ANY contract, because every value-moving
 * argument is pinned to the wallet itself (funds can only go back to the owner).
 * `owners` lists argument indexes that must equal the owner.
 */
export const STANDARD_RECOVERY: { sig: string; owners: number[] }[] = [
  { sig: "withdraw()", owners: [] },
  { sig: "exit()", owners: [] },
  { sig: "getReward()", owners: [] },
  { sig: "getReward(address)", owners: [0] },
  { sig: "claim()", owners: [] },
  { sig: "claimFees()", owners: [] },
  { sig: "vest()", owners: [] },
  { sig: "claimRewards()", owners: [] },
  { sig: "withdraw(uint256)", owners: [] },
  { sig: "withdrawAndUnwrap(uint256,bool)", owners: [] },
  { sig: "withdrawAndHarvest(uint256,uint256,address)", owners: [2] },
  { sig: "withdraw(uint256,uint256)", owners: [] },
  { sig: "withdraw(address,uint256,address)", owners: [2] },
  {
    sig: "completeQueuedWithdrawal((address staker,address delegatedTo,address withdrawer,uint256 nonce,uint32 startBlock,address[] strategies,uint256[] scaledShares),address[],bool)",
    owners: [-2],
  },
  { sig: "queueWithdrawals((address[] strategies,uint256[] depositShares,address withdrawer)[])", owners: [] },
  { sig: "redeem(uint256,address,address)", owners: [1, 2] },
  { sig: "withdrawToken(address,uint256)", owners: [] },
  { sig: "claimComp(address)", owners: [0] },
  { sig: "claimVenus(address)", owners: [0] },
  { sig: "claimWithdrawal(uint256)", owners: [] },
  { sig: "claimWithdraw(uint256)", owners: [] },
  { sig: "burnRedemptionTicketNft(uint256,address)", owners: [1] },
  { sig: "finalizeWithdrawal(uint256)", owners: [] },
  { sig: "claim(uint256)", owners: [] },
  { sig: "withdrawMax(uint256,address)", owners: [1] },
  { sig: "redeemPlans(uint256[])", owners: [] },
  { sig: "withdrawTokens(uint256)", owners: [] },
  { sig: "withdraw(address,uint256,uint256,uint256)", owners: [] },
  { sig: "downgrade(uint256)", owners: [] },
  { sig: "downgradeToETH(uint256)", owners: [] },
  { sig: "claimFundingFees(address[],address[],address)", owners: [2] },
  { sig: "claimCollateral()", owners: [] },
  { sig: "releaseDeed(bytes32)", owners: [] },
  { sig: "claim(uint256,address,uint256,bytes32[])", owners: [1] },
  { sig: "removeLiquidity(address,address,uint256,uint256,uint256,address,uint256)", owners: [5] },
  { sig: "exitPostExpToToken(address,address,uint256,uint256,(address,uint256,address,address,(uint8,address,bytes,bool)))", owners: [0] },
  { sig: "redeem(address,uint256,address,uint256,bool)", owners: [0] },
  { sig: "decreaseLiquidity((uint256 tokenId,uint128 liquidity,uint256 amount0Min,uint256 amount1Min,uint256 deadline))", owners: [] },
  {
    sig: "collect((uint256 tokenId,address recipient,uint128 amount0Max,uint128 amount1Max))",
    owners: [-1],
  },
];
const MULTICALL = fn("multicall(bytes[])");
const ABIS = STANDARD_RECOVERY.map((s) => ({ ...s, abi: fn(s.sig) }));

/** Decode a recovery tx and prove it can only pay the owner. Fails closed. */
export type Verdict = { readonly verified: true; readonly call: string } | { readonly verified: false; readonly reason: string };
export function verifyRecovery(tx: { to: string; data: string; value: string }, owner: string): Verdict {
  if (BigInt(tx.value || "0") !== 0n) return { verified: false, reason: "non-zero value" } as const;
  if (tx.data.startsWith("0x095ea7b3") && tx.data.slice(10, 74).toLowerCase() === "0".repeat(24) + PENDLE_ROUTER.slice(2))
    return { verified: true, call: "approve(Pendle Router) — approval step only" } as const;
  const sf = verifySafe(tx.data, owner);
  if (sf !== null) return sf ? ({ verified: true, call: "Safe execTransaction (every leg pays the owner)" } as const) : ({ verified: false, reason: "Safe tx with a leg that does not pay the owner" } as const);
  const v4 = verifyV4(tx.data, owner);
  if (v4 !== null) return v4 ? ({ verified: true, call: "modifyLiquidities(DECREASE_LIQUIDITY,TAKE_PAIR→owner)" } as const) : ({ verified: false, reason: "v4 actions other than decrease + take-to-owner" } as const);
  // TheDAO refund: approve(WithdrawDAO) on the DAO token, then WithdrawDAO.withdraw() (pays msg.sender); both contract-pinned
  if (tx.to.toLowerCase() === "0xbb9bc244d798123fde783fcc1c72d3bb8c189413" && tx.data.startsWith("0x095ea7b3") && tx.data.slice(10, 74).toLowerCase() === "0".repeat(24) + "bf4ed7b27f1d666546e30d74d50d173d20bca754")
    return { verified: true, call: "approve(WithdrawDAO) — TheDAO refund step 1" } as const;
  if (tx.to.toLowerCase() === "0xbf4ed7b27f1d666546e30d74d50d173d20bca754" && tx.data.toLowerCase() === "0x3ccfd60b")
    return { verified: true, call: "WithdrawDAO.withdraw() (pays the caller)" } as const;
  // Canonical bridge exits: these only execute a message the L2 initiator already committed (target, value, data are
  // fixed by the proof), so the caller cannot redirect funds; pinned to the Arbitrum Outbox and the OP Portal.
  if (tx.to.toLowerCase() === "0x0b9857ae2d4a3dbe74ffe1d7df045bb7f96e4840" && tx.data.toLowerCase().startsWith("0x08635a95"))
    return { verified: true, call: "Arbitrum Outbox.executeTransaction (executes a proven L2→L1 message)" } as const;
  if (tx.to.toLowerCase() === "0xbeb5fc579115071764c7423a4f75ededa441ec71" && /^0x(4870496f|43ca1c50)/i.test(tx.data))
    return { verified: true, call: "OptimismPortal prove/finalize (executes a committed L2→L1 withdrawal)" } as const;
  // IronHands payout(): pays the queue head; offered only when find_money saw the owner at the head
  if (tx.data.toLowerCase() === "0x63bd1d4a" && tx.to.toLowerCase() === "0xe58b65d1c0c8e8b2a0e3a3acec633271531084ed")
    return { verified: true, call: "IronHands payout() (zero value; pays the queue head)" } as const;
  // multicall(bytes[]): every inner call must itself be a verified recovery call
  try {
    const m = decodeFunctionData({ abi: MULTICALL, data: tx.data as `0x${string}` });
    const inner = m.args[0] as readonly `0x${string}`[];
    if (!inner.length) return { verified: false, reason: "empty multicall" } as const;
    for (const d of inner) {
      const v = verifyRecovery({ to: tx.to, data: d, value: "0" }, owner);
      if (!v.verified) return { verified: false, reason: `multicall: ${v.reason}` } as const;
    }
    return { verified: true, call: "multicall(bytes[])" } as const;
  } catch {}
  for (const s of ABIS) {
    try {
      const d = decodeFunctionData({ abi: s.abi, data: tx.data as `0x${string}` });
      const args = (d.args ?? []) as unknown[];
      const ok = s.owners.every((i) => {
        const v =
          i === -1
            ? (args[0] as { recipient: string }).recipient
            : i === -2
              ? (args[0] as { withdrawer: string }).withdrawer
              : args[i];
        return typeof v === "string" && v.toLowerCase() === owner.toLowerCase();
      });
      if (ok) {
        const g = exitGuard(s.sig, args);
        if (g) return { verified: false, reason: `${s.sig}: ${g}` } as const;
      }
      return ok
        ? ({ verified: true, call: s.sig } as const)
        : ({ verified: false, reason: `${s.sig}: recipient is not the owner` } as const);
    } catch {}
  }
  return { verified: false, reason: "not a standard recovery call" } as const;
}

/** Sandwich guard: liquidity/Pendle exits need a non-zero quoted minimum and a short deadline. */
function exitGuard(sig: string, args: unknown[]): string | null {
  const name = sig.slice(0, sig.indexOf("("));
  if (name === "removeLiquidity") {
    if (args[3] === 0n && args[4] === 0n) return "zero minimum outputs (sandwichable)";
    if (!deadlineOk(args[6] as bigint)) return "deadline too far out";
  }
  if (name === "decreaseLiquidity") {
    const p = args[0] as { liquidity: bigint; amount0Min: bigint; amount1Min: bigint; deadline: bigint };
    if (p.liquidity > 0n && p.amount0Min === 0n && p.amount1Min === 0n) return "zero minimum outputs (sandwichable)";
    if (!deadlineOk(p.deadline)) return "deadline too far out";
  }
  if (name === "exitPostExpToToken" && (args[4] as readonly unknown[])[1] === 0n) return "zero minTokenOut (sandwichable)";
  if (sig === "redeem(address,uint256,address,uint256,bool)" && args[3] === 0n) return "zero minTokenOut (sandwichable)";
  return null;
}

/** Permanent in-app signing page for one recovery step. */
export function recoverUrl(tx: RecoveryTx, title: string, next?: string) {
  const q = new URLSearchParams({
    chain: String(tx.chainId),
    to: tx.to,
    data: tx.data,
    ...(tx.value && tx.value !== "0" ? { value: tx.value } : {}),
    title: title.slice(0, 140),
    ...(next ? { next } : {}),
  });
  return `${SITE}/recover?${q}`;
}

export type Step = {
  step: number;
  kind: "recover" | "swap";
  label: string;
  url: string;
  shortUrl: string | null;
  tx?: RecoveryTx;
};
/** Build the guided flow. Every finding ends in a swap-to-USDC step. */
export interface Evidence {
  chainId: number;
  address: string;
  call: string;
  abi?: string | undefined;
  args: string[];
  raw: string | string[];
  block?: string | undefined;
}

const EXPLORERS: Record<number, string> = {
  1: "https://etherscan.io",
  8453: "https://basescan.org",
  10: "https://optimistic.etherscan.io",
  42161: "https://arbiscan.io",
  137: "https://polygonscan.com",
  56: "https://bscscan.com",
  43114: "https://snowtrace.io",
};

/** Machine-readable recovery package: everything an agent needs to verify and act without our UI. */
export function recoveryInfo(
  owner: string,
  it: { claimTx?: unknown; evidence?: Evidence[]; estUsd?: number | null; swapUrl: string },
) {
  const tx = it.claimTx as RecoveryTx | undefined;
  if (!tx || !("data" in (tx as object))) return undefined;
  const sel = tx.data.slice(0, 10).toLowerCase();
  const m = STANDARD_RECOVERY.find((r) => toFunctionSelector(`function ${r.sig}`) === sel);
  const ex = EXPLORERS[tx.chainId];
  return {
    contract: {
      chainId: tx.chainId,
      chain: chainName(tx.chainId),
      address: tx.to,
      explorer: ex ? `${ex}/address/${tx.to}` : undefined,
      verifiedSource: ex ? `${ex}/address/${tx.to}#code` : undefined,
    },
    detection: it.evidence ?? [],
    interface: {
      reads: [...new Set((it.evidence ?? []).map((e) => e.abi).filter(Boolean))],
      recovery: m ? `function ${m.sig}` : undefined,
    },
    value: {
      estUsd: it.estUsd ?? null,
      pricingSource: "DefiLlama coins API (coins.llama.fi), spot at scan time",
    },
    recoveryTx: {
      ...tx,
      unsigned: true,
      verified: verifyRecovery(tx, owner).verified,
      payee: owner,
    },
    swapUrl: it.swapUrl,
    trust: "Unsigned. SwapChan never signs, never holds keys or funds; your wallet signs.",
  };
}

export function recoveryFlow(
  db: DatabaseSync | null,
  shorten: ((db: DatabaseSync, url: string) => { shortUrl: string }) | null,
  owner: string,
  it: { title: string; claimTx?: unknown; swapUrl: string; protocolUrl?: string },
): { steps: Step[]; recoverUrl?: string; recovery?: ReturnType<typeof recoveryInfo> } {
  const s = (u: string) => (db && shorten && u.startsWith(SITE) ? shorten(db, u).shortUrl : null);
  const steps: Step[] = [];
  const tx = it.claimTx as RecoveryTx | undefined;
  let rurl: string | undefined;
  if (tx && "data" in (tx as object) && verifyRecovery(tx, owner).verified) {
    rurl = recoverUrl(tx, it.title, it.swapUrl);
    steps.push({
      step: 1,
      kind: "recover",
      label: `Sign: ${tx.description}`,
      url: rurl,
      shortUrl: s(rurl),
      tx,
    });
  }
  const tt = (it.claimTx as { tronTx?: unknown; description?: string } | undefined)?.tronTx;
  const spec = tt ? tronSpec(tt) : null;
  if (spec && verifyTronSpec(spec, owner)) {
    const q = new URLSearchParams({ tron: encodeSpec(spec), title: it.title.slice(0, 140), next: it.swapUrl });
    rurl = `${SITE}/recover?${q}`;
    steps.push({ step: 1, kind: "recover", label: `Sign: ${(it.claimTx as { description?: string }).description ?? spec.endpoint} (TronLink)`, url: rurl, shortUrl: s(rurl) } as Step);
  }
  const st = (it.claimTx as { solanaTx?: { kind?: string; data?: { instructions?: SolIx[] } }; description?: string } | undefined)?.solanaTx;
  if (!rurl && st?.kind === "svm-instructions" && st.data?.instructions?.length) {
    const sspec: SolSpec = { owner, ix: st.data.instructions };
    if (!checkSolSpec(sspec, owner)) {
      const q = new URLSearchParams({ sol: encodeSol(sspec), title: it.title.slice(0, 140), next: it.swapUrl });
      rurl = `${SITE}/recover?${q}`;
      steps.push({ step: 1, kind: "recover", label: `Sign: ${(it.claimTx as { description?: string }).description ?? "Solana recovery"} (Solana wallet)`, url: rurl, shortUrl: s(rurl) } as Step);
    }
  }
  const sw = (it as { sweep?: Sweep }).sweep;
  if (sw && !rurl) {
    rurl = sweepUrl(sw, it.title);
    const label = sw.kind === "utxo" ? `Build the unsigned ${sw.sym} sweep to your own ${sw.sym} address, then sign it offline` : `Get it back: sign the ${sw.sym} transfer to your connected wallet`;
    steps.push({ step: 1, kind: "recover", label, url: rurl, shortUrl: s(rurl) } as Step);
    // SwapChan has no route for these coins yet: no fake swap link
    const fc = Number(/fromChain=(\d+)&/.exec(it.swapUrl ?? "")?.[1] ?? "0");
    if (!it.swapUrl || !(fc in SUPPORTED_CHAINS)) return { steps, recoverUrl: rurl, swapUrl: rurl } as never;
  }
  // chains SwapChan cannot route yet (XRP, Signum): no fake swap link, no recover step
  if (!rurl && /fromChain=0&/.test(it.swapUrl ?? "")) return { steps, swapUrl: SITE } as never;
  // No buildable, verified tx -> no "Get it back" step. Never send people to an external portal
  // as a recovery step; the protocol link stays informational (protocolUrl) only.
  steps.push({
    step: steps.length + 1,
    kind: "swap",
    label: "Swap it to USDC at the best price on SwapChan",
    url: it.swapUrl,
    shortUrl: s(it.swapUrl),
  });
  const recovery = recoveryInfo(owner, it as never);
  return { steps, ...(rurl ? { recoverUrl: rurl } : {}), ...(recovery ? { recovery } : {}) };
}

export interface NewFound {
  kind: "claimable" | "legacy" | "lending" | "solana-rent" | "balance";
  protocol: string;
  chainId: number;
  what: string;
  valueUsd: number | null;
  claimTx?: RecoveryTx | { chainId: number; solanaTx: unknown; description: string };
  action: string;
  link?: string;
  risk?: string;
  evidence?: Evidence[];
  confidence?: "high" | "medium" | "low";
  recoveryHints?: { name: string; selector: string; abi?: string }[];
  /** Non-EVM / fork-chain balance: /recover?sweep= builds the unsigned sweep in the browser. */
  sweep?: Sweep;
}
export type Sweep = { kind: "utxo" | "fork" | "evm"; coin: string; from: string; sym: string; token?: string };
export function sweepUrl(sw: Sweep, title: string) {
  return `${SITE}/recover?${new URLSearchParams({ sweep: sw.kind, coin: sw.coin, from: sw.from, sym: sw.sym, ...(sw.token ? { token: sw.token } : {}), title: title.slice(0, 140) })}`;
}

// ---------- unwrapped native (WETH/WBNB/WPOL/WAVAX) ----------
export const WRAPPED: Record<number, `0x${string}`> = {
  1: "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
  8453: "0x4200000000000000000000000000000000000006",
  10: "0x4200000000000000000000000000000000000006",
  42161: "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1",
  137: "0x0d500B1d8E8eF31E21C99d1Db9A6444d3ADf1270",
  56: "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
  43114: "0xB31f66AA3C1e785363F0875A1B74E27b85FD66c7",
};
export async function wrappedNative(
  f: F,
  env: NodeJS.ProcessEnv,
  owner: `0x${string}`,
  blockNumber?: bigint,
): Promise<NewFound[]> {
  const ids = Object.keys(WRAPPED).map(Number);
  const bals = await Promise.all(
    ids.map((id) =>
      evmClient(id, env)
        .readContract({
          address: WRAPPED[id]!,
          abi: fn("balanceOf(address) view returns (uint256)"),
          functionName: "balanceOf",
          args: [owner],
          ...(blockNumber && id === 1 ? { blockNumber } : {}),
        })
        .catch(() => 0n),
    ),
  );
  const hits = ids.map((id, i) => ({ id, v: bals[i] as bigint })).filter((x) => x.v > 10n ** 12n);
  if (!hits.length) return [];
  const px = await prices(
    f,
    hits.map((h) => ({ chainId: h.id, address: NATIVE_TOKEN })),
  ).catch(() => new Map());
  return hits.map(({ id, v }) => {
    const amt = formatUnits(v, 18);
    const p = pxOf(px, id, NATIVE_TOKEN)?.price ?? null;
    return {
      kind: "claimable" as const,
      protocol: `Wrapped native on ${chainName(id)}`,
      chainId: id,
      what: `${Number(amt).toPrecision(6)} wrapped native token (WETH-style) sitting unwrapped`,
      valueUsd: p ? r2(Number(amt) * p) : null,
      claimTx: {
        chainId: id,
        to: WRAPPED[id]!,
        data: encodeFunctionData({
          abi: fn("withdraw(uint256)"),
          functionName: "withdraw",
          args: [v],
        }),
        value: "0",
        description: "withdraw(amount): unwrap to native gas token",
      },
      action: "Unwrap it (or swap it straight to USDC on SwapChan)",
      link: swapUrl(id, NATIVE_TOKEN, id, usdcOf(id)!, amt),
      evidence: [
        {
          chainId: id,
          address: WRAPPED[id]!,
          call: "balanceOf(address)",
          abi: "balanceOf(address) view returns (uint256)",
          args: [owner],
          raw: toHex(v),
          ...(blockNumber && id === 1 ? { block: blockNumber.toString() } : {}),
        },
      ],
      confidence: "high" as const,
    };
  });
}

// ---------- Lido withdrawal queue (unstake finalised, not claimed) ----------
export const LIDO_WQ = "0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1" as const;
export async function lidoWithdrawals(
  f: F,
  env: NodeJS.ProcessEnv,
  owner: `0x${string}`,
  blockNumber?: bigint,
): Promise<NewFound[]> {
  const c = evmClient(1, env);
  const bt = blockNumber ? { blockNumber } : {};
  const ids = (await c
    .readContract({
      address: LIDO_WQ,
      abi: fn("getWithdrawalRequests(address) view returns (uint256[])"),
      functionName: "getWithdrawalRequests",
      args: [owner],
      ...bt,
    })
    .catch(() => [])) as readonly bigint[];
  if (!ids.length) return [];
  const st = (await c.readContract({
    address: LIDO_WQ,
    abi: fn(
      "getWithdrawalStatus(uint256[]) view returns ((uint256 amountOfStETH,uint256 amountOfShares,address owner,uint256 timestamp,bool isFinalized,bool isClaimed)[])",
    ),
    functionName: "getWithdrawalStatus",
    args: [[...ids].slice(0, 50)],
    ...bt,
  })) as readonly { amountOfStETH: bigint; isFinalized: boolean; isClaimed: boolean }[];
  const px = await prices(f, [{ chainId: 1, address: NATIVE_TOKEN }]).catch(() => new Map());
  const p = pxOf(px, 1, NATIVE_TOKEN)?.price ?? null;
  return st.flatMap((s, i) => {
    if (s.isClaimed) return [];
    const eth = Number(formatUnits(s.amountOfStETH, 18));
    return [
      {
        kind: "claimable" as const,
        protocol: "Lido withdrawal",
        chainId: 1,
        what: `Unstake request #${ids[i]} for ${eth.toPrecision(6)} ETH: ${s.isFinalized ? "finalized, ready to claim" : "still in the queue"}`,
        valueUsd: p ? r2(eth * p) : null,
        ...(s.isFinalized
          ? {
              claimTx: {
                chainId: 1,
                to: LIDO_WQ,
                data: encodeFunctionData({
                  abi: fn("claimWithdrawal(uint256)"),
                  functionName: "claimWithdrawal",
                  args: [ids[i]!],
                }),
                value: "0",
                description: `claimWithdrawal(${ids[i]}): claim your unstaked ETH from Lido`,
              },
            }
          : {}),
        action: s.isFinalized
          ? "Claim the ETH, then swap it on SwapChan"
          : "Wait for Lido to finalize, then claim",
        link: swapUrl(1, NATIVE_TOKEN, 1, usdcOf(1)!, String(eth)),
        evidence: [
          {
            chainId: 1,
            address: LIDO_WQ,
            call: "getWithdrawalRequests(address)",
            abi: "getWithdrawalRequests(address) view returns (uint256[])",
            args: [owner],
            raw: ids.map((x) => x.toString()),
            ...(blockNumber ? { block: blockNumber.toString() } : {}),
          },
          {
            chainId: 1,
            address: LIDO_WQ,
            call: "getWithdrawalStatus(uint256[])",
            abi: "getWithdrawalStatus(uint256[]) view returns ((uint256,uint256,address,uint256,bool,bool)[])",
            args: [ids[i]!.toString()],
            raw: [toHex(s.amountOfStETH), String(s.isFinalized), String(s.isClaimed)],
            ...(blockNumber ? { block: blockNumber.toString() } : {}),
          },
        ],
        confidence: "high" as const,
      },
    ];
  });
}

export { ownedSafes } from "./safe.js";

// ---------- Solana stake accounts (deactivated = withdrawable) ----------
const STAKE = "Stake11111111111111111111111111111111111111";
export async function solanaStake(
  f: F,
  env: NodeJS.ProcessEnv,
  owner: string,
): Promise<NewFound[]> {
  const [accts, ep] = await Promise.all([
    solRpc<
      {
        pubkey: string;
        account: {
          lamports: number;
          data: {
            parsed: {
              info: { stake?: { delegation: { deactivationEpoch: string; stake: string } } };
            };
          };
        };
      }[]
    >(f, env, "getProgramAccounts", [
      STAKE,
      { encoding: "jsonParsed", filters: [{ memcmp: { offset: 44, bytes: owner } }] },
    ]).catch(() => []),
    solRpc<{ epoch: number }>(f, env, "getEpochInfo", []).catch(() => ({ epoch: 0 })),
  ]);
  if (!accts.length) return [];
  const px = await prices(f, [
    { chainId: SOLANA, address: "11111111111111111111111111111111" },
  ]).catch(() => new Map());
  const p = pxOf(px, SOLANA, "11111111111111111111111111111111")?.price ?? null;
  return accts.map((a) => {
    const d = a.account.data.parsed.info.stake?.delegation;
    const de = d ? Number(d.deactivationEpoch) : 0;
    const free = !d || (de < 1e15 && de < ep.epoch);
    const sol = a.account.lamports / 1e9;
    const lamports = a.account.lamports;
    const withdrawIx = free
      ? {
          chainId: SOLANA,
          solanaTx: {
            kind: "svm-instructions",
            data: {
              instructions: [
                {
                  programId: STAKE,
                  keys: [
                    { pubkey: a.pubkey, isSigner: false, isWritable: true },
                    { pubkey: owner, isSigner: false, isWritable: true },
                    {
                      pubkey: "SysvarC1ock11111111111111111111111111111111",
                      isSigner: false,
                      isWritable: false,
                    },
                    { pubkey: owner, isSigner: true, isWritable: false },
                  ],
                  // StakeInstruction::Withdraw = 4; lamports u64 LE
                  data: (() => {
                    const b = Buffer.alloc(12);
                    b.writeUInt32LE(4, 0);
                    b.writeBigUInt64LE(BigInt(lamports), 4);
                    return b.toString("hex");
                  })(),
                },
              ],
            },
          },
          description: `StakeProgram.Withdraw(${sol.toFixed(4)} SOL) from ${a.pubkey.slice(0, 8)}…`,
        }
      : undefined;
    return {
      kind: "claimable" as const,
      protocol: "Solana stake account",
      chainId: SOLANA,
      what: `${a.pubkey.slice(0, 6)}…: ${sol.toFixed(4)} SOL ${free ? "deactivated, withdrawable now" : de < 1e15 ? "deactivating" : "still delegated"}`,
      valueUsd: p ? r2(sol * p) : null,
      ...(withdrawIx ? { claimTx: withdrawIx } : {}),
      action: free
        ? "Sign the stake withdraw tx, then swap SOL on SwapChan"
        : "Still staked: deactivate first if you want it liquid",
      link: swapUrl(
        SOLANA,
        "11111111111111111111111111111111",
        SOLANA,
        usdcOf(SOLANA)!,
        sol.toFixed(4),
      ),
      evidence: [
        {
          chainId: SOLANA,
          address: a.pubkey,
          call: "getProgramAccounts(Stake1111…, memcmp authority)",
          args: [owner],
          raw: String(lamports),
        },
      ],
      confidence: free ? ("high" as const) : ("medium" as const),
    };
  });
}
