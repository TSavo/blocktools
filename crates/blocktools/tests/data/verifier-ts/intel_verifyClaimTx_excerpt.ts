        verifyClaimTx({ to: toAddr, data: body.data ?? "0x", value: String(body.value ?? "0") })
          .verified,
      note: "SwapChan's /build already decodes and verifies router, recipient, minOut and approvals before returning a tx; this re-checks the router allowlist on the tx you pass.",
    },
    hint:
      !ok &&
      /allowance|transfer amount exceeds|STF|TRANSFER_FROM_FAILED/i.test(swap.error?.message ?? "")
        ? "Looks like a missing ERC-20 approval: pass `approve` {token, spender, amount} to simulate approve+swap together."
        : undefined,
    method: "eth_simulateV1 with traceTransfers (public RPC)",
    next: cta(
      ok ? "Looks good. Execute it on SwapChan" : "Get a fresh best-price route on SwapChan",
      SITE,
    ),
  };
}

// ---------- 2. wallet_history + wallet_pnl ----------
/** Airdrop/phishing spam tokens: URL/claim-bait symbols, or nothing in the leg has a price. */
export const SPAM_SYMBOL =
  /(https?:|www\.|\.(com|io|org|net|xyz|cfd|top|site|online|app|fi|gift|lol|click|link|pro|vip|shop|live)\b|claim|visit|reward|airdrop|voucher|✅|\$\s?\d)/i;
export function isSpamLegs(ls: { symbol: string; usd?: number | null }[]) {
  if (!ls.length) return false;
  if (ls.some((l) => SPAM_SYMBOL.test(l.symbol) || /[^\x20-\x7e]/.test(l.symbol))) return true;
  return ls.every((l) => l.usd === null || l.usd === undefined);
}
interface Leg {
  chainId: number;
  address: string;
  symbol: string;
  amount: number;
}
export interface SwapEvent {
  chainId: number;
  chain: string;
  hash: string;
  time: string;
  sold: Leg[];
  bought: Leg[];
  explorer: string;
}

const HIST_CAP = 10_000;
/** Free Etherscan-compatible explorers with full account history. ETHERSCAN_API_KEY (free tier) unlocks every chain. */
function explorerApi(chainId: number, env: NodeJS.ProcessEnv) {
  const out: { name: string; url: (q: string) => string }[] = [];
  // Ethereum: Routescan (keyless) first. Etherscan's key is rate-limited per second across the whole process
  // (measured: half of one scan's ~40 Etherscan calls came back rate-limited); Routescan answered txlist/tokentx 2000 rows in 0.1-0.2 s and the items found were identical
  // (18/18 for one address). Etherscan then Blockscout stay as fallbacks.
  if (chainId === 1)
    out.push({ name: "Routescan", url: (q) => `https://api.routescan.io/v2/network/mainnet/evm/1/etherscan/api?${q}` });
  if (env.ETHERSCAN_API_KEY && ETHERSCAN_FREE.has(chainId))
    out.push({
      name: "Etherscan v2",
      url: (q: string) => `https://api.etherscan.io/v2/api?chainid=${chainId}&${q}&apikey=${env.ETHERSCAN_API_KEY}`,
    });
  const bs: Record<number, string> = {
    1: "https://eth.blockscout.com/api",
    10: "https://optimism.blockscout.com/api",
    534352: "https://scroll.blockscout.com/api",
    59144: "https://api-explorer.linea.build/api",
  };
  const rs: Record<number, string> = {
    43114: "https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan/api",
  };
  // Linea: its Blockscout returns the full history (measured for one address: 341 txs / 86 tokens vs Etherscan v2's
  // 0 / 44) and costs no Etherscan quota, so it goes first there; Etherscan stays the fallback.
  if (bs[chainId] && chainId === 59144) out.unshift({ name: "Blockscout", url: (q) => `${bs[chainId]}?${q}` });
  else if (bs[chainId]) out.push({ name: "Blockscout", url: (q) => `${bs[chainId]}?${q}` });
  if (rs[chainId]) out.push({ name: "Routescan", url: (q) => `${rs[chainId]}?${q}` });
  return out;
}
type ExRow = {
  blockNumber: string;
  hash: string;
  timeStamp: string;
  from: string;
  to: string;
  value: string;
  contractAddress?: string;
  tokenSymbol?: string;
  tokenDecimal?: string;
  isError?: string;
};
async function explorerAll(f: F, ex: { url: (q: string) => string }, owner: string) {
  let truncated = false;
  const page = async (action: string) => {
    const rows: ExRow[] = [];
    let endblock = "";
    // walk newest→oldest in pages of 1000 via endblock (avoids the 10k page×offset limit)
    for (let i = 0; i < HIST_CAP / 1000; i++) {
      const q = `module=account&action=${action}&address=${owner}&sort=desc&page=1&offset=1000${endblock ? `&endblock=${endblock}` : ""}`;
      let r: { message?: string; result: ExRow[] | string | null } = { result: null };
      for (let attempt = 0; ; attempt++) {
        try {
          r = await json(f, ex.url(q), undefined, 20_000);
          if (typeof r.result === "string" && /rate limit/i.test(r.result)) throw new Error("429");
          break;
        } catch (e) {
          if (attempt >= 3 || !/429/.test((e as Error).message)) throw e;
          await new Promise((ok) => setTimeout(ok, 1200 * (attempt + 1)));
        }
      }
      if (!Array.isArray(r.result)) {
        if (/No (transactions|token transfers|internal)/i.test(`${r.message} ${r.result}`))
          return rows;
        throw new Error(String(r.result ?? r.message));
      }
      const res: ExRow[] = r.result;
      if (res.length < 1000) {
        rows.push(...res);
        return rows;
      }
      const last: string = res[res.length - 1]!.blockNumber;
      const keep = res.filter((x) => x.blockNumber !== last);
      if (!keep.length) {
        rows.push(...res);
        return rows;
      }
      rows.push(...keep); // the boundary block is fetched whole on the next page
      endblock = last;
    }
    truncated = true;
    return rows;
  };
  // sequential: free explorers rate-limit parallel bursts
  const tok = await page("tokentx");
  const txs = await page("txlist");
  const internal = await page("txlistinternal").catch(() => [] as ExRow[]);
  const me = owner.toLowerCase();
  const rows = [
    ...tok.map((t) => ({
      hash: t.hash,
      ts: Number(t.timeStamp),
      token: getAddress(t.contractAddress ?? NATIVE_TOKEN),
      symbol: t.tokenSymbol || "?",
      dec: Number(t.tokenDecimal || 18),
      from: t.from.toLowerCase(),
      to: (t.to ?? "").toLowerCase(),
      value: BigInt(t.value || "0"),
    })),
    ...[...txs, ...internal]
      .filter((t) => t.isError !== "1" && t.value && t.value !== "0")
      .filter((t) => t.from.toLowerCase() === me || (t.to ?? "").toLowerCase() === me)
      .map((t) => ({
        hash: t.hash ?? (t as { transactionHash?: string }).transactionHash ?? "",
        ts: Number(t.timeStamp),
        token: NATIVE_TOKEN,
        symbol: "__native__",
        dec: 18,
