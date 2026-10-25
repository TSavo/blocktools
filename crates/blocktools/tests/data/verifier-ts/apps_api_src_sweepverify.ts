import { decodeFunctionData, erc20Abi, getAddress, isAddress } from "viem";
import type { Verdict } from "./recover.js";

/** EIP-3085 wallet_addEthereumChain params, so the /recover page can add a chain the wallet lacks. */
export type AddChain = {
  chainId: `0x${string}`;
  chainName: string;
  nativeCurrency: { name: string; symbol: string; decimals: number };
  rpcUrls: string[];
  blockExplorerUrls?: string[];
};
export const addChainParams = (
  id: number,
  name: string,
  cur: { name: string; symbol: string; decimals: number },
  rpcUrls: readonly string[],
  explorer?: string,
): AddChain => ({
  chainId: `0x${id.toString(16)}`,
  chainName: name,
  nativeCurrency: { name: cur.name, symbol: cur.symbol, decimals: cur.decimals },
  rpcUrls: [...rpcUrls],
  ...(explorer ? { blockExplorerUrls: [explorer] } : {}),
});

type SweepTx = {
  from?: unknown;
  to?: unknown;
  value?: unknown;
  data?: unknown;
  chainId?: unknown;
  gas?: unknown;
  gasPrice?: unknown;
};
/**
 * Fail-closed check for a fork / extra-EVM sweep: it must be an EIP-155 tx (chainId set, equal to the expected chain)
 * from the owner that can only pay the owner: native value straight to the owner with no calldata, or a zero-value
 * ERC-20 transfer(owner, amount) on the expected token.
 */
export function verifySweepTx(
  tx: SweepTx,
  owner: string,
  chainId: number,
  token?: string,
): Verdict {
  const no = (reason: string) => ({ verified: false, reason }) as const;
  try {
    if (!isAddress(owner)) return no("owner is not an address");
    const own = getAddress(owner);
    if (typeof tx.chainId !== "number" || tx.chainId !== chainId)
      return no("chainId missing or wrong (EIP-155 replay protection)");
    if (typeof tx.from !== "string" || !isAddress(tx.from) || getAddress(tx.from) !== own)
      return no("from is not the owner");
    if (typeof tx.to !== "string" || !isAddress(tx.to)) return no("bad to");
    const data = typeof tx.data === "string" ? tx.data : "0x";
    const value = BigInt(String(tx.value ?? "0"));
    if (!token) {
      if (data !== "0x") return no("native sweep must carry no calldata");
      if (getAddress(tx.to) !== own) return no("native sweep does not pay the owner");
      if (value <= 0n) return no("nothing to send");
      return { verified: true, call: `native transfer to owner (chainId ${chainId})` } as const;
    }
    if (!isAddress(token) || getAddress(tx.to) !== getAddress(token))
      return no("token sweep to the wrong contract");
    if (value !== 0n) return no("token sweep must send no native value");
    const d = decodeFunctionData({ abi: erc20Abi, data: data as `0x${string}` });
    if (d.functionName !== "transfer") return no("not an ERC-20 transfer");
    const [to, amt] = d.args as readonly [string, bigint];
    if (getAddress(to) !== own) return no("token transfer does not pay the owner");
    if (amt <= 0n) return no("nothing to send");
    return {
      verified: true,
      call: `transfer(owner, ${amt}) on ${getAddress(token)} (chainId ${chainId})`,
    } as const;
  } catch (e) {
    return no(`unverifiable: ${(e as Error).message.slice(0, 80)}`);
  }
}
