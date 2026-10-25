import { decodeFunctionData, erc20Abi, getAddress, isAddress } from "viem";

export type SweepTx = {
  from: string;
  to: string;
  value: string;
  gas?: string;
  gasPrice?: string;
  data?: string;
  chainId: number;
};

/**
 * Browser-side twin of the API's verifySweepTx. Fails closed: the transfer must carry chainId (EIP-155) equal to the
 * expected chain, come from the connected wallet and pay only the connected wallet (native value with no calldata,
 * or a zero-value ERC-20 transfer(owner, amount) on the expected token).
 */
export function checkSweepTx(
  tx: SweepTx | undefined,
  owner: string | undefined,
  chainId: number,
  token?: string,
): string | null {
  try {
    if (!tx || !owner || !isAddress(owner)) return "connect the wallet that holds these coins";
    const own = getAddress(owner);
    if (tx.chainId !== chainId) return "chainId missing or wrong (EIP-155 replay protection)";
    if (!isAddress(tx.from) || getAddress(tx.from) !== own)
      return "the transfer is not from your connected wallet";
    if (!isAddress(tx.to)) return "bad destination";
    const data = tx.data ?? "0x";
    const value = BigInt(tx.value || "0");
    if (!token) {
      if (data !== "0x") return "unexpected calldata";
      if (getAddress(tx.to) !== own) return "the transfer does not pay your connected wallet";
      return value > 0n ? null : "nothing to send after gas";
    }
    if (!isAddress(token) || getAddress(tx.to) !== getAddress(token)) return "wrong token contract";
    if (value !== 0n) return "token transfer must send no native value";
    const d = decodeFunctionData({ abi: erc20Abi, data: data as `0x${string}` });
    if (d.functionName !== "transfer") return "not a token transfer";
    const [to, amt] = d.args as readonly [string, bigint];
    if (getAddress(to) !== own) return "the token transfer does not pay your connected wallet";
    return amt > 0n ? null : "nothing to send";
  } catch (e) {
    return `could not verify (${(e as Error).message.slice(0, 60)})`;
  }
}

const hex = (v: string | number) => `0x${BigInt(v).toString(16)}`;
/** eth_sendTransaction params; chainId is always included so the wallet signs EIP-155. */
export const txParams = (tx: SweepTx) => ({
  from: tx.from,
  to: tx.to,
  value: hex(tx.value || "0"),
  ...(tx.gas ? { gas: hex(tx.gas) } : {}),
  ...(tx.gasPrice ? { gasPrice: hex(tx.gasPrice) } : {}),
  ...(tx.data && tx.data !== "0x" ? { data: tx.data } : {}),
  chainId: hex(tx.chainId),
});
