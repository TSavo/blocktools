/**
 * Sandwich guard for liquidity / Pendle exits: minimum outputs come from a live quote minus a
 * small slippage, and the deadline is short. No quote -> no tx (the finding shows a plain note).
 */
export const EXIT_SLIPPAGE_BPS = 100n; // 1%
export const EXIT_DEADLINE_S = 20 * 60; // 20 minutes
/** verifyRecovery rejects exit deadlines further out than this (covers clock skew + slow signing). */
export const EXIT_DEADLINE_MAX_S = 60 * 60;
export const minOut = (quoted: bigint, bps = EXIT_SLIPPAGE_BPS) => (quoted * (10_000n - bps)) / 10_000n;
export const exitDeadline = (nowMs = Date.now()) => BigInt(Math.floor(nowMs / 1000) + EXIT_DEADLINE_S);
export const deadlineOk = (d: bigint, nowMs = Date.now()) => d <= BigInt(Math.floor(nowMs / 1000) + EXIT_DEADLINE_MAX_S);
export const PRIVATE_SUBMISSION_NOTE =
  "This exit swaps or removes liquidity, so a bot could sandwich it in the public mempool. Minimums are set from a live quote (1% slippage) and the transaction expires in 20 minutes. For extra protection, send it through a private RPC such as Flashbots Protect or MEV Blocker.";
export const NO_QUOTE_NOTE =
  "Could not get a live quote to set a safe minimum output, so no transaction is offered (a zero-minimum exit could be sandwiched). Run find_money again later.";
