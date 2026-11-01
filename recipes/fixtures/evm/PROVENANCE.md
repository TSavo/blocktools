# Offline EVM fixtures (no keys)

- `eip712-mail.json`, `eip712-mail-signed.json`: the Mail example from the EIP-712 specification and its published signature.
- `candidate-errors.txt`: error declarations typed from the Uniswap Universal Router source.
- `erc20-plus-collision.txt`: the EIP-20 function list plus one colliding signature.
- `eip2612-permit-usdc.json`: a constructed, UNSIGNED EIP-2612 `Permit` for USDC on chain 1 (domain name "USD Coin",
  version "2"), unlimited value, spender Permit2. Written by hand for the recipe; it was never signed or sent.
- `permit2-single-02a.json`: the Permit2 `PermitSingle` and its signature carried inside the public mainnet Universal
  Router tx in `../evm-mainnet/02a-swap-tx.json` (first `execute` input, command 0x0a). The values and signature are
  copied from that tx's calldata; `signer` is that tx's `from`. Nothing here was signed by us.
