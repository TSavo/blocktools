# Offline EVM fixtures (no keys)

- `eip712-mail.json`, `eip712-mail-signed.json`: the Mail example from the EIP-712 specification and its published signature.
- `candidate-errors.txt`: error declarations typed from the Uniswap Universal Router source.
- `erc20-plus-collision.txt`: the EIP-20 function list plus one colliding signature.
- `eip2612-permit-usdc.json`: a constructed, UNSIGNED EIP-2612 `Permit` for USDC on chain 1 (domain name "USD Coin",
  version "2"), unlimited value, spender Permit2. Written by hand for the recipe; it was never signed or sent.
- `permit-drainer-exact-balance.json`: `eip2612-permit-usdc.json` with value 1234567890 and spender
  0x1111111111111111111111111111111111111111 (a constructed exact-balance drainer). UNSIGNED, never sent.
- `permit2-single-02a.json`: the Permit2 `PermitSingle` and its signature carried inside the public mainnet Universal
  Router tx in `../evm-mainnet/02a-swap-tx.json` (first `execute` input, command 0x0a). The values and signature are
  copied from that tx's calldata; `signer` is that tx's `from`. Nothing here was signed by us.
- `seaport-listing-1.6.json`: a constructed, UNSIGNED Seaport 1.6 `OrderComponents` listing (domain and types from
  ProjectOpenSea/seaport eip-712-types, canonical 1.6 address from its README): one ERC721 offered for 0.975 ETH to
  the offerer plus 0.025 ETH to another recipient. Written by hand; never signed or sent.
- `seaport-drainer-zero-consideration.json`: the same order with the only consideration (1 wei) going to
  0x1111111111111111111111111111111111111111: the offerer gets nothing back. UNSIGNED, never sent.
  Their EIP-712 digests (listing 0x1372f9ee…090b, drainer 0x0ab96a6c…d09f) were checked once against viem 2.57.14
  `hashTypedData` (scripts/abi-fuzz pin); this is a one-off local check, not a CI gate.
