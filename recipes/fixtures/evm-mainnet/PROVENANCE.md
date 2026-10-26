# RPC fixtures (Ethereum mainnet, chainId 0x1)
RPC: https://ethereum-rpc.publicnode.com (no key). eth.llamarpc.com returned HTTP 525, not used.
Captured 2026-10-26 ~03:20 UTC; head 0x190e93b at capture. Each *.json is the raw response body, untouched.
Notes:
- 04c: replaying reverted tx 0x61495cbd... at parent block via eth_call returned success "0x", so it did NOT reproduce the revert (in-block state differs). No revert data for a mined tx captured.
- 04e: data 0x5bf6f916 is a 4-byte custom-error selector, not decoded here.
- 05c/05d: CREATE2 salt/init-code not taken from the response; per Uniswap V3 these derive from token0/token1/fee in the PoolCreated log plus the factory's fixed init-code hash (not fetched).
- 06: code is ~4 KB, not tiny.
- Archive state (older than ~128 blocks) needs a token on this RPC; getLogs over 5000 blocks for one address worked.

## 04c-revert-replay-eth_call.json
- eth_call replaying reverted Universal Router tx 0x61495cbd... (from/to/input/value/gas copied from its tx object) at parent block 0x190e925; state is end-of-parent-block, not the exact in-block position
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:18Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0xd86c51b7a07bc01056470ec03e4adaff5044ab67","to":"0x66a9893cc07d91d95644aedd05d03f95e1dba8af","data":"0x3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000006adec4db00000000000000000000000000000000000000000000000000000000000000020a100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001c00000000000000000000000000000000000000000000000000000000000000160000000000000000000000000c8fb80fcc03f699c70ff0cc08c09106288888888000000000000000000000000000000000000000000000026ac9f0094d5adc898000000000000000000000000000000000000000000000000000000006adec4db00000000000000000000000000000000000000000000000000000000000014ff00000000000000000000000066a9893cc07d91d95644aedd05d03f95e1dba8af000000000000000000000000000000000000000000000000000000006adec4db00000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000041227c0ec057e93a419eda67e7b0fb645583f03ea404fc36875aab9defcebaed7b4137f74fd18e2fe02c518d06ada49d031dfe65c063df664468e6608dd7a591c11b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000340000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000003060c0f00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001e00000000000000000000000000000000000000000000000000000000000000240000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c8fb80fcc03f699c70ff0cc08c091062888888880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000026ac9f0094d5adc89800000000000000000000000000000000000000000000000000dcda35624848f9000000000000000000000000000000000000000000000000000000000000012000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000c8fb80fcc03f699c70ff0cc08c09106288888888000000000000000000000000000000000000000000000026ac9f0094d5adc898000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","value":"0x0","gas":"0x219db"},"0x190e925"]}' https://ethereum-rpc.publicnode.com
```

## 00-eth_blockNumber.json
- Chain head at capture time
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:18Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' https://ethereum-rpc.publicnode.com
```

## 01a-erc20-transfer-tx.json
- USDC transfer tx by hash (block 0x190e92a)
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:18Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0xc0ee5b5618437369d0925560368ee87b84569ef1e6a2763983efa5fc437231ab"]}' https://ethereum-rpc.publicnode.com
```

## 01b-erc20-transfer-receipt.json
- Receipt of that tx incl. USDC Transfer log(s)
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:18Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["0xc0ee5b5618437369d0925560368ee87b84569ef1e6a2763983efa5fc437231ab"]}' https://ethereum-rpc.publicnode.com
```

## 01c-usdc-transfer-getLogs.json
- eth_getLogs: all USDC Transfer logs in block 0x190e92a
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:18Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{"fromBlock":"0x190e92a","toBlock":"0x190e92a","address":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"]}]}' https://ethereum-rpc.publicnode.com
```

## 02a-swap-tx.json
- Uniswap Universal Router (0x66a9893c...) execute() tx with swap calldata, block 0x190e928
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:19Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0x612dba31f47c02efce03d5c7605a623dfcdac47c1aeda41d4475a87853e3a042"]}' https://ethereum-rpc.publicnode.com
```

## 02b-swap-receipt.json
- Receipt of that swap tx (Swap/Transfer logs)
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:19Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["0x612dba31f47c02efce03d5c7605a623dfcdac47c1aeda41d4475a87853e3a042"]}' https://ethereum-rpc.publicnode.com
```

## 03a-usdc-decimals.json
- eth_call USDC decimals() selector 0x313ce567 at latest
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:19Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x313ce567"},"latest"]}' https://ethereum-rpc.publicnode.com
```

## 03b-usdc-symbol.json
- eth_call USDC symbol() selector 0x95d89b41 at latest
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:19Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x95d89b41"},"latest"]}' https://ethereum-rpc.publicnode.com
```

## 03c-usdc-balanceOf.json
- eth_call USDC balanceOf(Uniswap V3 USDC/WETH 0.05% pool 0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640) selector 0x70a08231 at latest
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:19Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x70a0823100000000000000000000000088e6a0c2ddd26feeb64f039a2c41296fcb3f5640"},"latest"]}' https://ethereum-rpc.publicnode.com
```

## 04a-revert-tx.json
- Real reverted (status 0x0) Universal Router tx by hash, block 0x190e926
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:20Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0x61495cbde17c4adbbae9760b2bc94b485b782d9c3c8e11d94398815eff36bb14"]}' https://ethereum-rpc.publicnode.com
```

## 04b-revert-receipt.json
- Its receipt (status 0x0)
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:20Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["0x61495cbde17c4adbbae9760b2bc94b485b782d9c3c8e11d94398815eff36bb14"]}' https://ethereum-rpc.publicnode.com
```

## 04d-error-string-eth_call.json
- eth_call USDC transferFrom(0x...dEaD -> 0x...0001, 1) from 0x...0001 with no allowance; expected Error(string) revert
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:20Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000001","to":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","data":"0x23b872dd000000000000000000000000000000000000000000000000000000000000dead00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001"},"latest"]}' https://ethereum-rpc.publicnode.com
```

## 05a-create-tx.json
- CREATE deployment tx (to=null), block 0x190e922
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:20Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0x151d3bb3ff55ec951c90e059cdbc9ffdee3e0e2c86306c0239e6dadf29af9289"]}' https://ethereum-rpc.publicnode.com
```

## 05b-create-receipt.json
- Its receipt; contractAddress field
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:20Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["0x151d3bb3ff55ec951c90e059cdbc9ffdee3e0e2c86306c0239e6dadf29af9289"]}' https://ethereum-rpc.publicnode.com
```

## 05c-create2-pool-tx.json
- Uniswap V3 pool creation (CREATE2 by factory 0x1F98431c...) tx, block 0x190e590
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:21Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0xef7c200f7d463473cbbfe1d593178310182143e0f06681c3dfe3803e12b467f5"]}' https://ethereum-rpc.publicnode.com
```

## 05d-create2-pool-receipt.json
- Its receipt incl. PoolCreated log (token0, token1, fee, tickSpacing, pool)
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:21Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["0xef7c200f7d463473cbbfe1d593178310182143e0f06681c3dfe3803e12b467f5"]}' https://ethereum-rpc.publicnode.com
```

## 06-getCode-small.json
- eth_getCode of the CREATE-deployed contract 0x0a0e5274... at latest
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:21Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getCode","params":["0x0a0e5274d286a72614a4e4015370395ef9e42eed","latest"]}' https://ethereum-rpc.publicnode.com
```

## 07-block.json
- eth_getBlockByNumber 0x190e928 (tx hashes only), context block for swap
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:21Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["0x190e928",false]}' https://ethereum-rpc.publicnode.com
```

## 04e-custom-error-eth_call.json
- eth_call Universal Router execute(bytes,bytes[],uint256) selector 0x3593564c with empty commands/inputs and deadline=1; expected custom-error revert
- RPC: https://ethereum-rpc.publicnode.com
- fetched (UTC): 2026-10-26T03:15:31Z
```
curl -s -X POST -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x66a9893cc07D91D95644AEDD05D03f95e1DBA8Af","data":"0x3593564c00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},"latest"]}' https://ethereum-rpc.publicnode.com
```

