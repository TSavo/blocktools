# Roadmap (planned — not yet implemented unless marked)

| # | Item | Fits into |
|---|------|-----------|
| 1 | `derive --chain` presets from a data table (encoding, params, curve): BTC 44'/0', LTC 2' (hrp `ltc`), DOGE 3' (p2pkh 0x1e), ETH/EVM 44'/60'/0'/0/i, Tron (keccak, base58 0x41), Solana/TON (ed25519). Default range 0..9 (ETH 0..4). Legacy BTC-family: compressed **and** uncompressed. | M3 prelude |
| 2 | Electrum seeds in `seed-to-master`: version = HMAC-SHA512("Seed version", normalized phrase), prefix 01 standard / 100 segwit / 101 2FA; root = PBKDF2-SHA512 salt "electrum"+passphrase; old-Electrum non-hardened m/{0,1}/i; sliding window of last 12/13/15/24 words. | M5 |
| 3 | `classify`: stdin text → public JSON (type, line, hash fingerprint first/last 4) for BIP39/Electrum seeds, 64-hex, WIF, x/y/zprv, base64/base58 32-byte, V3 keystore, addresses. Never echoes the secret. | M5 |
| 4 | `rawkey-to-addresses`: 32-byte key (hex/base64/base58) → BTC/ETH/Tron/Solana addresses. | with 1 |
| 5 | Boundary: placeholder substitution then leak check before print. **Done** in kr-redact (redact + LEAK check in e2e); in-process re-check to add. | M3 |
| 6 | `tx-sign` / sweep: assert destination address before signing. | M3 |
| 7 | `tx-broadcast` chain config `{chain,type: bitcoind-rpc\|esplora\|evm-jsonrpc\|solana-rpc\|tron-api\|ton-api,url}`; credentials via stdin/config only. Default endpoint suggestions (unverified, check at use): mempool.space, litecoinspace.org, dogechain.info, trongrid, Solana mainnet-beta, publicnode (ETH/Base/Arbitrum/Optimism). Mock-tested only. | M4 |
| 8 | Known-answer tests: privkey 1 → P2PKH compressed/uncompressed; XRP ACCOUNT_ZERO. | with 1 |
