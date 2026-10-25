# Monero sweep design (DESIGN ONLY, not implemented, untested)

Status: blocktools derives Monero keys and addresses from a 25-word English seed (KAT-verified),
validates standard addresses, lists `xmr` in the chain table (verified flag covers address
encode/validate only), and writes a view-only `generate_from_keys` request (`xmr-keys --scan-out`).
It does not scan, build, sign, or broadcast Monero transactions.

## Why it is different from every other chain here
- Funds can't be looked up by address. Outputs are one-time stealth keys; finding them takes the
  private view key and a scan of every transaction since the restore height.
- Spending needs the private spend key, key images, ring members (decoys) taken from the chain,
  CLSAG ring signatures, Pedersen commitments and Bulletproofs+ range proofs. Getting any of that
  wrong burns funds or leaks privacy. We will not hand-roll it.

## Plan
1. Scan (view-only, no spend key leaves the box): `xmr-keys --scan-out req.json` (0600) is fed to
   the user's own `monero-wallet-rpc` (or a self-hosted LWS) talking to their own node. Output: balance
   and a list of received outputs. Public data only goes into the report.
2. Sweep: use upstream `monero-wallet-rpc` `restore_deterministic_wallet` (seed on stdin to a
   locally run, sealed process) and then `sweep_all` with `do_not_relay=true`, so we get the tx blob
   and the tx metadata unsigned for relay.
3. Simulate before relay, as for other chains: `describe_transfer` or decode the unsigned set,
   check the destination is exactly `--expect-to`, fee is within bounds, and the amount equals the
   scanned balance minus fee. TTY confirmation code. Then `relay_tx`.
4. KATs: stagenet only, with a published stagenet seed; record txids. No mainnet test.

## Secrets
Seed: stdin only, Zeroizing. View key: only in the 0600 scan file, never stdout/stderr.
Spend key: never written; exists only inside the wallet-rpc process.

## Untested / open
Everything in steps 1–4. Subaddresses (major/minor index scan), integrated addresses,
Polyseed, other wordlists, and MyMonero 13-word seeds are not supported yet.
