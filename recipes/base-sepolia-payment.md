# Review an exact Base Sepolia USDC payment

Use the standalone Linux `tx-sign` built from this checkout. Export the
public JSON result of SwapChan's `POST /payments/build` as `build.json`.
Supply the sender and recipient you intend to use, the exact payout in
micro-USDC, the reviewed maximum WETH spend in wei, and the reviewed
maximum gas charge in micro-USDC. One micro-USDC is 0.000001 USDC.

    tx-sign base-sepolia-payment build.json SENDER RECIPIENT PAYOUT MAX_WETH MAX_GAS --inspect

The recipient payment inside the batch is an ERC-20 transfer. To identify its selector when reading the batch calldata, run:

<!-- e2e: expect=0xa9059cbb -->
    sig-hash 'transfer(address,uint256)'

The inspection step also checks the decoded recipient and amount. Inspection requires no key. The command reconstructs the Simple7702Account
batch, checks the Uniswap router and Pimlico paymaster, and computes the
EntryPoint v0.8 UserOperation digest. A direct USDC payment has a WETH
spend cap of zero. The quote must still be valid when signing.

To sign, omit `--inspect` and pipe the sender's key from the existing
offline Block Tools key pipeline. Review the prompt in the signing terminal.
Send only the returned signature, quote ID, and operation hash to
`POST /payments/submit`. Look up the hash at `GET /payments/status/:hash`
to check the verified payout and gas charge.

For first-time account setup, use the account nonce from the fresh quote:

    tx-sign authorize-delegate 84532 NONCE SENDER 0x4Cd241E8d1510e30b2076397afc7508Ae59C66c9

Supply the sender key on stdin as above. The resulting authorization grants
persistent account delegation. The SmartWallet payment form accepts the
public JSON output. To authorize revocation, use the current account nonce
and the zero address as delegate. Revocation takes effect when that
authorization is included in a successful set-code transaction.
