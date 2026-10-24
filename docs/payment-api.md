# Payment API

HTTP gateway for native BTC, transparent LTC and native ETH. Each enabled currency has one shared wallet and scanner. The API and scanner serialize access to that same wallet, and the seed vault remains exclusively locked until shutdown. A second gateway using the same data directory is rejected.

## Run and backup

Copy `config.example.json` to `config.json`, replace the API key, vault password and enabled payout addresses, then run:

```sh
cargo run --release -p payment-api -- --config config.json
```

Enabled payout addresses are validated before opening or creating a vault. Ethereum payouts must be ordinary accounts without code; this is also checked against a verified account proof before signing.

New gateway vaults encrypt a random 64-byte seed directly. They do **not** generate, request or log a recovery phrase. Existing mnemonic-based vaults remain compatible and keep their existing keys and addresses. Back up the **entire `data_dir` and the vault password**: the vault is required to recover the keys, while invoices, issued address indices and payout journals preserve accounting and interrupted transfers. Keep backups private.

## Authentication

All `/api/*` endpoints require `X-Api-Key: YOUR_KEY` or `Authorization: Bearer YOUR_KEY`. The legacy `?api_key=` form remains accepted, but headers avoid placing credentials in URLs and access logs. Call this API from your site's backend; keep the key off public browser pages. Missing or incorrect credentials return HTTP 401.

## Merchant integration

1. Create an invoice with an exact expected amount, e.g. `POST /api/create/btc?amount=0.001`.
2. Save its `id` against the order and display its address with the correct network.
3. Poll `GET /api/status/{id}` and authorize the order only when **`payment_complete` is true**. Make order fulfillment idempotent in your site's database.
4. `POST /api/payend/{id}` closes the deposit window and permits automatic forwarding. Repeating it is safe. The window also closes after `max_payment_secs`.

`amount` is optional for donation/open-amount invoices. If supplied, **all of it** must be credited before `payment_complete` becomes true. Closing or forwarding an underpayment never makes it a fully paid order. BTC/LTC credit requires at least six confirmations (100 for coinbase); ETH balances must be verified at a finalized Beacon anchor. If peers cannot serve a finalized state proof, ETH waits rather than treating optimistic funds as final.

After window closure, known unconfirmed deposits, immature credits and unresolved payouts remain active until settlement. A closed empty invoice is archived after a current chain observation; a payout is archived after confirmation once only fee dust remains and there are no known pending deposits. Partial sweeps remain active while other deposits await maturity. Underpaid invoices can also finish after their funds are settled.

Finished invoices are read from saved receipts only: they are not rescanned or reopened for later deposits. **Do not reuse a finished invoice address for a new payment.** Deposits sent after retirement are outside that invoice's automatic processing. When a currency has no active invoices, its scanner disconnects and releases the wallet; a new invoice resumes scanning. Ethereum account queries are restricted to active invoice addresses, rather than polling all historical accounts. `idle_disconnect_secs` remains accepted for compatibility; disconnection after the last active invoice is immediate.

## Endpoints

- `POST /api/create/{currency}?amount=...`: currencies `btc`, `ltc`, `eth`; returns HTTP 201 and an invoice. Invalid amounts, disabled currencies and invalid configuration return errors.
- `GET /api/status/{id}`: returns an invoice; unknown ID returns HTTP 404.
- `POST /api/payend/{id}`: closes the window; returns the current invoice, including on repeated requests.
- `GET /health`: no authentication. Returns 200 with `{"ok":true}` while workers report no errors, or 503 with `{"ok":false}` after a worker error or shutdown. This is worker health, not a guarantee that initial chain sync has completed.

## Invoice fields

Amounts such as `received` use decimal strings in coin units. **Every `*_raw` monetary field is a decimal string in base units**, including transaction `amount_raw`; absent `expected_amount_raw` is null. Do not convert raw strings to JavaScript `Number`: use `BigInt` or an exact decimal library. This is an API change from earlier numeric raw fields.

- `id`, `currency`, `ticker`, `address`: invoice identity and receive destination.
- `expected_amount`, `expected_amount_raw`: full amount needed for the order, or null for an open-amount invoice.
- `received`, `received_raw`: cumulative credited deposits, including funds already forwarded. BTC/LTC use retained inclusion proofs, not the current unspent balance. ETH adds actual confirmed payout debits (including actual gas fees) to verified balances; new credits wait while a payout is unresolved.
- `received_unconfirmed`, `received_unconfirmed_raw`: deposits not yet credited under the confirmation policy, including best-effort relay observations on BTC/LTC. These are not payment proof.
- `balance_raw`: current observed balance remaining at the receive address; it may include immature BTC/LTC outputs.
- `payment_complete`: full expected amount credited, or positive credited funds for an open-amount invoice. This is the field for merchant order authorization.
- `verified`: observations were revalidated during the current process run. It starts false after a restart for unfinished invoices; those balances require fresh proofs. Finished receipts retain their completed result without restarting the scanner.
- `window_closed`: whether forwarding is permitted.
- `finished`: terminal archived receipt; no further deposits are processed for it and status reads do not start chain queries.
- `transactions`: available incoming transaction history. BTC/LTC entries retain spent deposits; `confirmed` means block inclusion and does not by itself imply the six-confirmation merchant threshold. ETH account balance proofs, including internal deposits, are authoritative; per-address transaction listings may be empty.
- `forward_txid`: latest journaled payout transaction ID, possibly still pending.
- `forward_txids`: all journaled payout transaction IDs. One invoice can have multiple sweeps for deposits maturing at different times or arriving later.
- `forward_error`: last preparation or relay error; preserved across restarts.
- `created_unix`, `expires_unix`, `expires_in_secs`: window timing.

## Status and forwarding

- `pending`: payment window is open.
- `awaiting_confirmation`: window closed with deposits that have not met the credit policy.
- `expired`: window closed with no credited funds; a currently observed empty invoice is archived.
- `underpaid`: closed with some credited funds below the expected amount.
- `paid`: expected amount credited and window closed; funds await forwarding.
- `forwarding`: an exact signed payout is journaled and awaits confirmation. A relay error can coexist with this status: check `forward_error`.
- `forward_failed`: payout preparation failed; the error is exposed and retried.
- `forwarded`: a payout is confirmed and the remaining balance is below its previous fee. After settlement it is archived (`finished: true`). This status does not replace `payment_complete` as proof of a fully paid order.

The gateway persists the signed payout **before** network delivery. Timeout, process termination or restart retries the same signed bytes and transaction ID rather than signing another spend. A peer pong or successful relay is not a confirmation. BTC/LTC payouts require six confirmations; ETH confirmation comes from finalized verified history and actual gas accounting. Already observed immature deposits remain watched and receive later sweeps when spendable; completed invoices are then retired. Preparation errors and save failures are propagated instead of silently marking payouts successful.

On upgrade, older payout IDs are reconciled against wallet reservations or verified history before another payout is signed. If evidence is unavailable, `forward_error` explains that reconciliation is pending. Older data with two invoices sharing a receive address is rejected at startup so the same deposit cannot silently credit two orders.

## Configuration

- `listen`: default example `127.0.0.1:8787`.
- `api_key`: shared server-side API secret.
- `data_dir`: vault, network state and `state/invoices.json`.
- `vault_password`: at least ten characters; required to decrypt the keys.
- `max_payment_secs`: 60–86400, default 3600.
- `idle_disconnect_secs`: compatibility setting, minimum 30.
- `networks.<id>.enabled`: enable `btc`, `ltc` or `eth`; keys must be lowercase.
- `networks.<id>.payout_address`: validated destination.
- `networks.<id>.fee_rate`: BTC/LTC 1–1000 satoshi/litoshi per vB; ETH 1–10000 max gwei/gas.
- `networks.<id>.max_peers`: configured peer budget. BTC/LTC require at least three connections for discovery plus the relay listener; ETH requires at least two.

This API supports native coins only. It does not process ERC-20, Litecoin MWEB or payments on other EVM networks.
