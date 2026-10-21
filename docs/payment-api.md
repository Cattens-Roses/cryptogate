# Payment API

HTTP payment gateway (`payment-api`). Shared SPV scan per currency, idle until invoices exist, multi-deposit window, then auto-forward to your payout address.

```sh
cp config.example.json config.json   # set api_key, vault_password, payouts
cargo run --release -p payment-api -- --config config.json
```

Default listen: value of `listen` in config (example: `127.0.0.1:8787`).

---

## Authentication

Every `/api/*` route requires the API key (except `/health`).

| Method | Example |
|---|---|
| Header | `X-Api-Key: YOUR_KEY` |
| Bearer | `Authorization: Bearer YOUR_KEY` |
| Query | `?api_key=YOUR_KEY` |

Missing/invalid key → `401` `{"error":"invalid api key"}`.

---

## Lifecycle

```text
POST /api/create/<currency>
        │
        ▼
   status: pending          ← accepts many deposits (confirmed + mempool)
        │
        ├── POST /api/payend/<id>
        │         or
        └── max_payment_secs elapsed
                │
                ▼
   paid (received > 0)  ──► auto-forward (≥6 conf LTC/BTC) ──► forwarded
   expired (received = 0)
```

- While **`pending`**, the invoice stays open; first receipt does **not** close it.
- Close with **`/api/payend/{id}`** or when **`expires_unix`** is reached (`created_unix + max_payment_secs`).
- Auto-forward runs only after the window is closed and confirmed funds are spendable.

---

## Endpoints

### `GET /health`

No auth. Liveness probe.

**Response `200`**
```json
{"ok": true}
```

---

### `POST /api/create/{currency}`

Create an invoice and allocate a fresh receive address.

**Path**

| Param | Values |
|---|---|
| `currency` | `ltc`, `btc`, or `eth` (must be `enabled` in config) |

**Query**

| Param | Required | Description |
|---|---|---|
| `amount` | no | Optional expected amount (display/hint only; does not auto-close) |
| `api_key` | if no header | API key |

**Response `201`** — invoice object (see [Invoice object](#invoice-object)).

**Errors**

| Code | When |
|---|---|
| `401` | bad API key |
| `400` | disabled/unknown currency, invalid amount |

**Example**
```sh
curl -sS -X POST -H "X-Api-Key: YOUR_KEY" \
  "http://127.0.0.1:8787/api/create/ltc"

curl -sS -X POST -H "X-Api-Key: YOUR_KEY" \
  "http://127.0.0.1:8787/api/create/ltc?amount=0.01"
```

---

### `GET /api/status/{id}`

Read invoice state, balances, and per-address transactions.

**Response `200`** — invoice object.

**Errors**

| Code | When |
|---|---|
| `401` | bad API key |
| `404` | unknown id |

**Example**
```sh
curl -sS -H "X-Api-Key: YOUR_KEY" \
  "http://127.0.0.1:8787/api/status/INVOICE_ID"
```

---

### `POST /api/payend/{id}`

Close the payment window.

- Confirmed `received > 0` → status becomes **`paid`** (forward when spendable).
- No confirmed funds → **`expired`**.
- Already closed → `400` (idempotent read of current state is via `/status`).

**Example**
```sh
curl -sS -X POST -H "X-Api-Key: YOUR_KEY" \
  "http://127.0.0.1:8787/api/payend/INVOICE_ID"
```

---

## Invoice object

```json
{
  "id": "2e28eb86-64f0-4220-8ba8-2ac52cd18073",
  "currency": "ltc",
  "ticker": "LTC",
  "address": "ltc1q…",
  "status": "pending",
  "expected_amount": "0.01000000",
  "expected_amount_raw": 1000000,
  "received": "0.00124781",
  "received_raw": 124781,
  "received_unconfirmed": "0.00010000",
  "received_unconfirmed_raw": 10000,
  "transactions": [
    {
      "txid": "abcd…",
      "amount": "0.00124781",
      "amount_raw": 124781,
      "confirmed": true,
      "height": 2912345
    },
    {
      "txid": "ef01…",
      "amount": "0.00010000",
      "amount_raw": 10000,
      "confirmed": false,
      "height": 0
    }
  ],
  "forward_txid": null,
  "forward_error": null,
  "created_unix": 1792619447,
  "expires_unix": 1792623047,
  "expires_in_secs": 3210
}
```

| Field | Meaning |
|---|---|
| `received` / `received_raw` | Confirmed incoming total on the invoice address |
| `received_unconfirmed*` | Mempool/relay observation (advisory, not payment proof) |
| `transactions[]` | Incoming txs for this address (`confirmed` + unconfirmed) |
| `expected_amount*` | Optional create-time hint; does not auto-close the invoice |
| `expires_unix` | Auto-payend deadline |
| `expires_in_secs` | Seconds left while `pending` (0 after close / past deadline) |
| `forward_txid` | Auto-payout broadcast txid when status is `forwarded` |
| `forward_error` | Last broadcast failure (`forward_failed`) |

Decimals: **8** for LTC/BTC, **18** for ETH. Raw values are integer base units (litoshi / satoshi / wei).

---

## Status values

| Status | Meaning |
|---|---|
| `pending` | Window open — still accepting deposits |
| `paid` | Window closed with confirmed funds; waiting for / doing auto-forward |
| `forwarded` | Swept to `payout_address` |
| `forward_failed` | Broadcast failed; worker retries |
| `expired` | Window closed with zero confirmed funds |

**Spendability (LTC/BTC):** forward needs **≥ 6 confirmations** (100 for coinbase). Until then status stays `paid` and forward is deferred.

---

## Config (`config.json`)

See `config.example.json`.

| Field | Description |
|---|---|
| `listen` | Bind address, e.g. `127.0.0.1:8787` |
| `api_key` | Shared secret for API auth |
| `data_dir` | Vault, SPV state, `state/invoices.json` |
| `vault_password` | Encrypts BIP39 seed (≥ 10 chars) |
| `idle_disconnect_secs` | Drop peers when no active invoices (min 30, default 120) |
| `max_payment_secs` | Open-window length (60–86400, default 3600) |
| `networks.<id>.enabled` | `ltc` / `btc` / `eth` |
| `networks.<id>.payout_address` | Auto-forward destination |
| `networks.<id>.fee_rate` | LTC/BTC: litoshi\|sat per vB; ETH: max gwei/gas |
| `networks.<id>.max_peers` | Peer slots (mempool needs ≥ 3 on UTXO) |

First start prints a recovery mnemonic once — back it up offline.

---

## Typical merchant flow

```sh
# 1. Create
ID=$(curl -sS -X POST -H "X-Api-Key: $KEY" \
  "http://127.0.0.1:8787/api/create/ltc" | jq -r .id)
ADDR=$(curl -sS -H "X-Api-Key: $KEY" \
  "http://127.0.0.1:8787/api/status/$ID" | jq -r .address)

# 2. Show $ADDR to the customer; poll status (multiple deposits OK)
curl -sS -H "X-Api-Key: $KEY" "http://127.0.0.1:8787/api/status/$ID" | jq

# 3. Close when done (or wait for expires_unix)
curl -sS -X POST -H "X-Api-Key: $KEY" \
  "http://127.0.0.1:8787/api/payend/$ID" | jq

# 4. Wait until status == forwarded (after ≥6 confs on UTXO)
```

---

## Notes

- Chains stay **idle** (no peer downloads) until at least one active invoice exists for that currency.
- Multiple open invoices on the same currency share **one** scanner.
- Unconfirmed amounts and txs are best-effort relay observations, not proof of acceptance.
- ETH has no public mempool listener in this gateway; unconfirmed incoming may stay empty.
