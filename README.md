# EngineCore

A Rust cryptocurrency wallet with a terminal UI and one backend crate per network. Litecoin, Bitcoin, and Ethereum mainnet each have a separate backend crate. The C++ `ltcengine/` directory is retained as a reference; the Rust wallet does not invoke it or share its wallet files.

## Run

Install a current stable Rust toolchain (Rust 1.88 or newer) and its platform linker. On Windows, use the MSVC toolchain with Visual Studio C++ Build Tools.

```sh
cargo run --release -p enginecore
```

The first run offers to create or restore a wallet. Without `--network`, the terminal interface then shows the available networks: use Up/Down and Space to select Litecoin, Bitcoin, or both, and Enter to start. Both are selected initially. Each enabled network has its own background worker; opening a large header cache or synchronizing one network does not block the other. Passwords and imported recovery words use hidden interactive prompts. A new wallet generates a 24-word BIP39 mnemonic and displays it once for backup. Recovery uses an empty BIP39 passphrase; mnemonics protected by an additional BIP39 passphrase are not supported.

Use a release build for header validation. First sync validates all headers from genesis and scans compact block filters, which can take a substantial time. Scrypt checks run on up to eight CPU workers. Subsequent launches authenticate the already verified header cache and skip its repeated Scrypt checks; every newly downloaded header still receives full validation. The TUI remains responsive and shows progress while opening the cache.

On the first launch after upgrading an older cache, the wallet performs one verification pass to create authenticated checkpoints. Checkpoints are saved every 2,000 headers, so cancellation or interruption resumes from the last completed batch. Keep `headers.verified.json` alongside `headers.dat`. A missing, changed, or differently keyed receipt triggers full verification; changing cached bytes also prevents reuse.

```sh
# Separate creation / restore commands
cargo run --release -p enginecore -- new
cargo run --release -p enginecore -- --data-dir ./restored-wallet restore

# Normal terminal UI with a network picker, or offline access to saved state
cargo run --release -p enginecore -- tui
cargo run --release -p enginecore -- --offline

# Start all networks in one interface without the picker
cargo run --release -p enginecore -- --network all
cargo run --release -p enginecore -- --network all --mempool

# Bitcoin mainnet with the same encrypted seed vault and separate network state
cargo run --release -p enginecore -- --network bitcoin
cargo run --release -p enginecore -- --network bitcoin --mempool
cargo run --release -p enginecore -- --network bitcoin address

# Ethereum mainnet light client (direct Beacon libp2p + execution eth/snap; no Infura/Alchemy)
cargo run --release -p enginecore -- --network ethereum
cargo run --release -p enginecore -- --network ethereum address
# Optional trusted weak-subjectivity checkpoint when the bundled anchor is stale
cargo run --release -p enginecore -- --network ethereum \
  --ethereum-checkpoint 0x… --ethereum-checkpoint-slot SLOT

# A particular trusted Litecoin Core peer, with NODE_NETWORK and NODE_COMPACT_FILTERS enabled
cargo run --release -p enginecore -- --network litecoin --peer 127.0.0.1:9333

# Optional separate mempool relay listener; uses one of the existing peer slots
cargo run --release -p enginecore -- --mempool

# Override the default maximum of 3 simultaneous peer connections
cargo run --release -p enginecore -- --max-peers 2

# CLI tools; status and address do not connect to peers
cargo run --release -p enginecore -- status
cargo run --release -p enginecore -- address
cargo run --release -p enginecore -- address --next
cargo run --release -p enginecore -- sync
```

Use `--litecoin-peer host:9333` and `--bitcoin-peer host:8333` for separate custom peers when using the picker or running multiple UTXO networks. Ethereum peers are `--ethereum-consensus-peer` (libp2p multiaddr with `/p2p/<id>`) and `--ethereum-execution-peer` (`enode://…`). The generic `--peer` requires an explicit single `--network litecoin|bitcoin`. `--max-peers` applies independently to each network (default 3; Ethereum needs at least 2 slots for consensus + execution).

A custom serving Bitcoin Core or Litecoin Core node needs `blockfilterindex=1` and `peerblockfilters=1`, with indexing complete. Nodes that only advertise Bloom support are not used. There is no BIP37 network fallback.

After building, the executable is `target/release/enginecore` (`enginecore.exe` on Windows). Wallet files default to `./wallet-data`, relative to the current directory. Use `--data-dir` to select an explicit location.

Without `--birthday`, new network state selects a scan start 10,000 blocks behind the tip after header synchronization (or block 1 on shorter chains). Header validation always starts at genesis. The selected start and scan progress are persisted; restarting continues from the saved cursor, without repeating the window. An explicit `--birthday HEIGHT` takes precedence for new/uninitialized state and is never overwritten later. When restoring a seed without a known birthday, the default tip window can omit older funds: use `--birthday 1` on the first opening/sync of the restored wallet for a full recovery, or supply a known earlier height. Existing state retains its original birthday and progress.

## Terminal controls

- `Tab` / `Shift+Tab`, `1`–`9`, or `[` / `]` on the dashboard: switch the active network. Enabled networks keep synchronizing in the background. Switching is disabled while editing, preparing, reviewing, or broadcasting a payment.
- `n`: issue and persist a fresh receive address for the active network.
- `s`: enter recipient, amount, and fee rate (litoshi/vB or sat/vB on UTXO chains; max gwei/gas on Ethereum).
- `Tab` / `Shift+Tab`: move between send fields; `Enter` advances to review.
- `y` on the review screen: broadcast exactly the reviewed transaction. `n` / `Esc` cancels.
- `r`: sync or reconnect immediately.
- `↑` / `↓` or `j` / `k`: scroll transaction history.
- `q` from the dashboard, or `Ctrl+C` anywhere: stop the worker and exit.

Use a terminal of at least 64 columns × 24 rows. Balances, receive address, header/scan progress, peer, transaction history, and errors update as sync proceeds. The peer indicator shows connected peers against the configured maximum, for example `2/3 connected`. Height `pending` means an own broadcast or observed relay transaction has no verified confirmation yet. `--mempool` is off by default; when enabled, the peer line shows its `live`/`waiting` status and pending incoming/outgoing amounts are separate from verified, spendable funds. It needs at least 3 peer slots, or 2 with an explicit trusted `--peer`, and stays within `--max-peers`. It downloads newly announced transparent transactions and filters locally, increasing traffic without sending wallet scripts. Observations are advisory, expire after an hour, and are not saved across restarts; transactions announced before connection or missed during overload/disconnection may only appear after confirmation. It requests no mempool dump and uses no Bloom filters.

## Payment API

Separate long-running HTTP service (not the TUI). Chains stay **idle** until an invoice exists; multiple invoices on one currency share **one** wallet and scanner. The payment window closes at `POST /api/payend/{id}` or `max_payment_secs`; known deposits and payouts awaiting confirmation remain active until settled. Finished invoices are archived without further scanning; when no active invoices remain, the scanner disconnects. Create a new invoice for each later payment. Authorize orders using `payment_complete`: the full expected amount must be credited (at least six confirmations on BTC/LTC, finalized state proofs on ETH). Signed payouts are journaled before relay and retried with the same transaction ID after interruption. Raw monetary API fields are exact decimal strings. New gateway vaults encrypt random seeds without creating recovery phrases; back up the complete data directory and vault password.

Full reference: **[docs/payment-api.md](docs/payment-api.md)**.

```sh
cp config.example.json config.json   # set api_key, vault_password, payout addresses, enabled networks
cargo run --release -p payment-api -- --config config.json
```

```sh
# Create / status / close (X-Api-Key, Authorization: Bearer, or ?api_key=)
curl -X POST -H "X-Api-Key: YOUR_KEY" "http://127.0.0.1:8787/api/create/ltc"
curl -H "X-Api-Key: YOUR_KEY" "http://127.0.0.1:8787/api/status/INVOICE_ID"
curl -X POST -H "X-Api-Key: YOUR_KEY" "http://127.0.0.1:8787/api/payend/INVOICE_ID"
```

## Workspace

```text
crates/
  wallet-core/           Network trait, snapshots, payments, amount parsing, encrypted vault
  networks/
    litecoin/            Litecoin addresses, Scrypt consensus, P2P, SPV state, signing
    bitcoin/             Bitcoin addresses, SHA256d consensus, P2P, SPV state, signing
    ethereum/            Ethereum addresses, Beacon+snap light client, EIP-1559 sends
  wallet-tui/            Network registration, CLI, background worker, Ratatui screens
  payment-api/           HTTP payment gateway · shared scan · auto-forward
```


`wallet-tui/src/tui.rs` depends only on the shared network contracts. To add a network, create another crate below `crates/networks/`, implement `wallet_core::Network`, add it to the workspace and application dependencies, and register its factory and CLI selector in `wallet-tui/src/main.rs`. Network-specific keys, transaction formats, fee units, receive hints, persistence, and synchronization belong in that backend.

## Litecoin implementation

- DNS seed discovery or an explicit peer; Litecoin mainnet magic and port 9333. The default connection limit is **3**, configurable with `--max-peers` (1–32). During header sync, peer workers prefetch subsequent batches while earlier batches undergo consensus validation. If a request stalls for 250 ms, alternate peers are queried concurrently; the first usable response advances the download. This avoids waiting for a slow peer's full timeout without duplicating every request. Four batches (about 640 KB) can wait in the validation queue, plus in-flight responses. Every connected peer must answer empty before header download is considered complete. All headers are retained; no trusted checkpoint shortcut replaces genesis validation. After header sync, the wallet reconnects for compact-filter scanning with cross-peer header checks and failover. An explicit `--peer` restricts discovery to that host's resolved endpoints; the wallet may therefore connect to fewer peers than the limit. The wallet advertises zero services and does not listen for incoming connections.
- Version/verack negotiation, ping/pong, exponentially spaced header locators, bounded frames, checksums, timeouts, and reconnect with backoff.
- SHA256d block identifiers and **Scrypt-1024-1-1** proof of work. Headers enforce links, expected difficulty, Litecoin's 2016-block retarget rules (including its first-period exception), median time past, future-time limits, historical checkpoints, and a historical minimum-work floor before sending.
- Candidate forks are validated across batches and replace the active chain only after accumulating strictly greater work. Orphaned wallet proofs are removed and scanning rewinds conservatively.
- BIP157/BIP158 basic block filters (`getcfcheckpt`, `getcfheaders`, `getcfilters`), queried locally against complete wallet scripts. No Bloom filter or wallet address is sent to peers. Checkpoints and filter hashes are compared across **all connected peers** before using filters; disagreement stops scanning. Untrusted discovery requires at least two peers. An explicit `--peer` opts into trusting that server for filter completeness, and works with `--max-peers 1`.
- Filters arrive in batches of up to 1,000, divided among the connected peers and downloaded concurrently. Local matching uses up to eight CPU workers and rechecks the batch whenever the watched address gap changes. Active scanning proceeds without a fixed pause between batches. Each filter is bound to the validated header chain by block hash, checked against the agreed filter hash, and evaluated locally. Only matching blocks are downloaded, from a randomly selected connected peer. `MSG_BLOCK` requests strip witnesses and MWEB serialization; transparent transaction IDs and the complete Merkle root are checked. Relevant transactions and locally generated inclusion proofs are retained; full blocks and nonmatching filters are discarded. The wallet maintains no global UTXO set.
- The newest 24 blocks are checked first during historical backfill, then new headers are polled every 15 seconds while catching up and every 10 seconds after completion. The TUI shows the recent scan height separately. A partial historical scan can show incomplete balances; sending remains disabled until backfill finishes. BIP157 has no mempool subscription: without the optional `--mempool` relay listener, incoming funds appear after inclusion in a block. Own broadcasts always appear as pending immediately.
- Filter headers connect through 1,000-block checkpoints. The newest 100 checked filter headers are pinned in wallet state across restarts and invalidated only when their blocks leave the validated chain. No complete filter archive is required.
- BIP84 receive/change branches at `m/84'/2'/0'/{0,1}/i`, with a 20-address discovery gap. The gap expands when used addresses are discovered, including rescanning the current block when necessary. Receive addresses are native SegWit `ltc1q…`.
- Outgoing P2WPKH inputs use BIP143 ECDSA signatures. Recipient addresses can be Litecoin P2PKH, either Litecoin P2SH prefix, P2WPKH, P2WSH, or Taproot. Bitcoin addresses and invalid checksums are rejected. Amounts use integer litoshi throughout.
- Coin selection requires six confirmations, or 100 for coinbase outputs. Conservative size estimates, bounded fee rates, dust change handling, and a separate review/broadcast step protect payment construction.
- Broadcast inputs are reserved on disk **before** socket delivery, including ambiguous failures. A peer pong establishes delivery, not mempool acceptance or mining. Own broadcast records remain available through confirmations/reorganizations; unconfirmed reservations are not automatically abandoned. There is currently no fee bump, abandon, or rebroadcast command.

## Bitcoin mainnet

Select `--network bitcoin` (alias `btc`), `--network litecoin` (alias `ltc`), `--network ethereum` (alias `eth`), or `--network all` (alias `both`) for every registered backend. Omit the flag to choose interactively. Each backend implements the same wallet interface, with its own consensus and transport. They share the encrypted seed vault, but use separate derivation paths and state directories: `bitcoin-mainnet/`, `litecoin-mainnet/`, and `ethereum-mainnet/`. The top bar shows balances and peer counts for enabled networks; addresses, transaction history, errors, payment forms, and commands belong to the active network. One vault lock remains held until all workers stop on exit. Switching networks does not import or overwrite another network's state. Do not run `new` again to add a network to an existing seed vault; open it with the desired `--network`.

Bitcoin uses native SegWit `bc1q…` receiving/change addresses at `m/84'/0'/0'/{0,1}/i`, BTC amounts, and satoshi/vB fees. Sending uses P2WPKH inputs and supports Bitcoin mainnet P2PKH, P2SH, P2WPKH, P2WSH and Taproot recipients. Litecoin Bech32 and testnet addresses are rejected. Mainnet P2SH addresses beginning with `3` are also historically accepted by Litecoin, so their network cannot be distinguished from the address string alone.

Headers are checked from Bitcoin genesis with SHA256d PoW, cumulative-work fork selection, 2,016-block difficulty changes over a two-week target interval, median-time-past, future-time bounds, and activated BIP34/66/65 version floors. Historical block anchors and a minimum-work floor come from [Bitcoin Core mainnet parameters](https://github.com/bitcoin/bitcoin/blob/master/src/kernel/chainparams.cpp). Address tests use the official [BIP84 vectors](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki); retarget tests use [Bitcoin Core's PoW vectors](https://github.com/bitcoin/bitcoin/blob/master/src/test/pow_tests.cpp). Header receipts use a separate Bitcoin HMAC domain.

Bitcoin discovers archival compact-filter peers on port 8333 with Bitcoin's network magic. BIP157/BIP158 filters, cross-peer checks, locally verified matching blocks, the default 10,000-block initial scan window, persisted `--birthday`/scan progress, a maximum of 3 connections, six-confirmation spending, 100-block coinbase maturity, and optional `--mempool` work as on Litecoin. The mempool listener stays within the peer limit and provides advisory unconfirmed observations; proofs are still required for confirmed balances. This is SPV, with no full-node consensus validation or a global UTXO database. Bitcoin testnet/signet and other derivation/import formats are not implemented.

## Ethereum mainnet

Select `--network ethereum` (alias `eth`). Ethereum is a light client over direct P2P: Beacon consensus (libp2p) plus execution `eth`/`snap` (RLPx). There is no Infura, Alchemy, hosted JSON-RPC, or Beacon REST client in this path. Receive addresses are EIP-55 checksummed `0x…` at BIP44 `m/44'/60'/0'/0/i`, with a 20-account discovery gap. Amounts use 18-decimal wei (`u128`). Sends are native EIP-1559 ETH transfers only (21 000 gas, empty calldata); contract calls and ERC-20 are out of scope.

Unlike Bitcoin/Litecoin header sync from genesis, Ethereum starts from a weak-subjectivity checkpoint (bundled mainnet anchor, or an explicit `--ethereum-checkpoint` / `--ethereum-checkpoint-slot` pair persisted into `ethereum-mainnet/`). A stale anchor parks sync until a fresh trusted checkpoint is supplied in a new data directory. Account balances come from snap Merkle proofs verified against the Beacon-attested execution head (ordinary peers prune finalized state roots within minutes). Spendable funds require a fresh head proof. Transaction history scans a bounded recent window for display; balance proofs still cover the full native balance. Own broadcasts reserve the account nonce on disk before relay. `--mempool` does not apply. `--max-peers` must be at least 2 for Beacon; execution discovery targets several snap peers independently.

## Storage and scope

`vault.json` encrypts the mnemonic with AES-256-GCM and a fresh salt/nonce. Password keys use Argon2id (version 19, 19 MiB, two iterations, one lane). A cross-process file lock prevents opening the same wallet twice. Recovery words, the working seed, and password buffers use best-effort zeroization; this is a hot wallet and process memory is not protected against a compromised machine.

Each network stores 80-byte headers in its own `<network>-mainnet/headers.dat`. `headers.verified.json` authenticates an exact verified prefix, tip, and cumulative work using HMAC-SHA256 with a domain-separated wallet-derived key. SHA256 integrity checks detect modifications without repeating PoW validation; unsealed appended headers receive full validation. Receipts are updated incrementally after validated appends, rebuilt after reorganizations, and atomically persisted. They contain no secret key or plaintext seed. `state.json` stores public addresses' derivation indices, scan position, proven relevant transactions, own broadcasts, and compact-filter header anchors. Existing state without filter anchors migrates on opening; issued addresses, old verified inclusion proofs, pending reservations, birthday, scan position, and authenticated header files are retained. These files contain sensitive financial metadata but no plaintext seed. State replacement is atomic, headers are validated before append, and incomplete final header writes recover on restart. Back up the complete data directory to preserve issued indices and pending reservations, in addition to keeping the recovery mnemonic offline. Restoring from words discovers activity within the standard 20-address gap; long runs of unused issued addresses need the original metadata.

This implementation supports Bitcoin mainnet, transparent Litecoin mainnet, and Ethereum mainnet native ETH. It does not support MWEB, ERC-20/contract calls, legacy-wallet derivation/import, hardware wallets, watch-only mode, additional BIP39 passphrases, or other networks yet. Compact-filter completeness relies on at least one honest connected peer; colluding peers can agree on fabricated filters. On a disagreement this implementation persists a dispute and stops instead of attempting automatic dispute resolution; reconnecting or restarting cannot erase it. Resolve the conflicting filter sources before deliberately clearing `filters.conflict` in `state.json`. A genuine reorganization that removes the disputed block invalidates the dispute automatically. Full-block requests can still reveal interests through traffic analysis. An explicit peer is a trust choice for completeness. SPV verifies header work and transaction inclusion, not every full-node consensus rule. No production security audit or real-funds transfer has been performed.

## Verify

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# Read-only Bitcoin probe: 40,000 headers including the first actual difficulty changes,
# cross-checked BIP157/BIP158 filters, and a verified block
cargo run --release -p network-bitcoin --example btc_probe -- auto
# Optional complete Bitcoin header verification and recent-block/filter probe
cargo run --release -p network-bitcoin --example btc_probe -- auto --full

# Full Scrypt verification through two historical Litecoin difficulty retargets
cargo test -p network-litecoin --release -- --ignored

# Read-only live-peer test: headers, cross-checked BIP157/BIP158 filters, block Merkle root
cargo run --release -p network-litecoin --example probe
# Optional explicit peer as the example's positional argument
cargo run --release -p network-litecoin --example probe -- 127.0.0.1:9333

# Benchmark first verification and authenticated restart on a temporary copy
cargo run --release -p network-litecoin --example cache_bench
# Optional source header file and maximum header count; never reads a vault
cargo run --release -p network-litecoin --example cache_bench -- wallet-data/litecoin-mainnet/headers.dat 100000

# Download and verify 20,000 live headers in a temporary directory
cargo run --release -p network-litecoin --example sync_bench
```

The tests cover encrypted vault round trips, password/tamper rejection, wallet locking, amount precision, address boundaries, real header persistence, authenticated-cache reuse, changed-header/receipt rejection, interrupted migration, crash-tail recovery, multi-batch chain selection, malformed protocol data, compact-filter checkpoint boundaries, peer disagreement, filter tampering/order/count checks, persisted-anchor changes, legacy-state migration, mock-peer handshakes, bounded header prefetch, stalled-peer hedging, Merkle verification, independently verified signatures, broadcast reservations, and TUI rendering/confirmation. Mock peers use loopback sockets. In restricted environments, allow loopback and place temporary test files within the writable workspace. Run `cargo test --workspace --release -- --include-ignored` to include the full migration and historical difficulty regressions.

Consensus parameters were checked against [Litecoin Core chain parameters](https://github.com/litecoin-project/litecoin/blob/master/src/chainparams.cpp) and [proof-of-work rules](https://github.com/litecoin-project/litecoin/blob/master/src/pow.cpp). Compact-filter handling follows [BIP157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki) and [BIP158](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki), using [Litecoin Core block filters](https://github.com/litecoin-project/litecoin/blob/master/src/blockfilter.cpp) and stripped-block serialization. Bitcoin Rust types are used for shared serialization/cryptography; Litecoin addresses, network magic, Scrypt, and retarget parameters are implemented explicitly.
