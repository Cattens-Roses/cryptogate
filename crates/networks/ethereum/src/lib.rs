//! Ethereum mainnet light wallet using direct consensus and execution P2P.
pub mod address;
mod state;
pub mod transaction;

use anyhow::{ensure, Context, Result};
use bitcoin::bip32::Xpriv;
use myotis_core::{keccak::keccak256, trie::EMPTY_CODE_HASH};
use myotis_net::{
    el::{evm::ReadAnchor, reader::{ElConfig, ElReader, VerifiedAccount}, readstats::ReadStats},
    ChainConfig, SyncHandle, SyncState,
};
use state::{Account, Pending, State};
use std::{collections::{BTreeMap, BTreeSet}, path::{Path, PathBuf}, sync::{atomic::{AtomicBool, Ordering}, Arc}, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
use tokio::{runtime::Runtime, task::JoinHandle};
use wallet_core::{Network, NetworkInfo, Payment, Snapshot, TransactionEntry};
use zeroize::Zeroizing;

const GAP: u32 = 20;
const HISTORY_WINDOW: u32 = 24;
const MAX_PENDING: usize = 128;

#[derive(Clone, Debug)]
pub struct Options {
    pub max_peers: usize,
    /// Optional execution peer, using its authenticated enode identity.
    pub execution_peer: Option<String>,
    /// Optional consensus peer, using its libp2p multiaddr and peer id.
    pub consensus_peer: Option<String>,
    /// Explicit recent weak-subjectivity checkpoint (beacon root, slot).
    pub checkpoint: Option<(String, u64)>,
}
impl Default for Options {
    fn default() -> Self {
        Self { max_peers: 3, execution_peer: None, consensus_peer: None, checkpoint: None }
    }
}

/// Mainnet parameters are pinned with the P2P implementation. No HTTP client,
/// hosted execution RPC, Beacon REST API, or automatic checkpoint fetch is used.
pub fn p2p_config(directory: &Path, options: &Options) -> Result<(ChainConfig, ElConfig)> {
    ensure!((2..=32).contains(&options.max_peers), "Ethereum needs at least two peer slots: consensus and execution");
    let mut cl = ChainConfig::mainnet();
    cl.max_connections = Some((options.max_peers - 1) as u32);
    cl.snapshot_path = Some(directory.join("beacon.snapshot"));
    cl.cl_peer_cache_path = Some(directory.join("beacon-peers.cache"));
    if let Some((root, slot)) = &options.checkpoint {
        let bytes = hex::decode(root.strip_prefix("0x").unwrap_or(root))?;
        cl.checkpoint_root = bytes.try_into().map_err(|_| anyhow::anyhow!("Checkpoint root must be 32 bytes"))?;
        ensure!(cl.checkpoint_root != [0; 32] && *slot > 0 && *slot <= cl.wall_clock_slot(), "Invalid checkpoint root or slot");
        cl.checkpoint_slot = *slot;
    }
    if let Some(peer) = &options.consensus_peer {
        let address: myotis_net::Multiaddr = peer.parse().context("Invalid Ethereum consensus multiaddr")?;
        ensure!(address.iter().any(|part| matches!(part, myotis_net::multiaddr::Protocol::P2p(_))), "Consensus peer must include /p2p/<peer-id>");
        cl.static_peers = vec![peer.clone()];
        cl.bootstrap_enrs.clear();
    }
    let mut el = ElConfig::mainnet();
    // Snap peers are independent of Beacon slots. Keep Myotis' default headroom:
    // finalized-root hedges need several peers, and head proofs still benefit.
    el.pool_config.target_snap_peers = 8;
    el.pool_config.max_concurrent_dials = 8;
    el.discv4_port = 0;
    el.listen_port = 0;
    el.cache_path = Some(directory.join("execution-peers.cache"));
    if let Some(peer) = &options.execution_peer {
        let enode = myotis_net::el::reader::parse_enode(peer).map_err(|error| anyhow::anyhow!(error))?;
        el.boot_enodes = vec![enode];
        // Keep discovery so alternate snap peers can still hedge finalized proofs.
        // Avoid previous discovered peers overriding an explicit preferred source.
        el.cache_path = None;
    }
    Ok((cl, el))
}

pub fn verified_account(account: &VerifiedAccount, expected: [u8; 20], finalized: bool) -> Result<Account> {
    ensure!(account.address == expected && account.account_hash == keccak256(&expected), "Account proof is for another address");
    ensure!(account.peer_proof_valid && account.beacon_chain_verified && account.bls_verified && account.beacon_synced && account.fail_reason.is_none(), "Ethereum account proof or Beacon verification failed: {:?}", account.fail_reason);
    ensure!(!finalized || account.finalized, "Account is not finalized");
    ensure!(account.peer_state_root != [0; 32] && account.block_number > 0, "Missing verified state root");
    let timestamp = account.block_timestamp.context("Missing verified block timestamp")?;
    let now = unix_time();
    let max_age = if finalized { 30 * 60 } else { 60 };
    ensure!(timestamp <= now.saturating_add(12) && now.saturating_sub(timestamp) <= max_age, "Verified Ethereum state is stale; waiting for fresh consensus");
    Ok(Account { balance: uint(&account.balance)?, nonce: account.nonce, height: account.block_number.try_into().context("Block height overflow")?, timestamp })
}

fn uint(bytes: &[u8]) -> Result<u128> {
    let bytes = bytes.iter().skip_while(|byte| **byte == 0).copied().collect::<Vec<_>>();
    ensure!(bytes.len() <= 16, "Ethereum amount exceeds wallet precision");
    Ok(bytes.into_iter().fold(0u128, |value, byte| (value << 8) | u128::from(byte)))
}
fn unix_time() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

struct Live {
    sync: SyncHandle,
    reader: Arc<ElReader>,
}
enum JobResult {
    Account(u32, Account),
    History(u32, Vec<TransactionEntry>),
}

pub struct Ethereum {
    master: Xpriv,
    key: Zeroizing<[u8; 32]>,
    path: PathBuf,
    options: Options,
    state: State,
    runtime: Runtime,
    live: Option<Live>,
    job: Option<JoinHandle<Result<JobResult>>>,
    queried: BTreeMap<u32, Instant>,
    history_turn: bool,
    next_job: Instant,
    status: String,
    last_query: Option<String>,
    peer_count: usize,
    height: u32,
    finalized: u32,
    prepared: Option<(Payment, u32, u64)>,
}

impl Ethereum {
    pub fn open(seed: &[u8; 64], directory: &Path, mut options: Options, cancel: &AtomicBool) -> Result<Self> {
        ensure!(!cancel.load(Ordering::Relaxed), "Cancelled");
        std::fs::create_dir_all(directory)?;
        let key = state::key(seed);
        let path = directory.join("state.json");
        let mut state = state::load(&path, &key)?;
        if let Some(saved) = &state.checkpoint {
            ensure!(options.checkpoint.as_ref().is_none_or(|requested| requested == saved), "Ethereum directory belongs to another checkpoint");
            options.checkpoint = Some(saved.clone());
        } else if let Some(requested) = &options.checkpoint {
            ensure!(!directory.join("beacon.snapshot").exists(), "Cannot change an existing Ethereum trust anchor; use a fresh network directory");
            state.checkpoint = Some(requested.clone());
        }
        p2p_config(directory, &options)?;
        let master = Xpriv::new_master(bitcoin::NetworkKind::Main, seed)?;
        let wallet = Self {
            master,
            key,
            path,
            options,
            state,
            runtime: tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?,
            live: None,
            job: None,
            queried: BTreeMap::new(),
            history_turn: false,
            next_job: Instant::now(),
            status: "Ethereum light client · direct Beacon + eth/snap P2P".into(),
            last_query: None,
            peer_count: 0,
            height: 0,
            finalized: 0,
            prepared: None,
        };
        wallet.save()?;
        Ok(wallet)
    }

    fn save(&self) -> Result<()> { state::save(&self.path, &self.state, &self.key) }
    fn address_at(&self, index: u32) -> Result<[u8; 20]> { Ok(address::from_key(&address::derive(&self.master, index)?)) }
    fn watch_end(&self) -> u32 {
        let used = self.state.accounts.iter().filter(|(_, account)| account.balance > 0 || account.nonce > 0).map(|(index, _)| *index).max().unwrap_or(0);
        self.state.receive_index.max(used).saturating_add(GAP).min((1 << 31) - 1)
    }
    fn reserved(&self, index: u32) -> bool { self.state.pending.iter().any(|pending| pending.index == index) }

    fn start(&mut self) -> Result<()> {
        if self.live.is_some() { return Ok(()); }
        let directory = self.path.parent().context("Missing Ethereum directory")?;
        let (cl, el) = p2p_config(directory, &self.options)?;
        self.live = Some(self.runtime.block_on(async {
            let sync = SyncHandle::start(cl).map_err(anyhow::Error::msg)?;
            match ElReader::start_for(sync.exec_anchor(), el.cache_path.clone(), el, Arc::new(ReadStats::new())).await {
                Ok(reader) => Ok(Live { sync, reader: Arc::new(reader) }),
                Err(error) => { sync.stop().await; Err(anyhow::anyhow!(error)) }
            }
        })?);
        Ok(())
    }

    fn update_status(&mut self) {
        if let Some(live) = &self.live {
            let status = live.sync.status();
            let el_peers = self.runtime.block_on(live.reader.snap_peer_count());
            self.peer_count = status.peer_count + el_peers;
            self.height = live.reader.optimistic_block_number().try_into().unwrap_or(0);
            self.finalized = live.reader.finalized_block_number().try_into().unwrap_or(0);
            if status.state == SyncState::StaleAnchor {
                self.status = "ETH checkpoint expired · supply a fresh trusted --ethereum-checkpoint and --ethereum-checkpoint-slot in a new Ethereum data directory".into();
            } else {
                let mut line = format!(
                    "ETH {} · Beacon peers {} · execution peers {} · finalized block {} · {}/{} account proofs",
                    status.state, status.peer_count, el_peers, self.finalized, self.queried.len(), self.watch_end()
                );
                if self.job.is_some() {
                    line.push_str(" · querying…");
                }
                if let Some(error) = &self.last_query {
                    line.push_str(" · ");
                    line.push_str(error);
                }
                self.status = line;
            }
        }
    }

    fn finish_job(&mut self) -> Result<bool> {
        if !self.job.as_ref().is_some_and(JoinHandle::is_finished) { return Ok(false); }
        let job = self.job.take().expect("checked above");
        match self.runtime.block_on(job).context("Ethereum query worker failed")? {
            Ok(JobResult::Account(index, account)) => {
                // Only a finalized account nonce can release a persisted send reservation.
                self.state.pending.retain(|pending| pending.index != index || account.nonce <= pending.nonce);
                self.state.accounts.insert(index, account);
                self.queried.insert(index, Instant::now());
                self.history_turn = true;
                self.last_query = None;
                self.save()?;
            }
            Ok(JobResult::History(height, entries)) => {
                for entry in entries {
                    self.state.history.retain(|old| old.txid != entry.txid);
                    self.state.history.push(entry);
                }
                self.state.history.sort_by_key(|entry| entry.height);
                if self.state.history.len() > 2000 { self.state.history.drain(..self.state.history.len() - 2000); }
                self.state.history_cursor = height;
                self.history_turn = false;
                self.last_query = None;
                self.save()?;
            }
            Err(error) => {
                // Keep the cause on the status line; update_status used to wipe it every tick.
                // Prefer the trailing cause ("…serve a verifiable account: …") over a truncated prefix.
                let brief = format!("{error:#}");
                let brief = brief
                    .rsplit_once("failed to ")
                    .map(|(head, tail)| {
                        let head = head.trim_end();
                        let kept = if head.len() > 48 { &head[head.len() - 48..] } else { head };
                        format!("{kept}failed to {tail}")
                    })
                    .unwrap_or(brief);
                let brief = if brief.len() > 220 {
                    format!("…{}", &brief[brief.len() - 217..])
                } else {
                    brief
                };
                self.last_query = Some(brief);
                self.next_job = Instant::now() + Duration::from_secs(3);
            }
        }
        Ok(true)
    }

    fn launch_job(&mut self) -> Result<()> {
        let live = self.live.as_ref().context("Ethereum not connected")?;
        if live.sync.status().state != SyncState::Synced || self.job.is_some() || Instant::now() < self.next_job { return Ok(()); }
        let reader = Arc::clone(&live.reader);
        let next_account = (0..self.watch_end()).find(|index| self.queried.get(index).is_none_or(|checked| checked.elapsed() >= Duration::from_secs(60)));
        let history_start = self.finalized.saturating_sub(HISTORY_WINDOW).max(1);
        let next_history = self.state.history_cursor.saturating_add(1).max(history_start);
        // Account proofs reveal the complete current native balance even when
        // transaction history is outside this bounded recent-body window.
        if next_history <= self.finalized && (self.history_turn || next_account.is_none()) {
            let watched: BTreeSet<_> = (0..self.watch_end()).map(|index| self.address_at(index)).collect::<Result<_>>()?;
            self.job = Some(self.runtime.spawn(async move {
                tokio::time::timeout(Duration::from_secs(45), async {
                    let block = reader.get_block_by_number(Some(next_history.into()), true).await.map_err(anyhow::Error::msg)?.context("No verified Ethereum block")?;
                    let relevant: Vec<_> = block.full_transactions.context("Missing verified transaction body")?.into_iter().filter(|entry| entry.tx.from.is_some_and(|from| watched.contains(&from)) || entry.tx.to.is_some_and(|to| watched.contains(&to))).collect();
                    let mut entries = Vec::new();
                    if !relevant.is_empty() {
                        let receipts = reader.get_block_receipts(Some(next_history.into())).await.map_err(anyhow::Error::msg)?.context("Missing verified receipts")?;
                        for entry in relevant {
                            let receipt = receipts.iter().find(|receipt| receipt.tx_hash == entry.tx_hash && receipt.block_hash == block.hash).context("Transaction receipt mismatch")?;
                            ensure!(receipt.receipt.has_status, "Missing Ethereum execution status");
                            let value = if receipt.receipt.success { uint(&entry.tx.value)? } else { 0 };
                            let mine_from = entry.tx.from.is_some_and(|from| watched.contains(&from));
                            let mine_to = entry.tx.to.is_some_and(|to| watched.contains(&to));
                            let fee = u128::from(receipt.gas_used).checked_mul(receipt.effective_gas_price.context("Missing verified gas price")?).context("Fee overflow")?;
                            entries.push(TransactionEntry { txid: format!("0x{}", hex::encode(entry.tx_hash)), height: next_history, received: if mine_to { value } else { 0 }, sent: if mine_from { value.checked_add(fee).context("Amount overflow")? } else { 0 } });
                        }
                    }
                    Ok(JobResult::History(next_history, entries))
                }).await.context("Ethereum block query timed out")?
            }));
        } else if let Some(index) = next_account {
            let expected = self.address_at(index)?;
            self.job = Some(self.runtime.spawn(async move {
                // Head state is what ordinary snap peers retain. Finalized roots
                // trail by epochs and are frequently pruned (the "all 1 snap
                // peer(s) failed" case). Sends already re-prove against Head.
                let account = tokio::time::timeout(Duration::from_secs(45), reader.get_account(ReadAnchor::Head, expected))
                    .await
                    .context("Ethereum account query timed out")?
                    .map_err(anyhow::Error::msg)?;
                Ok(JobResult::Account(index, verified_account(&account, expected, false)?))
            }));
        }
        Ok(())
    }
}

impl Network for Ethereum {
    fn info(&self) -> NetworkInfo { NetworkInfo { id: "ethereum-mainnet", name: "Ethereum", ticker: "ETH", decimals: 18, fee_rate_unit: "max gwei/gas" } }
    fn snapshot(&self) -> Snapshot {
        let balance = self.state.accounts.values().map(|account| account.balance).sum();
        let spendable = if self.live.as_ref().is_some_and(|live| live.sync.status().state == SyncState::Synced) {
            // Head proofs go stale quickly; refuse spendable from old observations.
            self.state.accounts.iter().filter(|(index, account)| !self.reserved(**index) && self.queried.contains_key(index) && unix_time().saturating_sub(account.timestamp) <= 120).map(|(_, account)| account.balance).max().unwrap_or(0)
        } else { 0 };
        let pending_outgoing = self.state.pending.iter().map(|pending| pending.amount + pending.fee).sum();
        let mut transactions: Vec<_> = self.state.pending.iter().map(|pending| TransactionEntry { txid: pending.txid.clone(), height: 0, received: 0, sent: pending.amount + pending.fee }).collect();
        transactions.extend(self.state.history.iter().rev().filter(|entry| !transactions_contains_pending(&self.state, &entry.txid)).cloned());
        let scanned = self.state.accounts.values().map(|account| account.height).min().unwrap_or(0);
        Snapshot { address: self.address_at(self.state.receive_index).map(|address| address::checksum(&address)).unwrap_or_default(), receive_note: "BIP44 · m/44'/60'/0'/0/i · Ethereum mainnet only".into(), spend_note: "Beacon-verified head proofs · one account per send · fee shown is maximum".into(), balance, spendable, pending_incoming: 0, pending_outgoing, mempool_status: "own pending sends; no public mempool listener".into(), height: self.height.max(scanned), scanned, recent_scanned: self.state.history_cursor, peer_height: self.height, connected_peers: self.peer_count, max_peers: self.options.max_peers, peer: "Beacon libp2p + execution RLPx/snap".into(), transactions }
    }
    fn sync_status(&self) -> Option<String> { Some(self.status.clone()) }
    fn next_address(&mut self) -> Result<String> {
        let index = self.state.receive_index.checked_add(1).context("Account index exhausted")?;
        let address = self.address_at(index)?;
        self.state.receive_index = index;
        self.save()?;
        Ok(address::checksum(&address))
    }
    fn sync_step(&mut self, cancel: &AtomicBool) -> Result<bool> {
        ensure!(!cancel.load(Ordering::Relaxed), "Cancelled");
        self.start()?;
        self.update_status();
        self.finish_job()?;
        self.launch_job()?;
        if self.job.is_some() || self.live.as_ref().is_some_and(|live| live.sync.status().state != SyncState::Synced) {
            std::thread::sleep(Duration::from_millis(100));
            return Ok(false);
        }
        Ok((0..self.watch_end()).all(|index| self.queried.contains_key(&index)))
    }
    fn poll_activity(&mut self) -> Result<bool> { self.finish_job() }
    fn disconnect(&mut self) {
        if let Some(job) = self.job.take() { job.abort(); }
        if let Some(live) = self.live.take() {
            self.runtime.block_on(async { live.reader.cancel_requests(); live.reader.stop().await; live.sync.stop().await; });
        }
        self.peer_count = 0;
        self.prepared = None;
        self.queried.clear();
    }
    fn address_balances(&self) -> Vec<(String, u128)> {
        self.state
            .accounts
            .iter()
            .filter_map(|(index, account)| {
                let address = self.address_at(*index).ok()?;
                Some((address::checksum(&address), account.balance))
            })
            .filter(|(_, balance)| *balance > 0)
            .collect()
    }

    fn prepare_forward(&mut self, from_address: &str, recipient: &str, fee_rate: u64) -> Result<Payment> {
        let from = address::parse(from_address)?;
        let index = (0..=self.state.receive_index)
            .find(|index| self.address_at(*index).ok() == Some(from))
            .context("Unknown invoice account")?;
        let account = self.state.accounts.get(&index).context("Invoice account has no verified balance")?;
        let max_fee = u128::from(fee_rate) * transaction::GWEI;
        let fee = max_fee * u128::from(transaction::TRANSFER_GAS);
        let amount = account.balance.checked_sub(fee).context("Invoice funds cannot cover the maximum fee")?;
        ensure!(amount > 0, "Nothing to forward after fees");
        self.prepare_payment_from(index, recipient, amount, fee_rate)
    }

    fn prepare_payment(&mut self, recipient: &str, amount: u128, fee_rate: u64) -> Result<Payment> {
        ensure!(amount > 0 && (1..=10_000).contains(&fee_rate), "Enter positive ETH and a maximum fee of 1–10000 gwei/gas");
        ensure!(self.state.pending.len() < MAX_PENDING, "Too many unresolved Ethereum sends");
        let max_fee = u128::from(fee_rate) * transaction::GWEI;
        let fee = max_fee * u128::from(transaction::TRANSFER_GAS);
        let required = amount.checked_add(fee).context("Amount overflow")?;
        let index = self.state.accounts.iter().find(|(index, account)| !self.reserved(**index) && self.queried.contains_key(index) && account.balance >= required).map(|(index, _)| *index).context("No single verified account covers the amount and maximum fee")?;
        self.prepare_payment_from(index, recipient, amount, fee_rate)
    }

    fn broadcast(&mut self, payment: &Payment, cancel: &AtomicBool) -> Result<()> {
        ensure!(!cancel.load(Ordering::Relaxed), "Cancelled");
        let (reviewed, index, nonce) = self.prepared.as_ref().context("Prepare and review the Ethereum transfer first")?;
        ensure!(reviewed.raw == payment.raw && reviewed.txid == payment.txid && reviewed.recipient == payment.recipient && reviewed.amount == payment.amount && reviewed.fee == payment.fee, "Ethereum payment changed after review");
        ensure!(!self.reserved(*index), "Ethereum account already has an unresolved send");
        let live = self.live.as_ref().context("Ethereum disconnected")?;
        ensure!(live.sync.status().state == SyncState::Synced, "Ethereum consensus is not current");
        let pending = Pending { index: *index, nonce: *nonce, raw: hex::encode(&payment.raw), txid: payment.txid.clone(), amount: payment.amount, fee: payment.fee };
        // Persist before any socket delivery. Timeout/rejection leaves the nonce
        // reserved until a finalized account proof shows it was consumed.
        self.state.pending.push(pending);
        self.save()?;
        self.prepared = None;
        let live = self.live.as_ref().expect("checked above");
        let hash = self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(20), live.reader.send_raw_transaction(&payment.raw)).await.context("Ethereum broadcast timed out; nonce remains reserved")?.map_err(|error| anyhow::anyhow!("Ethereum broadcast failed: {error:?}; nonce remains reserved"))
        })?;
        ensure!(format!("0x{}", hex::encode(hash)) == payment.txid, "Unexpected broadcast transaction hash");
        Ok(())
    }
}

impl Ethereum {
    fn prepare_payment_from(&mut self, index: u32, recipient: &str, amount: u128, fee_rate: u64) -> Result<Payment> {
        ensure!(amount > 0 && (1..=10_000).contains(&fee_rate), "Enter positive ETH and a maximum fee of 1–10000 gwei/gas");
        ensure!(self.state.pending.len() < MAX_PENDING, "Too many unresolved Ethereum sends");
        let recipient_bytes = address::parse(recipient)?;
        let max_fee = u128::from(fee_rate) * transaction::GWEI;
        let fee = max_fee * u128::from(transaction::TRANSFER_GAS);
        let required = amount.checked_add(fee).context("Amount overflow")?;
        ensure!(!self.reserved(index), "Ethereum account already has an unresolved send");
        let account = self.state.accounts.get(&index).context("Missing verified account")?;
        ensure!(self.queried.contains_key(&index) && account.balance >= required, "Invoice account cannot cover amount and fee");
        let sender = self.address_at(index)?;
        let live = self.live.as_ref().context("Connect Ethereum before sending")?;
        ensure!(live.sync.status().state == SyncState::Synced, "Finish Ethereum consensus sync before sending");
        let (nonce, tip) = self.runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(30), async {
                let account = live.reader.get_account(ReadAnchor::Head, sender).await.map_err(anyhow::Error::msg)?;
                let verified = verified_account(&account, sender, false)?;
                ensure!(account.code_hash == EMPTY_CODE_HASH, "Sending from delegated or contract accounts is not supported");
                ensure!(verified.balance >= required, "Account balance changed since last proof");
                let destination = live.reader.get_account(ReadAnchor::Head, recipient_bytes).await.map_err(anyhow::Error::msg)?;
                verified_account(&destination, recipient_bytes, false)?;
                ensure!(destination.code_hash == EMPTY_CODE_HASH, "This wallet sends native ETH to regular accounts; contract calls require gas simulation");
                let block = live.reader.get_block_by_number(None, false).await.map_err(anyhow::Error::msg)?.context("Missing verified fee header")?;
                let base = uint(block.header.base_fee_per_gas.as_deref().context("Missing verified base fee")?)?;
                ensure!(max_fee > base, "Maximum gas price is below the current base fee");
                Ok::<_, anyhow::Error>((verified.nonce, transaction::GWEI.min(max_fee - base)))
            }).await.context("Ethereum payment proof query timed out")?
        })?;
        let key = address::derive(&self.master, index)?;
        let raw = transaction::sign(&key, nonce, recipient_bytes, amount, max_fee, tip)?;
        let payment = Payment { recipient: address::checksum(&recipient_bytes), amount, fee, txid: format!("0x{}", hex::encode(keccak256(&raw))), raw };
        self.prepared = Some((payment.clone(), index, nonce));
        Ok(payment)
    }
}

fn transactions_contains_pending(state: &State, txid: &str) -> bool { state.pending.iter().any(|pending| pending.txid == txid) }
impl Drop for Ethereum { fn drop(&mut self) { self.disconnect(); } }
