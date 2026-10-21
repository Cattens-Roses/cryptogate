use crate::{
    address,
    chain::HeaderChain,
    compact_filters::{CompactFilters, FilterBatch},
    header_download::{Download, HeaderDownload},
    mempool::{Mempool, Watch},
    peer::Peer,
};
use anyhow::{bail, ensure, Context, Result};
use bitcoin::{
    absolute,
    bip32::Xpriv,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Message, Secp256k1},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
    Amount, BlockHash, MerkleBlock, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Txid, Witness,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use wallet_core::{
    vault::atomic_write, AddressTransaction, Network, NetworkInfo, Payment, Snapshot,
    TransactionEntry,
};

const GAP: u32 = 20;
const MAX_MONEY: u64 = 84_000_000 * 100_000_000;
const DUST: u64 = 1_000;
pub const DEFAULT_MAX_PEERS: usize = 3;
pub const DEFAULT_FIRST_SCAN_WINDOW: u32 = 10_000;

pub struct Options {
    /// Optional trusted archival BIP157 Litecoin Core peer (host:9333).
    pub peer: Option<String>,
    /// Explicit first scan height; None selects a tip window after header synchronization.
    pub birthday: Option<u32>,
    /// Maximum simultaneous peer connections, including the active sync peer.
    pub max_peers: usize,
    /// Observe unconfirmed transactions through a separate P2P relay connection.
    pub mempool: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            peer: None,
            birthday: None,
            max_peers: DEFAULT_MAX_PEERS,
            mempool: false,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
    height: u32,
    proof: String,
    transactions: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct State {
    version: u32,
    identity: String,
    birthday: u32,
    receive_index: u32,
    change_index: u32,
    scanned: u32,
    scanned_hash: Option<BlockHash>,
    records: Vec<Record>,
    /// Signed broadcasts reserve their inputs until confirmed (including across restarts).
    pending: Vec<String>,
    #[serde(default)]
    filters: CompactFilters,
}

impl State {
    fn resolve_scan_start(&mut self, tip: u32) -> bool {
        if self.birthday != 0 {
            return false;
        }
        self.birthday = tip.saturating_sub(DEFAULT_FIRST_SCAN_WINDOW).max(1);
        self.scanned = self.birthday - 1;
        true
    }
}

#[derive(Clone)]
struct Coin {
    outpoint: OutPoint,
    output: TxOut,
    height: u32,
    coinbase: bool,
    change: bool,
    index: u32,
}

pub struct Litecoin {
    master: Xpriv,
    chain: HeaderChain,
    state: State,
    state_path: PathBuf,
    options: Options,
    peers: Vec<Peer>,
    header_download: Option<HeaderDownload>,
    filter_batch: Option<FilterBatch>,
    mempool: Option<Mempool>,
    observed: Vec<(String, Instant)>,
    next_peer_maintenance: Instant,
    next_headers_poll: Instant,
    recent_scan: Option<(u32, u32)>,
    recent_scanned: u32,
    headers_current: bool,
    scripts: BTreeMap<ScriptBuf, (bool, u32)>,
    coins: BTreeMap<OutPoint, Coin>,
    history: Vec<TransactionEntry>,
    confirmed_ids: BTreeSet<Txid>,
    confirmed_spends: BTreeSet<OutPoint>,
    prepared: Option<Payment>,
}

impl Litecoin {
    pub fn open(
        seed: &[u8; 64],
        directory: &Path,
        options: Options,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        Self::open_with_progress(seed, directory, options, cancel, &|_| {})
    }

    pub fn open_with_progress(
        seed: &[u8; 64],
        directory: &Path,
        options: Options,
        cancel: &AtomicBool,
        progress: &dyn Fn(&str),
    ) -> Result<Self> {
        ensure!(
            (1..=32).contains(&options.max_peers),
            "max_peers must be between 1 and 32"
        );
        ensure!(
            !options.mempool || options.max_peers >= if options.peer.is_some() { 2 } else { 3 },
            "--mempool needs a spare connection: --max-peers >= 3, or >= 2 with a trusted --peer"
        );
        fs::create_dir_all(directory)?;
        let master = Xpriv::new_master(NetworkKind::Main, seed)?;
        let identity = address::derive(&master, false, 0)?.2;
        let state_path = directory.join("state.json");
        let birthday = options.birthday.map_or(0, |height| height.max(1));
        let mut state: State = if state_path.exists() {
            ensure!(
                fs::metadata(&state_path)?.len() <= 256_000_000,
                "Wallet state is too large"
            );
            serde_json::from_slice(&fs::read(&state_path)?)?
        } else {
            State {
                version: 1,
                identity: identity.clone(),
                birthday,
                receive_index: 0,
                change_index: 0,
                scanned: birthday.saturating_sub(1),
                scanned_hash: None,
                records: Vec::new(),
                pending: Vec::new(),
                filters: CompactFilters::default(),
            }
        };
        ensure!(
            state.version == 1 && state.identity == identity,
            "State belongs to a different wallet or format"
        );
        ensure!(
            state.receive_index < 100_000 && state.change_index < 100_000,
            "Address range exceeds wallet limit"
        );
        // Zero is a persisted, unresolved default, not an instruction to scan genesis.
        // It is resolved once, after headers reach the peer's tip. Existing starts win.
        if state.birthday == 0 && options.birthday.is_some() {
            state.birthday = birthday;
            state.scanned = birthday.saturating_sub(1);
            state.scanned_hash = None;
        }
        let chain = HeaderChain::open_authenticated(
            &directory.join("headers.dat"),
            seed,
            cancel,
            progress,
        )?;
        let mut wallet = Self {
            master,
            chain,
            state,
            state_path,
            options,
            peers: Vec::new(),
            header_download: None,
            filter_batch: None,
            mempool: None,
            observed: Vec::new(),
            next_peer_maintenance: Instant::now(),
            next_headers_poll: Instant::now(),
            recent_scan: None,
            recent_scanned: 0,
            headers_current: false,
            scripts: BTreeMap::new(),
            coins: BTreeMap::new(),
            history: Vec::new(),
            confirmed_ids: BTreeSet::new(),
            confirmed_spends: BTreeSet::new(),
            prepared: None,
        };
        wallet.refresh_scripts()?;
        wallet.reconcile()?;
        wallet.rebuild()?;
        wallet.reserved()?;
        wallet.save()?;
        Ok(wallet)
    }

    fn save(&self) -> Result<()> {
        atomic_write(&self.state_path, &serde_json::to_vec(&self.state)?)
    }

    fn refresh_scripts(&mut self) -> Result<()> {
        for change in [false, true] {
            let last = if change {
                self.state.change_index
            } else {
                self.state.receive_index
            };
            ensure!(last < 100_000, "Address range exceeds wallet limit");
            // Only derive new entries as the discovery window advances.
            for index in 0..last + GAP {
                if self.scripts.values().any(|v| *v == (change, index)) {
                    continue;
                }
                self.scripts.insert(
                    address::derive(&self.master, change, index)?.1,
                    (change, index),
                );
            }
        }
        self.update_mempool_watch();
        Ok(())
    }

    fn reconcile(&mut self) -> Result<()> {
        let mut rewind = self.state.scanned;
        if self.state.scanned_hash.is_some()
            && self.chain.hash(self.state.scanned) != self.state.scanned_hash
        {
            rewind = self.state.birthday.saturating_sub(1);
        }
        let mut kept = Vec::new();
        for record in &self.state.records {
            let proof: MerkleBlock = deserialize(&hex::decode(&record.proof)?)?;
            if self.chain.header(record.height) == Some(proof.header) {
                kept.push(record.clone());
            } else {
                rewind = rewind.min(record.height.saturating_sub(1));
            }
        }
        self.state.records = kept;
        self.state.scanned = rewind;
        self.state.scanned_hash = self.chain.hash(rewind);
        Ok(())
    }

    fn reserved(&self) -> Result<BTreeSet<OutPoint>> {
        let mut reserved = BTreeSet::new();
        for raw in &self.state.pending {
            let tx: Transaction = deserialize(&hex::decode(raw)?)?;
            reserved.extend(tx.input.iter().map(|i| i.previous_output));
        }
        Ok(reserved)
    }

    fn is_spendable(&self, coin: &Coin, reserved: &BTreeSet<OutPoint>) -> bool {
        let confirmations = self.chain.height().saturating_sub(coin.height) + 1;
        confirmations >= if coin.coinbase { 100 } else { 6 } && !reserved.contains(&coin.outpoint)
    }

    /// Rebuild from proofs, never from cached balance numbers or unproven tx messages.
    fn rebuild(&mut self) -> Result<()> {
        self.coins.clear();
        self.history.clear();
        self.confirmed_ids.clear();
        self.confirmed_spends.clear();
        self.state.records.sort_by_key(|r| r.height);
        let mut confirmed = BTreeSet::new();
        for record in &self.state.records {
            let proof: MerkleBlock = deserialize(&hex::decode(&record.proof)?)?;
            ensure!(
                self.chain.header(record.height) == Some(proof.header),
                "Proof is not on the validated header chain"
            );
            let transactions = verify_transactions(&proof, &record.transactions)?;
            for tx in transactions {
                let txid = tx.compute_txid();
                if !confirmed.insert(txid) {
                    continue;
                }
                self.confirmed_ids.insert(txid);
                let mut entry = TransactionEntry {
                    txid: txid.to_string(),
                    height: record.height,
                    ..Default::default()
                };
                for input in &tx.input {
                    self.confirmed_spends.insert(input.previous_output);
                    if let Some(coin) = self.coins.remove(&input.previous_output) {
                        entry.sent += u128::from(coin.output.value.to_sat());
                    }
                }
                for (vout, output) in tx.output.iter().enumerate() {
                    ensure!(
                        output.value.to_sat() <= MAX_MONEY,
                        "Invalid transaction output amount"
                    );
                    if let Some(&(change, index)) = self.scripts.get(&output.script_pubkey) {
                        entry.received += u128::from(output.value.to_sat());
                        let outpoint = OutPoint {
                            txid,
                            vout: vout as u32,
                        };
                        self.coins.insert(
                            outpoint,
                            Coin {
                                outpoint,
                                output: output.clone(),
                                height: record.height,
                                coinbase: tx.is_coinbase(),
                                change,
                                index,
                            },
                        );
                    }
                }
                if entry.received > 0 || entry.sent > 0 {
                    self.history.push(entry);
                }
            }
        }
        // Retain our broadcast records after confirmation, so inputs are reserved again
        // if that confirmation is later orphaned by a reorganization.
        self.prune_observed();
        self.update_mempool_watch();
        Ok(())
    }

    fn connect(&mut self, cancel: &AtomicBool) -> Result<()> {
        let needs_active = self.peers.is_empty();
        let maintenance = needs_active || Instant::now() >= self.next_peer_maintenance;
        if maintenance {
            // The active peer's traffic is handled by sync; keep standby peers alive.
            for index in (1..self.peers.len()).rev() {
                if self.peers[index].heartbeat(cancel).is_err() {
                    self.peers.remove(index);
                }
            }
            let live = usize::from(self.mempool.as_ref().is_some_and(Mempool::connected));
            let slots = self.options.max_peers - self.peers.len() - live;
            if slots > 0 {
                let mut exclude: Vec<_> = self.peers.iter().map(|peer| peer.address).collect();
                if let Some(monitor) = &self.mempool {
                    exclude.push(monitor.address);
                }
                let result = Peer::discover_many(
                    self.options.peer.as_deref(),
                    self.chain.height(),
                    slots,
                    &exclude,
                    cancel,
                );
                match result {
                    Ok(peers) => self.peers.extend(peers),
                    Err(error) if self.peers.is_empty() => return Err(error),
                    Err(_) => {} // An existing peer remains usable if extra slots cannot fill.
                }
            }
            self.next_peer_maintenance = Instant::now() + Duration::from_secs(30);
            if needs_active {
                self.headers_current = false;
            }
        }
        if maintenance && self.options.mempool && self.mempool.is_none() {
            let minimum = if self.options.peer.is_some() { 1 } else { 2 };
            let address = if self.peers.len() > minimum {
                // Close the standby socket before negotiating a relay socket, so
                // enabling the listener never exceeds the configured peer limit.
                self.peers.pop().map(|peer| peer.address)
            } else if self.peers.len() == minimum && minimum < self.options.max_peers {
                self.peers.first().map(|peer| peer.address)
            } else {
                None
            };
            if let Some(address) = address {
                if let Ok(peer) = Peer::connect_relay(address, self.chain.height(), cancel) {
                    self.mempool = Some(Mempool::start(peer, self.mempool_watch()));
                }
            }
        }
        Ok(())
    }

    fn scan_block(
        &mut self,
        height: u32,
        advance_history: bool,
        cancel: &AtomicBool,
    ) -> Result<bool> {
        let hash = self.chain.hash(height).context("Missing scan header")?;
        if !self
            .filter_batch
            .as_ref()
            .is_some_and(|batch| batch.contains(height, hash))
        {
            let download = self.state.filters.download(
                &mut self.peers,
                &self.chain,
                height,
                self.chain.height().min(height.saturating_add(999)),
                self.options.peer.is_some(),
                cancel,
            );
            if download.is_err() {
                self.save()?;
            }
            self.filter_batch = Some(download?);
        }
        let scripts: Vec<_> = self
            .scripts
            .keys()
            .map(|script| script.as_bytes())
            .collect();
        let batch = self
            .filter_batch
            .as_mut()
            .context("Missing compact filters")?;
        batch.match_scripts(&scripts)?;
        if !batch.matched(height)? {
            if advance_history {
                self.state.scanned = height;
                self.state.scanned_hash = Some(hash);
            }
            return Ok(true);
        }
        // Request legacy MSG_BLOCK: Litecoin Core strips witnesses and MWEB extensions.
        // The transparent txids still commit to the header's complete Merkle root.
        let peer_index = rand::random::<usize>() % self.peers.len();
        let block = crate::compact_filters::fetch_block(&mut self.peers[peer_index], hash, cancel);
        if block.is_err() {
            self.peers.swap(0, peer_index);
        }
        let block = block?;
        ensure!(
            self.chain.header(height) == Some(block.header),
            "Block header mismatch"
        );
        crate::compact_filters::validate_block(&block)?;
        // Discover all gap-window extensions in this block without downloading it again.
        loop {
            let before = (self.state.receive_index, self.state.change_index);
            for tx in &block.txdata {
                for output in &tx.output {
                    if let Some(&(change, index)) = self.scripts.get(&output.script_pubkey) {
                        let current = if change {
                            &mut self.state.change_index
                        } else {
                            &mut self.state.receive_index
                        };
                        *current = (*current).max(index + 1);
                    }
                }
            }
            if before == (self.state.receive_index, self.state.change_index) {
                break;
            }
            self.refresh_scripts()?;
        }
        let ids: Vec<_> = block.txdata.iter().map(Transaction::compute_txid).collect();
        let mut owned: BTreeSet<_> = self.coins.keys().copied().collect();
        let mut matches = BTreeSet::new();
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            if tx
                .input
                .iter()
                .any(|input| owned.contains(&input.previous_output))
            {
                matches.insert(txid);
            }
            for (vout, output) in tx.output.iter().enumerate() {
                if self.scripts.contains_key(&output.script_pubkey) {
                    matches.insert(txid);
                    owned.insert(OutPoint {
                        txid,
                        vout: vout as u32,
                    });
                }
            }
        }
        let proof = MerkleBlock::from_header_txids_with_predicate(&block.header, &ids, |id| {
            matches.contains(id)
        });
        let raw_transactions: Vec<_> = block
            .txdata
            .iter()
            .filter(|tx| matches.contains(&tx.compute_txid()))
            .map(|tx| hex::encode(serialize(tx)))
            .collect();
        verify_transactions(&proof, &raw_transactions)?;
        let relevant = !matches.is_empty();
        if relevant {
            // Keep complete proven match sets in block order, including false positives.
            self.state.records.retain(|r| r.height != height);
            self.state.records.push(Record {
                height,
                proof: hex::encode(serialize(&proof)),
                transactions: raw_transactions,
            });
        }
        if relevant {
            self.rebuild()?;
        }
        if advance_history {
            self.state.scanned = height;
            self.state.scanned_hash = Some(hash);
        }
        self.save()?;
        Ok(true)
    }

    fn mark_headers_current(&mut self) -> Result<()> {
        if self.state.resolve_scan_start(self.chain.height()) {
            self.state.scanned_hash = self.chain.hash(self.state.scanned);
            self.save()?;
        }
        self.headers_current = true;
        self.next_headers_poll = Instant::now() + Duration::from_secs(15);
        if self.chain.height().saturating_sub(self.state.scanned) > 32 {
            let start = if self.recent_scanned > 0 {
                self.recent_scanned.saturating_add(1)
            } else {
                self.chain
                    .height()
                    .saturating_sub(23)
                    .max(self.state.birthday)
            };
            if start <= self.chain.height() {
                self.recent_scan = Some((start, self.chain.height()));
            }
        }
        Ok(())
    }

    fn mempool_watch(&self) -> Watch {
        let mut outpoints: BTreeSet<_> = self.coins.keys().copied().collect();
        for raw in self
            .state
            .pending
            .iter()
            .map(String::as_str)
            .chain(self.observed.iter().map(|(raw, _)| raw.as_str()))
        {
            if let Some(tx) = decode_transaction(raw) {
                for (vout, output) in tx.output.iter().enumerate() {
                    if self.scripts.contains_key(&output.script_pubkey) {
                        outpoints.insert(OutPoint {
                            txid: tx.compute_txid(),
                            vout: vout as u32,
                        });
                    }
                }
            }
        }
        Watch {
            scripts: self.scripts.keys().cloned().collect(),
            outpoints,
        }
    }

    fn update_mempool_watch(&self) {
        if let Some(monitor) = &self.mempool {
            monitor.update(self.mempool_watch());
        }
    }

    fn prune_observed(&mut self) {
        self.observed.retain(|(raw, seen)| {
            seen.elapsed() < Duration::from_secs(3600)
                && decode_transaction(raw).is_some_and(|tx| {
                    !self.confirmed_ids.contains(&tx.compute_txid())
                        && !tx
                            .input
                            .iter()
                            .any(|input| self.confirmed_spends.contains(&input.previous_output))
                })
        });
    }

    fn observe_transaction(&mut self, raw: &[u8]) -> Result<bool> {
        if raw.len() > 400_000 {
            return Ok(false);
        }
        let Ok(tx) = deserialize::<Transaction>(raw) else {
            return Ok(false);
        };
        let id = tx.compute_txid();
        let inputs: BTreeSet<_> = tx.input.iter().map(|input| input.previous_output).collect();
        let total = tx
            .output
            .iter()
            .try_fold(0u64, |sum, output| sum.checked_add(output.value.to_sat()));
        if tx.is_coinbase()
            || tx.input.is_empty()
            || tx.output.is_empty()
            || inputs.len() != tx.input.len()
            || !total.is_some_and(|sum| sum <= MAX_MONEY)
            || self.confirmed_ids.contains(&id)
            || self
                .state
                .pending
                .iter()
                .filter_map(|raw| decode_transaction(raw))
                .any(|own| {
                    own.input
                        .iter()
                        .any(|input| inputs.contains(&input.previous_output))
                })
            || inputs
                .iter()
                .any(|input| self.confirmed_spends.contains(input))
            || self
                .state
                .pending
                .iter()
                .chain(self.observed.iter().map(|(raw, _)| raw))
                .filter_map(|raw| decode_transaction(raw))
                .any(|seen| seen.compute_txid() == id)
        {
            return Ok(false);
        }
        let watch = self.mempool_watch();
        if !tx
            .output
            .iter()
            .any(|output| watch.scripts.contains(&output.script_pubkey))
            && !inputs.iter().any(|input| watch.outpoints.contains(input))
        {
            return Ok(false);
        }
        // Withdraw older conflicting observations and their children. These are
        // advisory relay observations, never proof of mempool acceptance or payment.
        let mut removed = BTreeSet::new();
        loop {
            let before = removed.len();
            for (raw, _) in &self.observed {
                if let Some(seen) = decode_transaction(raw) {
                    if seen.input.iter().any(|input| {
                        inputs.contains(&input.previous_output)
                            || removed.contains(&input.previous_output.txid)
                    }) {
                        removed.insert(seen.compute_txid());
                    }
                }
            }
            if before == removed.len() {
                break;
            }
        }
        self.observed.retain(|(raw, _)| {
            decode_transaction(raw).is_some_and(|tx| !removed.contains(&tx.compute_txid()))
        });
        self.observed.push((hex::encode(raw), Instant::now()));
        while self.observed.len() > 128
            || self
                .observed
                .iter()
                .map(|(raw, _)| raw.len())
                .sum::<usize>()
                > 8_000_000
        {
            self.observed.remove(0);
        }
        self.update_mempool_watch();
        Ok(true)
    }

    fn pending_entries(&self) -> Vec<TransactionEntry> {
        let mut transactions = BTreeMap::new();
        for raw in self
            .state
            .pending
            .iter()
            .map(String::as_str)
            .chain(self.observed.iter().map(|(raw, _)| raw.as_str()))
        {
            if let Some(tx) = decode_transaction(raw) {
                if !self.confirmed_ids.contains(&tx.compute_txid())
                    && !tx
                        .input
                        .iter()
                        .any(|input| self.confirmed_spends.contains(&input.previous_output))
                {
                    transactions.insert(tx.compute_txid(), tx);
                }
            }
        }
        let mut owned: BTreeMap<OutPoint, u64> = self
            .coins
            .iter()
            .map(|(outpoint, coin)| (*outpoint, coin.output.value.to_sat()))
            .collect();
        for (txid, tx) in &transactions {
            for (index, output) in tx.output.iter().enumerate() {
                if self.scripts.contains_key(&output.script_pubkey) {
                    owned.insert(
                        OutPoint {
                            txid: *txid,
                            vout: index as u32,
                        },
                        output.value.to_sat(),
                    );
                }
            }
        }
        transactions
            .into_iter()
            .map(|(txid, tx)| TransactionEntry {
                txid: txid.to_string(),
                height: 0,
                sent: tx
                    .input
                    .iter()
                    .filter_map(|input| owned.get(&input.previous_output))
                    .map(|value| u128::from(*value))
                    .sum(),
                received: tx
                    .output
                    .iter()
                    .filter(|output| self.scripts.contains_key(&output.script_pubkey))
                    .map(|output| u128::from(output.value.to_sat()))
                    .sum(),
            })
            .collect()
    }
}

fn decode_transaction(raw: &str) -> Option<Transaction> {
    hex::decode(raw).ok().and_then(|raw| deserialize(&raw).ok())
}

/// Validate every supplied transaction against the proof and order by its block position.
fn verify_transactions(proof: &MerkleBlock, raws: &[String]) -> Result<Vec<Transaction>> {
    let mut matches = Vec::new();
    let mut indices = Vec::new();
    proof.extract_matches(&mut matches, &mut indices)?;
    let mut by_id = BTreeMap::new();
    for raw in raws {
        let tx: Transaction = deserialize(&hex::decode(raw)?)?;
        let output_total = tx.output.iter().try_fold(0u64, |total, output| {
            total.checked_add(output.value.to_sat())
        });
        ensure!(
            output_total.is_some_and(|total| total <= MAX_MONEY),
            "Transaction outputs exceed Litecoin money range"
        );
        ensure!(
            matches.contains(&tx.compute_txid()),
            "Transaction has no inclusion proof"
        );
        ensure!(
            by_id.insert(tx.compute_txid(), tx).is_none(),
            "Duplicate transaction in proof record"
        );
    }
    ensure!(
        by_id.len() == matches.len(),
        "Missing proven transaction data"
    );
    let mut ordered: Vec<_> = indices.into_iter().zip(matches).collect();
    ordered.sort_by_key(|(index, _)| *index);
    Ok(ordered
        .into_iter()
        .map(|(_, txid)| by_id.remove(&txid).expect("checked above"))
        .collect())
}

impl Litecoin {
    fn sign_payment(
        &mut self,
        recipient: &str,
        amount: u64,
        fee_rate: u64,
        mut available: Vec<Coin>,
        sweep: bool,
    ) -> Result<Payment> {
        ensure!(
            self.header_download.is_none()
                && self.state.scanned >= self.chain.height()
                && self.chain.height() > 0,
            "Finish SPV sync before sending"
        );
        ensure!(
            self.chain.has_minimum_work(),
            "Header chain has not reached the minimum-work floor"
        );
        let destination = address::script_for_address(recipient)?;
        let (_, change_script, _) = address::derive(&self.master, true, self.state.change_index)?;
        available.sort_by_key(|c| c.output.value.to_sat());
        let mut selected = Vec::new();
        let mut total = 0u64;
        let mut fee = 0u64;
        if sweep {
            selected = available;
            total = selected
                .iter()
                .map(|c| c.output.value.to_sat())
                .try_fold(0u64, |sum, value| sum.checked_add(value))
                .context("Coin amount overflow")?;
            let vbytes = 12 + selected.len() as u64 * 69 + 9 + destination.len() as u64;
            fee = vbytes.checked_mul(fee_rate).context("Fee overflow")?;
            ensure!(
                !selected.is_empty() && total == amount.checked_add(fee).context("Payment overflow")?,
                "Sweep amount does not match selected coins"
            );
        } else {
            for coin in available {
                total = total
                    .checked_add(coin.output.value.to_sat())
                    .context("Coin amount overflow")?;
                selected.push(coin);
                let vbytes = 12
                    + selected.len() as u64 * 69
                    + 9
                    + destination.len() as u64
                    + 9
                    + change_script.len() as u64;
                fee = vbytes.checked_mul(fee_rate).context("Fee overflow")?;
                if total >= amount.checked_add(fee).context("Payment overflow")? {
                    break;
                }
                ensure!(
                    selected.len() < 100,
                    "Payment requires too many inputs; consolidate smaller coins first"
                );
            }
            ensure!(
                !selected.is_empty()
                    && total >= amount.checked_add(fee).context("Payment overflow")?,
                "Insufficient spendable funds (six confirmations required)"
            );
        }
        let change = total - amount - fee;
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: selected
                .iter()
                .map(|coin| TxIn {
                    previous_output: coin.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: Amount::from_sat(amount),
                script_pubkey: destination,
            }],
        };
        if !sweep && change >= DUST {
            tx.output.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: change_script,
            });
        } else if !sweep {
            fee += change;
        }
        let secp = Secp256k1::new();
        for (i, coin) in selected.iter().enumerate() {
            let key = address::derive(&self.master, coin.change, coin.index)?.0;
            let digest = SighashCache::new(&tx).p2wpkh_signature_hash(
                i,
                &coin.output.script_pubkey,
                coin.output.value,
                EcdsaSighashType::All,
            )?;
            let signature = secp.sign_ecdsa(&Message::from_digest(digest.to_byte_array()), &key);
            let mut bytes = signature.serialize_der().to_vec();
            bytes.push(EcdsaSighashType::All as u8);
            let public = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &key).serialize();
            tx.input[i].witness = Witness::from_slice(&[bytes.as_slice(), &public]);
        }
        ensure!(
            fee >= tx.vsize() as u64 * fee_rate,
            "Signed transaction fee below requested rate"
        );
        let payment = Payment {
            recipient: recipient.to_owned(),
            amount: amount.into(),
            fee: fee.into(),
            txid: tx.compute_txid().to_string(),
            raw: serialize(&tx),
        };
        self.prepared = Some(payment.clone());
        Ok(payment)
    }
}

impl Network for Litecoin {
    fn info(&self) -> NetworkInfo {
        NetworkInfo {
            id: "litecoin-mainnet",
            name: "Litecoin",
            ticker: "LTC",
            decimals: 8,
            fee_rate_unit: "litoshi/vB",
        }
    }

    fn snapshot(&self) -> Snapshot {
        let reserved = self.reserved().unwrap_or_default();
        let mut transactions = self.pending_entries();
        let pending_incoming = transactions
            .iter()
            .map(|entry| entry.received.saturating_sub(entry.sent))
            .sum();
        let pending_outgoing = transactions
            .iter()
            .map(|entry| entry.sent.saturating_sub(entry.received))
            .sum();
        transactions.extend(self.history.iter().rev().cloned());
        let mut peers: Vec<_> = if let Some(download) = &self.header_download {
            download
                .peers()
                .iter()
                .map(|peer| (peer.address, peer.height))
                .collect()
        } else {
            self.peers
                .iter()
                .map(|peer| (peer.address, peer.height))
                .collect()
        };
        if let Some(monitor) = &self.mempool {
            if monitor.connected() {
                peers.push((monitor.address, monitor.height));
            }
        }
        Snapshot {
            mempool_status: if !self.options.mempool {
                "off"
            } else if self.mempool.as_ref().is_some_and(Mempool::connected) {
                "live"
            } else {
                "waiting"
            }
            .into(),
            pending_incoming,
            pending_outgoing,
            receive_note: "Native SegWit · m/84'/2'/0'/0/i".into(),
            spend_note: "6 confirmations · coinbase 100".into(),
            address: address::derive(&self.master, false, self.state.receive_index)
                .map(|d| d.2)
                .unwrap_or_default(),
            balance: self.coins.values().map(|c| u128::from(c.output.value.to_sat())).sum(),
            spendable: self
                .coins
                .values()
                .filter(|c| self.is_spendable(c, &reserved))
                .map(|c| u128::from(c.output.value.to_sat()))
                .sum(),
            height: self.chain.height(),
            scanned: self.state.scanned,
            recent_scanned: self.recent_scanned,
            peer_height: peers.first().map_or(0, |p| p.1),
            connected_peers: peers.len(),
            max_peers: self.options.max_peers,
            peer: peers.first().map(|p| p.0.to_string()).unwrap_or_default(),
            transactions,
        }
    }

    fn next_address(&mut self) -> Result<String> {
        self.state.receive_index = self
            .state
            .receive_index
            .checked_add(1)
            .context("Address index overflow")?;
        self.refresh_scripts()?;
        self.save()?;
        Ok(address::derive(&self.master, false, self.state.receive_index)?.2)
    }

    fn disconnect(&mut self) {
        self.header_download = None;
        self.filter_batch = None;
        if !self.peers.is_empty() {
            let failed = self.state.filters.take_failed_peer();
            let index = failed
                .and_then(|address| self.peers.iter().position(|peer| peer.address == address))
                .unwrap_or(0);
            self.peers.remove(index);
        }
        self.headers_current = false;
        self.chain.discard_candidate();
    }

    fn poll_activity(&mut self) -> Result<bool> {
        let mut changed = false;
        let messages = self.mempool.as_ref().map_or_else(Vec::new, Mempool::drain);
        for raw in messages {
            changed |= self.observe_transaction(&raw)?;
        }
        let before = self.observed.len();
        self.observed
            .retain(|(_, seen)| seen.elapsed() < Duration::from_secs(3600));
        changed |= self.observed.len() != before;
        if self
            .mempool
            .as_ref()
            .is_some_and(|monitor| !monitor.connected())
        {
            self.mempool = None;
            self.next_peer_maintenance = Instant::now();
            changed = true;
        }
        if changed {
            self.update_mempool_watch();
        }
        Ok(changed)
    }

    fn sync_step(&mut self, cancel: &AtomicBool) -> Result<bool> {
        self.poll_activity()?;
        if self.headers_current && Instant::now() >= self.next_headers_poll {
            self.headers_current = false;
        }
        if self.header_download.is_none() {
            self.connect(cancel)?;
        }
        if !self.headers_current {
            if self.header_download.is_none()
                && self.peers.len() > 1
                && self
                    .peers
                    .iter()
                    .any(|peer| peer.height > self.chain.height().saturating_add(2000))
            {
                self.header_download = Some(HeaderDownload::start(
                    std::mem::take(&mut self.peers),
                    self.chain.locator(),
                ));
            }
            if let Some(download) = &self.header_download {
                match download.next(cancel)? {
                    Download::Batch { headers, peer } => {
                        let old_tip = self.chain.height();
                        let ancestor = self.chain.apply(&headers, cancel).with_context(|| {
                            format!("Validating headers downloaded from {peer}")
                        })?;
                        if ancestor < old_tip {
                            self.filter_batch = None;
                            self.recent_scan = None;
                            self.recent_scanned = self.recent_scanned.min(ancestor);
                            self.reconcile()?;
                            self.rebuild()?;
                            self.save()?;
                        }
                    }
                    Download::Complete => {
                        ensure!(
                            !self.chain.has_candidate(),
                            "Header peers ended a fork with insufficient work"
                        );
                        self.header_download = None;
                        // Download sockets are drained and closed before opening compact-filter connections.
                        self.connect(cancel)?;
                        self.mark_headers_current()?;
                    }
                    Download::Failed(_) => unreachable!("next turns worker failures into errors"),
                }
                return Ok(false);
            }
            let headers = self
                .peers
                .first_mut()
                .context("No peer")?
                .headers(&self.chain.locator(), cancel)?;
            let old_tip = self.chain.height();
            let ancestor = self.chain.apply(&headers, cancel)?;
            ensure!(
                !self.chain.has_candidate() || headers.len() == 2000,
                "Peer stopped on a fork with insufficient chain work"
            );
            if ancestor < old_tip {
                self.filter_batch = None;
                self.recent_scan = None;
                self.recent_scanned = self.recent_scanned.min(ancestor);
                self.reconcile()?;
                self.rebuild()?;
                self.save()?;
            }
            if headers.len() < 2000 {
                self.mark_headers_current()?;
            }
            return Ok(false);
        }
        if self.recent_scan.is_some() {
            for _ in 0..2 {
                let Some((height, end)) = self.recent_scan else {
                    break;
                };
                if self.scan_block(height, false, cancel)? {
                    self.recent_scanned = height;
                    self.recent_scan = if height < end {
                        Some((height + 1, end))
                    } else {
                        None
                    };
                }
            }
            return Ok(false);
        }
        for _ in 0..1000 {
            let next = self
                .state
                .scanned
                .saturating_add(1)
                .max(self.state.birthday);
            if next > self.chain.height() {
                self.save()?;
                return Ok(true);
            }
            self.scan_block(next, true, cancel)?;
        }
        self.save()?;
        Ok(false)
    }

    fn address_balances(&self) -> Vec<(String, u128)> {
        let mut balances = BTreeMap::<String, u128>::new();
        for coin in self.coins.values() {
            if coin.change {
                continue;
            }
            if let Ok((_, _, address)) = address::derive(&self.master, false, coin.index) {
                *balances.entry(address).or_default() += u128::from(coin.output.value.to_sat());
            }
        }
        balances.into_iter().collect()
    }

    fn address_unconfirmed_balances(&self) -> Vec<(String, u128)> {
        let mut balances = BTreeMap::<String, u128>::new();
        for raw in self
            .state
            .pending
            .iter()
            .map(String::as_str)
            .chain(self.observed.iter().map(|(raw, _)| raw.as_str()))
        {
            let Some(tx) = decode_transaction(raw) else {
                continue;
            };
            if self.confirmed_ids.contains(&tx.compute_txid())
                || tx
                    .input
                    .iter()
                    .any(|input| self.confirmed_spends.contains(&input.previous_output))
            {
                continue;
            }
            for output in &tx.output {
                let Some((change, index)) = self.scripts.get(&output.script_pubkey) else {
                    continue;
                };
                if *change {
                    continue;
                }
                if let Ok((_, _, address)) = address::derive(&self.master, false, *index) {
                    *balances.entry(address).or_default() += u128::from(output.value.to_sat());
                }
            }
        }
        balances.into_iter().collect()
    }

    fn address_transactions(&self, address: &str) -> Vec<AddressTransaction> {
        let mut by_txid = BTreeMap::<String, AddressTransaction>::new();
        for coin in self.coins.values() {
            if coin.change {
                continue;
            }
            let Ok((_, _, coin_address)) = address::derive(&self.master, false, coin.index) else {
                continue;
            };
            if coin_address != address {
                continue;
            }
            let txid = coin.outpoint.txid.to_string();
            let entry = by_txid.entry(txid.clone()).or_insert(AddressTransaction {
                txid,
                amount: 0,
                confirmed: true,
                height: coin.height,
            });
            entry.amount += u128::from(coin.output.value.to_sat());
            entry.confirmed = true;
            entry.height = coin.height;
        }
        for raw in self
            .state
            .pending
            .iter()
            .map(String::as_str)
            .chain(self.observed.iter().map(|(raw, _)| raw.as_str()))
        {
            let Some(tx) = decode_transaction(raw) else {
                continue;
            };
            let txid = tx.compute_txid();
            if self.confirmed_ids.contains(&txid)
                || tx
                    .input
                    .iter()
                    .any(|input| self.confirmed_spends.contains(&input.previous_output))
            {
                continue;
            }
            let key = txid.to_string();
            if by_txid.contains_key(&key) {
                continue;
            }
            let mut amount = 0u128;
            for output in &tx.output {
                let Some((change, index)) = self.scripts.get(&output.script_pubkey) else {
                    continue;
                };
                if *change {
                    continue;
                }
                let Ok((_, _, coin_address)) = address::derive(&self.master, false, *index) else {
                    continue;
                };
                if coin_address == address {
                    amount += u128::from(output.value.to_sat());
                }
            }
            if amount > 0 {
                by_txid.insert(
                    key.clone(),
                    AddressTransaction {
                        txid: key,
                        amount,
                        confirmed: false,
                        height: 0,
                    },
                );
            }
        }
        by_txid.into_values().collect()
    }

    fn prepare_forward(
        &mut self,
        from_address: &str,
        recipient: &str,
        fee_rate: u64,
    ) -> Result<Payment> {
        ensure!(
            (1..=1000).contains(&fee_rate),
            "Fee rate must be 1–1000 litoshi/vbyte"
        );
        let reserved = self.reserved()?;
        let available: Vec<Coin> = self
            .coins
            .values()
            .filter(|c| {
                !c.change
                    && self.is_spendable(c, &reserved)
                    && address::derive(&self.master, false, c.index)
                        .ok()
                        .is_some_and(|(_, _, address)| address == from_address)
            })
            .cloned()
            .collect();
        let total: u64 = available
            .iter()
            .map(|c| c.output.value.to_sat())
            .try_fold(0u64, |sum, value| sum.checked_add(value))
            .context("Coin amount overflow")?;
        ensure!(total > 0, "No spendable funds on invoice address yet");
        let destination = address::script_for_address(recipient)?;
        let vbytes = 12 + available.len() as u64 * 69 + 9 + destination.len() as u64;
        let fee = vbytes.checked_mul(fee_rate).context("Fee overflow")?;
        let amount = total.checked_sub(fee).context("Invoice funds cannot cover the fee")?;
        ensure!(amount >= DUST, "Forward amount is below dust after fees");
        self.sign_payment(recipient, amount, fee_rate, available, true)
    }

    fn prepare_payment(&mut self, recipient: &str, amount: u128, fee_rate: u64) -> Result<Payment> {
        let amount = u64::try_from(amount).context("Amount exceeds this network's maximum")?;
        ensure!(
            (DUST..=MAX_MONEY).contains(&amount),
            "Amount is below dust or exceeds Litecoin supply"
        );
        ensure!(
            (1..=1000).contains(&fee_rate),
            "Fee rate must be 1–1000 litoshi/vbyte"
        );
        let reserved = self.reserved()?;
        let available: Vec<Coin> = self
            .coins
            .values()
            .filter(|c| self.is_spendable(c, &reserved))
            .cloned()
            .collect();
        self.sign_payment(recipient, amount, fee_rate, available, false)
    }

    fn broadcast(&mut self, payment: &Payment, cancel: &AtomicBool) -> Result<()> {
        ensure!(
            self.prepared
                .as_ref()
                .is_some_and(|p| p.raw == payment.raw && p.txid == payment.txid),
            "Payment does not match the reviewed transaction"
        );
        let tx: Transaction = deserialize(&payment.raw)?;
        let reserved = self.reserved()?;
        ensure!(
            self.state.scanned >= self.chain.height()
                && tx.input.iter().all(|i| self
                    .coins
                    .get(&i.previous_output)
                    .is_some_and(|c| self.is_spendable(c, &reserved))),
            "Inputs changed since review; prepare a new payment"
        );
        self.connect(cancel)?;
        // Persist reservations before writing to the socket; disconnects have ambiguous delivery.
        self.state.pending.push(hex::encode(&payment.raw));
        if tx.output.len() > 1 {
            self.state.change_index += 1;
            self.refresh_scripts()?;
        }
        self.save()?;
        self.prepared = None;
        let peer = self.peers.first_mut().context("No peer")?;
        peer.send("tx", &payment.raw)?;
        let nonce: u64 = rand::random();
        peer.send("ping", &nonce.to_le_bytes())?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let message = peer.receive_until(cancel, deadline)?;
            match message.command.as_str() {
                "pong" if message.payload == nonce.to_le_bytes() => return Ok(()),
                "ping" => peer.pong(&message.payload)?,
                "reject" => bail!("Peer rejected a message after broadcast; inputs remain reserved until resolved"),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::genesis;

    #[test]
    fn new_default_wallet_defers_tip_window_until_headers_are_current() {
        for (tip, start) in [
            (0, 1),
            (100, 1),
            (DEFAULT_FIRST_SCAN_WINDOW, 1),
            (30_000, 20_000),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut wallet = Litecoin::open(
                &[31; 64],
                dir.path(),
                Options::default(),
                &AtomicBool::new(false),
            )
            .unwrap();
            assert_eq!(wallet.state.birthday, 0); // Unresolved, including across offline opens.
            assert_eq!(wallet.state.scanned, 0);
            assert!(wallet.state.resolve_scan_start(tip));
            assert_eq!(wallet.state.birthday, start);
            assert_eq!(wallet.state.scanned + 1, start);
            assert!(!wallet.state.resolve_scan_start(tip + 1000));
            assert_eq!(wallet.state.birthday, start);
        }
    }

    #[test]
    fn explicit_birthday_wins_and_pending_default_can_be_resolved_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        // A status/address call may have created state before the first online sync.
        drop(Litecoin::open(&[32; 64], dir.path(), Options::default(), &cancel).unwrap());
        let mut wallet = Litecoin::open(
            &[32; 64],
            dir.path(),
            Options {
                birthday: Some(50),
                ..Options::default()
            },
            &cancel,
        )
        .unwrap();
        assert!(!wallet.state.resolve_scan_start(30_000));
        assert_eq!(wallet.state.birthday, 50);
        assert_eq!(wallet.state.scanned, 49);
        drop(wallet);
        let wallet = Litecoin::open(
            &[32; 64],
            dir.path(),
            Options {
                birthday: Some(500),
                ..Options::default()
            },
            &cancel,
        )
        .unwrap();
        assert_eq!(wallet.state.birthday, 50);
        assert_eq!(wallet.state.scanned, 49);
    }

    #[test]
    fn resolved_window_restart_continues_saved_cursor_and_legacy_state_stays_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut wallet =
            Litecoin::open(&[33; 64], dir.path(), Options::default(), &cancel).unwrap();
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let headers: Vec<_> = fixture[..80 * 8]
            .chunks_exact(80)
            .map(|raw| deserialize(raw).unwrap())
            .collect();
        wallet.chain.apply(&headers, &cancel).unwrap();
        wallet.mark_headers_current().unwrap();
        wallet.state.scanned = 5;
        wallet.state.scanned_hash = wallet.chain.hash(5);
        wallet.save().unwrap();
        drop(wallet);
        let mut wallet = Litecoin::open(
            &[33; 64],
            dir.path(),
            Options {
                birthday: Some(7),
                ..Options::default()
            },
            &cancel,
        )
        .unwrap();
        assert_eq!(wallet.state.birthday, 1);
        assert_eq!(wallet.state.scanned, 5);
        wallet.mark_headers_current().unwrap();
        assert_eq!(wallet.state.scanned, 5);
        assert_eq!(wallet.state.scanned + 1, 6);
    }

    #[test]
    fn relay_observations_are_pending_only_and_confirmation_requires_a_proof() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut wallet =
            Litecoin::open(&[34; 64], dir.path(), Options::default(), &cancel).unwrap();
        let mut tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: address::derive(&wallet.master, false, 0).unwrap().1,
            }],
        };
        assert!(wallet.observe_transaction(&serialize(&tx)).unwrap());
        assert!(!wallet.observe_transaction(&serialize(&tx)).unwrap());
        assert_eq!(wallet.snapshot().pending_incoming, 100_000);
        assert_eq!(wallet.snapshot().transactions[0].height, 0);
        assert_eq!(
            (wallet.snapshot().balance, wallet.snapshot().spendable),
            (0, 0)
        );
        tx.output[0].value = Amount::from_sat(200_000); // Conflicting newer observation.
        assert!(wallet.observe_transaction(&serialize(&tx)).unwrap());
        assert_eq!(wallet.snapshot().transactions.len(), 1);
        assert_eq!(wallet.snapshot().pending_incoming, 200_000);
        let id = tx.compute_txid();
        let mut header = genesis();
        header.merkle_root = bitcoin::TxMerkleNode::from_byte_array(id.to_byte_array());
        wallet.chain.proof_test_chain(header);
        let proof = MerkleBlock::from_header_txids_with_predicate(&header, &[id], |_| true);
        wallet.state.records.push(Record {
            height: 1,
            proof: hex::encode(serialize(&proof)),
            transactions: vec![hex::encode(serialize(&tx))],
        });
        wallet.rebuild().unwrap();
        assert_eq!(wallet.snapshot().pending_incoming, 0);
        assert_eq!(wallet.snapshot().balance, 200_000);
        assert_eq!(wallet.snapshot().spendable, 0);
        assert_eq!(wallet.snapshot().transactions[0].height, 1);
        assert!(wallet.observed.is_empty());
        assert!(wallet.state.pending.is_empty()); // Observations never reserve broadcast inputs.
    }

    #[test]
    fn mempool_connection_counts_toward_the_existing_three_peer_limit() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut wallet = Litecoin::open(
            &[35; 64],
            dir.path(),
            Options {
                mempool: true,
                ..Options::default()
            },
            &cancel,
        )
        .unwrap();
        let mut servers = Vec::new();
        for relay in [false, false, true] {
            let (address, server) = crate::peer::mock_peer_with_relay(relay, |mut peer| {
                while let Ok(message) = peer.receive(&AtomicBool::new(false)) {
                    assert_eq!(message.command, "ping");
                    peer.pong(&message.payload).unwrap();
                }
            });
            servers.push(server);
            if relay {
                let peer = Peer::connect_relay(address.parse().unwrap(), 0, &cancel).unwrap();
                wallet.mempool = Some(Mempool::start(peer, wallet.mempool_watch()));
            } else {
                wallet
                    .peers
                    .push(Peer::connect(address.parse().unwrap(), 0, &cancel).unwrap());
            }
        }
        // Maintenance must find zero free slots, not dial a fourth connection.
        wallet.connect(&cancel).unwrap();
        assert_eq!(wallet.peers.len(), 2);
        assert_eq!(wallet.snapshot().connected_peers, 3);
        assert_eq!(wallet.snapshot().max_peers, 3);
        assert_eq!(wallet.snapshot().mempool_status, "live");
        drop(wallet);
        for server in servers {
            server.join().unwrap();
        }
        assert!(Litecoin::open(
            &[35; 64],
            dir.path(),
            Options {
                mempool: true,
                max_peers: 2,
                ..Options::default()
            },
            &cancel
        )
        .is_err());
    }
    #[test]
    fn merkle_proof_is_required_and_transactions_are_ordered() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(42),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let id = tx.compute_txid();
        let mut header = genesis();
        header.merkle_root = bitcoin::TxMerkleNode::from_byte_array(id.to_byte_array());
        let proof = MerkleBlock::from_header_txids_with_predicate(&header, &[id], |_| true);
        let raw = hex::encode(serialize(&tx));
        assert_eq!(
            verify_transactions(&proof, std::slice::from_ref(&raw)).unwrap(),
            vec![tx]
        );
        assert!(verify_transactions(&proof, &[]).is_err());
        let mut tampered = proof.clone();
        tampered.header.merkle_root = bitcoin::TxMerkleNode::all_zeros();
        assert!(verify_transactions(&tampered, &[raw]).is_err());
    }
    #[test]
    fn offline_wallet_persists_addresses_without_fabricating_balance() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let seed = [1; 64];
        let mut wallet = Litecoin::open(&seed, dir.path(), Options::default(), &cancel).unwrap();
        let first = wallet.snapshot().address;
        let next = wallet.next_address().unwrap();
        assert_ne!(first, next);
        assert_eq!(wallet.snapshot().balance, 0);
        assert!(wallet.prepare_payment(&first, 100_000, 1).is_err());
        drop(wallet);
        let state_path = dir.path().join("state.json");
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
        legacy.as_object_mut().unwrap().remove("filters");
        fs::write(&state_path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let wallet = Litecoin::open(&seed, dir.path(), Options::default(), &cancel).unwrap();
        assert_eq!(wallet.snapshot().address, next);
        assert_eq!(wallet.snapshot().balance, 0);
        assert!(Litecoin::open(&[2; 64], dir.path(), Options::default(), &cancel).is_err());
    }

    #[test]
    fn signed_payment_verifies_and_broadcast_reserves_inputs() {
        let (peer_address, server) = crate::peer::mock_peer(|mut peer| {
            let cancel = AtomicBool::new(false);
            let payment = peer.receive(&cancel).unwrap();
            assert_eq!(payment.command, "tx");
            let tx: Transaction = deserialize(&payment.payload).unwrap();
            assert_eq!(tx.input.len(), 1);
            assert_eq!(tx.output.len(), 2);
            let ping = peer.receive(&cancel).unwrap();
            assert_eq!(ping.command, "ping");
            peer.send("pong", &ping.payload).unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut wallet = Litecoin::open(
            &[7; 64],
            dir.path(),
            Options {
                peer: Some(peer_address),
                birthday: Some(1),
                ..Options::default()
            },
            &cancel,
        )
        .unwrap();
        wallet.chain.signing_test_chain();
        wallet.state.scanned = 6;
        let (_, script, recipient) = address::derive(&wallet.master, false, 0).unwrap();
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([42; 32]),
            vout: 0,
        };
        let output = TxOut {
            value: Amount::from_sat(500_000),
            script_pubkey: script,
        };
        wallet.coins.insert(
            outpoint,
            Coin {
                outpoint,
                output: output.clone(),
                height: 1,
                coinbase: false,
                change: false,
                index: 0,
            },
        );
        let payment = wallet.prepare_payment(&recipient, 100_000, 2).unwrap();
        let tx: Transaction = deserialize(&payment.raw).unwrap();
        assert_eq!(tx.compute_txid().to_string(), payment.txid);
        assert_eq!(
            tx.output.iter().map(|o| o.value.to_sat()).sum::<u64>() + payment.fee,
            500_000
        );
        assert!(payment.fee >= tx.vsize() as u64 * 2);
        let items: Vec<&[u8]> = tx.input[0].witness.iter().collect();
        let signature =
            bitcoin::secp256k1::ecdsa::Signature::from_der(&items[0][..items[0].len() - 1])
                .unwrap();
        let public = bitcoin::secp256k1::PublicKey::from_slice(items[1]).unwrap();
        let hash = SighashCache::new(&tx)
            .p2wpkh_signature_hash(
                0,
                &output.script_pubkey,
                output.value,
                EcdsaSighashType::All,
            )
            .unwrap();
        Secp256k1::verification_only()
            .verify_ecdsa(
                &Message::from_digest(hash.to_byte_array()),
                &signature,
                &public,
            )
            .unwrap();
        wallet.broadcast(&payment, &cancel).unwrap();
        assert_eq!(wallet.snapshot().spendable, 0);
        assert_eq!(wallet.snapshot().transactions[0].height, 0);
        assert!(wallet.prepare_payment(&recipient, 100_000, 2).is_err());
        let persisted: State =
            serde_json::from_slice(&fs::read(&wallet.state_path).unwrap()).unwrap();
        assert_eq!(persisted.pending, vec![hex::encode(&payment.raw)]);
        assert!(wallet.broadcast(&payment, &cancel).is_err());
        server.join().unwrap();
    }

    #[test]
    fn compact_sync_expands_address_gap_and_credits_only_proven_transactions() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut wallet = Litecoin::open(&[9; 64], dir.path(), Options::default(), &cancel).unwrap();
        let make_tx = |index: u32| Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([index as u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: address::derive(&wallet.master, false, index).unwrap().1,
            }],
        };
        let txs = [make_tx(19), make_tx(20)];
        let ids = [txs[0].compute_txid(), txs[1].compute_txid()];
        let mut joined = ids[0].to_byte_array().to_vec();
        joined.extend(ids[1].to_byte_array());
        let mut header = genesis();
        header.prev_blockhash = genesis().block_hash();
        header.time += 150;
        header.merkle_root = bitcoin::TxMerkleNode::from_byte_array(
            bitcoin::hashes::sha256d::Hash::hash(&joined).to_byte_array(),
        );
        wallet.chain.proof_test_chain(header);
        let block = bitcoin::Block {
            header,
            txdata: txs.to_vec(),
        };
        let filter =
            bitcoin::bip158::BlockFilter::new_script_filter(&block, |_| Ok(ScriptBuf::new()))
                .unwrap();
        let (address, server) = crate::peer::mock_peer(move |mut peer| {
            use bitcoin::{
                p2p::message_filter::{CFCheckpt, CFHeaders, CFilter},
                FilterHash, FilterHeader,
            };
            let cancel = AtomicBool::new(false);
            assert_eq!(peer.receive(&cancel).unwrap().command, "getheaders");
            peer.send("headers", &[0]).unwrap();
            assert_eq!(peer.receive(&cancel).unwrap().command, "getcfcheckpt");
            peer.send(
                "cfcheckpt",
                &serialize(&CFCheckpt {
                    filter_type: 0,
                    stop_hash: header.block_hash(),
                    filter_headers: vec![],
                }),
            )
            .unwrap();
            assert_eq!(peer.receive(&cancel).unwrap().command, "getcfheaders");
            peer.send(
                "cfheaders",
                &serialize(&CFHeaders {
                    filter_type: 0,
                    stop_hash: header.block_hash(),
                    previous_filter_header: FilterHeader::all_zeros(),
                    filter_hashes: vec![FilterHash::hash(&[0]), FilterHash::hash(&filter.content)],
                }),
            )
            .unwrap();
            let request = peer.receive(&cancel).unwrap();
            assert_eq!(request.command, "getcfilters");
            peer.send(
                "cfilter",
                &serialize(&CFilter {
                    filter_type: 0,
                    block_hash: header.block_hash(),
                    filter: filter.content,
                }),
            )
            .unwrap();
            let request = peer.receive(&cancel).unwrap();
            assert_eq!(request.command, "getdata");
            assert_eq!(
                u32::from_le_bytes(request.payload[1..5].try_into().unwrap()),
                2
            );
            peer.send("block", &serialize(&block)).unwrap();
        });
        wallet.options.peer = Some(address);
        assert_eq!(wallet.snapshot().balance, 0);
        assert!(!wallet.sync_step(&cancel).unwrap());
        assert!(wallet.sync_step(&cancel).unwrap());
        assert_eq!(wallet.snapshot().balance, 200_000);
        assert_eq!(wallet.snapshot().spendable, 0);
        assert_eq!(wallet.state.scanned, 1);
        assert_eq!(wallet.state.receive_index, 21);
        assert_eq!(wallet.history.len(), 2);
        wallet.rebuild().unwrap();
        assert_eq!(wallet.snapshot().balance, 200_000);
        server.join().unwrap();
    }

    #[test]
    fn default_three_peer_pool_promotes_a_standby_after_disconnect() {
        let mut addresses = Vec::new();
        let mut servers = Vec::new();
        for _ in 0..3 {
            let (address, server) = crate::peer::mock_peer(|mut peer| {
                let cancel = AtomicBool::new(false);
                while let Ok(message) = peer.receive(&cancel) {
                    assert_eq!(message.command, "ping");
                    peer.send("pong", &message.payload).unwrap();
                }
            });
            addresses.push(address.parse().unwrap());
            servers.push(server);
        }
        let cancel = AtomicBool::new(false);
        let options = Options::default();
        assert_eq!(options.max_peers, 3);
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = Litecoin::open(&[4; 64], dir.path(), options, &cancel).unwrap();
        wallet.peers =
            Peer::connect_candidates(&addresses, 0, wallet.options.max_peers, &cancel).unwrap();
        assert_eq!(wallet.snapshot().connected_peers, 3);
        assert_eq!(wallet.snapshot().max_peers, 3);
        for peer in &mut wallet.peers {
            peer.heartbeat(&cancel).unwrap();
        }
        let active = wallet.snapshot().peer;
        wallet.disconnect();
        assert_eq!(wallet.snapshot().connected_peers, 2);
        assert_ne!(wallet.snapshot().peer, active);
        wallet.peers[0].heartbeat(&cancel).unwrap();
        drop(wallet);
        for server in servers {
            server.join().unwrap();
        }
    }
}
