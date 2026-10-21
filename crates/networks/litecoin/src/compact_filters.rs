//! BIP157 basic-filter transport and locally evaluated BIP158 filters.
use crate::{chain::HeaderChain, peer::Peer};
use anyhow::{bail, ensure, Context, Result};
use bitcoin::{
    bip158::BlockFilter,
    consensus::{deserialize, serialize, Decodable},
    hashes::Hash,
    p2p::message_filter::{CFCheckpt, CFHeaders, CFilter, GetCFCheckpt, GetCFHeaders, GetCFilters},
    Block, BlockHash, FilterHash, FilterHeader,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    thread,
    time::{Duration, Instant},
};

#[derive(Default, Serialize, Deserialize)]
pub struct CompactFilters {
    // Pin the newest 100 verified headers across sessions. Block hashes let a
    // genuine PoW-chain reorganization invalidate only its orphaned anchors.
    anchors: BTreeMap<u32, (BlockHash, FilterHeader)>,
    #[serde(default)]
    conflict: Option<(u32, BlockHash)>,
    #[serde(skip)]
    failed_peer: Option<SocketAddr>,
    #[serde(skip)]
    checkpoints: Option<(BlockHash, Vec<FilterHeader>)>,
}

#[derive(Debug)]
pub struct FilterBatch {
    start: u32,
    blocks: Vec<BlockHash>,
    filters: Vec<BlockFilter>,
    queries: Vec<Vec<u8>>,
    matches: Vec<bool>,
}

impl FilterBatch {
    pub fn contains(&self, height: u32, hash: BlockHash) -> bool {
        height
            .checked_sub(self.start)
            .and_then(|i| self.blocks.get(i as usize))
            == Some(&hash)
    }
    pub fn get(&self, height: u32) -> Result<&BlockFilter> {
        height
            .checked_sub(self.start)
            .and_then(|i| self.filters.get(i as usize))
            .context("Compact filter outside downloaded range")
    }
    /// Evaluate a batch in parallel. A changed address gap invalidates cached
    /// decisions, including newly discovered scripts within the same batch.
    pub fn match_scripts(&mut self, scripts: &[&[u8]]) -> Result<()> {
        if self.matches.len() == self.filters.len()
            && self.queries.len() == scripts.len()
            && self
                .queries
                .iter()
                .zip(scripts)
                .all(|(old, new)| old.as_slice() == *new)
        {
            return Ok(());
        }
        let workers = thread::available_parallelism()
            .map_or(1, usize::from)
            .min(8)
            .min(self.filters.len())
            .max(1);
        let chunk = self.filters.len().div_ceil(workers).max(1);
        let matches = thread::scope(|scope| -> Result<Vec<bool>> {
            let handles: Vec<_> = self
                .filters
                .chunks(chunk)
                .zip(self.blocks.chunks(chunk))
                .map(|(filters, hashes)| {
                    scope.spawn(move || -> Result<Vec<bool>> {
                        filters
                            .iter()
                            .zip(hashes)
                            .map(|(filter, hash)| {
                                filter
                                    .match_any(hash, scripts.iter().copied())
                                    .map_err(Into::into)
                            })
                            .collect()
                    })
                })
                .collect();
            let mut matches = Vec::new();
            for handle in handles {
                matches.extend(
                    handle
                        .join()
                        .map_err(|_| anyhow::anyhow!("Filter matching worker panicked"))??,
                );
            }
            Ok(matches)
        })?;
        self.matches = matches;
        self.queries = scripts.iter().map(|script| script.to_vec()).collect();
        Ok(())
    }
    pub fn matched(&self, height: u32) -> Result<bool> {
        height
            .checked_sub(self.start)
            .and_then(|i| self.matches.get(i as usize))
            .copied()
            .context("Compact filter has not been matched locally")
    }
}

fn response(peer: &mut Peer, command: &str, cancel: &AtomicBool) -> Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let message = peer
            .receive_until(cancel, deadline)
            .with_context(|| format!("Waiting for {command} from {}", peer.address))?;
        if message.command == command {
            return Ok(message.payload);
        }
        match message.command.as_str() {
            "ping" => peer.pong(&message.payload)?,
            "reject" | "notfound" => bail!("Peer {} declined {command}", peer.address),
            _ => {}
        }
    }
}

impl CompactFilters {
    pub fn take_failed_peer(&mut self) -> Option<SocketAddr> {
        self.failed_peer.take()
    }

    pub fn download(
        &mut self,
        peers: &mut [Peer],
        chain: &HeaderChain,
        start: u32,
        end: u32,
        trusted: bool,
        cancel: &AtomicBool,
    ) -> Result<FilterBatch> {
        self.failed_peer = None;
        if let Some((height, hash)) = self.conflict {
            ensure!(chain.hash(height) != Some(hash),
                "Unresolved compact-filter conflict at block {height}; verify filter sources before clearing the persisted dispute");
            self.conflict = None;
        }
        ensure!(!peers.is_empty(), "No compact-filter peer");
        ensure!(trusted || peers.len() >= 2,
            "BIP157 needs at least two peers to cross-check filters; reconnect or configure a trusted --peer host:9333");
        ensure!(
            end >= start && end - start < 1000,
            "Invalid compact-filter range"
        );
        let stop = chain
            .hash(end)
            .context("Missing compact-filter stop header")?;
        let tip = chain.hash(chain.height()).context("Missing header tip")?;
        self.anchors
            .retain(|height, (hash, _)| chain.hash(*height) == Some(*hash));
        if self.checkpoints.as_ref().map(|entry| entry.0) != Some(tip) {
            let request = serialize(&GetCFCheckpt {
                filter_type: 0,
                stop_hash: tip,
            });
            for peer in peers.iter_mut() {
                self.failed_peer = Some(peer.address);
                peer.send("getcfcheckpt", &request)?;
            }
            let mut agreed: Option<Vec<FilterHeader>> = None;
            for peer in peers.iter_mut() {
                self.failed_peer = Some(peer.address);
                let reply: CFCheckpt = deserialize(&response(peer, "cfcheckpt", cancel)?)?;
                ensure!(
                    reply.filter_type == 0
                        && reply.stop_hash == tip
                        && reply.filter_headers.len() == (chain.height() / 1000) as usize,
                    "Malformed compact-filter checkpoints from {}",
                    peer.address
                );
                if let Some(expected) = &agreed {
                    if *expected != reply.filter_headers {
                        self.failed_peer = None;
                        self.conflict = Some((chain.height(), tip));
                        bail!("Peers disagree on compact-filter checkpoints; refusing to advance scan");
                    }
                } else {
                    agreed = Some(reply.filter_headers);
                }
            }
            self.checkpoints = Some((tip, agreed.context("Missing compact-filter checkpoints")?));
        }
        let checkpoints = &self.checkpoints.as_ref().context("Missing checkpoints")?.1;
        // Begin immediately after the preceding 1,000-block checkpoint, or genesis.
        // This permits a recent-block preview without downloading millions of filters.
        let base = start.saturating_sub(1) / 1000 * 1000;
        let first = if base == 0 { 0 } else { base + 1 };
        let previous = if base == 0 {
            FilterHeader::all_zeros()
        } else {
            checkpoints[(base / 1000 - 1) as usize]
        };
        ensure!(end - first < 2000, "Compact-filter header range too large");
        let request = serialize(&GetCFHeaders {
            filter_type: 0,
            start_height: first,
            stop_hash: stop,
        });
        for peer in peers.iter_mut() {
            self.failed_peer = Some(peer.address);
            peer.send("getcfheaders", &request)?;
        }
        let mut agreed: Option<Vec<FilterHash>> = None;
        for peer in peers.iter_mut() {
            self.failed_peer = Some(peer.address);
            let reply: CFHeaders = deserialize(&response(peer, "cfheaders", cancel)?)?;
            ensure!(
                reply.filter_type == 0
                    && reply.stop_hash == stop
                    && reply.filter_hashes.len() == (end - first + 1) as usize,
                "Invalid compact-filter header chain from {}",
                peer.address
            );
            if reply.previous_filter_header != previous {
                self.failed_peer = None;
                self.conflict = Some((end, stop));
                bail!("Peers disagree on previous compact-filter header; refusing to advance scan");
            }
            if let Some(expected) = &agreed {
                if *expected != reply.filter_hashes {
                    self.failed_peer = None;
                    self.conflict = Some((end, stop));
                    bail!("Peers disagree on compact-filter hashes; refusing to advance scan");
                }
            } else {
                agreed = Some(reply.filter_hashes);
            }
        }
        let hashes = agreed.context("Missing compact-filter hashes")?;
        // Validate every checkpoint link and every still-canonical persisted anchor
        // before committing new anchors or downloading filter bytes.
        let mut header = previous;
        let mut additions = Vec::new();
        for (index, hash) in hashes.iter().enumerate() {
            let height = first + index as u32;
            header = hash.filter_header(&header);
            if height > 0
                && height.is_multiple_of(1000)
                && header != checkpoints[(height / 1000 - 1) as usize]
            {
                self.failed_peer = None;
                self.conflict = Some((end, stop));
                bail!("Compact-filter headers do not connect to checkpoint at {height}");
            }
            if let Some((_, expected)) = self.anchors.get(&height) {
                if header != *expected {
                    self.failed_peer = None;
                    self.conflict = Some((end, stop));
                    bail!("Compact-filter header changed on unchanged block {height}");
                }
            }
            additions.push((
                height,
                (chain.hash(height).context("Missing filter block")?, header),
            ));
        }
        let blocks: Vec<_> = (start..=end)
            .map(|height| chain.hash(height).expect("checked range"))
            .collect();
        // Partition this already cross-checked range over existing sockets;
        // no extra connections are opened and block-height order is preserved.
        let workers = peers.len().min(blocks.len());
        let chunk = blocks.len().div_ceil(workers);
        let total_bytes = AtomicUsize::new(0);
        let expected = &hashes[(start - first) as usize..];
        let downloads = thread::scope(|scope| {
            let mut handles = Vec::new();
            for (index, peer) in peers.iter_mut().take(workers).enumerate() {
                let offset = index * chunk;
                if offset >= blocks.len() {
                    break;
                }
                let until = (offset + chunk).min(blocks.len());
                let blocks = &blocks[offset..until];
                let expected = &expected[offset..until];
                let total_bytes = &total_bytes;
                handles.push(scope.spawn(move || {
                    let address = peer.address;
                    (
                        address,
                        download_filters(
                            peer,
                            start + offset as u32,
                            blocks,
                            expected,
                            total_bytes,
                            cancel,
                        ),
                    )
                }));
            }
            handles
                .into_iter()
                .map(|handle| {
                    handle
                        .join()
                        .map_err(|_| anyhow::anyhow!("Filter download worker panicked"))
                })
                .collect::<Vec<_>>()
        });
        let mut filters = Vec::with_capacity(blocks.len());
        for result in downloads {
            let (address, result) = result?;
            match result {
                Ok(part) => filters.extend(part),
                Err(error) => {
                    self.failed_peer = Some(address);
                    return Err(error);
                }
            }
        }
        self.failed_peer = None;
        self.anchors.extend(additions);
        while self.anchors.len() > 100 {
            self.anchors.pop_first();
        }
        Ok(FilterBatch {
            start,
            blocks,
            filters,
            queries: Vec::new(),
            matches: Vec::new(),
        })
    }
}

fn download_filters(
    peer: &mut Peer,
    start: u32,
    blocks: &[BlockHash],
    hashes: &[FilterHash],
    total_bytes: &AtomicUsize,
    cancel: &AtomicBool,
) -> Result<Vec<BlockFilter>> {
    peer.send(
        "getcfilters",
        &serialize(&GetCFilters {
            filter_type: 0,
            start_height: start,
            stop_hash: *blocks.last().context("Empty filter request")?,
        }),
    )?;
    let mut filters = Vec::with_capacity(blocks.len());
    for (index, block_hash) in blocks.iter().enumerate() {
        let reply: CFilter = deserialize(&response(peer, "cfilter", cancel)?)?;
        ensure!(
            reply.filter_type == 0 && reply.block_hash == *block_hash,
            "Compact filter is for the wrong block or out of order"
        );
        ensure!(reply.filter.len() <= 512_000, "Oversized basic filter");
        let bytes =
            total_bytes.fetch_add(reply.filter.len(), Ordering::Relaxed) + reply.filter.len();
        ensure!(
            bytes <= 32_000_000,
            "Compact-filter batch exceeds memory limit"
        );
        ensure!(
            FilterHash::hash(&reply.filter) == hashes[index],
            "Compact-filter hash mismatch at {}",
            start + index as u32
        );
        let count =
            bitcoin::consensus::encode::VarInt::consensus_decode(&mut reply.filter.as_slice())?.0;
        ensure!(count <= 1_000_000, "Basic filter has too many elements");
        filters.push(BlockFilter::new(&reply.filter));
    }
    Ok(filters)
}

pub fn fetch_block(peer: &mut Peer, hash: BlockHash, cancel: &AtomicBool) -> Result<Block> {
    let mut inventory = vec![1];
    inventory.extend(2u32.to_le_bytes()); // MSG_BLOCK, no witness or MWEB flags.
    inventory.extend(hash.to_byte_array());
    peer.send("getdata", &inventory)?;
    let block: Block = deserialize(&response(peer, "block", cancel)?)
        .context("Malformed stripped Litecoin block")?;
    ensure!(block.block_hash() == hash, "Received unexpected block");
    validate_block(&block)?;
    Ok(block)
}

pub fn validate_block(block: &Block) -> Result<()> {
    ensure!(
        !block.txdata.is_empty() && block.check_merkle_root(),
        "Block Merkle root mismatch"
    );
    // Reject duplicate leaves, including the classic Merkle-tree mutation ambiguity.
    let ids: std::collections::BTreeSet<_> =
        block.txdata.iter().map(|tx| tx.compute_txid()).collect();
    ensure!(
        ids.len() == block.txdata.len(),
        "Duplicate transaction in block"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::mock_peer;
    use bitcoin::p2p::message_filter::{GetCFCheckpt, GetCFHeaders, GetCFilters};

    // All filters are empty. Deliberately faulty messages must fail before a
    // historical scan can advance, even when their P2P framing is valid.
    fn server(blocks: Vec<BlockHash>, fault: u8) -> (String, std::thread::JoinHandle<()>) {
        server_with_gate(blocks, fault, None)
    }

    fn server_with_gate(
        blocks: Vec<BlockHash>,
        fault: u8,
        gate: Option<std::sync::Arc<AtomicUsize>>,
    ) -> (String, std::thread::JoinHandle<()>) {
        mock_peer(move |mut peer| {
            let cancel = AtomicBool::new(false);
            let mut headers = Vec::new();
            let mut previous = FilterHeader::all_zeros();
            for _ in &blocks {
                previous = FilterHash::hash(&[0]).filter_header(&previous);
                headers.push(previous);
            }
            while let Ok(message) = peer.receive(&cancel) {
                let result = match message.command.as_str() {
                    "getcfcheckpt" => {
                        let request: GetCFCheckpt = deserialize(&message.payload).unwrap();
                        let stop = blocks
                            .iter()
                            .position(|hash| *hash == request.stop_hash)
                            .unwrap();
                        let mut checkpoints: Vec<_> = (1000..=stop)
                            .step_by(1000)
                            .map(|height| headers[height])
                            .collect();
                        if fault == 1 {
                            checkpoints[0] = FilterHeader::all_zeros();
                        }
                        peer.send(
                            "cfcheckpt",
                            &serialize(&CFCheckpt {
                                filter_type: 0,
                                stop_hash: request.stop_hash,
                                filter_headers: checkpoints,
                            }),
                        )
                    }
                    "getcfheaders" => {
                        let request: GetCFHeaders = deserialize(&message.payload).unwrap();
                        let stop = blocks
                            .iter()
                            .position(|hash| *hash == request.stop_hash)
                            .unwrap();
                        let mut hashes =
                            vec![FilterHash::hash(&[0]); stop - request.start_height as usize + 1];
                        if fault == 4 {
                            hashes[0] = FilterHash::hash(&[1]);
                        }
                        if fault == 5 {
                            hashes.pop();
                        }
                        peer.send(
                            "cfheaders",
                            &serialize(&CFHeaders {
                                filter_type: 0,
                                stop_hash: request.stop_hash,
                                previous_filter_header: if request.start_height == 0 {
                                    FilterHeader::all_zeros()
                                } else {
                                    headers[request.start_height as usize - 1]
                                },
                                filter_hashes: hashes,
                            }),
                        )
                    }
                    "getcfilters" => {
                        let request: GetCFilters = deserialize(&message.payload).unwrap();
                        if let Some(gate) = &gate {
                            gate.fetch_add(1, Ordering::SeqCst);
                            let deadline = Instant::now() + Duration::from_secs(3);
                            while gate.load(Ordering::SeqCst) < 2 {
                                assert!(
                                    Instant::now() < deadline,
                                    "Filter requests were serialized"
                                );
                                thread::sleep(Duration::from_millis(1));
                            }
                        }
                        let stop = blocks
                            .iter()
                            .position(|hash| *hash == request.stop_hash)
                            .unwrap();
                        for block in &blocks[request.start_height as usize..=stop] {
                            if peer
                                .send(
                                    "cfilter",
                                    &serialize(&CFilter {
                                        filter_type: 0,
                                        block_hash: if fault == 3 {
                                            BlockHash::all_zeros()
                                        } else {
                                            *block
                                        },
                                        filter: if fault == 2 { vec![1] } else { vec![0] },
                                    }),
                                )
                                .is_err()
                            {
                                return;
                            }
                        }
                        Ok(())
                    }
                    "ping" => peer.pong(&message.payload),
                    _ => panic!("Unexpected message: {}", message.command),
                };
                if result.is_err() {
                    break;
                }
            }
        })
    }

    fn download_test(
        chain: &HeaderChain,
        state: &mut CompactFilters,
        start: u32,
        end: u32,
        faults: [u8; 2],
    ) -> Result<FilterBatch> {
        let blocks: Vec<_> = (0..=chain.height())
            .map(|height| chain.hash(height).unwrap())
            .collect();
        let mut servers = Vec::new();
        let mut peers = Vec::new();
        let cancel = AtomicBool::new(false);
        let gate = (faults == [6, 6]).then(|| std::sync::Arc::new(AtomicUsize::new(0)));
        for fault in faults {
            let (address, handle) = server_with_gate(blocks.clone(), fault, gate.clone());
            servers.push(handle);
            peers.push(Peer::connect(address.parse().unwrap(), chain.height(), &cancel).unwrap());
        }
        let result = state.download(&mut peers, chain, start, end, false, &cancel);
        if matches!(faults[0], 2 | 3) {
            assert_eq!(state.failed_peer, Some(peers[0].address));
        }
        if matches!(faults[1], 2 | 3) && end > start {
            assert_eq!(state.failed_peer, Some(peers[1].address));
        }
        drop(peers);
        for server in servers {
            server.join().unwrap();
        }
        result
    }

    #[test]
    fn checkpoints_ranges_and_empty_filter_matching() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut chain = HeaderChain::open(&dir.path().join("headers.dat"), &cancel).unwrap();
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let headers: Vec<_> = fixture[..80 * 2001]
            .chunks_exact(80)
            .map(|raw| deserialize(raw).unwrap())
            .collect();
        for batch in headers.chunks(2000) {
            chain.apply(batch, &cancel).unwrap();
        }
        let mut state = CompactFilters::default();
        // Cross a checkpoint and then start immediately after one.
        for (start, end) in [(1, 1000), (999, 1001), (1001, 2000), (2000, 2001)] {
            let batch = download_test(&chain, &mut state, start, end, [0, 0]).unwrap();
            assert!(batch.contains(start, chain.hash(start).unwrap()));
            assert!(!batch.contains(start, BlockHash::all_zeros()));
            assert!(batch.get(start - 1).is_err());
            assert!(!batch
                .get(start)
                .unwrap()
                .match_any(
                    &chain.hash(start).unwrap(),
                    [b"wallet script".as_slice()].into_iter()
                )
                .unwrap());
        }
        // Both peers must receive their disjoint filter requests before either
        // sends data. A sequential downloader cannot pass this bounded gate.
        let mut parallel = download_test(&chain, &mut state, 1, 1000, [6, 6]).unwrap();
        parallel.match_scripts(&[b"wallet script"]).unwrap();
        for height in 1..=1000 {
            assert!(parallel.contains(height, chain.hash(height).unwrap()));
            assert!(!parallel.matched(height).unwrap());
        }
        assert!(download_test(&chain, &mut state, 1, 1000, [0, 2]).is_err());
        assert_eq!(state.anchors.len(), 100);
        assert!(
            download_test(&chain, &mut CompactFilters::default(), 1001, 1002, [0, 1])
                .unwrap_err()
                .to_string()
                .contains("disagree")
        );
    }

    #[test]
    fn bad_filters_headers_and_persisted_anchor_changes_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut chain = HeaderChain::open(&dir.path().join("headers.dat"), &cancel).unwrap();
        let mut header = crate::chain::genesis();
        header.prev_blockhash = header.block_hash();
        header.time += 150;
        chain.proof_test_chain(header);
        for faults in [[2, 0], [3, 0], [4, 0], [5, 0]] {
            assert!(download_test(&chain, &mut CompactFilters::default(), 1, 1, faults).is_err());
        }
        let mut state = CompactFilters::default();
        download_test(&chain, &mut state, 1, 1, [0, 0]).unwrap();
        let mut reopened: CompactFilters =
            serde_json::from_slice(&serde_json::to_vec(&state).unwrap()).unwrap();
        assert!(reopened.checkpoints.is_none());
        // Both new peers agree, but contradict the last session on the same block.
        assert!(download_test(&chain, &mut reopened, 1, 1, [4, 4])
            .unwrap_err()
            .to_string()
            .contains("changed"));
        let mut disputed: CompactFilters =
            serde_json::from_slice(&serde_json::to_vec(&reopened).unwrap()).unwrap();
        assert!(download_test(&chain, &mut disputed, 1, 1, [0, 0])
            .unwrap_err()
            .to_string()
            .contains("Unresolved"));
        // A changed canonical block invalidates its saved dispute, but merely
        // reconnecting to different peers did not erase the disagreement.
        header.time += 150;
        chain.proof_test_chain(header);
        // Orphaned anchors do not pin a genuine replacement PoW-chain block.
        reopened
            .anchors
            .insert(1, (BlockHash::all_zeros(), FilterHeader::all_zeros()));
        download_test(&chain, &mut reopened, 1, 1, [0, 0]).unwrap();
        assert!(CompactFilters::default()
            .download(&mut [], &chain, 1, 1, false, &cancel)
            .is_err());
    }

    #[test]
    fn single_discovered_peer_requires_explicit_trust() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut chain = HeaderChain::open(&dir.path().join("headers.dat"), &cancel).unwrap();
        let mut header = crate::chain::genesis();
        header.time += 150;
        chain.proof_test_chain(header);
        let blocks = vec![chain.hash(0).unwrap(), chain.hash(1).unwrap()];
        let (address, server) = server(blocks, 0);
        let mut peers = vec![Peer::connect(address.parse().unwrap(), 1, &cancel).unwrap()];
        let mut state = CompactFilters::default();
        assert!(state
            .download(&mut peers, &chain, 1, 1, false, &cancel)
            .unwrap_err()
            .to_string()
            .contains("at least two"));
        assert!(state.anchors.is_empty());
        state
            .download(&mut peers, &chain, 1, 1, true, &cancel)
            .unwrap();
        drop(peers);
        server.join().unwrap();
    }

    #[test]
    fn cached_matches_follow_changed_and_expanded_address_queries() {
        use bitcoin::{absolute, transaction::Version, Amount, ScriptBuf, Transaction, TxOut};
        let owned = ScriptBuf::from_bytes(vec![0x51]);
        let other = ScriptBuf::from_bytes(vec![0x52]);
        let block = Block {
            header: crate::chain::genesis(),
            txdata: vec![Transaction {
                version: Version::TWO,
                lock_time: absolute::LockTime::ZERO,
                input: vec![],
                output: vec![TxOut {
                    value: Amount::from_sat(1),
                    script_pubkey: owned.clone(),
                }],
            }],
        };
        let filter = BlockFilter::new_script_filter(&block, |_| Ok(ScriptBuf::new())).unwrap();
        let mut batch = FilterBatch {
            start: 12,
            blocks: vec![block.block_hash(); 32],
            filters: vec![filter; 32],
            queries: vec![],
            matches: vec![],
        };
        assert!(batch.matched(12).is_err());
        for (queries, expected) in [
            (vec![other.as_bytes()], false),
            (vec![owned.as_bytes()], true),
            (vec![other.as_bytes()], false),
            (vec![other.as_bytes(), owned.as_bytes()], true),
        ] {
            batch.match_scripts(&queries).unwrap();
            // Reusing the cache must preserve the same result.
            batch.match_scripts(&queries).unwrap();
            for height in 12..44 {
                assert_eq!(batch.matched(height).unwrap(), expected);
            }
        }
        assert!(batch.matched(11).is_err());
        assert!(batch.matched(44).is_err());
    }

    #[test]
    fn full_block_merkle_mismatch_and_mutation_are_rejected() {
        use bitcoin::{absolute, transaction::Version, Transaction};
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let mut block = Block {
            header: crate::chain::genesis(),
            txdata: vec![tx.clone()],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        validate_block(&block).unwrap();
        block.txdata[0].version = Version::ONE;
        assert!(validate_block(&block).is_err());
        block.txdata = vec![tx.clone(), tx];
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        assert!(validate_block(&block).is_err());
    }
}
