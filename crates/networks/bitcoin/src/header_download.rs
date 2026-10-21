//! Bounded header prefetch with delayed requests to alternate peers when a peer stalls.
use crate::peer::Peer;
use anyhow::{bail, Context, Result};
use bitcoin::{block::Header, BlockHash};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, Sender, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub(crate) struct PeerView {
    pub address: SocketAddr,
    pub height: u32,
    connected: bool,
}

struct Request {
    generation: u64,
    locator: Vec<BlockHash>,
}
struct Reply {
    worker: usize,
    generation: u64,
    result: Result<Vec<Header>>,
}
pub(crate) enum Download {
    Batch {
        headers: Vec<Header>,
        peer: SocketAddr,
    },
    Complete,
    Failed(String),
}

pub(crate) struct HeaderDownload {
    stop: Arc<AtomicBool>,
    results: Receiver<Download>,
    views: Arc<Mutex<Vec<PeerView>>>,
    active: Arc<AtomicUsize>,
    coordinator: Option<JoinHandle<()>>,
}

impl HeaderDownload {
    pub fn start(peers: Vec<Peer>, locator: Vec<BlockHash>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let views = Arc::new(Mutex::new(
            peers
                .iter()
                .map(|p| PeerView {
                    address: p.address,
                    height: p.height,
                    connected: true,
                })
                .collect(),
        ));
        let active = Arc::new(AtomicUsize::new(0));
        // At most four 2,000-header batches (640 KB) wait for consensus validation.
        let (sender, results) = mpsc::sync_channel(4);
        let worker_stop = stop.clone();
        let worker_views = views.clone();
        let worker_active = active.clone();
        let coordinator = thread::spawn(move || {
            coordinate(
                peers,
                locator,
                sender,
                worker_stop,
                worker_views,
                worker_active,
            )
        });
        Self {
            stop,
            results,
            views,
            active,
            coordinator: Some(coordinator),
        }
    }

    pub fn next(&self, cancel: &AtomicBool) -> Result<Download> {
        loop {
            if cancel.load(Ordering::Relaxed) {
                bail!("Cancelled");
            }
            match self.results.recv_timeout(Duration::from_millis(100)) {
                Ok(Download::Failed(message)) => bail!(message),
                Ok(result) => return Ok(result),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("Header download workers stopped")
                }
            }
        }
    }

    pub fn peers(&self) -> Vec<PeerView> {
        let views = self.views.lock().unwrap_or_else(|e| e.into_inner());
        let active = self.active.load(Ordering::Relaxed);
        (0..views.len())
            .map(|offset| views[(active + offset) % views.len()])
            .filter(|p| p.connected)
            .collect()
    }
}

impl Drop for HeaderDownload {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.coordinator.take() {
            let _ = handle.join();
        }
    }
}

fn publish(sender: &SyncSender<Download>, mut result: Download, stop: &AtomicBool) -> bool {
    while !stop.load(Ordering::Relaxed) {
        match sender.try_send(result) {
            Ok(()) => return true,
            Err(TrySendError::Full(returned)) => {
                result = returned;
                thread::sleep(Duration::from_millis(10));
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
    false
}

fn coordinate(
    peers: Vec<Peer>,
    mut locator: Vec<BlockHash>,
    sender: SyncSender<Download>,
    stop: Arc<AtomicBool>,
    views: Arc<Mutex<Vec<PeerView>>>,
    active: Arc<AtomicUsize>,
) {
    let (replies, receive) = mpsc::channel();
    let mut workers = Vec::new();
    let mut commands = Vec::new();
    for (index, mut peer) in peers.into_iter().enumerate() {
        let (command, requests) = mpsc::channel::<Request>();
        commands.push(command);
        let replies = replies.clone();
        let stop = stop.clone();
        let views = views.clone();
        workers.push(thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let request = match requests.recv_timeout(Duration::from_millis(100)) {
                    Ok(request) => request,
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                let result = peer
                    .headers(&request.locator, &stop)
                    .with_context(|| format!("Downloading headers from {}", peer.address));
                let failed = result.is_err();
                if failed {
                    views.lock().unwrap_or_else(|e| e.into_inner())[index].connected = false;
                }
                if replies
                    .send(Reply {
                        worker: index,
                        generation: request.generation,
                        result,
                    })
                    .is_err()
                    || failed
                {
                    break;
                }
            }
        }));
    }
    drop(replies);
    let result = download_rounds(
        &commands,
        &receive,
        &sender,
        &stop,
        &views,
        &active,
        &mut locator,
    );
    if let Err(error) = result {
        publish(&sender, Download::Failed(format!("{error:#}")), &stop);
    }
    stop.store(true, Ordering::Relaxed);
    drop(commands);
    for worker in workers {
        let _ = worker.join();
    }
    for peer in views.lock().unwrap_or_else(|e| e.into_inner()).iter_mut() {
        peer.connected = false;
    }
}

fn download_rounds(
    commands: &[Sender<Request>],
    replies: &Receiver<Reply>,
    output: &SyncSender<Download>,
    stop: &AtomicBool,
    views: &Mutex<Vec<PeerView>>,
    active: &AtomicUsize,
    locator: &mut Vec<BlockHash>,
) -> Result<()> {
    let mut generation = 0;
    let mut inflight = vec![false; commands.len()];
    let mut last_error = None;
    while !stop.load(Ordering::Relaxed) {
        let mut attempted = vec![false; commands.len()];
        let mut next_hedge = Instant::now();
        let batch = loop {
            if stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            let available: Vec<_> = views.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if !available.iter().any(|p| p.connected) {
                bail!(
                    "All header peers disconnected: {}",
                    last_error.as_deref().unwrap_or("no usable peers")
                );
            }
            if Instant::now() >= next_hedge {
                let idle = available
                    .iter()
                    .enumerate()
                    .filter(|(i, p)| p.connected && !inflight[*i] && !attempted[*i])
                    .max_by_key(|(i, p)| {
                        (usize::from(*i == active.load(Ordering::Relaxed)), p.height)
                    })
                    .map(|(i, _)| i);
                if let Some(index) = idle {
                    commands[index]
                        .send(Request {
                            generation,
                            locator: locator.clone(),
                        })
                        .context("Header peer worker stopped")?;
                    inflight[index] = true;
                    attempted[index] = true;
                    next_hedge = Instant::now() + Duration::from_millis(250);
                }
            }
            // An empty response is accepted only after all live peers have answered empty.
            if available
                .iter()
                .enumerate()
                .filter(|(_, p)| p.connected)
                .all(|(i, _)| attempted[i] && !inflight[i])
            {
                publish(output, Download::Complete, stop);
                return Ok(());
            }
            match replies.recv_timeout(Duration::from_millis(50)) {
                Ok(reply) => {
                    inflight[reply.worker] = false;
                    if reply.generation != generation {
                        continue;
                    }
                    match reply.result {
                        Ok(headers) if !headers.is_empty() => {
                            active.store(reply.worker, Ordering::Relaxed);
                            break (headers, available[reply.worker].address);
                        }
                        Ok(_) => next_hedge = Instant::now(),
                        Err(error) => {
                            last_error = Some(format!("{error:#}"));
                            next_hedge = Instant::now();
                        }
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    bail!("All header peer workers stopped")
                }
            }
        };
        let tip = batch.0.last().expect("nonempty batch").block_hash();
        // Keep fallbacks for a remote reorganization, always retaining genesis.
        if locator.len() > 30 {
            locator.remove(1);
        }
        locator.insert(0, tip);
        if !publish(
            output,
            Download::Batch {
                headers: batch.0,
                peer: batch.1,
            },
            stop,
        ) {
            return Ok(());
        }
        generation += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{genesis, HeaderChain};
    use bitcoin::consensus::deserialize;

    fn payload(first: usize, count: usize) -> Vec<u8> {
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let mut bytes = vec![count as u8];
        for raw in fixture[first * 80..(first + count) * 80].chunks_exact(80) {
            bytes.extend(raw);
            bytes.push(0);
        }
        bytes
    }

    #[test]
    fn downloads_next_batch_before_the_consumer_finishes_validation() {
        let (seen, second_request) = mpsc::channel();
        let (address, server) = crate::peer::mock_peer(move |mut peer| {
            let cancel = AtomicBool::new(false);
            for index in 0..2 {
                assert_eq!(peer.receive(&cancel).unwrap().command, "getheaders");
                if index == 1 {
                    seen.send(()).unwrap();
                }
                peer.send("headers", &payload(index * 4, 4)).unwrap();
            }
            assert_eq!(peer.receive(&cancel).unwrap().command, "getheaders");
            peer.send("headers", &[0]).unwrap();
        });
        let cancel = AtomicBool::new(false);
        let peer = Peer::connect(address.parse().unwrap(), 0, &cancel).unwrap();
        let download = HeaderDownload::start(vec![peer], vec![genesis().block_hash()]);
        let Download::Batch { headers, .. } = download.next(&cancel).unwrap() else {
            panic!("missing first batch");
        };
        // The consumer has not validated or requested the second batch yet.
        second_request.recv_timeout(Duration::from_secs(2)).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut chain = HeaderChain::open(&dir.path().join("headers.dat"), &cancel).unwrap();
        chain.apply(&headers, &cancel).unwrap();
        let Download::Batch { headers, .. } = download.next(&cancel).unwrap() else {
            panic!("missing second batch");
        };
        chain.apply(&headers, &cancel).unwrap();
        assert_eq!(chain.height(), 8);
        assert!(matches!(
            download.next(&cancel).unwrap(),
            Download::Complete
        ));
        drop(download);
        server.join().unwrap();
    }

    #[test]
    fn stalled_peer_is_hedged_without_waiting_for_its_timeout() {
        let (release, stalled) = mpsc::channel();
        let (slow_address, slow_server) = crate::peer::mock_peer(move |mut peer| {
            assert_eq!(
                peer.receive(&AtomicBool::new(false)).unwrap().command,
                "getheaders"
            );
            stalled.recv_timeout(Duration::from_secs(5)).unwrap();
        });
        let (seen, request) = mpsc::channel();
        let (fast_address, fast_server) = crate::peer::mock_peer(move |mut peer| {
            let cancel = AtomicBool::new(false);
            assert_eq!(peer.receive(&cancel).unwrap().command, "getheaders");
            seen.send(()).unwrap();
            peer.send("headers", &payload(0, 8)).unwrap();
            assert_eq!(peer.receive(&cancel).unwrap().command, "getheaders");
            peer.send("headers", &[0]).unwrap();
        });
        let cancel = AtomicBool::new(false);
        let slow = Peer::connect(slow_address.parse().unwrap(), 0, &cancel).unwrap();
        let fast = Peer::connect(fast_address.parse().unwrap(), 0, &cancel).unwrap();
        let download = HeaderDownload::start(vec![slow, fast], vec![genesis().block_hash()]);
        // The alternate must be asked before the stalled request is released.
        request.recv_timeout(Duration::from_secs(2)).unwrap();
        let Download::Batch { headers, peer } = download.next(&cancel).unwrap() else {
            panic!("missing hedged batch");
        };
        assert_eq!(peer, fast_address.parse::<SocketAddr>().unwrap());
        assert_eq!(headers.len(), 8);
        let expected: Header =
            deserialize(&include_bytes!("../tests/fixtures/mainnet-4032.dat")[..80]).unwrap();
        assert_eq!(headers[0], expected);
        release.send(()).unwrap();
        assert!(matches!(
            download.next(&cancel).unwrap(),
            Download::Complete
        ));
        drop(download);
        slow_server.join().unwrap();
        fast_server.join().unwrap();
    }
}
