//! Optional, best-effort relay observer. No Bloom filters or mempool dump requests.
use crate::peer::Peer;
use bitcoin::{
    consensus::{deserialize, serialize},
    p2p::message_blockdata::Inventory,
    OutPoint, ScriptBuf, Transaction, Txid,
};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Default)]
pub(crate) struct Watch {
    pub scripts: BTreeSet<ScriptBuf>,
    pub outpoints: BTreeSet<OutPoint>,
}

pub(crate) struct Mempool {
    pub address: SocketAddr,
    pub height: u32,
    watch: Arc<Mutex<Watch>>,
    stop: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    receiver: Receiver<Vec<u8>>,
    worker: Option<JoinHandle<()>>,
}

impl Mempool {
    /// `peer` must have negotiated relay=true in its initial version message.
    pub fn start(mut peer: Peer, watch: Watch) -> Self {
        let address = peer.address;
        let height = peer.height;
        let watch = Arc::new(Mutex::new(watch));
        let stop = Arc::new(AtomicBool::new(false));
        let connected = Arc::new(AtomicBool::new(true));
        // Bounded to 16 * 400 kB even while header validation occupies the wallet.
        let (sender, receiver) = mpsc::sync_channel(16);
        let (thread_watch, thread_stop, thread_connected) =
            (watch.clone(), stop.clone(), connected.clone());
        let worker = thread::spawn(move || {
            let mut requested: BTreeMap<Txid, Instant> = BTreeMap::new();
            let mut seen = VecDeque::new();
            let mut next_ping = Instant::now() + Duration::from_secs(30);
            let mut ping: Option<(u64, Instant)> = None;
            let mut run = || -> anyhow::Result<()> {
                while !thread_stop.load(Ordering::Relaxed) {
                    requested.retain(|_, time| time.elapsed() < Duration::from_secs(30));
                    anyhow::ensure!(
                        !ping.is_some_and(|(_, sent)| sent.elapsed() > Duration::from_secs(10)),
                        "Relay heartbeat timed out"
                    );
                    if Instant::now() >= next_ping {
                        let nonce = rand::random::<u64>();
                        peer.send("ping", &nonce.to_le_bytes())?;
                        ping = Some((nonce, Instant::now()));
                        next_ping = Instant::now() + Duration::from_secs(30);
                    }
                    let Some(message) =
                        peer.poll(&thread_stop, Instant::now() + Duration::from_millis(250))?
                    else {
                        continue;
                    };
                    match message.command.as_str() {
                        "ping" => peer.pong(&message.payload)?,
                        "pong"
                            if ping.is_some_and(|(nonce, _)| {
                                message.payload == nonce.to_le_bytes()
                            }) =>
                        {
                            ping = None;
                        }
                        "inv" => {
                            let inventory: Vec<Inventory> = deserialize(&message.payload)?;
                            anyhow::ensure!(inventory.len() <= 50_000, "Oversized relay inventory");
                            let mut fetch = Vec::new();
                            for item in inventory {
                                if let Inventory::Transaction(id) = item {
                                    if requested.len() < 512
                                        && !requested.contains_key(&id)
                                        && !seen.contains(&id)
                                    {
                                        requested.insert(id, Instant::now());
                                        // MSG_TX requests Litecoin's stripped transparent transaction.
                                        fetch.push(Inventory::Transaction(id));
                                    }
                                }
                            }
                            if !fetch.is_empty() {
                                peer.send("getdata", &serialize(&fetch))?;
                            }
                        }
                        "tx" if message.payload.len() <= 400_000 => {
                            let Ok(tx) = deserialize::<Transaction>(&message.payload) else {
                                continue;
                            };
                            let id = tx.compute_txid();
                            if requested.remove(&id).is_none() {
                                continue;
                            }
                            seen.push_back(id);
                            if seen.len() > 4096 {
                                seen.pop_front();
                            }
                            let relevant = {
                                let watch = thread_watch.lock().expect("relay watch mutex");
                                tx.output
                                    .iter()
                                    .any(|output| watch.scripts.contains(&output.script_pubkey))
                                    || tx.input.iter().any(|input| {
                                        watch.outpoints.contains(&input.previous_output)
                                    })
                            };
                            if relevant {
                                let _ = sender.try_send(message.payload);
                            }
                        }
                        "notfound" => {
                            if let Ok(items) = deserialize::<Vec<Inventory>>(&message.payload) {
                                for item in items {
                                    if let Inventory::Transaction(id) = item {
                                        requested.remove(&id);
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(())
            };
            let _ = run();
            thread_connected.store(false, Ordering::Relaxed);
        });
        Self {
            address,
            height,
            watch,
            stop,
            connected,
            receiver,
            worker: Some(worker),
        }
    }

    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }
    pub fn update(&self, watch: Watch) {
        *self.watch.lock().expect("relay watch mutex") = watch;
    }
    pub fn drain(&self) -> Vec<Vec<u8>> {
        self.receiver.try_iter().collect()
    }
}

impl Drop for Mempool {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::{absolute, transaction::Version, Amount, Sequence, TxIn, TxOut, Witness};

    #[test]
    fn relay_fetches_announced_transactions_and_filters_locally_without_bloom() {
        let make = |index: u8, script: u8| Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([index; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![script]),
            }],
        };
        let incoming = make(1, 0x51);
        let irrelevant = make(2, 0x52);
        let later = make(3, 0x52);
        let mut outgoing = make(4, 0x53);
        outgoing.input[0].previous_output = OutPoint {
            txid: incoming.compute_txid(),
            vout: 0,
        };
        let expected = [
            serialize(&incoming),
            serialize(&later),
            serialize(&outgoing),
        ];
        let incoming_id = incoming.compute_txid();
        let (stage, staged) = mpsc::channel();
        let (advance, gate) = mpsc::channel();
        let (address, server) = crate::peer::mock_peer_with_relay(true, move |mut peer| {
            let cancel = AtomicBool::new(false);
            // Unrequested traffic must not produce wallet observations.
            peer.send("tx", &serialize(&incoming)).unwrap();
            for transactions in [vec![incoming, irrelevant], vec![later, outgoing]] {
                let items: Vec<_> = transactions
                    .iter()
                    .map(|tx| Inventory::Transaction(tx.compute_txid()))
                    .collect();
                let mut duplicates = items.clone();
                duplicates.push(items[0]);
                peer.send("inv", &serialize(&duplicates)).unwrap();
                let request = peer.receive(&cancel).unwrap();
                assert_eq!(request.command, "getdata");
                assert_eq!(
                    deserialize::<Vec<Inventory>>(&request.payload).unwrap(),
                    items
                );
                for tx in transactions {
                    peer.send("tx", &serialize(&tx)).unwrap();
                }
                peer.send("ping", &42u64.to_le_bytes()).unwrap();
                assert_eq!(peer.receive(&cancel).unwrap().command, "pong");
                stage.send(()).unwrap();
                gate.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            assert!(peer.receive(&cancel).is_err());
        });
        let peer =
            Peer::connect_relay(address.parse().unwrap(), 0, &AtomicBool::new(false)).unwrap();
        let observer = Mempool::start(
            peer,
            Watch {
                scripts: [ScriptBuf::from_bytes(vec![0x51])].into(),
                outpoints: BTreeSet::new(),
            },
        );
        staged.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(observer.drain(), vec![expected[0].clone()]);
        assert!(observer.connected());
        observer.update(Watch {
            scripts: [ScriptBuf::from_bytes(vec![0x52])].into(),
            outpoints: [OutPoint {
                txid: incoming_id,
                vout: 0,
            }]
            .into(),
        });
        advance.send(()).unwrap();
        staged.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(observer.drain(), expected[1..]);
        advance.send(()).unwrap();
        drop(observer);
        server.join().unwrap();
    }
}
