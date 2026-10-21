use anyhow::{bail, ensure, Context, Result};
use bitcoin::{
    block::Header,
    consensus::{encode::VarInt, serialize, Decodable},
    hashes::{sha256d, Hash},
    p2p::{address::Address, message_network::VersionMessage, ServiceFlags},
    BlockHash,
};
use rand::{seq::SliceRandom, Rng};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const MAGIC: [u8; 4] = [0xfb, 0xc0, 0xb6, 0xdb];
const MAX_PAYLOAD: usize = 4_000_000;
const SEEDS: &[&str] = &[
    "seed-a.litecoin.loshan.co.uk",
    "dnsseed.thrasher.io",
    "dnsseed.litecointools.com",
    "dnsseed.ltcpool.org",
];

pub struct WireMessage {
    pub command: String,
    pub payload: Vec<u8>,
}

pub struct Peer {
    stream: TcpStream,
    incoming: Vec<u8>,
    pub address: SocketAddr,
    pub height: u32,
}

impl Peer {
    pub fn discover(explicit: Option<&str>, height: u32, cancel: &AtomicBool) -> Result<Self> {
        Ok(Self::discover_many(explicit, height, 1, &[], cancel)?.remove(0))
    }

    /// Dial no more than the available slots concurrently; only completed handshakes count.
    pub fn discover_many(
        explicit: Option<&str>,
        height: u32,
        slots: usize,
        exclude: &[SocketAddr],
        cancel: &AtomicBool,
    ) -> Result<Vec<Self>> {
        ensure!(
            (1..=32).contains(&slots),
            "Peer slots must be between 1 and 32"
        );
        let mut addresses = Vec::new();
        if let Some(peer) = explicit {
            addresses.extend(
                peer.to_socket_addrs()
                    .context("Resolve --peer as host:port")?,
            );
        } else {
            let mut seeds = SEEDS.to_vec();
            seeds.shuffle(&mut rand::thread_rng());
            for seed in seeds {
                if cancel.load(Ordering::Relaxed) {
                    bail!("Cancelled");
                }
                // DNS seed service-bit query: NODE_NETWORK | NODE_COMPACT_FILTERS.
                let filtered = format!("x41.{seed}");
                let found = (filtered.as_str(), 9333)
                    .to_socket_addrs()
                    .or_else(|_| (seed, 9333).to_socket_addrs());
                if let Ok(found) = found {
                    addresses.extend(found);
                }
            }
        }
        addresses.sort_unstable();
        addresses.dedup();
        addresses.retain(|address| !exclude.contains(address));
        addresses.shuffle(&mut rand::thread_rng());
        // Mix address families so an unavailable IPv6 route cannot occupy every dial slot.
        let (v4, v6): (Vec<_>, Vec<_>) = addresses.into_iter().partition(SocketAddr::is_ipv4);
        let mut candidates = Vec::new();
        for index in 0..v4.len().max(v6.len()) {
            if let Some(address) = v4.get(index) {
                candidates.push(*address);
            }
            if let Some(address) = v6.get(index) {
                candidates.push(*address);
            }
        }
        candidates.truncate(48);
        Self::connect_candidates(&candidates, height, slots, cancel)
    }

    pub(crate) fn connect_candidates(
        addresses: &[SocketAddr],
        height: u32,
        slots: usize,
        cancel: &AtomicBool,
    ) -> Result<Vec<Self>> {
        ensure!(
            (1..=32).contains(&slots),
            "Peer slots must be between 1 and 32"
        );
        let stop = AtomicBool::new(false);
        let cursor = AtomicUsize::new(0);
        let (sender, receiver) = mpsc::channel();
        let mut peers = Vec::new();
        let mut errors = Vec::new();
        std::thread::scope(|scope| {
            for _ in 0..slots.min(addresses.len()) {
                let sender = sender.clone();
                let cursor = &cursor;
                let stop = &stop;
                scope.spawn(move || loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let Some(&address) = addresses.get(cursor.fetch_add(1, Ordering::Relaxed))
                    else {
                        break;
                    };
                    match Self::connect(address, height, stop) {
                        Ok(peer) => {
                            let _ = sender.send(Ok(peer));
                            break;
                        }
                        Err(error) => {
                            let _ = sender.send(Err(format!("{address}: {error:#}")));
                        }
                    }
                });
            }
            drop(sender);
            let deadline = Instant::now() + Duration::from_secs(15);
            while Instant::now() < deadline && !cancel.load(Ordering::Relaxed) {
                match receiver.recv_timeout(Duration::from_millis(100)) {
                    Ok(Ok(peer)) => peers.push(peer),
                    Ok(Err(error)) => errors.push(error),
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
                if peers.len() == slots {
                    break;
                }
            }
            stop.store(true, Ordering::Relaxed);
        });
        if cancel.load(Ordering::Relaxed) {
            bail!("Cancelled");
        }
        if peers.is_empty() {
            bail!(
                "No reachable archival NODE_COMPACT_FILTERS peer. Try --peer host:9333. {}",
                errors
                    .last()
                    .map(String::as_str)
                    .unwrap_or("No new peer addresses available")
            );
        }
        Ok(peers)
    }

    pub fn connect(address: SocketAddr, height: u32, cancel: &AtomicBool) -> Result<Self> {
        Self::connect_with_relay(address, height, cancel, false)
    }

    pub(crate) fn connect_relay(
        address: SocketAddr,
        height: u32,
        cancel: &AtomicBool,
    ) -> Result<Self> {
        Self::connect_with_relay(address, height, cancel, true)
    }

    fn connect_with_relay(
        address: SocketAddr,
        height: u32,
        cancel: &AtomicBool,
        relay: bool,
    ) -> Result<Self> {
        let stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
            .context("TCP connection failed")?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut peer = Self {
            stream,
            incoming: Vec::new(),
            address,
            height: 0,
        };
        let nonce: u64 = rand::thread_rng().gen();
        let mut version = VersionMessage::new(
            ServiceFlags::NONE,
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
            Address::new(&address, ServiceFlags::NONE),
            Address::new(&"0.0.0.0:0".parse()?, ServiceFlags::NONE),
            nonce,
            "/enginecore:0.1.0/".into(),
            height as i32,
        );
        version.version = 70015;
        version.relay = relay;
        peer.send("version", &serialize(&version))?;
        let mut got_version = false;
        let mut got_verack = false;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !got_version || !got_verack {
            let message = peer
                .receive_until(cancel, deadline)
                .context("Litecoin version/verack handshake failed")?;
            match message.command.as_str() {
                "version" => {
                    ensure!(!got_version, "Duplicate version message");
                    // Litecoin can append version extensions; decode the common prefix.
                    let remote = VersionMessage::consensus_decode(&mut message.payload.as_slice())?;
                    ensure!(
                        remote.version >= 70015 && remote.nonce != nonce,
                        "Incompatible peer"
                    );
                    ensure!(
                        remote.services.has(ServiceFlags::COMPACT_FILTERS)
                            && remote.services.has(ServiceFlags::NETWORK),
                        "Peer does not serve archival BIP157 compact filters"
                    );
                    peer.height = remote.start_height.max(0) as u32;
                    peer.send("verack", &[])?;
                    got_version = true;
                }
                "verack" => {
                    ensure!(message.payload.is_empty(), "Malformed verack");
                    got_verack = true;
                }
                "ping" => peer.pong(&message.payload)?,
                _ => {}
            }
        }
        peer.heartbeat(cancel)
            .context("Peer did not respond after the handshake")?;
        Ok(peer)
    }

    /// Keep standby connections responsive and remove dead sockets from the peer count.
    pub fn heartbeat(&mut self, cancel: &AtomicBool) -> Result<()> {
        let nonce: u64 = rand::random();
        self.send("ping", &nonce.to_le_bytes())?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let message = self.receive_until(cancel, deadline)?;
            match message.command.as_str() {
                "pong" if message.payload == nonce.to_le_bytes() => return Ok(()),
                "ping" => self.pong(&message.payload)?,
                _ => {}
            }
        }
    }

    pub fn send(&mut self, command: &str, payload: &[u8]) -> Result<()> {
        self.stream.write_all(&frame(command, payload)?)?;
        Ok(())
    }

    pub fn receive(&mut self, cancel: &AtomicBool) -> Result<WireMessage> {
        self.receive_until(cancel, Instant::now() + Duration::from_secs(15))
    }

    /// An idle poll is normal; partial frames remain buffered across polling deadlines.
    pub fn poll(&mut self, cancel: &AtomicBool, deadline: Instant) -> Result<Option<WireMessage>> {
        loop {
            if cancel.load(Ordering::Relaxed) {
                bail!("Cancelled");
            }
            if self.incoming.len() >= 24 {
                let header: [u8; 24] = self.incoming[..24].try_into()?;
                let (command, length) = parse_frame_header(&header)?;
                if self.incoming.len() >= 24 + length {
                    let payload = self.incoming[24..24 + length].to_vec();
                    ensure!(
                        sha256d::Hash::hash(&payload).to_byte_array()[..4] == header[20..24],
                        "Message checksum mismatch"
                    );
                    self.incoming.drain(..24 + length);
                    return Ok(Some(WireMessage { command, payload }));
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            self.stream
                .set_read_timeout(Some(remaining.min(Duration::from_millis(250))))?;
            let mut chunk = [0u8; 16_384];
            match self.stream.read(&mut chunk) {
                Ok(0) => bail!("Peer closed the connection"),
                Ok(n) => self.incoming.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub fn receive_until(&mut self, cancel: &AtomicBool, deadline: Instant) -> Result<WireMessage> {
        self.poll(cancel, deadline)?
            .context("Peer response timed out")
    }

    pub fn pong(&mut self, payload: &[u8]) -> Result<()> {
        ensure!(payload.len() == 8, "Malformed ping");
        self.send("pong", payload)
    }

    pub fn headers(&mut self, locator: &[BlockHash], cancel: &AtomicBool) -> Result<Vec<Header>> {
        let mut request = 70015u32.to_le_bytes().to_vec();
        request.extend(serialize(&locator.to_vec()));
        request.extend([0; 32]);
        self.send("getheaders", &request)?;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let message = self.receive_until(cancel, deadline)?;
            match message.command.as_str() {
                "headers" => return parse_headers(&message.payload),
                "ping" => self.pong(&message.payload)?,
                "reject" => bail!("Peer rejected getheaders"),
                _ => {}
            }
        }
    }
}

pub fn frame(command: &str, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(
        !command.is_empty()
            && command.len() <= 12
            && command
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
        "Invalid message command"
    );
    ensure!(payload.len() <= MAX_PAYLOAD, "Oversized P2P message");
    let mut frame = Vec::with_capacity(24 + payload.len());
    frame.extend(MAGIC);
    let mut name = [0; 12];
    name[..command.len()].copy_from_slice(command.as_bytes());
    frame.extend(name);
    frame.extend((payload.len() as u32).to_le_bytes());
    frame.extend(&sha256d::Hash::hash(payload).to_byte_array()[..4]);
    frame.extend(payload);
    Ok(frame)
}

pub fn parse_frame_header(header: &[u8; 24]) -> Result<(String, usize)> {
    ensure!(header[..4] == MAGIC, "Wrong network magic");
    let command_bytes = &header[4..16];
    let length = command_bytes.iter().position(|b| *b == 0).unwrap_or(12);
    ensure!(
        length > 0
            && command_bytes[length..].iter().all(|b| *b == 0)
            && command_bytes[..length]
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
        "Invalid command padding"
    );
    let payload_len = u32::from_le_bytes(header[16..20].try_into()?) as usize;
    ensure!(payload_len <= MAX_PAYLOAD, "Oversized peer payload");
    Ok((
        std::str::from_utf8(&command_bytes[..length])?.to_owned(),
        payload_len,
    ))
}

pub fn parse_headers(payload: &[u8]) -> Result<Vec<Header>> {
    let mut data = payload;
    let count = VarInt::consensus_decode(&mut data)?.0;
    ensure!(count <= 2000, "Too many headers");
    let mut headers = Vec::with_capacity(count as usize);
    for _ in 0..count {
        headers.push(Header::consensus_decode(&mut data)?);
        ensure!(
            VarInt::consensus_decode(&mut data)?.0 == 0,
            "Nonzero header transaction count"
        );
    }
    ensure!(data.is_empty(), "Trailing header bytes");
    Ok(headers)
}

#[cfg(test)]
pub(crate) fn mock_peer(
    handler: impl FnOnce(Peer) + Send + 'static,
) -> (String, std::thread::JoinHandle<()>) {
    mock_peer_with_relay(false, handler)
}

#[cfg(test)]
pub(crate) fn mock_peer_with_relay(
    relay: bool,
    handler: impl FnOnce(Peer) + Send + 'static,
) -> (String, std::thread::JoinHandle<()>) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (stream, remote) = listener.accept().unwrap();
        let mut server = Peer {
            stream,
            incoming: Vec::new(),
            address: remote,
            height: 6,
        };
        let cancel = AtomicBool::new(false);
        let request = server.receive(&cancel).unwrap();
        assert_eq!(request.command, "version");
        let client: VersionMessage = bitcoin::consensus::deserialize(&request.payload).unwrap();
        assert_eq!(client.services, ServiceFlags::NONE);
        assert_eq!(client.relay, relay);
        let services = ServiceFlags::NETWORK | ServiceFlags::COMPACT_FILTERS;
        let mut response = VersionMessage::new(
            services,
            client.timestamp,
            client.sender,
            client.receiver,
            client.nonce.wrapping_add(1),
            "/mock-litecoin/".into(),
            6,
        );
        response.version = 70015;
        server.send("version", &serialize(&response)).unwrap();
        server.send("verack", &[]).unwrap();
        assert_eq!(server.receive(&cancel).unwrap().command, "verack");
        let ping = server.receive(&cancel).unwrap();
        assert_eq!(ping.command, "ping");
        server.send("pong", &ping.payload).unwrap();
        handler(server);
    });
    (address.to_string(), handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing_limits_and_network_isolation() {
        let bytes = frame("ping", &[42; 8]).unwrap();
        let header: [u8; 24] = bytes[..24].try_into().unwrap();
        assert_eq!(parse_frame_header(&header).unwrap(), ("ping".into(), 8));
        let mut wrong = header;
        wrong[0] = 0xf9;
        assert!(parse_frame_header(&wrong).is_err());
        let mut oversized = header;
        oversized[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_frame_header(&oversized).is_err());
        assert!(parse_headers(&[0xfd, 0xd1, 0x07]).is_err());
        assert!(parse_headers(&[0, 1]).is_err());
    }
    #[test]
    fn mock_litecoin_handshake_headers_and_ping() {
        let fixture = include_bytes!("../tests/fixtures/mainnet-4032.dat");
        let (address, server) = mock_peer(move |mut peer| {
            let cancel = AtomicBool::new(false);
            assert_eq!(peer.receive(&cancel).unwrap().command, "getheaders");
            peer.send("ping", &42u64.to_le_bytes()).unwrap();
            let pong = peer.receive(&cancel).unwrap();
            assert_eq!(pong.command, "pong");
            assert_eq!(pong.payload, 42u64.to_le_bytes());
            let mut payload = vec![8];
            for raw in fixture[..80 * 8].chunks_exact(80) {
                payload.extend(raw);
                payload.push(0);
            }
            peer.send("headers", &payload).unwrap();
        });
        let cancel = AtomicBool::new(false);
        let mut peer = Peer::connect(address.parse().unwrap(), 0, &cancel).unwrap();
        let headers = peer
            .headers(&[crate::chain::genesis().block_hash()], &cancel)
            .unwrap();
        assert_eq!(headers.len(), 8);
        assert_eq!(
            headers[0].prev_blockhash,
            crate::chain::genesis().block_hash()
        );
        server.join().unwrap();
    }

    #[test]
    fn peer_limit_does_not_open_an_extra_connection() {
        let (address, server) = mock_peer(|mut peer| {
            let cancel = AtomicBool::new(false);
            let ping = peer.receive(&cancel).unwrap();
            assert_eq!(ping.command, "ping");
            peer.send("pong", &ping.payload).unwrap();
        });
        let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        unused.set_nonblocking(true).unwrap();
        let candidates = [address.parse().unwrap(), unused.local_addr().unwrap()];
        let cancel = AtomicBool::new(false);
        let mut peers = Peer::connect_candidates(&candidates, 0, 1, &cancel).unwrap();
        assert_eq!(peers.len(), 1);
        peers[0].heartbeat(&cancel).unwrap();
        assert_eq!(
            unused.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(Peer::connect_candidates(&candidates, 0, 0, &cancel).is_err());
        server.join().unwrap();
    }
}
