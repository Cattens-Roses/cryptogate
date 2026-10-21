//! Read-only Bitcoin P2P smoke test; never opens a vault or broadcasts.
use anyhow::Result;
use network_bitcoin::{
    chain::HeaderChain,
    compact_filters::{fetch_block, CompactFilters},
    peer::Peer,
    DEFAULT_MAX_PEERS,
};
use std::{sync::atomic::AtomicBool, time::Instant};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let explicit = args
        .first()
        .filter(|arg| arg.as_str() != "auto")
        .map(String::as_str);
    let full = args.iter().any(|arg| arg == "--full");
    let cancel = AtomicBool::new(false);
    let mut peers = Peer::discover_many(explicit, 0, DEFAULT_MAX_PEERS, &[], &cancel)?;
    println!(
        "Connected compact-filter peers: {}/{}",
        peers.len(),
        DEFAULT_MAX_PEERS
    );
    for peer in &peers {
        println!("{} height {}", peer.address, peer.height);
    }
    let dir = tempfile::tempdir()?;
    let mut chain = HeaderChain::open(&dir.path().join("headers.dat"), &cancel)?;
    let started = Instant::now();
    loop {
        let headers = peers[0].headers(&chain.locator(), &cancel)?;
        let count = headers.len();
        chain.apply(&headers, &cancel)?;
        if chain.height().is_multiple_of(100_000) {
            println!("Validated {} Bitcoin headers", chain.height());
        }
        if count < 2000 || (!full && chain.height() >= 40_000) {
            break;
        }
    }
    println!(
        "Validated {} Bitcoin headers in {:.2}s; minimum work reached: {}",
        chain.height(),
        started.elapsed().as_secs_f64(),
        chain.has_minimum_work()
    );
    if args.iter().any(|arg| arg == "--save-fixture") {
        let mut fixture = Vec::new();
        for height in 1..=4032 {
            fixture.extend(bitcoin::consensus::serialize(
                &chain.header(height).expect("fixture header"),
            ));
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mainnet-4032.dat");
        std::fs::write(path, fixture)?;
        println!(
            "Verified fixture block 4032: {}",
            chain.hash(4032).expect("fixture tip")
        );
    }
    let end = chain.height();
    let start = end.saturating_sub(255).max(1);
    let mut filters = CompactFilters::default();
    let batch = filters.download(&mut peers, &chain, start, end, explicit.is_some(), &cancel)?;
    let matched = batch.get(end)?.match_any(
        &chain.hash(end).expect("tip"),
        [b"probe unrelated script".as_slice()].into_iter(),
    )?;
    println!("Verified {} BIP158 filters and cross-checked BIP157 commitments; local test match: {matched}", end - start + 1);
    let block = fetch_block(&mut peers[0], chain.hash(end).expect("tip"), &cancel)?;
    println!(
        "Verified block {end} Merkle root: {} transactions",
        block.txdata.len()
    );
    Ok(())
}
