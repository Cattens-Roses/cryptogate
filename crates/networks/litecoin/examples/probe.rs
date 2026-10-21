//! Read-only live compact-filter and stripped-block probe; no vault or broadcasts.
use anyhow::{ensure, Result};
use network_litecoin::{
    chain::HeaderChain,
    compact_filters::{fetch_block, CompactFilters},
    peer::Peer,
    DEFAULT_MAX_PEERS,
};
use std::sync::atomic::AtomicBool;
fn main() -> Result<()> {
    let cancel = AtomicBool::new(false);
    let explicit = std::env::args().nth(1).filter(|arg| arg != "auto");
    let mut peers = Peer::discover_many(explicit.as_deref(), 0, DEFAULT_MAX_PEERS, &[], &cancel)?;
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
    let headers = peers[0].headers(&chain.locator(), &cancel)?;
    chain.apply(&headers, &cancel)?;
    println!("Validated {} Litecoin headers", chain.height());
    let mut filters = CompactFilters::default();
    let batch = filters.download(
        &mut peers,
        &chain,
        1,
        chain.height().min(1000),
        explicit.is_some(),
        &cancel,
    )?;
    // Exercise the local Golomb-Rice decoder, without uploading the queried script.
    let matches = batch.get(1)?.match_any(
        &chain.hash(1).expect("first"),
        [b"unrelated script".as_slice()].into_iter(),
    )?;
    ensure!(!matches, "Unexpected test-script match");
    println!("Verified BIP157 header/checkpoint chains and 1,000 BIP158 filters");
    let block = fetch_block(&mut peers[0], chain.hash(1).expect("first"), &cancel)?;
    println!(
        "Verified stripped block 1 Merkle root: {} transactions",
        block.txdata.len()
    );
    // Optional public header cache allows exercising a post-MWEB block without a vault.
    if let Some(path) = std::env::args().nth(2) {
        use std::io::{Read, Seek, SeekFrom};
        let mut file = std::fs::File::open(path)?;
        file.seek(SeekFrom::End(-80))?;
        let mut raw = [0u8; 80];
        file.read_exact(&mut raw)?;
        let header: bitcoin::block::Header = bitcoin::consensus::deserialize(&raw)?;
        let recent = fetch_block(&mut peers[0], header.block_hash(), &cancel)?;
        println!(
            "Verified recent stripped block {} Merkle root: {} transactions",
            header.block_hash(),
            recent.txdata.len()
        );
    }
    Ok(())
}
