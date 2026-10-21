//! Benchmark a COPY of public headers with a throwaway cache key. Never reads a vault.
use anyhow::Result;
use network_litecoin::chain::HeaderChain;
use std::{fs, sync::atomic::AtomicBool, time::Instant};

fn main() -> Result<()> {
    let source = std::env::args().nth(1);
    let limit: usize = std::env::args()
        .nth(2)
        .map(|n| n.parse())
        .transpose()?
        .unwrap_or(usize::MAX);
    let mut headers = if let Some(source) = source {
        fs::read(source)?
    } else {
        include_bytes!("../tests/fixtures/mainnet-4032.dat").to_vec()
    };
    headers.truncate(headers.len().min(limit.saturating_mul(80)));
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("headers.dat");
    fs::write(&path, headers)?;
    let seed = [42; 64];
    let cancel = AtomicBool::new(false);
    for label in ["First verification", "Authenticated restart"] {
        let started = Instant::now();
        let chain = HeaderChain::open_authenticated(&path, &seed, &cancel, &|_| {})?;
        println!(
            "{label}: {} headers, {:.3}s; {} reused, {} Scrypt checks",
            chain.height(),
            started.elapsed().as_secs_f64(),
            chain.cache_load_stats().authenticated_headers,
            chain.cache_load_stats().validated_headers
        );
    }
    Ok(())
}
