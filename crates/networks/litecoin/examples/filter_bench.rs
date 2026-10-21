//! Read-only compact-filter throughput probe on a temporary validated header fixture.
use anyhow::Result;
use bitcoin::{bip32::Xpriv, NetworkKind};
use network_litecoin::{address, chain::HeaderChain, compact_filters::CompactFilters, peer::Peer};
use std::{sync::atomic::AtomicBool, time::Instant};
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let step: u32 = args.first().map_or(Ok(256), |arg| arg.parse())?;
    anyhow::ensure!((1..=1000).contains(&step), "Batch must be 1..1000");
    let cancel = AtomicBool::new(false);
    let explicit = args.get(1).filter(|arg| arg.as_str() != "auto");
    let mut peers = if let Some(explicit) = explicit {
        let mut peers = Vec::new();
        for address in explicit.split(',') {
            peers.push(Peer::connect(address.parse()?, 4032, &cancel)?);
        }
        anyhow::ensure!(peers.len() <= 3, "At most three peers");
        peers
    } else {
        Peer::discover_many(None, 4032, 3, &[], &cancel)?
    };
    println!(
        "Peers: {}",
        peers
            .iter()
            .map(|peer| peer.address.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("headers.dat");
    std::fs::write(&path, include_bytes!("../tests/fixtures/mainnet-4032.dat"))?;
    let chain = HeaderChain::open(&path, &cancel)?;
    let master = Xpriv::new_master(NetworkKind::Main, &[0; 64])?;
    let scripts = (0..40)
        .map(|index| address::derive(&master, index >= 20, index % 20).map(|(_, script, _)| script))
        .collect::<Result<Vec<_>>>()?;
    let mut compact = CompactFilters::default();
    let started = Instant::now();
    let mut matches = 0;
    for start in (1..=4000).step_by(step as usize) {
        let end = (start + step - 1).min(4000);
        let mut batch =
            compact.download(&mut peers, &chain, start, end, explicit.is_some(), &cancel)?;
        batch.match_scripts(
            &scripts
                .iter()
                .map(|script| script.as_bytes())
                .collect::<Vec<_>>(),
        )?;
        for height in start..=end {
            matches += usize::from(batch.matched(height)?);
        }
    }
    println!("4000 verified filters, batch {step}, {} peers: {:.3}s, {:.0} filters/s, {matches} candidate blocks", peers.len(), started.elapsed().as_secs_f64(), 4000.0 / started.elapsed().as_secs_f64());
    Ok(())
}
