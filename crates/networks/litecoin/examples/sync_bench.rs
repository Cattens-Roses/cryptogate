//! Read-only live header sync in a temporary, throwaway wallet directory.
use anyhow::Result;
use network_litecoin::{Litecoin, Options};
use std::{sync::atomic::AtomicBool, time::Instant};
use wallet_core::Network;

fn main() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let cancel = AtomicBool::new(false);
    let options = Options {
        peer: std::env::args().nth(1),
        ..Options::default()
    };
    let mut wallet = Litecoin::open(&[42; 64], directory.path(), options, &cancel)?;
    let started = Instant::now();
    let mut transfer_started = None;
    loop {
        wallet.sync_step(&cancel)?;
        let snapshot = wallet.snapshot();
        if snapshot.height > 0 && transfer_started.is_none() {
            transfer_started = Some(Instant::now());
        }
        println!(
            "headers={} peers={}/{} elapsed={:.2}s",
            snapshot.height,
            snapshot.connected_peers,
            snapshot.max_peers,
            started.elapsed().as_secs_f64()
        );
        if snapshot.height >= 20_000 {
            break;
        }
    }
    println!(
        "18,000 additional headers after first batch: {:.2}s",
        transfer_started
            .expect("headers received")
            .elapsed()
            .as_secs_f64()
    );
    Ok(())
}
