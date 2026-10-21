mod api;
mod banner;
mod config;
mod engine;
mod store;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "EngineCore payment API — shared SPV scan per currency, idle until invoices exist")]
struct Args {
    /// Path to config.json (see config.example.json).
    #[arg(long, default_value = "config.json")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    banner::print();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("payment_api=info".parse()?))
        .init();
    let args = Args::parse();
    let config = config::Config::load(&args.config)?;
    let listen = config.listen.clone();
    let engine = engine::Engine::open(config)?;
    engine.spawn_workers();
    let app = api::router(engine.clone());
    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    tracing::info!(%listen, "payment API listening · chains stay idle until /api/create/<currency>");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await?;
    engine.stop();
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
