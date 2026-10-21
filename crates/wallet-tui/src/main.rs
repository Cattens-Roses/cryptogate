mod tui;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use network_bitcoin::Bitcoin;
use network_ethereum::Ethereum;
use network_litecoin::{Litecoin, DEFAULT_MAX_PEERS};
use std::{
    io::{self, IsTerminal, Write},
    path::PathBuf,
    sync::atomic::AtomicBool,
};
use wallet_core::{format_amount, vault::Vault, Network, NetworkFactory};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Chain {
    Litecoin,
    Bitcoin,
    Ethereum,
}
const AVAILABLE_NETWORKS: [Chain; 3] = [Chain::Litecoin, Chain::Bitcoin, Chain::Ethereum];

#[derive(Clone, Copy, Debug, ValueEnum)]
enum Selection {
    #[value(alias = "ltc")]
    Litecoin,
    #[value(alias = "btc")]
    Bitcoin,
    #[value(alias = "eth")]
    Ethereum,
    #[value(alias = "both")]
    All,
}
impl Selection {
    fn chains(self) -> Vec<Chain> {
        match self {
            Self::Litecoin => vec![Chain::Litecoin],
            Self::Bitcoin => vec![Chain::Bitcoin],
            Self::Ethereum => vec![Chain::Ethereum],
            Self::All => AVAILABLE_NETWORKS.to_vec(),
        }
    }
}

#[derive(Parser)]
#[command(version, about = "EngineCore — a modular Rust SPV wallet")]
struct Args {
    #[arg(long, default_value = "wallet-data", global = true)]
    data_dir: PathBuf,
    /// Select a network or all; omitted: choose interactively.
    #[arg(long, value_enum, global = true)]
    network: Option<Selection>,
    /// Trusted archival NODE_COMPACT_FILTERS peer (LTC host:9333, BTC host:8333).
    #[arg(long, global = true)]
    peer: Option<String>,
    /// Override the Litecoin peer when running multiple networks.
    #[arg(long, global = true)]
    litecoin_peer: Option<String>,
    /// Override the Bitcoin peer when running multiple networks.
    #[arg(long, global = true)]
    bitcoin_peer: Option<String>,
    /// Explicit Ethereum execution peer (`enode://…@ip:port`).
    #[arg(long, global = true)]
    ethereum_execution_peer: Option<String>,
    /// Explicit Ethereum consensus peer (`/ip4/…/tcp/…/p2p/<peer-id>`).
    #[arg(long, global = true)]
    ethereum_consensus_peer: Option<String>,
    /// Trusted Ethereum Beacon weak-subjectivity checkpoint root (32-byte hex).
    #[arg(long, global = true)]
    ethereum_checkpoint: Option<String>,
    /// Slot for `--ethereum-checkpoint`.
    #[arg(long, global = true)]
    ethereum_checkpoint_slot: Option<u64>,
    /// Maximum simultaneous peer connections per network.
    #[arg(long, default_value_t = DEFAULT_MAX_PEERS as u32, value_parser = clap::value_parser!(u32).range(1..=32), global = true)]
    max_peers: u32,
    /// Disable all peer connections; use cached, verified state only.
    #[arg(long, global = true)]
    offline: bool,
    /// First scan height for new network state; default: last 10,000 blocks at synced tip.
    #[arg(long, global = true)]
    birthday: Option<u32>,
    /// Observe new unconfirmed transactions via a separate P2P connection (extra traffic).
    #[arg(long, global = true)]
    mempool: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Clone, Subcommand)]
enum Command {
    /// Create an encrypted wallet; show its recovery mnemonic once.
    New,
    /// Restore a BIP39 mnemonic, entered through a hidden prompt.
    Restore,
    /// Open the terminal interface (default).
    Tui,
    /// Print the current receive address; --next issues a fresh address.
    Address {
        #[arg(long)]
        next: bool,
    },
    /// Show cached, proof-verified balances without connecting.
    Status,
    /// Synchronize headers and compact block filters, then exit.
    Sync,
}

fn password(prompt: &str) -> Result<Zeroizing<String>> {
    ensure_terminal()?;
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

fn ensure_terminal() -> Result<()> {
    if !io::stdin().is_terminal() {
        bail!("Use an interactive terminal for hidden wallet prompts");
    }
    Ok(())
}

fn create(args: &Args, restore: bool) -> Result<Vault> {
    let words = if restore {
        Some(password("Recovery mnemonic (hidden): ")?)
    } else {
        None
    };
    let pass = password("New wallet password (at least 10 characters): ")?;
    let confirm = password("Confirm password: ")?;
    if *pass != *confirm {
        bail!("Passwords do not match");
    }
    let (vault, mnemonic) =
        Vault::create(&args.data_dir, &pass, words.as_ref().map(|s| s.as_str()))?;
    if !restore {
        println!(
            "\nWrite these 24 recovery words down and keep them private:\n\n{}\n",
            mnemonic.as_str()
        );
        print!("Press Enter after saving your recovery words. ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
    }
    println!("Encrypted wallet saved to {}", args.data_dir.display());
    Ok(vault)
}

fn main() -> Result<()> {
    let args = Args::parse();
    if matches!(args.command, Some(Command::Sync)) && args.offline {
        bail!("sync requires network access; remove --offline");
    }
    if !matches!(args.command, Some(Command::New | Command::Restore))
        && args.peer.is_some()
        && !matches!(args.network, Some(Selection::Litecoin | Selection::Bitcoin))
    {
        bail!("--peer requires a single --network litecoin|bitcoin; for the picker or --network all use --litecoin-peer / --bitcoin-peer (Ethereum uses --ethereum-*-peer)");
    }
    if args.ethereum_checkpoint.is_some() != args.ethereum_checkpoint_slot.is_some() {
        bail!("Provide both --ethereum-checkpoint and --ethereum-checkpoint-slot, or neither");
    }
    if (args.ethereum_checkpoint.is_some()
        || args.ethereum_execution_peer.is_some()
        || args.ethereum_consensus_peer.is_some())
        && matches!(args.network, Some(Selection::Litecoin | Selection::Bitcoin))
    {
        bail!("Ethereum checkpoint/peer flags require --network ethereum, the picker, or --network all");
    }
    let vault = match &args.command {
        Some(Command::New) => {
            create(&args, false)?;
            return Ok(());
        }
        Some(Command::Restore) => {
            create(&args, true)?;
            return Ok(());
        }
        _ if !args.data_dir.join("vault.json").exists() => {
            if !matches!(args.command, None | Some(Command::Tui)) {
                bail!("No wallet found; run enginecore new or enginecore restore");
            }
            ensure_terminal()?;
            print!("No wallet found. [c]reate, [r]estore, or [q]uit: ");
            io::stdout().flush()?;
            let mut answer = String::new();
            io::stdin().read_line(&mut answer)?;
            match answer.trim().to_ascii_lowercase().as_str() {
                "c" => create(&args, false)?,
                "r" => create(&args, true)?,
                _ => return Ok(()),
            }
        }
        _ => Vault::open(&args.data_dir, &password("Wallet password: ")?)?,
    };
    let explicit = args.network.map(Selection::chains);
    match args.command.clone() {
        None | Some(Command::Tui) => {
            let chains = explicit.as_deref().unwrap_or(&AVAILABLE_NETWORKS);
            let setups = network_setups(&args, chains);
            let choose = explicit.is_none();
            tui::run(vault, setups, choose, args.offline)
        }
        Some(command) => {
            let chains = match explicit {
                Some(chains) => chains,
                None => choose_cli_networks()?,
            };
            let setups = network_setups(&args, &chains);
            let multiple = setups.len() > 1;
            let cancel = AtomicBool::new(false);
            // Each selected CLI backend also runs independently; a slow sync does
            // not prevent the other network from opening or making progress.
            std::thread::scope(|scope| -> Result<()> {
                let handles: Vec<_> = setups.into_iter().map(|setup| {
                    let cancel = &cancel;
                    let seed = vault.seed();
                    let command = &command;
                    scope.spawn(move || -> Result<()> {
                        eprintln!("{}: opening wallet and checking header cache…", setup.name);
                        let mut network = (setup.factory)(seed, cancel, &|message| eprintln!("{}: {message}", setup.name))?;
                        match command {
                            Command::Address { next } => {
                                let address = if *next { network.next_address()? } else { network.snapshot().address };
                                if multiple { println!("{}: {address}", setup.name); } else { println!("{address}"); }
                            }
                            Command::Sync => {
                                loop {
                                    let done = network.sync_step(cancel).with_context(|| format!("{} SPV sync failed; verified progress is saved", setup.name))?;
                                    let snapshot = network.snapshot();
                                    eprintln!("{}: headers={} scanned={} peer={}", setup.name, snapshot.height, snapshot.scanned, snapshot.peer);
                                    if done { break; }
                                }
                                show_status(network.as_ref());
                            }
                            Command::Status => show_status(network.as_ref()),
                            _ => unreachable!(),
                        }
                        Ok(())
                    })
                }).collect();
                let mut failures = Vec::new();
                for handle in handles {
                    match handle.join() {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => failures.push(format!("{error:#}")),
                        Err(_) => failures.push("Network worker panicked".into()),
                    }
                }
                if !failures.is_empty() {
                    bail!("{}", failures.join("\n"));
                }
                Ok(())
            })
        }
    }
}

fn choose_cli_networks() -> Result<Vec<Chain>> {
    ensure_terminal()?;
    loop {
        print!("Networks: [1] Litecoin  [2] Bitcoin  [3] Ethereum  [4] All  [q] quit: ");
        io::stdout().flush()?;
        let mut choice = String::new();
        if io::stdin().read_line(&mut choice)? == 0 {
            bail!("Network selection cancelled");
        }
        match choice.trim().to_ascii_lowercase().as_str() {
            "1" | "ltc" | "litecoin" => return Ok(Selection::Litecoin.chains()),
            "2" | "btc" | "bitcoin" => return Ok(Selection::Bitcoin.chains()),
            "3" | "eth" | "ethereum" => return Ok(Selection::Ethereum.chains()),
            "4" | "all" | "both" => return Ok(Selection::All.chains()),
            "q" => bail!("Network selection cancelled"),
            _ => eprintln!("Choose 1, 2, 3 or 4."),
        }
    }
}

fn network_setups(args: &Args, chains: &[Chain]) -> Vec<tui::NetworkSetup> {
    chains
        .iter()
        .map(|chain| {
            let directory = args.data_dir.clone();
            let birthday = args.birthday;
            let max_peers = args.max_peers as usize;
            let mempool = args.mempool;
            let (name, ticker, factory): (_, _, NetworkFactory) = match chain {
                Chain::Litecoin => {
                    let peer = args.litecoin_peer.clone().or_else(|| args.peer.clone());
                    (
                        "Litecoin",
                        "LTC",
                        Box::new(move |seed, cancel, progress| {
                            Ok(Box::new(Litecoin::open_with_progress(
                                seed,
                                &directory.join("litecoin-mainnet"),
                                network_litecoin::Options {
                                    peer,
                                    birthday,
                                    max_peers,
                                    mempool,
                                },
                                cancel,
                                progress,
                            )?))
                        }),
                    )
                }
                Chain::Bitcoin => {
                    let peer = args.bitcoin_peer.clone().or_else(|| args.peer.clone());
                    (
                        "Bitcoin",
                        "BTC",
                        Box::new(move |seed, cancel, progress| {
                            Ok(Box::new(Bitcoin::open_with_progress(
                                seed,
                                &directory.join("bitcoin-mainnet"),
                                network_bitcoin::Options {
                                    peer,
                                    birthday,
                                    max_peers,
                                    mempool,
                                },
                                cancel,
                                progress,
                            )?))
                        }),
                    )
                }
                Chain::Ethereum => {
                    let checkpoint = match (
                        args.ethereum_checkpoint.clone(),
                        args.ethereum_checkpoint_slot,
                    ) {
                        (Some(root), Some(slot)) => Some((root, slot)),
                        _ => None,
                    };
                    let execution_peer = args.ethereum_execution_peer.clone();
                    let consensus_peer = args.ethereum_consensus_peer.clone();
                    (
                        "Ethereum",
                        "ETH",
                        Box::new(move |seed, cancel, progress| {
                            progress("Opening Ethereum light client (Beacon + eth/snap P2P)…");
                            Ok(Box::new(Ethereum::open(
                                seed,
                                &directory.join("ethereum-mainnet"),
                                network_ethereum::Options {
                                    max_peers,
                                    execution_peer,
                                    consensus_peer,
                                    checkpoint,
                                },
                                cancel,
                            )?))
                        }),
                    )
                }
            };
            tui::NetworkSetup {
                name,
                ticker,
                factory,
            }
        })
        .collect()
}

fn show_status(network: &dyn Network) {
    let s = network.snapshot();
    let info = network.info();
    println!("{} mainnet\nReceive: {}\nVerified balance: {} {}\nSpendable: {} {}\nPending incoming: {} {}\nPending outgoing: {} {}\nMempool: {}\nHeaders: {}\nScanned: {}\nConnected peers: {}/{}\nTransactions: {}",
        info.name, s.address, format_amount(s.balance, info.decimals), info.ticker,
        format_amount(s.spendable, info.decimals), info.ticker, format_amount(s.pending_incoming, info.decimals), info.ticker, format_amount(s.pending_outgoing, info.decimals), info.ticker, s.mempool_status, s.height, s.scanned, s.connected_peers, s.max_peers, s.transactions.len());
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn birthday_is_optional_and_mempool_is_opt_in() {
        let defaults = Args::try_parse_from(["enginecore"]).unwrap();
        assert_eq!(defaults.birthday, None);
        assert!(!defaults.mempool);
        assert_eq!(defaults.max_peers, 3);
        let explicit =
            Args::try_parse_from(["enginecore", "--birthday", "1", "--mempool", "sync"]).unwrap();
        assert_eq!(explicit.birthday, Some(1));
        assert!(explicit.mempool);
    }

    #[test]
    fn omitted_network_opens_picker_and_explicit_selectors_support_all() {
        assert!(Args::try_parse_from(["enginecore"])
            .unwrap()
            .network
            .is_none());
        for network in ["bitcoin", "btc"] {
            let args =
                Args::try_parse_from(["enginecore", "--network", network, "--mempool", "status"])
                    .unwrap();
            assert!(matches!(args.network, Some(Selection::Bitcoin)));
            assert!(args.mempool);
        }
        for network in ["ethereum", "eth"] {
            let args = Args::try_parse_from([
                "enginecore",
                "--network",
                network,
                "--ethereum-checkpoint",
                "0x1111111111111111111111111111111111111111111111111111111111111111",
                "--ethereum-checkpoint-slot",
                "100",
                "status",
            ])
            .unwrap();
            assert!(matches!(args.network, Some(Selection::Ethereum)));
            assert_eq!(
                args.ethereum_checkpoint.as_deref(),
                Some("0x1111111111111111111111111111111111111111111111111111111111111111")
            );
            assert_eq!(args.ethereum_checkpoint_slot, Some(100));
        }
        let all = Args::try_parse_from(["enginecore", "--network", "all"]).unwrap();
        assert_eq!(all.network.unwrap().chains(), AVAILABLE_NETWORKS);
        assert!(Args::try_parse_from(["enginecore", "--network", "unknown"]).is_err());
    }

    #[test]
    fn shared_seed_keeps_network_addresses_and_state_separate() {
        let directory = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let seed = [55; 64];
        let btc_dir = directory.path().join("bitcoin-mainnet");
        let ltc_dir = directory.path().join("litecoin-mainnet");
        let eth_dir = directory.path().join("ethereum-mainnet");
        let mut btc = Bitcoin::open(
            &seed,
            &btc_dir,
            network_bitcoin::Options::default(),
            &cancel,
        )
        .unwrap();
        let ltc = Litecoin::open(
            &seed,
            &ltc_dir,
            network_litecoin::Options::default(),
            &cancel,
        )
        .unwrap();
        let eth = Ethereum::open(
            &seed,
            &eth_dir,
            network_ethereum::Options::default(),
            &cancel,
        )
        .unwrap();
        let btc_address = btc.snapshot().address;
        let ltc_address = ltc.snapshot().address;
        let eth_address = eth.snapshot().address;
        assert!(btc_address.starts_with("bc1q"));
        assert!(ltc_address.starts_with("ltc1q"));
        assert!(eth_address.starts_with("0x") && eth_address.len() == 42);
        assert_eq!(btc.info().ticker, "BTC");
        assert_eq!(ltc.info().ticker, "LTC");
        assert_eq!(eth.info().ticker, "ETH");
        assert_eq!(eth.info().decimals, 18);
        assert_ne!(btc.info().id, ltc.info().id);
        assert_ne!(btc.info().id, eth.info().id);
        let next = btc.next_address().unwrap();
        assert_ne!(btc_address, next);
        assert_eq!(ltc.snapshot().address, ltc_address);
        assert_eq!(eth.snapshot().address, eth_address);
        drop(btc);
        let btc = Bitcoin::open(
            &seed,
            &btc_dir,
            network_bitcoin::Options::default(),
            &cancel,
        )
        .unwrap();
        assert_eq!(btc.snapshot().address, next);
        // Wrong network state must be rejected even when its encrypted seed is the same.
        assert!(Bitcoin::open(
            &seed,
            &ltc_dir,
            network_bitcoin::Options::default(),
            &cancel
        )
        .is_err());
        assert!(Litecoin::open(
            &seed,
            &btc_dir,
            network_litecoin::Options::default(),
            &cancel
        )
        .is_err());
        assert!(Ethereum::open(
            &seed,
            &btc_dir,
            network_ethereum::Options::default(),
            &cancel
        )
        .is_err());
        assert_eq!(
            (
                btc.snapshot().balance,
                ltc.snapshot().balance,
                eth.snapshot().balance
            ),
            (0, 0, 0)
        );
    }
}
