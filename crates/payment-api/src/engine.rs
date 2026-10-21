use crate::{
    config::{Config, NetworkConfig},
    store::{Invoice, InvoiceStatus, InvoiceTx, Store},
};
use anyhow::{bail, Result};
use network_bitcoin::Bitcoin;
use network_ethereum::Ethereum;
use network_litecoin::Litecoin;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use wallet_core::{format_amount, vault::Vault, Network};
use zeroize::Zeroizing;

pub struct Engine {
    config: Config,
    seed: Zeroizing<[u8; 64]>,
    data_dir: PathBuf,
    store: Mutex<Store>,
    address_lock: Mutex<()>,
    cancel: AtomicBool,
}

impl Engine {
    pub fn open(config: Config) -> Result<Arc<Self>> {
        let data_dir = PathBuf::from(&config.data_dir);
        std::fs::create_dir_all(&data_dir)?;
        let vault_dir = data_dir.join("vault");
        let password = Zeroizing::new(config.vault_password.clone());
        let vault = if vault_dir.join("vault.json").exists() {
            Vault::open(&vault_dir, &password)?
        } else {
            let (vault, mnemonic) = Vault::create(&vault_dir, &password, None)?;
            tracing::warn!(
                "Created payment vault — back up this mnemonic offline: {}",
                mnemonic.as_str()
            );
            vault
        };
        let seed = Zeroizing::new(*vault.seed());
        drop(vault);
        let store = Store::open(&data_dir.join("state"))?;
        Ok(Arc::new(Self {
            config,
            seed,
            data_dir,
            store: Mutex::new(store),
            address_lock: Mutex::new(()),
            cancel: AtomicBool::new(false),
        }))
    }

    pub fn check_api_key(&self, provided: Option<&str>) -> bool {
        let Some(provided) = provided else {
            return false;
        };
        let expected = self.config.api_key.as_bytes();
        let got = provided.as_bytes();
        if expected.len() != got.len() {
            return false;
        }
        expected
            .iter()
            .zip(got.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    pub fn create_invoice(&self, currency: &str, expected_amount: Option<u128>) -> Result<Invoice> {
        let currency = currency.to_ascii_lowercase();
        let _ = self.config.network(&currency)?;
        let address = self.allocate_address(&currency)?;
        let invoice = self.store.lock().expect("store lock").create(
            &currency,
            address,
            expected_amount,
            self.config.max_payment_secs,
        )?;
        tracing::info!(
            id = %invoice.id,
            currency = %currency,
            address = %invoice.address,
            expires_unix = invoice.expires_unix,
            "invoice created"
        );
        Ok(invoice)
    }

    pub fn status(&self, id: &str) -> Result<Invoice> {
        self.store.lock().expect("store lock").get(id)
    }

    pub fn payend(&self, id: &str) -> Result<Invoice> {
        let invoice = self.store.lock().expect("store lock").payend(id)?;
        tracing::info!(
            id = %invoice.id,
            status = ?invoice.status,
            received = invoice.received,
            "payment window closed via payend"
        );
        Ok(invoice)
    }

    pub fn stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    pub fn spawn_workers(self: &Arc<Self>) {
        for (id, network) in &self.config.networks {
            if !network.enabled {
                continue;
            }
            let currency = id.to_ascii_lowercase();
            let engine = Arc::clone(self);
            std::thread::Builder::new()
                .name(format!("pay-{currency}"))
                .spawn(move || {
                    if let Err(error) = engine.currency_loop(&currency) {
                        tracing::error!(
                            currency = %currency,
                            error = %format!("{error:#}"),
                            "currency worker stopped"
                        );
                    }
                })
                .expect("spawn currency worker");
        }
    }

    fn allocate_address(&self, currency: &str) -> Result<String> {
        let _guard = self.address_lock.lock().expect("address lock");
        let cancel = AtomicBool::new(false);
        let mut wallet = open_wallet(
            currency,
            &self.seed,
            &self.data_dir,
            self.config.network(currency)?,
            &cancel,
        )?;
        let address = wallet.next_address()?;
        wallet.disconnect();
        Ok(address)
    }

    fn currency_loop(&self, currency: &str) -> Result<()> {
        let network_cfg = self.config.network(currency)?.clone();
        let mut wallet: Option<Box<dyn Network>> = None;
        let mut idle_since: Option<Instant> = None;
        let mut reconnect_attempt: u32 = 0;
        while !self.cancel.load(Ordering::Relaxed) {
            let active = self.store.lock().expect("store lock").any_active(currency);
            if !active {
                if let Some(mut live) = wallet.take() {
                    live.disconnect();
                    tracing::info!(currency, "no active invoices — disconnected");
                }
                idle_since = None;
                reconnect_attempt = 0;
                std::thread::sleep(Duration::from_millis(400));
                continue;
            }

            if wallet.is_none() {
                let _guard = self.address_lock.lock().expect("address lock");
                if reconnect_attempt == 0 {
                    tracing::info!(currency, "active invoice — starting shared chain scanner");
                } else {
                    tracing::info!(
                        currency,
                        attempt = reconnect_attempt,
                        "reconnecting shared chain scanner"
                    );
                }
                wallet = Some(open_wallet(
                    currency,
                    &self.seed,
                    &self.data_dir,
                    &network_cfg,
                    &self.cancel,
                )?);
                idle_since = None;
            }

            let sync_result = {
                let live = wallet.as_mut().expect("wallet opened");
                live.sync_step(&self.cancel)
            };
            let caught_up = match sync_result {
                Ok(done) => {
                    if reconnect_attempt > 0 {
                        tracing::info!(
                            currency,
                            after_attempts = reconnect_attempt,
                            "chain sync resumed after reconnect"
                        );
                        reconnect_attempt = 0;
                    }
                    let live = wallet.as_mut().expect("wallet opened");
                    let _ = live.poll_activity();
                    {
                        let _guard = self.address_lock.lock().expect("address lock");
                        self.refresh_invoices(currency, live.as_mut(), &network_cfg)?;
                    }
                    done
                }
                Err(error) => {
                    reconnect_attempt = reconnect_attempt.saturating_add(1);
                    let peers = wallet
                        .as_ref()
                        .map(|live| live.snapshot().connected_peers)
                        .unwrap_or(0);
                    let backoff_secs = (3u64
                        * 2u64.pow(reconnect_attempt.min(4).saturating_sub(1)))
                    .min(60);
                    tracing::warn!(
                        currency,
                        attempt = reconnect_attempt,
                        retry_in_secs = backoff_secs,
                        connected_peers = peers,
                        error = %format!("{error:#}"),
                        "sync failed — dropping peers and reconnecting"
                    );
                    if let Some(mut live) = wallet.take() {
                        live.disconnect();
                    }
                    std::thread::sleep(Duration::from_secs(backoff_secs));
                    continue;
                }
            };

            if !self.store.lock().expect("store lock").any_active(currency) {
                idle_since.get_or_insert_with(Instant::now);
            } else {
                idle_since = None;
            }
            if idle_since.is_some_and(|started| {
                started.elapsed() >= Duration::from_secs(self.config.idle_disconnect_secs)
            }) {
                if let Some(mut live) = wallet.take() {
                    live.disconnect();
                    tracing::info!(currency, "idle timeout — stopped block downloads");
                }
                idle_since = None;
            }

            if caught_up {
                std::thread::sleep(Duration::from_secs(1));
            } else {
                std::thread::yield_now();
            }
        }
        if let Some(mut live) = wallet.take() {
            live.disconnect();
        }
        Ok(())
    }

    fn refresh_invoices(
        &self,
        currency: &str,
        wallet: &mut dyn Network,
        network_cfg: &NetworkConfig,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for ended in self
            .store
            .lock()
            .expect("store lock")
            .expire_due(currency, now, self.config.max_payment_secs)?
        {
            tracing::info!(
                id = %ended.id,
                status = ?ended.status,
                received = ended.received,
                "payment window closed — max_payment_secs elapsed"
            );
        }

        let balances: BTreeMap<_, _> = wallet.address_balances().into_iter().collect();
        let unconfirmed: BTreeMap<_, _> =
            wallet.address_unconfirmed_balances().into_iter().collect();
        let pending = self.store.lock().expect("store lock").pending_for(currency);
        for invoice in pending {
            let received = *balances.get(&invoice.address).unwrap_or(&0);
            let received_unconfirmed = *unconfirmed.get(&invoice.address).unwrap_or(&0);
            let transactions: Vec<InvoiceTx> = wallet
                .address_transactions(&invoice.address)
                .into_iter()
                .map(InvoiceTx::from)
                .collect();
            let updated = self.store.lock().expect("store lock").update_observation(
                &invoice.id,
                received,
                received_unconfirmed,
                transactions,
            )?;
            // Forward only after the window is closed (payend / max time).
            if !matches!(
                updated.status,
                InvoiceStatus::Paid | InvoiceStatus::ForwardFailed
            ) || updated.received == 0
            {
                continue;
            }
            match wallet.prepare_forward(
                &updated.address,
                &network_cfg.payout_address,
                network_cfg.fee_rate,
            ) {
                Ok(payment) => match wallet.broadcast(&payment, &self.cancel) {
                    Ok(()) => {
                        let _ = self
                            .store
                            .lock()
                            .expect("store lock")
                            .mark_forwarded(&updated.id, payment.txid.clone());
                        tracing::info!(
                            id = %updated.id,
                            txid = %payment.txid,
                            "auto-forwarded invoice"
                        );
                    }
                    Err(error) => {
                        let _ = self
                            .store
                            .lock()
                            .expect("store lock")
                            .mark_forward_failed(&updated.id, format!("{error:#}"));
                    }
                },
                Err(error) => {
                    tracing::debug!(
                        id = %updated.id,
                        error = %format!("{error:#}"),
                        "forward deferred"
                    );
                }
            }
        }
        Ok(())
    }
}

fn open_wallet(
    currency: &str,
    seed: &[u8; 64],
    data_dir: &Path,
    network: &NetworkConfig,
    cancel: &AtomicBool,
) -> Result<Box<dyn Network>> {
    let dir = data_dir.join(format!("{currency}-mainnet"));
    match currency {
        "ltc" => Ok(Box::new(Litecoin::open(
            seed,
            &dir,
            network_litecoin::Options {
                peer: None,
                birthday: None,
                max_peers: network.max_peers.max(3),
                mempool: true,
            },
            cancel,
        )?)),
        "btc" => Ok(Box::new(Bitcoin::open(
            seed,
            &dir,
            network_bitcoin::Options {
                peer: None,
                birthday: None,
                max_peers: network.max_peers.max(3),
                mempool: true,
            },
            cancel,
        )?)),
        "eth" => Ok(Box::new(Ethereum::open(
            seed,
            &dir,
            network_ethereum::Options {
                max_peers: network.max_peers.max(2),
                execution_peer: None,
                consensus_peer: None,
                checkpoint: None,
            },
            cancel,
        )?)),
        other => bail!("Unsupported currency `{other}`"),
    }
}

pub fn invoice_json(invoice: &Invoice, decimals: u8, ticker: &str) -> serde_json::Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let expires_in_secs = if invoice.status == InvoiceStatus::Pending && invoice.expires_unix > 0 {
        invoice.expires_unix.saturating_sub(now)
    } else {
        0
    };
    let transactions: Vec<_> = invoice
        .transactions
        .iter()
        .map(|tx| {
            serde_json::json!({
                "txid": tx.txid,
                "amount": format_amount(tx.amount, decimals),
                "amount_raw": tx.amount,
                "confirmed": tx.confirmed,
                "height": tx.height,
            })
        })
        .collect();
    serde_json::json!({
        "id": invoice.id,
        "currency": invoice.currency,
        "ticker": ticker,
        "address": invoice.address,
        "status": invoice.status,
        "expected_amount": invoice.expected_amount.map(|v| format_amount(v, decimals)),
        "expected_amount_raw": invoice.expected_amount,
        "received": format_amount(invoice.received, decimals),
        "received_raw": invoice.received,
        "received_unconfirmed": format_amount(invoice.received_unconfirmed, decimals),
        "received_unconfirmed_raw": invoice.received_unconfirmed,
        "transactions": transactions,
        "forward_txid": invoice.forward_txid,
        "forward_error": invoice.forward_error,
        "created_unix": invoice.created_unix,
        "expires_unix": invoice.expires_unix,
        "expires_in_secs": expires_in_secs,
    })
}

pub fn decimals_for(currency: &str) -> u8 {
    match currency {
        "eth" => 18,
        _ => 8,
    }
}

pub fn ticker_for(currency: &str) -> &'static str {
    match currency {
        "ltc" => "LTC",
        "btc" => "BTC",
        "eth" => "ETH",
        _ => "???",
    }
}
