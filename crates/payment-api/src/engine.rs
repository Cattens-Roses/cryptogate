use crate::{
    config::{Config, NetworkConfig},
    store::{Invoice, InvoiceStatus, InvoiceTx, Store},
};
use anyhow::{bail, ensure, Context, Result};
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

#[cfg(test)]
#[path = "gateway_tests.rs"]
pub(crate) mod tests;

pub struct Engine {
    config: Config,
    seed: Zeroizing<[u8; 64]>,
    data_dir: PathBuf,
    store: Mutex<Store>,
    wallets: BTreeMap<String, Mutex<Option<Box<dyn Network>>>>,
    _vault: Vault,
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
    worker_errors: Mutex<BTreeMap<String, String>>,
    forward_retries: Mutex<BTreeMap<String, Instant>>,
    cancel: AtomicBool,
}

impl Engine {
    pub fn open(mut config: Config) -> Result<Arc<Self>> {
        config.validate()?;
        let data_dir = PathBuf::from(&config.data_dir);
        std::fs::create_dir_all(&data_dir)?;
        let vault_dir = data_dir.join("vault");
        let password = Zeroizing::new(std::mem::take(&mut config.vault_password));
        let vault = if vault_dir.join("vault.json").exists() {
            Vault::open(&vault_dir, &password)?
        } else {
            Vault::create_random(&vault_dir, &password)?
        };
        let seed = Zeroizing::new(*vault.seed());
        let store = Store::open(&data_dir.join("state"))?;
        Ok(Arc::new(Self {
            wallets: config
                .networks
                .iter()
                .filter(|(_, network)| network.enabled)
                .map(|(id, _)| (id.clone(), Mutex::new(None)))
                .collect(),
            config,
            seed,
            data_dir,
            store: Mutex::new(store),
            _vault: vault,
            workers: Mutex::new(Vec::new()),
            worker_errors: Mutex::new(BTreeMap::new()),
            forward_retries: Mutex::new(BTreeMap::new()),
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
        let mut invoice = self.store.lock().expect("store lock").get(id)?;
        if !invoice.finished
            && self
                .worker_errors
                .lock()
                .expect("worker error lock")
                .contains_key(&invoice.currency)
        {
            invoice.verified = false;
        }
        Ok(invoice)
    }

    pub fn payend(&self, id: &str) -> Result<Invoice> {
        let invoice = self.store.lock().expect("store lock").payend(id)?;
        tracing::info!(
            id = %invoice.id,
            status = ?invoice.status,
            received = invoice.received,
            "payment window closed via payend"
        );
        self.status(&invoice.id)
    }

    pub fn stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
        for worker in self.workers.lock().expect("worker lock").drain(..) {
            let _ = worker.join();
        }
        // Ethereum owns a Tokio runtime. Drop residual wallets on a blocking
        // thread even when stop() is called from the HTTP server's runtime.
        for slot in self.wallets.values() {
            if let Some(mut wallet) = slot.lock().expect("wallet lock").take() {
                let _ = std::thread::spawn(move || wallet.disconnect()).join();
            }
        }
    }

    pub fn healthy(&self) -> bool {
        !self.cancel.load(Ordering::Relaxed)
            && self
                .worker_errors
                .lock()
                .expect("worker error lock")
                .is_empty()
    }

    pub fn spawn_workers(self: &Arc<Self>) {
        let mut workers = self.workers.lock().expect("worker lock");
        if !workers.is_empty() {
            return;
        }
        for currency in self.wallets.keys() {
            let currency = currency.clone();
            let engine = Arc::clone(self);
            workers.push(
                std::thread::Builder::new()
                    .name(format!("pay-{currency}"))
                    .spawn(move || engine.currency_loop(&currency))
                    .expect("spawn currency worker"),
            );
        }
    }

    fn allocate_address(&self, currency: &str) -> Result<String> {
        ensure!(!self.cancel.load(Ordering::Relaxed), "Gateway is stopping");
        let mut wallet = self
            .wallets
            .get(currency)
            .context("Unknown currency")?
            .lock()
            .expect("wallet lock");
        if wallet.is_none() {
            *wallet = Some(open_wallet(
                currency,
                &self.seed,
                &self.data_dir,
                self.config.network(currency)?,
                &self.cancel,
            )?);
        }
        wallet.as_mut().expect("wallet opened").next_address()
    }

    fn pause(&self, duration: Duration) {
        let until = Instant::now() + duration;
        while Instant::now() < until && !self.cancel.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn currency_loop(&self, currency: &str) {
        let network = self.config.network(currency).expect("validated network");
        let mut failures = 0u32;
        while !self.cancel.load(Ordering::Relaxed) {
            if !self.store.lock().expect("store lock").any_active(currency) {
                let mut slot = self.wallets[currency].lock().expect("wallet lock");
                // A create request can arrive between the first check and this lock.
                if self.store.lock().expect("store lock").any_active(currency) {
                    continue;
                }
                if let Some(mut wallet) = slot.take() {
                    wallet.disconnect();
                }
                drop(slot);
                self.worker_errors
                    .lock()
                    .expect("worker error lock")
                    .remove(currency);
                self.pause(Duration::from_millis(400));
                continue;
            }
            let result = (|| -> Result<bool> {
                let mut slot = self.wallets[currency].lock().expect("wallet lock");
                if slot.is_none() {
                    *slot = Some(open_wallet(
                        currency,
                        &self.seed,
                        &self.data_dir,
                        network,
                        &self.cancel,
                    )?);
                }
                let wallet = slot.as_mut().expect("wallet opened");
                let addresses: Vec<_> = self
                    .store
                    .lock()
                    .expect("store lock")
                    .pending_for(currency)
                    .into_iter()
                    .map(|invoice| invoice.address)
                    .collect();
                wallet.set_active_addresses(&addresses)?;
                let caught_up = wallet.sync_step(&self.cancel)?;
                wallet.poll_activity()?;
                self.refresh_invoices(currency, wallet.as_mut(), network, caught_up)?;
                Ok(caught_up)
            })();
            match result {
                Ok(caught_up) => {
                    failures = 0;
                    self.worker_errors
                        .lock()
                        .expect("worker error lock")
                        .remove(currency);
                    self.pause(if caught_up {
                        Duration::from_secs(1)
                    } else {
                        Duration::from_millis(10)
                    });
                }
                Err(error) => {
                    if self.cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    failures = failures.saturating_add(1);
                    let message = format!("{error:#}");
                    self.worker_errors
                        .lock()
                        .expect("worker error lock")
                        .insert(currency.into(), message.clone());
                    tracing::warn!(currency, error = %message, "scanner failed; reconnecting");
                    if let Some(wallet) =
                        self.wallets[currency].lock().expect("wallet lock").as_mut()
                    {
                        wallet.disconnect();
                    }
                    self.pause(Duration::from_secs(
                        (3 * 2u64.pow(failures.min(5) - 1)).min(60),
                    ));
                }
            }
        }
        if let Some(mut wallet) = self.wallets[currency].lock().expect("wallet lock").take() {
            wallet.disconnect();
        }
    }

    fn refresh_invoices(
        &self,
        currency: &str,
        wallet: &mut dyn Network,
        network_cfg: &NetworkConfig,
        caught_up: bool,
    ) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let balances: BTreeMap<_, _> = wallet.address_balances().into_iter().collect();
        let unconfirmed: BTreeMap<_, _> =
            wallet.address_unconfirmed_balances().into_iter().collect();
        let watched = self.store.lock().expect("store lock").pending_for(currency);
        for mut invoice in watched {
            // Update observations before expiration. During initial backfill a
            // missing balance is not evidence that an invoice received nothing.
            if caught_up || wallet.address_is_current(&invoice.address) {
                if invoice.forwards.is_empty() && invoice.legacy_forward_debit.is_none() {
                    if let Some(txid) = invoice.forward_txid.clone() {
                        if let Some(payment) =
                            wallet.saved_payment(&txid, &network_cfg.payout_address)
                        {
                            invoice = self
                                .store
                                .lock()
                                .expect("store lock")
                                .begin_forward(&invoice.id, payment)?;
                        } else if wallet.payment_confirmations(&txid)
                            >= if currency == "eth" { 1 } else { 6 }
                        {
                            if let Some(debit) = wallet.payment_debit(&txid) {
                                invoice = self
                                    .store
                                    .lock()
                                    .expect("store lock")
                                    .reconcile_legacy_forward(&invoice.id, debit)?;
                            }
                        }
                        if invoice.forwards.is_empty() && invoice.legacy_forward_debit.is_none() {
                            self.store.lock().expect("store lock").mark_forward_failed(&invoice.id, "Previous-version payout is awaiting verified reconciliation; no new payout will be signed".into())?;
                            continue;
                        }
                    }
                }
                for forward in &invoice.forwards {
                    let needed = if currency == "eth" { 1 } else { 6 };
                    let confirmations = wallet.payment_confirmations(&forward.payment.txid);
                    if forward.confirmed {
                        if currency != "eth" && confirmations < needed {
                            self.store
                                .lock()
                                .expect("store lock")
                                .unconfirm_forward(&invoice.id, &forward.payment.txid)?;
                        }
                    } else if confirmations >= needed {
                        if let Some(debit) = wallet.payment_debit(&forward.payment.txid) {
                            self.store.lock().expect("store lock").confirm_forward(
                                &invoice.id,
                                &forward.payment.txid,
                                debit,
                            )?;
                        }
                    }
                }
                let current = self.store.lock().expect("store lock").get(&invoice.id)?;
                let balance = balances.get(&invoice.address).copied().unwrap_or(0);
                let received = if currency == "eth" {
                    // Native account balances include internal contract deposits.
                    // Add actual finalized payout debits, never the gas fee cap.
                    let debits = current
                        .forwards
                        .iter()
                        .filter(|forward| forward.confirmed)
                        .try_fold(
                            current.legacy_forward_debit.unwrap_or(0),
                            |total, forward| {
                                total
                                    .checked_add(forward.debit)
                                    .context("Deposit accounting overflow")
                            },
                        )?;
                    if current.forwards.iter().any(|forward| !forward.confirmed) {
                        current.received
                    } else {
                        balance
                            .checked_add(debits)
                            .context("Deposit accounting overflow")?
                    }
                } else {
                    wallet.address_credited(&invoice.address).unwrap_or(0)
                };
                let immature = if currency == "eth" {
                    0
                } else {
                    wallet
                        .address_received(&invoice.address)
                        .unwrap_or(0)
                        .saturating_sub(received)
                };
                let transactions = wallet
                    .address_transactions(&invoice.address)
                    .into_iter()
                    .map(InvoiceTx::from)
                    .collect();
                self.store.lock().expect("store lock").update_observation(
                    &invoice.id,
                    received,
                    balance,
                    unconfirmed
                        .get(&invoice.address)
                        .copied()
                        .unwrap_or(0)
                        .checked_add(immature)
                        .context("Pending deposit overflow")?,
                    transactions,
                )?;
            }
        }
        self.store.lock().expect("store lock").expire_due(
            currency,
            now,
            self.config.max_payment_secs,
        )?;
        let invoices = self.store.lock().expect("store lock").pending_for(currency);
        for invoice in invoices {
            if !caught_up && !wallet.address_is_current(&invoice.address) {
                continue;
            }
            if !invoice.closed {
                continue;
            }
            if self
                .store
                .lock()
                .expect("store lock")
                .finish_if_settled(&invoice.id)?
            {
                continue;
            }
            if invoice.forward_txid.is_some()
                && invoice.forwards.is_empty()
                && invoice.legacy_forward_debit.is_none()
            {
                continue;
            }
            if invoice.balance == 0 && !invoice.forwards.iter().any(|forward| !forward.confirmed) {
                continue;
            }
            if self
                .forward_retries
                .lock()
                .expect("retry lock")
                .get(&invoice.id)
                .is_some_and(|last| last.elapsed() < Duration::from_secs(30))
            {
                continue;
            }
            self.forward_retries
                .lock()
                .expect("retry lock")
                .insert(invoice.id.clone(), Instant::now());
            if let Some(forward) = invoice.forwards.iter().find(|forward| !forward.confirmed) {
                if let Err(error) = wallet.resume_broadcast(&forward.payment, &self.cancel) {
                    self.store
                        .lock()
                        .expect("store lock")
                        .mark_forward_failed(&invoice.id, format!("{error:#}"))?;
                }
                continue;
            }
            if invoice.balance == 0 {
                continue;
            }
            match wallet.prepare_forward(
                &invoice.address,
                &network_cfg.payout_address,
                network_cfg.fee_rate,
            ) {
                Ok(payment) => {
                    // Journal the exact signed bytes BEFORE any network delivery.
                    // A restart retries these bytes, never a new payment.
                    self.store
                        .lock()
                        .expect("store lock")
                        .begin_forward(&invoice.id, payment.clone())?;
                    if let Err(error) = wallet.broadcast(&payment, &self.cancel) {
                        self.store
                            .lock()
                            .expect("store lock")
                            .mark_forward_failed(&invoice.id, format!("{error:#}"))?;
                    }
                }
                Err(error) => {
                    self.store
                        .lock()
                        .expect("store lock")
                        .mark_forward_failed(&invoice.id, format!("{error:#}"))?;
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
        "eth" => {
            let mut wallet = Ethereum::open(
                seed,
                &dir,
                network_ethereum::Options {
                    max_peers: network.max_peers.max(2),
                    execution_peer: None,
                    consensus_peer: None,
                    checkpoint: None,
                },
                cancel,
            )?;
            wallet.require_finalized_balances();
            Ok(Box::new(wallet))
        }
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
                "amount_raw": tx.amount.to_string(),
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
        "payment_complete": invoice.payment_complete(),
        "verified": invoice.verified,
        "window_closed": invoice.closed,
        "finished": invoice.finished,
        "balance_raw": invoice.balance.to_string(),
        "forward_txids": invoice.forwards.iter().map(|forward| &forward.payment.txid).collect::<Vec<_>>(),
        "expected_amount": invoice.expected_amount.map(|v| format_amount(v, decimals)),
        "expected_amount_raw": invoice.expected_amount.map(|value| value.to_string()),
        "received": format_amount(invoice.received, decimals),
        "received_raw": invoice.received.to_string(),
        "received_unconfirmed": format_amount(invoice.received_unconfirmed, decimals),
        "received_unconfirmed_raw": invoice.received_unconfirmed.to_string(),
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
