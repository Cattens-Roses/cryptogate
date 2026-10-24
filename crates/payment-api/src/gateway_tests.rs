use super::*;
use crate::store::InvoiceStatus;
use wallet_core::{NetworkInfo, Payment, Snapshot};

pub(crate) fn config(root: &Path) -> Config {
    Config {
        listen: "127.0.0.1:0".into(),
        api_key: "test-api-key".into(),
        data_dir: root.to_string_lossy().into(),
        vault_password: "test-vault-password".into(),
        idle_disconnect_secs: 120,
        max_payment_secs: 3600,
        networks: [
            (
                "btc".into(),
                NetworkConfig {
                    enabled: true,
                    payout_address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".into(),
                    fee_rate: 1,
                    max_peers: 3,
                },
            ),
            (
                "ltc".into(),
                NetworkConfig {
                    enabled: true,
                    payout_address: "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy".into(),
                    fee_rate: 1,
                    max_peers: 3,
                },
            ),
            (
                "eth".into(),
                NetworkConfig {
                    enabled: true,
                    payout_address: "0x0000000000000000000000000000000000000001".into(),
                    fee_rate: 1,
                    max_peers: 3,
                },
            ),
        ]
        .into(),
    }
}

#[derive(Default)]
struct FakeWallet {
    balance: u128,
    received: u128,
    unconfirmed: u128,
    sweep: Option<u128>,
    prepared: usize,
    broadcasts: Vec<String>,
    resumes: Vec<String>,
    confirmations: u32,
    debit: u128,
    fail_delivery: bool,
}

impl Network for FakeWallet {
    fn info(&self) -> NetworkInfo {
        NetworkInfo {
            id: "test",
            name: "test",
            ticker: "BTC",
            decimals: 8,
            fee_rate_unit: "sat/vB",
        }
    }
    fn snapshot(&self) -> Snapshot {
        Snapshot::default()
    }
    fn next_address(&mut self) -> Result<String> {
        unreachable!()
    }
    fn sync_step(&mut self, _: &AtomicBool) -> Result<bool> {
        Ok(true)
    }
    fn disconnect(&mut self) {}
    fn prepare_payment(&mut self, _: &str, _: u128, _: u64) -> Result<Payment> {
        unreachable!()
    }
    fn address_balances(&self) -> Vec<(String, u128)> {
        vec![("invoice-address".into(), self.balance)]
    }
    fn address_received(&self, _: &str) -> Option<u128> {
        Some(self.received)
    }
    fn address_unconfirmed_balances(&self) -> Vec<(String, u128)> {
        vec![("invoice-address".into(), self.unconfirmed)]
    }
    fn prepare_forward(&mut self, _: &str, recipient: &str, _: u64) -> Result<Payment> {
        self.prepared += 1;
        let amount = self.sweep.context("No spendable funds yet")?;
        Ok(Payment {
            recipient: recipient.into(),
            amount,
            fee: 1,
            txid: format!("tx-{}", self.prepared),
            raw: vec![self.prepared as u8],
        })
    }
    fn broadcast(&mut self, payment: &Payment, _: &AtomicBool) -> Result<()> {
        self.broadcasts.push(payment.txid.clone());
        ensure!(!self.fail_delivery, "ambiguous delivery");
        Ok(())
    }
    fn resume_broadcast(&mut self, payment: &Payment, _: &AtomicBool) -> Result<()> {
        self.resumes.push(payment.txid.clone());
        Ok(())
    }
    fn payment_confirmations(&self, _: &str) -> u32 {
        self.confirmations
    }
    fn payment_debit(&self, _: &str) -> Option<u128> {
        Some(self.debit)
    }
}

fn invoice(engine: &Engine, expected: Option<u128>, seconds: u64) -> Invoice {
    engine
        .store
        .lock()
        .unwrap()
        .create("btc", "invoice-address".into(), expected, seconds)
        .unwrap()
}

fn refresh(engine: &Engine, wallet: &mut FakeWallet) {
    engine
        .refresh_invoices("btc", wallet, engine.config.network("btc").unwrap(), true)
        .unwrap();
}

#[test]
fn second_instance_cannot_open_gateway_and_lock_releases_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    engine.create_invoice("btc", None).unwrap();
    assert!(Engine::open(config(dir.path())).is_err());
    drop(engine);
    assert!(Engine::open(config(dir.path())).is_ok());
}

#[test]
fn invoice_allocation_and_scanner_share_one_wallet_in_every_network() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    for currency in ["btc", "ltc", "eth"] {
        let first = engine.create_invoice(currency, None).unwrap();
        let second = engine.create_invoice(currency, None).unwrap();
        let scanner_address = engine.wallets[currency]
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .snapshot()
            .address;
        assert_eq!(scanner_address, second.address);
        assert_ne!(first.address, second.address);
        let third = engine.create_invoice(currency, None).unwrap();
        assert_ne!(second.address, third.address);
    }
    drop(engine);
    let engine = Engine::open(config(dir.path())).unwrap();
    for currency in ["btc", "ltc", "eth"] {
        let previous: Vec<_> = engine
            .store
            .lock()
            .unwrap()
            .pending_for(currency)
            .into_iter()
            .map(|invoice| invoice.address)
            .collect();
        assert!(!previous.contains(&engine.create_invoice(currency, None).unwrap().address));
    }
}

#[test]
fn concurrent_creates_never_reuse_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let engine = Arc::clone(&engine);
            std::thread::spawn(move || engine.create_invoice("btc", None).unwrap().address)
        })
        .collect();
    let addresses: std::collections::BTreeSet<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(addresses.len(), 8);
}

#[test]
fn closing_unconfirmed_invoice_keeps_tracking_and_accepts_late_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = invoice(&engine, Some(100), 3600);
    let mut wallet = FakeWallet {
        unconfirmed: 100,
        ..Default::default()
    };
    refresh(&engine, &mut wallet);
    assert_eq!(
        engine.payend(&invoice.id).unwrap().status,
        InvoiceStatus::AwaitingConfirmation
    );
    assert!(engine.store.lock().unwrap().any_active("btc"));
    wallet.unconfirmed = 0;
    wallet.balance = 100;
    wallet.received = 100;
    wallet.sweep = Some(99);
    refresh(&engine, &mut wallet);
    assert!(engine.status(&invoice.id).unwrap().payment_complete());
    assert_eq!(wallet.broadcasts.len(), 1);
}

#[test]
fn empty_expired_invoice_is_retired_and_does_not_accept_later_deposits() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = invoice(&engine, Some(100), 0);
    let mut wallet = FakeWallet::default();
    refresh(&engine, &mut wallet);
    assert_eq!(
        engine.status(&invoice.id).unwrap().status,
        InvoiceStatus::Expired
    );
    wallet.balance = 100;
    wallet.received = 100;
    wallet.sweep = Some(99);
    refresh(&engine, &mut wallet);
    assert_eq!(engine.status(&invoice.id).unwrap().received, 0);
    assert_eq!(wallet.broadcasts.len(), 0);
    assert!(engine.status(&invoice.id).unwrap().finished);
    assert!(!engine.store.lock().unwrap().any_active("btc"));
}

#[test]
fn expiry_applies_fresh_deposit_before_deciding_whether_to_retire() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = invoice(&engine, Some(100), 0);
    let mut wallet = FakeWallet {
        balance: 100,
        received: 100,
        sweep: Some(99),
        ..Default::default()
    };
    refresh(&engine, &mut wallet);
    assert!(!engine.status(&invoice.id).unwrap().finished);
    assert_eq!(wallet.broadcasts.len(), 1);
}

#[test]
fn idle_scanner_disconnects_and_resumes_only_for_a_new_invoice() {
    use std::sync::atomic::AtomicUsize;
    struct Probe {
        syncs: Arc<AtomicUsize>,
        disconnected: Arc<AtomicBool>,
    }
    impl Network for Probe {
        fn info(&self) -> NetworkInfo {
            unreachable!()
        }
        fn snapshot(&self) -> Snapshot {
            Snapshot::default()
        }
        fn next_address(&mut self) -> Result<String> {
            unreachable!()
        }
        fn sync_step(&mut self, _: &AtomicBool) -> Result<bool> {
            self.syncs.fetch_add(1, Ordering::SeqCst);
            Ok(false)
        }
        fn disconnect(&mut self) {
            self.disconnected.store(true, Ordering::SeqCst);
        }
        fn prepare_payment(&mut self, _: &str, _: u128, _: u64) -> Result<Payment> {
            unreachable!()
        }
        fn broadcast(&mut self, _: &Payment, _: &AtomicBool) -> Result<()> {
            unreachable!()
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = invoice(&engine, None, 0);
    engine
        .store
        .lock()
        .unwrap()
        .update_observation(&invoice.id, 0, 0, 0, vec![])
        .unwrap();
    engine.payend(&invoice.id).unwrap();
    assert!(engine
        .store
        .lock()
        .unwrap()
        .finish_if_settled(&invoice.id)
        .unwrap());
    let syncs = Arc::new(AtomicUsize::new(0));
    let disconnected = Arc::new(AtomicBool::new(false));
    *engine.wallets["btc"].lock().unwrap() = Some(Box::new(Probe {
        syncs: syncs.clone(),
        disconnected: disconnected.clone(),
    }));
    engine.spawn_workers();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !disconnected.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(disconnected.load(Ordering::SeqCst));
    assert_eq!(syncs.load(Ordering::SeqCst), 0);
    let mut slot = engine.wallets["btc"].lock().unwrap();
    engine
        .store
        .lock()
        .unwrap()
        .create("btc", "new-invoice-address".into(), None, 3600)
        .unwrap();
    *slot = Some(Box::new(Probe {
        syncs: syncs.clone(),
        disconnected,
    }));
    drop(slot);
    let deadline = Instant::now() + Duration::from_secs(3);
    while syncs.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    engine.stop();
    assert!(syncs.load(Ordering::SeqCst) > 0);
}

#[test]
fn backfill_does_not_overwrite_stored_receipts_with_incomplete_balance() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = invoice(&engine, Some(100), 0);
    engine
        .store
        .lock()
        .unwrap()
        .update_observation(&invoice.id, 100, 100, 0, vec![])
        .unwrap();
    let mut wallet = FakeWallet::default();
    engine
        .refresh_invoices(
            "btc",
            &mut wallet,
            engine.config.network("btc").unwrap(),
            false,
        )
        .unwrap();
    assert_eq!(engine.status(&invoice.id).unwrap().received, 100);
    assert_eq!(wallet.prepared, 0);
}

#[test]
fn short_payment_is_not_paid_and_payend_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = invoice(&engine, Some(100_000_000), 3600);
    engine
        .store
        .lock()
        .unwrap()
        .update_observation(&invoice.id, 1, 1, 0, vec![])
        .unwrap();
    let closed = engine.payend(&invoice.id).unwrap();
    assert_eq!(closed.status, InvoiceStatus::Underpaid);
    assert!(!closed.payment_complete());
    assert_eq!(
        engine.payend(&invoice.id).unwrap().status,
        InvoiceStatus::Underpaid
    );
}

#[test]
fn partial_sweep_tracks_remainder_then_retires_the_invoice() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = invoice(&engine, Some(200), 3600);
    let mut wallet = FakeWallet {
        balance: 200,
        received: 200,
        sweep: Some(99),
        ..Default::default()
    };
    refresh(&engine, &mut wallet);
    engine.payend(&invoice.id).unwrap();
    refresh(&engine, &mut wallet);
    assert_eq!(
        engine.status(&invoice.id).unwrap().status,
        InvoiceStatus::Forwarding
    );
    wallet.confirmations = 6;
    wallet.debit = 100;
    wallet.balance = 100;
    engine.forward_retries.lock().unwrap().clear();
    refresh(&engine, &mut wallet);
    assert_eq!(engine.status(&invoice.id).unwrap().forwards.len(), 2);
    wallet.balance = 0;
    refresh(&engine, &mut wallet);
    assert_eq!(
        engine.status(&invoice.id).unwrap().status,
        InvoiceStatus::Forwarded
    );
    assert_eq!(engine.status(&invoice.id).unwrap().received, 200);
    assert!(!engine.store.lock().unwrap().any_active("btc"));
    assert!(engine.status(&invoice.id).unwrap().finished);
    engine
        .worker_errors
        .lock()
        .unwrap()
        .insert("btc".into(), "unrelated active scan failed".into());
    assert!(engine.status(&invoice.id).unwrap().payment_complete());
    engine.worker_errors.lock().unwrap().clear();
    wallet.confirmations = 6;
    wallet.balance = 100;
    wallet.received = 300;
    engine.forward_retries.lock().unwrap().clear();
    refresh(&engine, &mut wallet);
    assert_eq!(engine.status(&invoice.id).unwrap().forwards.len(), 2);
    assert_eq!(engine.status(&invoice.id).unwrap().received, 200);
    drop(engine);
    let engine = Engine::open(config(dir.path())).unwrap();
    assert!(engine.status(&invoice.id).unwrap().payment_complete());
    assert!(!engine.store.lock().unwrap().any_active("btc"));
}

#[test]
fn ambiguous_delivery_retries_same_signed_bytes_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = invoice(&engine, Some(100), 3600);
    let mut wallet = FakeWallet {
        balance: 100,
        received: 100,
        sweep: Some(99),
        fail_delivery: true,
        ..Default::default()
    };
    refresh(&engine, &mut wallet);
    engine.payend(&invoice.id).unwrap();
    refresh(&engine, &mut wallet);
    let txid = engine.status(&invoice.id).unwrap().forward_txid.unwrap();
    drop(engine);
    let engine = Engine::open(config(dir.path())).unwrap();
    refresh(&engine, &mut wallet);
    assert_eq!(wallet.prepared, 1);
    assert_eq!(wallet.resumes, vec![txid]);
    assert_eq!(engine.status(&invoice.id).unwrap().forwards.len(), 1);
}

#[test]
fn preparation_error_is_visible_without_claiming_payment_complete() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = invoice(&engine, Some(200), 3600);
    let mut wallet = FakeWallet {
        balance: 100,
        received: 100,
        ..Default::default()
    };
    refresh(&engine, &mut wallet);
    engine.payend(&invoice.id).unwrap();
    refresh(&engine, &mut wallet);
    let invoice = engine.status(&invoice.id).unwrap();
    assert!(invoice
        .forward_error
        .unwrap()
        .contains("No spendable funds"));
    assert!(!engine.status(&invoice.id).unwrap().payment_complete());
}

#[test]
fn large_eth_amounts_roundtrip_and_api_uses_exact_strings() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let value = 20 * 10u128.pow(18);
    let invoice = store
        .create("eth", "invoice-address".into(), Some(value), 3600)
        .unwrap();
    store
        .update_observation(&invoice.id, value, value, 0, vec![])
        .unwrap();
    drop(store);
    let reopened = Store::open(dir.path()).unwrap().get(&invoice.id).unwrap();
    let json = invoice_json(&reopened, 18, "ETH");
    assert_eq!(json["received_raw"], value.to_string());
    assert_eq!(json["expected_amount_raw"], value.to_string());
    assert_eq!(json["payment_complete"], false); // startup requires fresh proofs
    let mut store = Store::open(dir.path()).unwrap();
    let verified = store
        .update_observation(&invoice.id, value, value, 0, vec![])
        .unwrap();
    assert!(verified.payment_complete());
}

#[test]
fn payout_reorganization_retries_original_transaction_without_signing_again() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = invoice(&engine, Some(100), 3600);
    let mut wallet = FakeWallet {
        balance: 100,
        received: 100,
        sweep: Some(99),
        ..Default::default()
    };
    refresh(&engine, &mut wallet);
    engine.payend(&invoice.id).unwrap();
    refresh(&engine, &mut wallet);
    wallet.confirmations = 5;
    wallet.balance = 0;
    wallet.debit = 100;
    refresh(&engine, &mut wallet);
    assert_eq!(
        engine.status(&invoice.id).unwrap().status,
        InvoiceStatus::Forwarding
    );
    wallet.confirmations = 0;
    wallet.balance = 100;
    engine.forward_retries.lock().unwrap().clear();
    refresh(&engine, &mut wallet);
    assert_eq!(wallet.prepared, 1);
    assert_eq!(wallet.resumes, vec!["tx-1"]);
    assert_eq!(
        engine.status(&invoice.id).unwrap().status,
        InvoiceStatus::Forwarding
    );
}

#[test]
fn invalid_payouts_are_rejected_before_vault_creation() {
    let dir = tempfile::tempdir().unwrap();
    for currency in ["btc", "ltc", "eth"] {
        let mut cfg = config(dir.path());
        cfg.networks.get_mut(currency).unwrap().payout_address = "invalid-address".into();
        assert!(Engine::open(cfg).is_err());
    }
    assert!(!dir.path().join("vault/vault.json").exists());
}

#[test]
fn failed_invoice_save_rolls_back_memory_and_duplicate_address_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(dir.path()).unwrap();
    let invoice = store
        .create("btc", "invoice-address".into(), None, 3600)
        .unwrap();
    assert!(store
        .create("btc", "invoice-address".into(), None, 3600)
        .is_err());
    std::fs::remove_file(dir.path().join("invoices.json")).unwrap();
    std::fs::create_dir(dir.path().join("invoices.json")).unwrap();
    assert!(store.payend(&invoice.id).is_err());
    assert!(!store.get(&invoice.id).unwrap().closed);
}

#[test]
fn previous_version_finalized_payout_is_reconciled_without_another_send() {
    for currency in ["btc", "eth"] {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::open(config(dir.path())).unwrap();
        let mut legacy = engine
            .store
            .lock()
            .unwrap()
            .create(currency, "invoice-address".into(), Some(100), 3600)
            .unwrap();
        legacy.received = 100;
        legacy.status = InvoiceStatus::Forwarded;
        legacy.forward_txid = Some("old-payout".into());
        let id = legacy.id.clone();
        drop(engine);
        let json = serde_json::json!({"invoices": { &id: legacy }});
        std::fs::write(
            dir.path().join("state/invoices.json"),
            serde_json::to_vec(&json).unwrap(),
        )
        .unwrap();
        let engine = Engine::open(config(dir.path())).unwrap();
        assert!(!engine.status(&id).unwrap().payment_complete());
        let mut wallet = FakeWallet {
            balance: 0,
            received: 100,
            confirmations: 6,
            debit: 100,
            ..Default::default()
        };
        engine
            .refresh_invoices(
                currency,
                &mut wallet,
                engine.config.network(currency).unwrap(),
                true,
            )
            .unwrap();
        let invoice = engine.status(&id).unwrap();
        assert_eq!(invoice.legacy_forward_debit, Some(100));
        assert!(invoice.payment_complete());
        assert_eq!(wallet.prepared, 0);
    }
}

#[test]
fn eth_accounting_adds_actual_payout_debit_instead_of_maximum_fee() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(config(dir.path())).unwrap();
    let invoice = engine
        .store
        .lock()
        .unwrap()
        .create("eth", "invoice-address".into(), Some(100), 3600)
        .unwrap();
    let mut wallet = FakeWallet {
        balance: 100,
        received: 100,
        sweep: Some(90),
        ..Default::default()
    };
    engine
        .refresh_invoices(
            "eth",
            &mut wallet,
            engine.config.network("eth").unwrap(),
            true,
        )
        .unwrap();
    engine.payend(&invoice.id).unwrap();
    engine
        .refresh_invoices(
            "eth",
            &mut wallet,
            engine.config.network("eth").unwrap(),
            true,
        )
        .unwrap();
    wallet.balance = 14; // residual 9 plus a new deposit of 5
    engine
        .refresh_invoices(
            "eth",
            &mut wallet,
            engine.config.network("eth").unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(engine.status(&invoice.id).unwrap().received, 100); // unresolved send freezes new credits
    wallet.confirmations = 1;
    wallet.debit = 91;
    engine
        .refresh_invoices(
            "eth",
            &mut wallet,
            engine.config.network("eth").unwrap(),
            true,
        )
        .unwrap();
    assert_eq!(engine.status(&invoice.id).unwrap().received, 105);
}
