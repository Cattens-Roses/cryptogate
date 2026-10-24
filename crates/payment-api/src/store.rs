use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use wallet_core::{vault::atomic_write, AddressTransaction, Payment};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    /// Still accepting deposits (payend / max time not reached).
    Pending,
    AwaitingConfirmation,
    Underpaid,
    /// Payment window closed with funds — waiting for / doing auto-forward.
    Paid,
    Forwarded,
    ForwardFailed,
    Forwarding,
    /// Window closed with no confirmed funds.
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvoiceTx {
    pub txid: String,
    pub amount: u128,
    pub confirmed: bool,
    pub height: u32,
}

impl From<AddressTransaction> for InvoiceTx {
    fn from(tx: AddressTransaction) -> Self {
        Self {
            txid: tx.txid,
            amount: tx.amount,
            confirmed: tx.confirmed,
            height: tx.height,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invoice {
    pub id: String,
    pub currency: String,
    pub address: String,
    pub expected_amount: Option<u128>,
    pub received: u128,
    /// Mempool / relay observation only — not confirmation.
    #[serde(default)]
    pub received_unconfirmed: u128,
    pub status: InvoiceStatus,
    pub forward_txid: Option<String>,
    pub forward_error: Option<String>,
    pub created_unix: u64,
    /// After this unix time the worker auto-ends the payment window.
    #[serde(default)]
    pub expires_unix: u64,
    #[serde(default)]
    pub transactions: Vec<InvoiceTx>,
    #[serde(default)]
    pub closed: bool,
    #[serde(default)]
    pub balance: u128,
    #[serde(default)]
    pub forwards: Vec<Forward>,
    /// Startup must revalidate saved observations before authorizing an order.
    #[serde(skip)]
    pub verified: bool,
    #[serde(default)]
    pub legacy_forward_debit: Option<u128>,
    /// Terminal receipt: retained for status reads, excluded from scanning.
    #[serde(default)]
    pub finished: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Forward {
    pub payment: Payment,
    pub confirmed: bool,
    pub debit: u128,
}

impl Invoice {
    pub fn payment_complete(&self) -> bool {
        self.verified
            && self.received > 0
            && self
                .expected_amount
                .is_none_or(|expected| self.received >= expected)
    }

    fn refresh_status(&mut self) {
        if self.finished {
            return;
        }
        if !self.closed {
            self.status = InvoiceStatus::Pending;
        } else if self.forwards.iter().any(|forward| !forward.confirmed) {
            self.status = InvoiceStatus::Forwarding;
        } else if self.forward_error.is_some() {
            self.status = InvoiceStatus::ForwardFailed;
        } else if !self.payment_complete() {
            self.status = if self.received > 0 {
                InvoiceStatus::Underpaid
            } else if self.received_unconfirmed > 0 {
                InvoiceStatus::AwaitingConfirmation
            } else {
                InvoiceStatus::Expired
            };
        } else if self
            .forwards
            .last()
            .is_some_and(|forward| forward.confirmed && self.balance < forward.payment.fee)
        {
            self.status = InvoiceStatus::Forwarded;
        } else {
            self.status = InvoiceStatus::Paid;
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Envelope {
    invoices: BTreeMap<String, Invoice>,
}

pub struct Store {
    path: PathBuf,
    invoices: BTreeMap<String, Invoice>,
    active: BTreeMap<String, BTreeSet<String>>,
}

impl Store {
    pub fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join("invoices.json");
        let mut invoices: BTreeMap<String, Invoice> = if path.exists() {
            let envelope: Envelope = serde_json::from_slice(&std::fs::read(&path)?)?;
            envelope.invoices
        } else {
            BTreeMap::new()
        };
        let mut assigned = BTreeSet::new();
        let mut active: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for invoice in invoices.values_mut() {
            ensure!(assigned.insert((invoice.currency.clone(), invoice.address.clone())), "Multiple invoices share a receive address; reconcile these invoices before starting the gateway");
            // Older versions encoded window closure only in status.
            invoice.closed |= invoice.status != InvoiceStatus::Pending;
            invoice.verified = invoice.finished;
            invoice.refresh_status();
            if !invoice.finished {
                active
                    .entry(invoice.currency.clone())
                    .or_default()
                    .insert(invoice.id.clone());
            }
        }
        Ok(Self {
            path,
            invoices,
            active,
        })
    }

    fn save(&self) -> Result<()> {
        atomic_write(
            &self.path,
            &serde_json::to_vec_pretty(&Envelope {
                invoices: self.invoices.clone(),
            })?,
        )
    }

    fn change(
        &mut self,
        id: &str,
        edit: impl FnOnce(&mut Invoice) -> Result<()>,
    ) -> Result<Invoice> {
        let previous = self.get(id)?;
        let invoice = self.invoices.get_mut(id).context("Unknown invoice")?;
        edit(invoice)?;
        invoice.refresh_status();
        let out = invoice.clone();
        if let Err(error) = self.save() {
            self.invoices.insert(id.to_owned(), previous);
            return Err(error);
        }
        if out.finished {
            if let Some(active) = self.active.get_mut(&out.currency) {
                active.remove(id);
            }
        }
        Ok(out)
    }

    pub fn create(
        &mut self,
        currency: &str,
        address: String,
        expected_amount: Option<u128>,
        max_payment_secs: u64,
    ) -> Result<Invoice> {
        ensure!(
            expected_amount != Some(0),
            "Expected amount must be positive"
        );
        ensure!(
            !self
                .invoices
                .values()
                .any(|invoice| invoice.currency == currency && invoice.address == address),
            "Receive address was already assigned to an invoice"
        );
        let created_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let invoice = Invoice {
            id: Uuid::new_v4().to_string(),
            currency: currency.to_ascii_lowercase(),
            address,
            expected_amount,
            received: 0,
            received_unconfirmed: 0,
            status: InvoiceStatus::Pending,
            forward_txid: None,
            forward_error: None,
            created_unix,
            expires_unix: created_unix.saturating_add(max_payment_secs),
            transactions: Vec::new(),
            closed: false,
            balance: 0,
            forwards: Vec::new(),
            verified: false,
            legacy_forward_debit: None,
            finished: false,
        };
        self.invoices.insert(invoice.id.clone(), invoice.clone());
        if let Err(error) = self.save() {
            self.invoices.remove(&invoice.id);
            return Err(error);
        }
        self.active
            .entry(invoice.currency.clone())
            .or_default()
            .insert(invoice.id.clone());
        Ok(invoice)
    }

    pub fn get(&self, id: &str) -> Result<Invoice> {
        self.invoices
            .get(id)
            .cloned()
            .with_context(|| format!("Unknown invoice `{id}`"))
    }

    /// Invoices that still need chain sync / balance updates / forwarding.
    pub fn pending_for(&self, currency: &str) -> Vec<Invoice> {
        let currency = currency.to_ascii_lowercase();
        self.active
            .get(&currency)
            .into_iter()
            .flatten()
            .filter_map(|id| self.invoices.get(id))
            .cloned()
            .collect()
    }

    pub fn any_active(&self, currency: &str) -> bool {
        self.active
            .get(&currency.to_ascii_lowercase())
            .is_some_and(|ids| !ids.is_empty())
    }

    /// Retire only after a current observation and resolution of known deposits
    /// and payouts. Unknown future deposits do not reopen an archived invoice.
    pub fn finish_if_settled(&mut self, id: &str) -> Result<bool> {
        let invoice = self.get(id)?;
        if invoice.finished {
            return Ok(true);
        }
        let legacy_unresolved = invoice.forward_txid.is_some()
            && invoice.forwards.is_empty()
            && invoice.legacy_forward_debit.is_none();
        let remainder_is_fee_dust = invoice
            .forwards
            .last()
            .is_some_and(|forward| forward.confirmed && invoice.balance < forward.payment.fee);
        if !invoice.closed
            || !invoice.verified
            || invoice.received_unconfirmed > 0
            || invoice.forwards.iter().any(|forward| !forward.confirmed)
            || legacy_unresolved
            || (invoice.balance > 0 && !remainder_is_fee_dust)
        {
            return Ok(false);
        }
        self.change(id, |invoice| {
            invoice.finished = true;
            Ok(())
        })?;
        Ok(true)
    }

    pub fn update_observation(
        &mut self,
        id: &str,
        received: u128,
        balance: u128,
        received_unconfirmed: u128,
        transactions: Vec<InvoiceTx>,
    ) -> Result<Invoice> {
        let current = self.get(id)?;
        if current.verified
            && current.received == received
            && current.balance == balance
            && current.received_unconfirmed == received_unconfirmed
            && current.transactions == transactions
        {
            return Ok(current);
        }
        self.change(id, |invoice| {
            invoice.received = received;
            invoice.balance = balance;
            invoice.received_unconfirmed = received_unconfirmed;
            invoice.transactions = transactions;
            invoice.verified = true;
            Ok(())
        })
    }

    /// Close the payment window (API payend or max-time). Forwards only after this.
    pub fn end_payment(&mut self, id: &str) -> Result<Invoice> {
        if self.get(id)?.closed {
            return self.get(id);
        }
        self.change(id, |invoice| {
            invoice.closed = true;
            Ok(())
        })
    }

    pub fn expire_due(
        &mut self,
        currency: &str,
        now_unix: u64,
        max_payment_secs: u64,
    ) -> Result<Vec<Invoice>> {
        let currency = currency.to_ascii_lowercase();
        let mut ended = Vec::new();
        let ids: Vec<_> = self
            .invoices
            .values()
            .filter(|invoice| {
                if invoice.currency != currency || invoice.closed {
                    return false;
                }
                let expires = if invoice.expires_unix > 0 {
                    invoice.expires_unix
                } else {
                    invoice.created_unix.saturating_add(max_payment_secs)
                };
                now_unix >= expires
            })
            .map(|invoice| invoice.id.clone())
            .collect();
        for id in ids {
            ended.push(self.end_payment(&id)?);
        }
        Ok(ended)
    }

    pub fn begin_forward(&mut self, id: &str, payment: Payment) -> Result<Invoice> {
        let current = self.get(id)?;
        ensure!(
            current.closed && !current.forwards.iter().any(|forward| !forward.confirmed),
            "Invoice already has an unresolved forward or is still open"
        );
        self.change(id, |invoice| {
            invoice.forward_txid = Some(payment.txid.clone());
            invoice.forward_error = None;
            invoice.forwards.push(Forward {
                payment,
                confirmed: false,
                debit: 0,
            });
            Ok(())
        })
    }

    pub fn reconcile_legacy_forward(&mut self, id: &str, debit: u128) -> Result<Invoice> {
        self.change(id, |invoice| {
            invoice.legacy_forward_debit = Some(debit);
            invoice.forward_error = None;
            Ok(())
        })
    }

    pub fn confirm_forward(&mut self, id: &str, txid: &str, debit: u128) -> Result<Invoice> {
        self.change(id, |invoice| {
            let forward = invoice
                .forwards
                .iter_mut()
                .find(|forward| forward.payment.txid == txid)
                .context("Unknown forward")?;
            forward.confirmed = true;
            forward.debit = debit;
            invoice.forward_error = None;
            Ok(())
        })
    }

    pub fn unconfirm_forward(&mut self, id: &str, txid: &str) -> Result<Invoice> {
        self.change(id, |invoice| {
            let forward = invoice
                .forwards
                .iter_mut()
                .find(|forward| forward.payment.txid == txid)
                .context("Unknown forward")?;
            forward.confirmed = false;
            forward.debit = 0;
            Ok(())
        })
    }

    pub fn mark_forward_failed(&mut self, id: &str, error: String) -> Result<()> {
        if self.get(id)?.forward_error.as_deref() == Some(error.as_str()) {
            return Ok(());
        }
        self.change(id, |invoice| {
            invoice.forward_error = Some(error);
            Ok(())
        })?;
        Ok(())
    }

    pub fn payend(&mut self, id: &str) -> Result<Invoice> {
        self.end_payment(id)
    }
}
