use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};
use uuid::Uuid;
use wallet_core::{vault::atomic_write, AddressTransaction};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InvoiceStatus {
    /// Still accepting deposits (payend / max time not reached).
    Pending,
    /// Payment window closed with funds — waiting for / doing auto-forward.
    Paid,
    Forwarded,
    ForwardFailed,
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
}

#[derive(Default, Serialize, Deserialize)]
struct Envelope {
    invoices: BTreeMap<String, Invoice>,
}

pub struct Store {
    path: PathBuf,
    invoices: BTreeMap<String, Invoice>,
}

impl Store {
    pub fn open(data_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let path = data_dir.join("invoices.json");
        let invoices = if path.exists() {
            let envelope: Envelope = serde_json::from_slice(&std::fs::read(&path)?)?;
            envelope.invoices
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, invoices })
    }

    fn save(&self) -> Result<()> {
        atomic_write(
            &self.path,
            &serde_json::to_vec_pretty(&Envelope {
                invoices: self.invoices.clone(),
            })?,
        )
    }

    pub fn create(
        &mut self,
        currency: &str,
        address: String,
        expected_amount: Option<u128>,
        max_payment_secs: u64,
    ) -> Result<Invoice> {
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
        };
        self.invoices.insert(invoice.id.clone(), invoice.clone());
        self.save()?;
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
        self.invoices
            .values()
            .filter(|invoice| {
                invoice.currency == currency
                    && matches!(
                        invoice.status,
                        InvoiceStatus::Pending
                            | InvoiceStatus::Paid
                            | InvoiceStatus::ForwardFailed
                    )
            })
            .cloned()
            .collect()
    }

    pub fn any_active(&self, currency: &str) -> bool {
        !self.pending_for(currency).is_empty()
    }

    pub fn update_observation(
        &mut self,
        id: &str,
        received: u128,
        received_unconfirmed: u128,
        transactions: Vec<InvoiceTx>,
    ) -> Result<Invoice> {
        let invoice = self.invoices.get_mut(id).context("Unknown invoice")?;
        let dirty = invoice.received != received
            || invoice.received_unconfirmed != received_unconfirmed
            || invoice.transactions != transactions;
        invoice.received = received;
        invoice.received_unconfirmed = received_unconfirmed;
        invoice.transactions = transactions;
        // Do not auto-close on first receipt — payend / max time owns that.
        let out = invoice.clone();
        if dirty {
            self.save()?;
        }
        Ok(out)
    }

    /// Close the payment window (API payend or max-time). Forwards only after this.
    pub fn end_payment(&mut self, id: &str) -> Result<Invoice> {
        let invoice = self.invoices.get_mut(id).context("Unknown invoice")?;
        match invoice.status {
            InvoiceStatus::Pending => {
                if invoice.received > 0 {
                    invoice.status = InvoiceStatus::Paid;
                    invoice.forward_error = None;
                } else {
                    invoice.status = InvoiceStatus::Expired;
                }
                let out = invoice.clone();
                self.save()?;
                Ok(out)
            }
            InvoiceStatus::Paid
            | InvoiceStatus::Forwarded
            | InvoiceStatus::ForwardFailed
            | InvoiceStatus::Expired => Ok(invoice.clone()),
        }
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
                if invoice.currency != currency || invoice.status != InvoiceStatus::Pending {
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

    pub fn mark_forwarded(&mut self, id: &str, txid: String) -> Result<Invoice> {
        let invoice = self.invoices.get_mut(id).context("Unknown invoice")?;
        ensure!(
            matches!(
                invoice.status,
                InvoiceStatus::Paid | InvoiceStatus::ForwardFailed
            ),
            "Invoice is not ready to forward"
        );
        invoice.status = InvoiceStatus::Forwarded;
        invoice.forward_txid = Some(txid);
        invoice.forward_error = None;
        let out = invoice.clone();
        self.save()?;
        Ok(out)
    }

    pub fn mark_forward_failed(&mut self, id: &str, error: String) -> Result<()> {
        let invoice = self.invoices.get_mut(id).context("Unknown invoice")?;
        if invoice.status == InvoiceStatus::Paid || invoice.status == InvoiceStatus::ForwardFailed {
            invoice.status = InvoiceStatus::ForwardFailed;
            invoice.forward_error.replace(error);
            self.save()?;
        }
        Ok(())
    }

    pub fn payend(&mut self, id: &str) -> Result<Invoice> {
        let invoice = self.get(id)?;
        if invoice.status != InvoiceStatus::Pending {
            bail!(
                "Invoice `{id}` is already {} — payend only applies while pending",
                status_label(&invoice.status)
            );
        }
        self.end_payment(id)
    }
}

fn status_label(status: &InvoiceStatus) -> &'static str {
    match status {
        InvoiceStatus::Pending => "pending",
        InvoiceStatus::Paid => "paid",
        InvoiceStatus::Forwarded => "forwarded",
        InvoiceStatus::ForwardFailed => "forward_failed",
        InvoiceStatus::Expired => "expired",
    }
}
