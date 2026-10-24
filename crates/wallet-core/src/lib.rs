//! Network-independent wallet contracts and authenticated seed storage.
pub mod vault;

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;

#[derive(Clone, Copy, Debug)]
pub struct NetworkInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub ticker: &'static str,
    pub decimals: u8,
    pub fee_rate_unit: &'static str,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransactionEntry {
    pub txid: String,
    pub height: u32,
    pub received: u128,
    pub sent: u128,
}

/// Per-address payment observation for gateways (incoming only).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddressTransaction {
    pub txid: String,
    pub amount: u128,
    pub confirmed: bool,
    pub height: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub address: String,
    pub receive_note: String,
    pub spend_note: String,
    pub balance: u128,
    pub spendable: u128,
    pub pending_incoming: u128,
    pub mempool_status: String,
    pub pending_outgoing: u128,
    pub height: u32,
    pub scanned: u32,
    pub recent_scanned: u32,
    pub peer_height: u32,
    pub connected_peers: usize,
    pub max_peers: usize,
    pub peer: String,
    pub transactions: Vec<TransactionEntry>,
}

/// Immutable review of a signed payment. Broadcast requires a separate explicit action.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payment {
    pub recipient: String,
    pub amount: u128,
    pub fee: u128,
    pub txid: String,
    pub raw: Vec<u8>,
}

/// Implement this trait in a separate crate for each blockchain.
/// A step is bounded so frontends can process commands between sync batches.
pub trait Network: Send {
    fn info(&self) -> NetworkInfo;
    fn snapshot(&self) -> Snapshot;
    fn next_address(&mut self) -> Result<String>;
    fn sync_step(&mut self, cancel: &AtomicBool) -> Result<bool>;
    fn disconnect(&mut self);
    /// Gateway account queries can be limited to invoices still being settled.
    /// None of the TUI flows call this; their normal discovery is unchanged.
    fn set_active_addresses(&mut self, _addresses: &[String]) -> Result<()> {
        Ok(())
    }
    /// Drain optional, unconfirmed relay observations without blocking network I/O.
    fn poll_activity(&mut self) -> Result<bool> {
        Ok(false)
    }
    /// Optional live sync detail for the status bar. Bitcoin/Litecoin keep the
    /// default BIP157 wording in the TUI; Ethereum supplies Beacon/snap progress.
    fn sync_status(&self) -> Option<String> {
        None
    }
    fn prepare_payment(&mut self, recipient: &str, amount: u128, fee_rate: u64) -> Result<Payment>;
    fn broadcast(&mut self, payment: &Payment, cancel: &AtomicBool) -> Result<()>;
    /// Retry exactly the same signed payment after an interrupted gateway send.
    /// Implementations must validate ownership and preserve existing reservations.
    fn resume_broadcast(&mut self, _payment: &Payment, _cancel: &AtomicBool) -> Result<()> {
        bail!("Resuming broadcasts is not supported on this network")
    }
    /// Recover pre-journal gateway sends from the wallet's own reservations.
    fn saved_payment(&self, _txid: &str, _recipient: &str) -> Option<Payment> {
        None
    }
    fn payment_confirmations(&self, txid: &str) -> u32 {
        let snapshot = self.snapshot();
        snapshot
            .transactions
            .iter()
            .find(|tx| tx.txid == txid && tx.height > 0)
            .map(|tx| snapshot.height.saturating_sub(tx.height) + 1)
            .unwrap_or(0)
    }
    /// Actual confirmed debit, including the fee (not an Ethereum fee cap).
    fn payment_debit(&self, txid: &str) -> Option<u128> {
        self.snapshot()
            .transactions
            .iter()
            .find(|tx| tx.txid == txid && tx.height > 0)
            .map(|tx| tx.sent)
    }
    /// Cumulative deposits; UTXO backends override this using retained proofs.
    fn address_received(&self, address: &str) -> Option<u128> {
        self.address_balances()
            .into_iter()
            .find(|(a, _)| a == address)
            .map(|(_, value)| value)
    }
    /// Deposits deep enough to authorize merchant fulfillment.
    fn address_credited(&self, address: &str) -> Option<u128> {
        self.address_received(address)
    }
    /// Account networks can have a fresh proof for one invoice while other
    /// addresses are still being queried. UTXO networks require full backfill.
    fn address_is_current(&self, _address: &str) -> bool {
        false
    }
    /// Confirmed balances keyed by receive address (payment gateways).
    fn address_balances(&self) -> Vec<(String, u128)> {
        let snap = self.snapshot();
        if snap.address.is_empty() {
            Vec::new()
        } else {
            vec![(snap.address, snap.balance)]
        }
    }
    /// Unconfirmed (mempool / relay) incoming amounts keyed by receive address.
    /// Advisory only — not proof of acceptance or final payment.
    fn address_unconfirmed_balances(&self) -> Vec<(String, u128)> {
        Vec::new()
    }
    /// Incoming transactions credited to one receive address (confirmed + unconfirmed).
    fn address_transactions(&self, _address: &str) -> Vec<AddressTransaction> {
        Vec::new()
    }
    /// Sweep confirmed funds from one receive address to `recipient` (gateway auto-forward).
    fn prepare_forward(
        &mut self,
        _from_address: &str,
        _recipient: &str,
        _fee_rate: u64,
    ) -> Result<Payment> {
        bail!("Forwarding is not supported on this network")
    }
}

pub type NetworkFactory =
    Box<dyn FnOnce(&[u8; 64], &AtomicBool, &dyn Fn(&str)) -> Result<Box<dyn Network>> + Send>;

pub fn format_amount(amount: u128, decimals: u8) -> String {
    let scale = 10u128.pow(decimals as u32);
    format!(
        "{}.{:0width$}",
        amount / scale,
        amount % scale,
        width = decimals as usize
    )
}

/// Parse user amounts without floating point or rounding.
pub fn parse_amount(text: &str, decimals: u8) -> Result<u128> {
    let text = text.trim();
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty()
        || !whole.bytes().all(|c| c.is_ascii_digit())
        || !fraction.bytes().all(|c| c.is_ascii_digit())
        || fraction.len() > decimals as usize
    {
        bail!("Enter a positive decimal amount with at most {decimals} decimal places");
    }
    let scale = 10u128
        .checked_pow(decimals as u32)
        .ok_or_else(|| anyhow::anyhow!("Invalid precision"))?;
    let whole: u128 = whole.parse()?;
    let fraction_digits = fraction.len() as u32;
    let fraction: u128 = if fraction.is_empty() {
        0
    } else {
        fraction.parse()?
    };
    whole
        .checked_mul(scale)
        .and_then(|n| n.checked_add(fraction * 10u128.pow(decimals as u32 - fraction_digits)))
        .ok_or_else(|| anyhow::anyhow!("Amount is too large"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_amounts() {
        assert_eq!(parse_amount("0.00000001", 8).unwrap(), 1);
        assert_eq!(parse_amount("21.42", 8).unwrap(), 2_142_000_000);
        assert_eq!(parse_amount("1", 8).unwrap(), 100_000_000);
        for bad in [
            "-1",
            "1e8",
            "NaN",
            "0.000000001",
            "1.2.3",
            "340282366920938463463374607431768211455",
        ] {
            assert!(parse_amount(bad, 8).is_err(), "{bad}");
        }
        assert_eq!(format_amount(142, 8), "0.00000142");
    }
}
