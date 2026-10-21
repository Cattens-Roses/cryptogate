use anyhow::{ensure, Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{collections::BTreeMap, path::Path};
use wallet_core::{vault::atomic_write, TransactionEntry};
use zeroize::Zeroizing;

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Account {
    pub balance: u128,
    pub nonce: u64,
    pub height: u32,
    pub timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Pending {
    pub index: u32,
    pub nonce: u64,
    pub raw: String,
    pub txid: String,
    pub amount: u128,
    pub fee: u128,
}

#[derive(Serialize, Deserialize)]
pub struct State {
    pub network: String,
    pub receive_index: u32,
    pub accounts: BTreeMap<u32, Account>,
    pub history: Vec<TransactionEntry>,
    pub history_cursor: u32,
    pub pending: Vec<Pending>,
    pub checkpoint: Option<(String, u64)>,
}

impl Default for State {
    fn default() -> Self {
        Self { network: "ethereum-mainnet".into(), receive_index: 0, accounts: BTreeMap::new(), history: vec![], history_cursor: 0, pending: vec![], checkpoint: None }
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    state: State,
    mac: String,
}

pub fn key(seed: &[u8; 64]) -> Zeroizing<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(seed).expect("HMAC accepts any key length");
    mac.update(b"enginecore/ethereum-mainnet/state/v1");
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn seal(state: &State, key: &[u8; 32]) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&serde_json::to_vec(state)?);
    Ok(mac)
}

pub fn load(path: &Path, key: &[u8; 32]) -> Result<State> {
    if !path.exists() { return Ok(State::default()); }
    ensure!(std::fs::metadata(path)?.len() <= 16_000_000, "Ethereum state is too large");
    let envelope: Envelope = serde_json::from_slice(&std::fs::read(path)?)?;
    seal(&envelope.state, key)?.verify_slice(&hex::decode(&envelope.mac)?).context("Ethereum state authentication failed")?;
    ensure!(envelope.state.network == "ethereum-mainnet", "Wrong network state");
    ensure!(envelope.state.receive_index < 1 << 31, "Invalid account index");
    Ok(envelope.state)
}

pub fn save(path: &Path, state: &State, key: &[u8; 32]) -> Result<()> {
    #[derive(Serialize)]
    struct Borrowed<'a> { state: &'a State, mac: String }
    let mac = hex::encode(seal(state, key)?.finalize().into_bytes());
    atomic_write(path, &serde_json::to_vec(&Borrowed { state, mac })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn balances_above_u64_and_reservations_survive_restart_and_detect_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let key = key(&[42; 64]);
        let mut state = State::default();
        state.accounts.insert(0, Account { balance: 120_000_000 * 10u128.pow(18), nonce: 2, height: 25_000_000, timestamp: 1 });
        state.pending.push(Pending { index: 0, nonce: 2, raw: "signed bytes".into(), txid: "hash".into(), amount: 10u128.pow(18), fee: 21_000 });
        save(&path, &state, &key).unwrap();
        let reopened = load(&path, &key).unwrap();
        assert_eq!(reopened.accounts[&0].balance, state.accounts[&0].balance);
        assert_eq!(reopened.pending.len(), 1);
        assert!(load(&path, &[0; 32]).is_err());
        let text = std::fs::read_to_string(&path).unwrap().replace("120000000000000000000000000", "120000000000000000000000001");
        std::fs::write(&path, text).unwrap();
        assert!(load(&path, &key).is_err());
    }
}
