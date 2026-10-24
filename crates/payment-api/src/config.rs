use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub listen: String,
    pub api_key: String,
    pub data_dir: String,
    pub vault_password: String,
    #[serde(default = "default_idle")]
    pub idle_disconnect_secs: u64,
    /// How long an invoice stays open for deposits before auto payend.
    #[serde(default = "default_max_payment")]
    pub max_payment_secs: u64,
    pub networks: BTreeMap<String, NetworkConfig>,
}

fn default_idle() -> u64 {
    120
}

fn default_max_payment() -> u64 {
    3_600
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub enabled: bool,
    pub payout_address: String,
    pub fee_rate: u64,
    #[serde(default = "default_peers")]
    pub max_peers: usize,
}

fn default_peers() -> usize {
    3
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("Missing config at {}", path.display()))?;
        let config: Self = serde_json::from_str(&text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.api_key.is_empty() && self.api_key != "change-me-to-a-long-random-secret",
            "Set a real api_key in config.json"
        );
        ensure!(
            self.vault_password.chars().count() >= 10,
            "vault_password must be at least 10 characters"
        );
        ensure!(
            self.idle_disconnect_secs >= 30,
            "idle_disconnect_secs must be at least 30"
        );
        ensure!(
            (60..=86_400).contains(&self.max_payment_secs),
            "max_payment_secs must be 60–86400"
        );
        let enabled: Vec<_> = self.networks.iter().filter(|(_, n)| n.enabled).collect();
        ensure!(
            !enabled.is_empty(),
            "Enable at least one network in config.json"
        );
        for (id, network) in &self.networks {
            ensure!(
                id == &id.to_ascii_lowercase(),
                "Network keys must be lowercase: {id}"
            );
            ensure!(
                matches!(id.as_str(), "ltc" | "btc" | "eth"),
                "Unknown network `{id}`"
            );
            if !network.enabled {
                continue;
            }
            ensure!(
                !network.payout_address.is_empty(),
                "networks.{id}.payout_address is required when enabled"
            );
            match id.as_str() {
                "btc" => {
                    network_bitcoin::address::script_for_address(&network.payout_address)?;
                }
                "ltc" => {
                    network_litecoin::address::script_for_address(&network.payout_address)?;
                }
                "eth" => {
                    network_ethereum::address::parse(&network.payout_address)?;
                }
                _ => bail!("unsupported network"),
            }
            ensure!(
                (1..=32).contains(&network.max_peers),
                "networks.{id}.max_peers must be 1–32"
            );
            match id.as_str() {
                "ltc" | "btc" => ensure!(
                    (1..=1000).contains(&network.fee_rate),
                    "UTXO fee_rate must be 1–1000"
                ),
                "eth" => {
                    ensure!(
                        (1..=10_000).contains(&network.fee_rate),
                        "ETH fee_rate must be 1–10000 gwei/gas"
                    );
                    ensure!(network.max_peers >= 2, "ETH needs max_peers >= 2");
                }
                _ => bail!("unsupported network"),
            }
        }
        Ok(())
    }

    pub fn network(&self, currency: &str) -> Result<&NetworkConfig> {
        let key = currency.to_ascii_lowercase();
        let network = self
            .networks
            .get(&key)
            .with_context(|| format!("Network `{key}` is not configured"))?;
        ensure!(
            network.enabled,
            "Network `{key}` is disabled in config.json"
        );
        Ok(network)
    }
}
