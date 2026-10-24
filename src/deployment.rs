use crate::cli::Network;
use alloy_primitives::{Address, B256};
use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde::Deserialize;
use std::{collections::HashSet, str::FromStr};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DeploymentManifest {
    pub schema_version: u32,
    pub network: Network,
    pub chain_id: u64,
    pub native_symbol: String,
    pub native_decimals: u8,
    pub primary_rpc: String,
    pub archival_rpc: Option<String>,
    pub mining_enabled: bool,
    #[serde(default)]
    pub solidity_source: Option<SoliditySource>,
    #[serde(default)]
    pub reference_snapshot: Option<ReferenceSnapshot>,
    #[serde(default)]
    pub ast_token: Option<TokenPin>,
    #[serde(default)]
    pub nodes: Vec<NodePin>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SoliditySource {
    pub canonical_main_commit: String,
    pub observed_deployment_checkout: String,
    pub observed_deployment_branch: String,
    pub deployment_label_reference: String,
    pub work_codec_identical_to_canonical_main: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ReferenceSnapshot {
    pub block_number: u64,
    pub block_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TokenPin {
    pub address: String,
    pub decimals: u8,
    pub runtime_code_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NodePin {
    pub id: u8,
    pub address: String,
    pub runtime_code_hash: String,
}

impl DeploymentManifest {
    pub fn load(network: Network) -> Result<Self> {
        let contents = match network {
            Network::Testnet => include_str!("../deployments/testnet.toml"),
            Network::Mainnet => include_str!("../deployments/mainnet.toml"),
        };
        let manifest: Self =
            toml::from_str(contents).context("parse built-in deployment manifest")?;
        manifest.validate(network)?;
        Ok(manifest)
    }

    pub fn validate(&self, expected_network: Network) -> Result<()> {
        if self.schema_version != 1
            || self.network != expected_network
            || self.native_symbol != "INJ"
            || self.native_decimals != 18
        {
            bail!("deployment manifest schema or network identity is invalid");
        }
        for endpoint in std::iter::once(&self.primary_rpc).chain(self.archival_rpc.iter()) {
            let parsed = Url::parse(endpoint).context("parse configured RPC URL")?;
            if parsed.scheme() != "https" {
                bail!("only HTTPS RPC endpoints are permitted");
            }
        }

        match expected_network {
            Network::Testnet => {
                if self.chain_id != 1439 || !self.mining_enabled || self.nodes.len() != 9 {
                    bail!("Testnet manifest must pin chain 1439 and exactly nine mining nodes");
                }
                let source = self
                    .solidity_source
                    .as_ref()
                    .context("Testnet Solidity source provenance is missing")?;
                if !is_commit(&source.canonical_main_commit)
                    || !is_commit(&source.observed_deployment_checkout)
                    || !source.work_codec_identical_to_canonical_main
                    || source.observed_deployment_branch.is_empty()
                    || source.deployment_label_reference.is_empty()
                {
                    bail!("Testnet Solidity source provenance is malformed or unreviewed");
                }
                let snapshot = self
                    .reference_snapshot
                    .as_ref()
                    .context("Testnet reference snapshot is missing")?;
                if snapshot.block_number == 0 {
                    bail!("Testnet reference snapshot block is invalid");
                }
                parse_hash(&snapshot.block_hash).context("invalid Testnet reference block hash")?;
                let token = self
                    .ast_token
                    .as_ref()
                    .context("Testnet AST token pin is missing")?;
                parse_address(&token.address).context("invalid AST token address")?;
                parse_hash(&token.runtime_code_hash).context("invalid AST token runtime hash")?;
                if token.decimals != 9 {
                    bail!("Testnet AST token decimals must match the verified deployment pin");
                }
                let mut ids = HashSet::with_capacity(9);
                let mut addresses = HashSet::with_capacity(9);
                for (index, node) in self.nodes.iter().enumerate() {
                    if node.id != (index + 1) as u8 || !ids.insert(node.id) {
                        bail!("Testnet node IDs must be unique and ordered 1 through 9");
                    }
                    let address = parse_address(&node.address).context("invalid miner address")?;
                    if address.is_zero() || !addresses.insert(address) {
                        bail!("Testnet miner addresses must be unique and nonzero");
                    }
                    parse_hash(&node.runtime_code_hash).context("invalid miner runtime hash")?;
                }
            }
            Network::Mainnet => {
                if self.chain_id != 1776
                    || self.mining_enabled
                    || !self.nodes.is_empty()
                    || self.ast_token.is_some()
                {
                    bail!("Mainnet is read-only and has no approved mining deployment");
                }
            }
        }
        Ok(())
    }
}

pub fn parse_address(value: &str) -> Result<Address> {
    Address::from_str(value).with_context(|| format!("invalid EVM address {value}"))
}

pub fn parse_hash(value: &str) -> Result<B256> {
    B256::from_str(value).with_context(|| format!("invalid bytes32 {value}"))
}

fn is_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_testnet_registry_is_pinned_and_complete() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        assert_eq!(manifest.chain_id, 1439);
        assert_eq!(manifest.nodes.len(), 9);
        assert!(manifest.mining_enabled);
    }

    #[test]
    fn mainnet_profile_has_no_mining_deployment() {
        let manifest = DeploymentManifest::load(Network::Mainnet).unwrap();
        assert_eq!(manifest.chain_id, 1776);
        assert!(!manifest.mining_enabled);
        assert!(manifest.nodes.is_empty());
    }
}
