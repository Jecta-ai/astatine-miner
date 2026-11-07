use crate::cli::Network;
use alloy_primitives::{Address, B256, U256};
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
    pub submission_fee_wei: Option<u64>,
    #[serde(default)]
    pub solidity_source: Option<SoliditySource>,
    #[serde(default)]
    pub reference_snapshot: Option<ReferenceSnapshot>,
    #[serde(default)]
    pub miner_config: Option<MinerConfigPin>,
    #[serde(default)]
    pub ast_token: Option<TokenPin>,
    #[serde(default)]
    pub nodes: Vec<NodePin>,
    #[serde(default)]
    pub genesis_coordinator: Option<CoordinatorPin>,
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
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply_base_units: String,
    pub owner: String,
    pub bank_denom: String,
    pub token_factory_admin: String,
    pub runtime_code_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NodePin {
    pub id: u8,
    pub address: String,
    pub runtime_code_hash: String,
    pub deployment_tx_hash: String,
    pub deployment_block_number: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct MinerConfigPin {
    pub expected_ast_decimals: u8,
    pub total_mining_allocation_base_units: String,
    pub other_allocations_base_units: String,
    pub per_node_allocation_base_units: String,
    pub unassigned_node_remainder_base_units: String,
    pub initial_reward_base_units: String,
    pub initial_target: String,
    pub min_target: String,
    pub max_target: String,
    pub window_secs: u64,
    pub target_spacing_secs: u64,
    pub ema_alpha_bps: u16,
    pub retarget_interval: u64,
    pub retarget_clamp_num: u64,
    pub retarget_clamp_den: u64,
    pub max_header_length: u32,
    pub max_empty_sample_secs: u64,
    pub genesis_authority: String,
    pub revenue_handler: String,
    pub revenue_recipient: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct CoordinatorPin {
    pub address: String,
    pub runtime_code_hash: String,
    pub deployment_tx_hash: String,
    pub deployment_block_number: u64,
    pub source_commit: String,
    pub owner: String,
    pub expected_ast_token: String,
    pub configuration_tx_hash: String,
    pub configuration_block_number: u64,
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
        let expected_schema = match expected_network {
            Network::Testnet => 2,
            Network::Mainnet => 1,
        };
        if self.schema_version != expected_schema
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
                if self.submission_fee_wei != Some(3_000_000_000_000_000) {
                    bail!("Testnet manifest must pin the exact 0.003 INJ submission fee");
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
                if token.name != "Astatine" || token.symbol != "AST" || token.decimals != 9 {
                    bail!(
                        "Testnet AST token identity or decimals differ from the verified deployment pin"
                    );
                }
                if !token.bank_denom.starts_with("factory/")
                    || !token.token_factory_admin.starts_with("inj1")
                    || token.bank_denom != format!("factory/{}/AST", token.token_factory_admin)
                    || parse_decimal_u256(&token.total_supply_base_units)?.is_zero()
                {
                    bail!("Testnet AST token identity metadata is incomplete or invalid");
                }
                parse_address(&token.owner).context("invalid AST token owner address")?;

                let miner_config = self
                    .miner_config
                    .as_ref()
                    .context("Testnet miner constructor configuration is missing")?;
                validate_miner_config(miner_config, token, self.nodes.len())?;

                let coordinator = self
                    .genesis_coordinator
                    .as_ref()
                    .context("Testnet Genesis Coordinator pin is missing")?;
                parse_address(&coordinator.address)
                    .context("invalid Genesis Coordinator address")?;
                parse_hash(&coordinator.runtime_code_hash)
                    .context("invalid Genesis Coordinator runtime hash")?;
                parse_hash(&coordinator.deployment_tx_hash)
                    .context("invalid Genesis Coordinator deployment transaction hash")?;
                parse_hash(&coordinator.configuration_tx_hash)
                    .context("invalid Genesis Coordinator configuration transaction hash")?;
                parse_address(&coordinator.owner).context("invalid Genesis Coordinator owner")?;
                parse_address(&coordinator.expected_ast_token)
                    .context("invalid Genesis Coordinator AST token")?;
                if !is_commit(&coordinator.source_commit)
                    || coordinator.deployment_block_number == 0
                    || coordinator.configuration_block_number == 0
                    || !coordinator
                        .owner
                        .eq_ignore_ascii_case(&miner_config.genesis_authority)
                    || !coordinator
                        .expected_ast_token
                        .eq_ignore_ascii_case(&token.address)
                {
                    bail!("Testnet Genesis Coordinator provenance or identity is inconsistent");
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
                    parse_hash(&node.deployment_tx_hash)
                        .context("invalid miner deployment transaction hash")?;
                    if node.deployment_block_number == 0 {
                        bail!("Testnet miner deployment block number is invalid");
                    }
                }
            }
            Network::Mainnet => {
                if self.chain_id != 1776
                    || self.mining_enabled
                    || !self.nodes.is_empty()
                    || self.ast_token.is_some()
                    || self.submission_fee_wei.is_some()
                    || self.miner_config.is_some()
                    || self.genesis_coordinator.is_some()
                {
                    bail!("Mainnet is read-only and has no approved mining deployment");
                }
            }
        }
        Ok(())
    }
}

fn validate_miner_config(
    config: &MinerConfigPin,
    token: &TokenPin,
    node_count: usize,
) -> Result<()> {
    if config.expected_ast_decimals != token.decimals {
        bail!("miner AST decimals differ from the pinned token decimals");
    }
    let total_mining = parse_decimal_u256(&config.total_mining_allocation_base_units)?;
    let other_allocations = parse_decimal_u256(&config.other_allocations_base_units)?;
    let per_node = parse_decimal_u256(&config.per_node_allocation_base_units)?;
    let remainder = parse_decimal_u256(&config.unassigned_node_remainder_base_units)?;
    let supply = parse_decimal_u256(&token.total_supply_base_units)?;
    let distributed_allocation = per_node
        .checked_mul(U256::from(node_count))
        .and_then(|value| value.checked_add(remainder))
        .context("Testnet nine-node allocation arithmetic overflow")?;
    let total_allocation = total_mining
        .checked_add(other_allocations)
        .context("Testnet AST allocation arithmetic overflow")?;
    if distributed_allocation != total_mining || total_allocation != supply {
        bail!("Testnet AST allocations do not match the pinned token supply");
    }

    let initial_reward = parse_decimal_u256(&config.initial_reward_base_units)?;
    if per_node.is_zero() || initial_reward.is_zero() || initial_reward > per_node {
        bail!("Testnet per-node allocation or initial reward is invalid");
    }
    let initial_target = parse_decimal_u256(&config.initial_target)?;
    let min_target = parse_decimal_u256(&config.min_target)?;
    let max_target = parse_decimal_u256(&config.max_target)?;
    if min_target.is_zero()
        || min_target >= max_target
        || initial_target < min_target
        || initial_target > max_target
        || config.window_secs == 0
        || config.target_spacing_secs == 0
        || config.retarget_interval == 0
        || !(1..=10_000).contains(&config.ema_alpha_bps)
        || config.retarget_clamp_den == 0
        || config.retarget_clamp_num <= config.retarget_clamp_den
        || config.max_header_length == 0
        || config.max_header_length > 1_024
        || config.max_empty_sample_secs
            < config
                .window_secs
                .saturating_add(config.target_spacing_secs)
    {
        bail!("Testnet miner constructor configuration is invalid");
    }
    let authority =
        parse_address(&config.genesis_authority).context("invalid Testnet genesis authority")?;
    let handler =
        parse_address(&config.revenue_handler).context("invalid Testnet revenue handler")?;
    let recipient =
        parse_address(&config.revenue_recipient).context("invalid Testnet revenue recipient")?;
    if authority.is_zero() || handler.is_zero() || recipient.is_zero() || handler == authority {
        bail!("Testnet genesis or fee-revenue roles are invalid");
    }
    Ok(())
}

fn parse_decimal_u256(value: &str) -> Result<U256> {
    U256::from_str(value).with_context(|| format!("invalid deployment integer {value}"))
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
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.chain_id, 1439);
        assert_eq!(manifest.nodes.len(), 9);
        assert!(manifest.mining_enabled);
        assert_eq!(manifest.submission_fee_wei, Some(3_000_000_000_000_000));
        let token = manifest.ast_token.as_ref().unwrap();
        assert_eq!(token.address, "0x5C730A3110a565bf388120ce64F37bb7dd0c7F83");
        assert_eq!(token.name, "Astatine");
        assert_eq!(token.symbol, "AST");
        assert_eq!(token.decimals, 9);
        assert_eq!(token.total_supply_base_units, "3000000000000000");
        assert_eq!(
            manifest
                .solidity_source
                .as_ref()
                .unwrap()
                .canonical_main_commit,
            "80e8f7cbeb21b18bc5f7475d8b751c9d9e8fb9d1"
        );
        assert_eq!(manifest.nodes[0].id, 1);
        assert_eq!(
            manifest.nodes[0].address,
            "0xd85330911C21830F5e3E15e63cE29655Db9D6FBb"
        );
        assert_eq!(manifest.nodes[8].id, 9);
        let coordinator = manifest.genesis_coordinator.as_ref().unwrap();
        assert_eq!(
            coordinator.address,
            "0x126DeE584cd3b643374b6BC464242581d1bF5d1f"
        );
        assert_eq!(
            coordinator.source_commit,
            "c710b4d7add5f10de326487d0ff851eb926499c6"
        );
        assert_eq!(
            manifest
                .miner_config
                .as_ref()
                .unwrap()
                .per_node_allocation_base_units,
            "327000000000000"
        );
    }

    #[test]
    fn testnet_registry_rejects_old_submission_fee_and_incomplete_node_set() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let mut old_fee = manifest.clone();
        old_fee.submission_fee_wei = Some(10_000_000_000_000_000);
        assert!(old_fee.validate(Network::Testnet).is_err());

        let mut missing_node = manifest;
        missing_node.nodes.pop();
        assert!(missing_node.validate(Network::Testnet).is_err());
    }

    #[test]
    fn mainnet_profile_has_no_mining_deployment() {
        let manifest = DeploymentManifest::load(Network::Mainnet).unwrap();
        assert_eq!(manifest.chain_id, 1776);
        assert!(!manifest.mining_enabled);
        assert!(manifest.nodes.is_empty());
    }
}
