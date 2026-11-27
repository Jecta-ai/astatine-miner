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
    pub safer_a: String,
    pub safer_b: String,
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
            Network::Testnet => 3,
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
                    || !source
                        .deployment_label_reference
                        .eq_ignore_ascii_case(&source.observed_deployment_checkout)
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
                if token.name != "Astatine Testnet" || token.symbol != "AST" || token.decimals != 9
                {
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
                if parse_address(&token.owner)
                    .context("invalid AST token owner address")?
                    .is_zero()
                {
                    bail!("Testnet AST token owner must be nonzero");
                }

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
                let safer_a = parse_address(&miner_config.safer_a)
                    .context("invalid Testnet safer voter A")?;
                let safer_b = parse_address(&miner_config.safer_b)
                    .context("invalid Testnet safer voter B")?;
                let mut ids = HashSet::with_capacity(9);
                let mut addresses = HashSet::with_capacity(9);
                for (index, node) in self.nodes.iter().enumerate() {
                    if node.id != (index + 1) as u8 || !ids.insert(node.id) {
                        bail!("Testnet node IDs must be unique and ordered 1 through 9");
                    }
                    let address = parse_address(&node.address).context("invalid miner address")?;
                    if address.is_zero()
                        || !addresses.insert(address)
                        || address == safer_a
                        || address == safer_b
                    {
                        bail!(
                            "Testnet miner addresses must be unique, nonzero, and distinct from governance roles"
                        );
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
    let safer_a = parse_address(&config.safer_a).context("invalid Testnet safer voter A")?;
    let safer_b = parse_address(&config.safer_b).context("invalid Testnet safer voter B")?;
    let recipient =
        parse_address(&config.revenue_recipient).context("invalid Testnet revenue recipient")?;
    if authority.is_zero()
        || safer_a.is_zero()
        || safer_b.is_zero()
        || recipient.is_zero()
        || safer_a == safer_b
        || safer_a == authority
        || safer_b == authority
    {
        bail!("Testnet genesis, governance, or fee-revenue roles are invalid");
    }
    Ok(())
}

fn parse_decimal_u256(value: &str) -> Result<U256> {
    U256::from_str(value).with_context(|| format!("invalid deployment integer {value}"))
}

pub fn parse_address(value: &str) -> Result<Address> {
    Address::from_str(value).map_err(|_| anyhow::anyhow!("invalid EVM address"))
}

pub fn parse_hash(value: &str) -> Result<B256> {
    B256::from_str(value).map_err(|_| anyhow::anyhow!("invalid bytes32"))
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
        assert_eq!(manifest.schema_version, 3);
        assert_eq!(manifest.chain_id, 1439);
        assert_eq!(manifest.nodes.len(), 9);
        assert!(manifest.mining_enabled);
        assert_eq!(manifest.submission_fee_wei, Some(3_000_000_000_000_000));
        let token = manifest.ast_token.as_ref().unwrap();
        assert_eq!(token.address, "0x8D1d98b79C45e59fF69b38E1162977B1329e7D86");
        assert_eq!(token.name, "Astatine Testnet");
        assert_eq!(token.symbol, "AST");
        assert_eq!(token.decimals, 9);
        assert_eq!(token.total_supply_base_units, "3000000000000000");
        assert_eq!(token.owner, "0xC8572cCF22653695D2292b7aE5d1b61C75870930");
        assert_eq!(
            token.bank_denom,
            "factory/inj1eptjenezv5mft53f9dawt5dkr36cwzfskgh9sx/AST"
        );
        assert_eq!(
            token.token_factory_admin,
            "inj1eptjenezv5mft53f9dawt5dkr36cwzfskgh9sx"
        );
        assert_eq!(
            token.runtime_code_hash,
            "0x374e8e354b84990e6fb359b78f1b32e4c56c857facd619ceb223d5ed270b4d1d"
        );
        let source = manifest.solidity_source.as_ref().unwrap();
        assert_eq!(
            source.canonical_main_commit,
            "2daaf73695e27d8eaa7ba6d8a5ebd0547097afe8"
        );
        assert_eq!(
            source.observed_deployment_checkout,
            "21bc1c4a05f0d528312236c48a2aa94485c1f75f"
        );
        assert_eq!(
            source.observed_deployment_branch,
            "feature/remove-mining-admin-controls"
        );
        assert!(source.work_codec_identical_to_canonical_main);
        let snapshot = manifest.reference_snapshot.as_ref().unwrap();
        assert_eq!(snapshot.block_number, 150633433);
        assert_eq!(
            snapshot.block_hash,
            "0x6f9b43e89596572277655166c866b02b2dfaabb6f695a57b1edfbda216f7e757"
        );
        let config = manifest.miner_config.as_ref().unwrap();
        assert_eq!(config.initial_reward_base_units, "1380000000000");
        assert_eq!(config.retarget_interval, 5);
        assert_eq!(config.safer_a, "0xDbdBb186e2D2941381d8F053346E1b80A0f2e20D");
        assert_eq!(config.safer_b, "0x3DFBC94B0b8D5A73553250604300B1bAFDC2A4DD");
        assert_eq!(
            config.revenue_recipient,
            "0xcA4c19c88c03Dcf11aBCd97dAb8dF1bC6875B783"
        );
        assert_eq!(config.per_node_allocation_base_units, "327000000000000");
        let expected_nodes: [(u8, &str, &str, u64); 9] = [
            (
                1,
                "0xa97a84eE12c54B07e76f2273A3c0aF46db11633e",
                "0x0ce48f653197d4f437d31a6e5cc499f96474a27d42f7c75d7bd1c1bda46d2b7b",
                150630832,
            ),
            (
                2,
                "0x053cEC373A8cAa627Ca04FbE6F60B29637D95C7f",
                "0xd69398e924a2858b67666ea15b8267111f0c8de4e56935c2d8b905208ac35c32",
                150630848,
            ),
            (
                3,
                "0x0a18e886163165070Aa1ED28b1013066F843636d",
                "0xab0c7a9253418e5c9fecf268399061a659b15595d478fdf87bbf9f77bd4e3912",
                150630865,
            ),
            (
                4,
                "0x985a8b7EcA3224b7779c60C2e4F9f692b6380946",
                "0xb7b7b0ee4c7f138170cd91aa70b96c7b266d3f9158a704c87861a575ca881a8f",
                150630881,
            ),
            (
                5,
                "0x1eC645Fb162eFE5f7EE6E1c592415a04D8a9072F",
                "0x63c93ddeaf7ff8ab32f064413ca9b61f2e159bafcc24a63b4645c2ab4d2587f8",
                150630897,
            ),
            (
                6,
                "0x10E114d76275C71564a937a85d8bEb81b54A7310",
                "0x9c65dd20f747fb87da0938e5ab0b4e375bacd18f6a0c900df9434850ccd96c06",
                150630912,
            ),
            (
                7,
                "0x1E14C031F6FcB22d38c456c6f245EA131107c7F2",
                "0x86565bcba9f567e88dfab482f031dd40432259f3d5d7813c5a7d6d21756c33d0",
                150630929,
            ),
            (
                8,
                "0x31bCd3eaaD1d663F9c477d527276BbBc8a48ad12",
                "0x75ba16803a672fdfe6210da470e71c292ce70176a2ff91da9fdd5d457084b93c",
                150630945,
            ),
            (
                9,
                "0xE68Ce329731C32b072b9473fa3d80F038cD05AeC",
                "0x67dc59cb108cf584f0e69dcdf115ad6123bba637226a5e01932d8cae6524f63e",
                150630960,
            ),
        ];
        for (node, (id, address, tx_hash, block_number)) in
            manifest.nodes.iter().zip(expected_nodes)
        {
            assert_eq!(node.id, id);
            assert_eq!(node.address, address);
            assert_eq!(node.deployment_tx_hash, tx_hash);
            assert_eq!(node.deployment_block_number, block_number);
            assert_eq!(
                node.runtime_code_hash,
                "0x71bdbb742fc827c3db04b81ac6bf0aaf295aad5f594f9892666c9cf183bba557"
            );
        }
        let coordinator = manifest.genesis_coordinator.as_ref().unwrap();
        assert_eq!(
            coordinator.address,
            "0x920da459728Ea9f8a402221F30042B50413C7Ea8"
        );
        assert_eq!(
            coordinator.runtime_code_hash,
            "0x2e2b24299225231ddee1501aa99c10443a55e1b94215d524eb6a93418792f2d2"
        );
        assert_eq!(
            coordinator.deployment_tx_hash,
            "0x9907905e87354ea2408153ae0df397b73c50f5da7fa77ad94d38e5324514d13a"
        );
        assert_eq!(coordinator.deployment_block_number, 150631388);
        assert_eq!(
            coordinator.source_commit,
            "21bc1c4a05f0d528312236c48a2aa94485c1f75f"
        );
        assert_eq!(
            coordinator.owner,
            "0x7292b8Ef9D9CdeC82c5047d957eE799701026F24"
        );
        assert_eq!(
            coordinator.expected_ast_token,
            "0x8D1d98b79C45e59fF69b38E1162977B1329e7D86"
        );
        assert_eq!(
            coordinator.configuration_tx_hash,
            "0x381665260e2613c5cca455021302a4d58e0df5fef75d707f2c5d031e3b11b571"
        );
        assert_eq!(coordinator.configuration_block_number, 150632026);
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
    fn testnet_registry_rejects_old_token_or_coordinator_identity() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let mut old_token = manifest.clone();
        old_token.ast_token.as_mut().unwrap().name = "Astatine".to_owned();
        assert!(old_token.validate(Network::Testnet).is_err());

        let mut old_coordinator = manifest;
        old_coordinator
            .genesis_coordinator
            .as_mut()
            .unwrap()
            .expected_ast_token = "0x5C730A3110a565bf388120ce64F37bb7dd0c7F83".to_owned();
        assert!(old_coordinator.validate(Network::Testnet).is_err());
    }

    #[test]
    fn mainnet_profile_has_no_mining_deployment() {
        let manifest = DeploymentManifest::load(Network::Mainnet).unwrap();
        assert_eq!(manifest.chain_id, 1776);
        assert!(!manifest.mining_enabled);
        assert!(manifest.nodes.is_empty());
    }
}
