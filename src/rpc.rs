use crate::{
    contracts::{AstatineMinerRead, IERC20Read},
    deployment::{DeploymentManifest, NodePin, parse_address, parse_hash},
    diagnostics::DiagnosticBuffer,
    protocol::{WorkContext, WorkHasher, meets_target, work_domain_v2},
};
use alloy_primitives::{Address, B256, Bytes, U256, hex, keccak256};
use alloy_sol_types::{SolCall, SolEvent, SolType, SolValue};
use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde::{Deserialize, de::DeserializeOwned};
use std::{collections::HashMap, time::Duration};
use tokio::task::JoinSet;

#[cfg(test)]
use crate::deployment::TokenPin;

const RPC_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_RPC_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_LOG_QUERY_RANGE: u64 = 10_000;
const SUBMISSION_FEE_WEI: u128 = 10_000_000_000_000_000;
const ABI_PROBE_NONCE: u128 = u128::MAX - 7;

#[derive(Clone, Debug)]
pub struct WorkInfo {
    pub started: bool,
    pub ended: bool,
    pub window_id: u64,
    pub window_start_time: u64,
    pub window_expiry_time: u64,
    pub seed: B256,
    pub prev_hash: B256,
    pub target: U256,
    pub reward_per_window: U256,
    pub remaining_allocation: U256,
    pub max_header_length: u32,
    pub submission_fee: U256,
}

#[derive(Clone, Debug)]
pub struct CandidateInfo {
    pub miner: Address,
    pub nonce: u128,
    pub work_hash: B256,
    pub submitted_at: u64,
    pub header: Bytes,
    pub first_valid_solve_secs: u64,
}

#[derive(Clone, Debug)]
pub struct MiningInfo {
    pub started: bool,
    pub ended: bool,
    pub window_id: u64,
    pub reward_per_window: U256,
    pub target: U256,
    pub seed: B256,
    pub prev_hash: B256,
}

#[derive(Clone, Debug)]
pub struct NodeState {
    pub work: WorkInfo,
    pub candidate: Option<CandidateInfo>,
    pub mining_paused: bool,
    pub eligible: bool,
    pub finalizable: bool,
    pub eligibility_reason: &'static str,
}

#[derive(Clone, Debug)]
pub struct FeeQuote {
    pub gas_limit: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RpcLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_number: Option<u64>,
    pub block_hash: Option<B256>,
}

#[derive(Clone, Debug)]
pub struct TransactionReceipt {
    pub transaction_hash: B256,
    pub status: bool,
    pub gas_used: U256,
    pub effective_gas_price: Option<U256>,
    pub block_number: u64,
    pub block_hash: B256,
    pub logs: Vec<RpcLog>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptJson {
    transaction_hash: String,
    status: String,
    gas_used: String,
    effective_gas_price: Option<String>,
    block_number: String,
    block_hash: String,
    logs: Vec<ReceiptLogJson>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptLogJson {
    address: String,
    topics: Vec<String>,
    data: String,
    block_number: Option<String>,
    block_hash: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionSenderJson {
    hash: String,
    from: String,
}

impl TryFrom<ReceiptJson> for TransactionReceipt {
    type Error = anyhow::Error;

    fn try_from(receipt: ReceiptJson) -> Result<Self> {
        let logs = receipt
            .logs
            .into_iter()
            .map(parse_rpc_log)
            .collect::<Result<Vec<_>>>()?;
        let status = parse_hex_quantity(&receipt.status)?;
        if status > 1 {
            bail!("transaction receipt status must be 0 or 1");
        }
        Ok(Self {
            transaction_hash: parse_hash(&receipt.transaction_hash)?,
            status: status == 1,
            gas_used: parse_hex_u256(&receipt.gas_used)?,
            effective_gas_price: receipt
                .effective_gas_price
                .as_deref()
                .map(parse_hex_u256)
                .transpose()?,
            block_number: parse_hex_quantity(&receipt.block_number)?,
            block_hash: parse_hash(&receipt.block_hash)?,
            logs,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NodeView {
    pub id: u8,
    pub address: Address,
    pub pin: ContractPinStatus,
    pub state: Option<NodeState>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct BlockSnapshot {
    pub number: u64,
    pub timestamp: u64,
    pub hash: B256,
}

#[derive(Clone, Debug)]
pub struct ReadSnapshot {
    pub block: BlockSnapshot,
    pub native_balance: Option<U256>,
    pub native_balance_error: Option<String>,
    pub ast_balance: Option<U256>,
    pub ast_balance_error: Option<String>,
    pub nodes: Vec<NodeView>,
}

#[derive(Clone, Debug)]
pub struct ContractPinStatus {
    pub runtime_verified: bool,
    pub abi_verified: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
struct RpcEndpoint {
    name: String,
    url: Url,
    client: reqwest::Client,
}

#[derive(Clone, Debug)]
pub struct DeploymentVerification {
    pub token_verified: bool,
    pub reference_snapshot_verified: bool,
    pub nodes: HashMap<u8, ContractPinStatus>,
}

#[derive(Clone, Debug)]
pub struct NetworkClient {
    pub manifest: DeploymentManifest,
    endpoints: Vec<RpcEndpoint>,
    pub verification: DeploymentVerification,
    diagnostics: Option<DiagnosticBuffer>,
}

impl NetworkClient {
    pub async fn connect(network: crate::cli::Network) -> Result<Self> {
        let manifest = DeploymentManifest::load(network)?;
        let configured = std::iter::once(("primary", manifest.primary_rpc.as_str())).chain(
            manifest
                .archival_rpc
                .as_deref()
                .map(|url| ("archival", url)),
        );
        let mut endpoints = Vec::new();

        for (name, url) in configured {
            match connect_endpoint(name, url).await {
                Ok(endpoint) => {
                    match rpc_request::<String>(&endpoint, "eth_chainId", serde_json::json!([]))
                        .await
                        .and_then(|chain| parse_hex_quantity(&chain))
                    {
                        Ok(chain_id) if chain_id == manifest.chain_id => endpoints.push(endpoint),
                        Ok(chain_id) => eprintln!(
                            "RPC {} reports chain ID {}; expected {}. Ignoring endpoint.",
                            endpoint.name, chain_id, manifest.chain_id
                        ),
                        Err(error) => {
                            eprintln!("RPC {} chain-ID check failed: {error:#}", endpoint.name)
                        }
                    }
                }
                Err(error) => eprintln!("RPC {name} unavailable: {error:#}"),
            }
        }
        if endpoints.is_empty() {
            bail!(
                "no configured RPC endpoint reports the expected chain ID {}",
                manifest.chain_id
            );
        }

        let mut client = Self {
            manifest,
            endpoints,
            diagnostics: None,
            verification: DeploymentVerification {
                token_verified: false,
                reference_snapshot_verified: false,
                nodes: HashMap::new(),
            },
        };
        client.verify_deployment().await?;
        Ok(client)
    }

    pub fn set_diagnostics(&mut self, diagnostics: DiagnosticBuffer) {
        self.diagnostics = Some(diagnostics);
    }

    fn report_diagnostic(&self, message: impl Into<String>) {
        let message = message.into();
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.push(message);
        } else {
            eprintln!("{message}");
        }
    }

    pub fn has_mining_deployment(&self) -> bool {
        self.manifest.mining_enabled && self.manifest.nodes.len() == 9
    }

    pub fn can_broadcast(&self) -> bool {
        self.manifest.network == crate::cli::Network::Testnet
            && self
                .endpoints
                .iter()
                .any(|endpoint| endpoint.name == "primary")
    }

    pub async fn verify_node_runtime_at(&self, node_id: u8, block: u64) -> Result<Address> {
        let pin = self
            .manifest
            .nodes
            .iter()
            .find(|pin| pin.id == node_id)
            .with_context(|| format!("node {node_id} is absent from the verified manifest"))?;
        let endpoint = self.primary_endpoint()?;
        let address = parse_address(&pin.address)?;
        let expected_hash = parse_hash(&pin.runtime_code_hash)?;
        let code = get_code(endpoint, address, block).await?;
        if code.is_empty() || keccak256(code) != expected_hash {
            bail!("node {node_id} runtime code no longer matches the approved pin");
        }
        let status = self
            .verification
            .nodes
            .get(&node_id)
            .context("node ABI verification is missing")?;
        if !status.runtime_verified || !status.abi_verified {
            bail!("node {node_id} runtime or ABI verification is not trusted");
        }
        Ok(address)
    }

    pub async fn verify_broadcast_snapshot(&self, snapshot: &BlockSnapshot) -> Result<()> {
        let endpoint = self.primary_endpoint()?;
        let (latest_number, _) = endpoint_block(endpoint).await?;
        if latest_number < snapshot.number {
            bail!(
                "primary RPC is behind the verified work snapshot ({} < {})",
                latest_number,
                snapshot.number
            );
        }
        let primary_block = block_at(endpoint, snapshot.number).await?;
        if primary_block.hash != snapshot.hash {
            bail!("primary RPC disagrees with the verified work snapshot; refusing to broadcast");
        }
        Ok(())
    }

    pub async fn pending_balance(&self, address: Address) -> Result<U256> {
        let result = rpc_request::<String>(
            self.primary_endpoint()?,
            "eth_getBalance",
            serde_json::json!([format!("{address:#x}"), "pending"]),
        )
        .await?;
        parse_hex_u256(&result)
    }

    pub async fn pending_nonce(&self, address: Address) -> Result<u64> {
        let result = rpc_request::<String>(
            self.primary_endpoint()?,
            "eth_getTransactionCount",
            serde_json::json!([format!("{address:#x}"), "pending"]),
        )
        .await?;
        parse_hex_quantity(&result)
    }

    pub async fn fee_quote(
        &self,
        from: Address,
        to: Address,
        value: U256,
        data: &[u8],
    ) -> Result<FeeQuote> {
        let endpoint = self.primary_endpoint()?;
        let transaction = serde_json::json!({
            "from": format!("{from:#x}"),
            "to": format!("{to:#x}"),
            "value": format!("{value:#x}"),
            "data": format!("0x{}", hex::encode(data)),
        });
        let estimate = rpc_request::<String>(
            endpoint,
            "eth_estimateGas",
            serde_json::json!([transaction]),
        )
        .await
        .context("estimate transaction gas")
        .and_then(|value| parse_hex_quantity(&value))?;
        let gas_limit = estimate
            .checked_mul(120)
            .and_then(|value| value.checked_add(99))
            .map(|value| value / 100)
            .context("gas estimate overflow")?;
        if gas_limit == 0 || gas_limit > 10_000_000 {
            bail!("estimated transaction gas is outside the supported 1..=10,000,000 range");
        }

        let block = rpc_request::<serde_json::Value>(
            endpoint,
            "eth_getBlockByNumber",
            serde_json::json!(["latest", false]),
        )
        .await?;
        let base_fee = block
            .get("baseFeePerGas")
            .and_then(serde_json::Value::as_str)
            .context("latest block does not expose EIP-1559 baseFeePerGas")
            .and_then(parse_hex_u256)?;
        let priority = match rpc_request::<String>(
            endpoint,
            "eth_maxPriorityFeePerGas",
            serde_json::json!([]),
        )
        .await
        {
            Ok(value) => parse_hex_u256(&value)?,
            Err(_) => {
                let gas_price =
                    rpc_request::<String>(endpoint, "eth_gasPrice", serde_json::json!([])).await?;
                parse_hex_u256(&gas_price)?
            }
        };
        let max_fee_per_gas = base_fee
            .checked_mul(U256::from(2))
            .and_then(|base| base.checked_add(priority))
            .context("EIP-1559 maximum fee calculation overflow")?;
        Ok(FeeQuote {
            gas_limit,
            max_priority_fee_per_gas: priority,
            max_fee_per_gas,
        })
    }

    pub async fn broadcast_raw_transaction(&self, raw_transaction: &[u8]) -> Result<B256> {
        let result = rpc_request::<String>(
            self.primary_endpoint()?,
            "eth_sendRawTransaction",
            serde_json::json!([format!("0x{}", hex::encode(raw_transaction))]),
        )
        .await?;
        parse_hash(&result).context("RPC returned an invalid transaction hash")
    }

    pub async fn transaction_known(&self, hash: B256) -> Result<bool> {
        let mut saw_pending = false;
        let mut errors = Vec::new();
        for endpoint in &self.endpoints {
            match rpc_request::<Option<serde_json::Value>>(
                endpoint,
                "eth_getTransactionByHash",
                serde_json::json!([format!("{hash:#x}")]),
            )
            .await
            {
                Ok(Some(_)) => return Ok(true),
                Ok(None) => saw_pending = true,
                Err(error) => errors.push(format!("{}: {error:#}", endpoint.name)),
            }
        }
        if !saw_pending && !errors.is_empty() {
            bail!(
                "all configured RPC endpoints failed to look up transaction {hash:#x}: {}",
                errors.join("; ")
            );
        }
        Ok(false)
    }

    pub async fn transaction_sender(&self, hash: B256) -> Result<Option<Address>> {
        let mut sender = None;
        let mut last_error = None;
        for endpoint in &self.endpoints {
            match rpc_request::<Option<TransactionSenderJson>>(
                endpoint,
                "eth_getTransactionByHash",
                serde_json::json!([format!("{hash:#x}")]),
            )
            .await
            {
                Ok(Some(transaction)) => {
                    if parse_hash(&transaction.hash)? != hash {
                        bail!("RPC returned a different transaction while recovering sender");
                    }
                    let observed = parse_address(&transaction.from)?;
                    if sender.is_some_and(|previous| previous != observed) {
                        bail!("RPC endpoints disagree on recovered transaction sender");
                    }
                    sender = Some(observed);
                }
                Ok(None) => {}
                Err(error) => last_error = Some(error),
            }
        }
        if sender.is_some() {
            return Ok(sender);
        }
        if let Some(error) = last_error {
            return Err(error).context("recover transaction sender from configured RPC endpoints");
        }
        Ok(None)
    }

    pub async fn transaction_receipt(&self, hash: B256) -> Result<Option<TransactionReceipt>> {
        let mut endpoint_errors = Vec::new();
        let mut verified_receipt = None;
        let mut saw_pending = false;
        for endpoint in &self.endpoints {
            match rpc_request::<Option<ReceiptJson>>(
                endpoint,
                "eth_getTransactionReceipt",
                serde_json::json!([format!("{hash:#x}")]),
            )
            .await
            {
                Ok(Some(receipt)) => {
                    let receipt = TransactionReceipt::try_from(receipt).with_context(|| {
                        format!("decode transaction receipt from {}", endpoint.name)
                    })?;
                    if let Some(previous) = &mut verified_receipt {
                        if !receipts_agree(previous, &receipt) {
                            bail!(
                                "RPC endpoints disagree on transaction receipt {hash:#x}; refusing an uncorroborated result"
                            );
                        }
                        if previous.effective_gas_price.is_none() {
                            previous.effective_gas_price = receipt.effective_gas_price;
                        }
                    } else {
                        verified_receipt = Some(receipt);
                    }
                }
                Ok(None) => saw_pending = true,
                Err(error) => endpoint_errors.push(format!("{}: {error:#}", endpoint.name)),
            }
        }
        if let Some(receipt) = verified_receipt {
            return Ok(Some(receipt));
        }
        if saw_pending && endpoint_errors.is_empty() {
            return Ok(None);
        }
        if !endpoint_errors.is_empty() {
            let status = if saw_pending {
                "some endpoints returned pending while other endpoints failed"
            } else {
                "all configured endpoints failed"
            };
            return Err(anyhow::Error::new(ReceiptStatusUnavailable {
                details: format!("{status}: {}", endpoint_errors.join("; ")),
            }))
            .context("read transaction receipt from configured RPC endpoints");
        }
        Ok(None)
    }

    pub async fn window_finalization_logs(
        &self,
        address: Address,
        token: Address,
        window_id: u64,
        from_block: u64,
    ) -> Result<Vec<RpcLog>> {
        let mut errors = Vec::new();
        let mut found_empty = false;
        for endpoint in &self.endpoints {
            match window_finalization_logs_at(endpoint, address, token, window_id, from_block).await
            {
                Ok(logs) if !logs.is_empty() => return Ok(logs),
                Ok(_) => found_empty = true,
                Err(error) => errors.push(format!("{}: {error:#}", endpoint.name)),
            }
        }
        if found_empty && errors.is_empty() {
            return Ok(Vec::new());
        }
        bail!(
            "configured RPCs could not confirm finalization logs: {}",
            errors.join("; ")
        )
    }

    pub async fn primary_nonce(&self, address: Address, block_tag: &str) -> Result<u64> {
        let result = rpc_request::<String>(
            self.primary_endpoint()?,
            "eth_getTransactionCount",
            serde_json::json!([format!("{address:#x}"), block_tag]),
        )
        .await?;
        parse_hex_quantity(&result)
    }

    pub async fn latest_block_snapshot(&self) -> Result<BlockSnapshot> {
        self.best_block().await.map(|(_, block)| block)
    }

    pub async fn canonical_block_hash(&self, block_number: u64) -> Result<B256> {
        let primary = self.primary_endpoint()?;
        let canonical = block_at(primary, block_number).await?.hash;
        for endpoint in &self.endpoints {
            if endpoint.name == "primary" {
                continue;
            }
            match block_at(endpoint, block_number).await {
                Ok(block) if block.hash == canonical => {}
                Ok(_) => bail!(
                    "RPC {} disagrees with the primary block hash at {block_number}; refusing to settle the receipt",
                    endpoint.name
                ),
                Err(error) => self.report_diagnostic(format!(
                    "RPC {} cannot corroborate block {block_number}: {error:#}",
                    endpoint.name
                )),
            }
        }
        Ok(canonical)
    }

    pub async fn receipt_confirmations(
        &self,
        block_number: u64,
        block_hash: B256,
        latest_block_number: u64,
    ) -> Result<Option<u64>> {
        if latest_block_number < block_number {
            return Ok(Some(0));
        }
        // Count confirmations only against a head the transaction's primary RPC can
        // serve and that configured archival endpoints do not contradict. A faster
        // archive must not settle receipts while the primary is still behind.
        self.canonical_block_hash(latest_block_number).await?;
        let canonical_hash = self.canonical_block_hash(block_number).await?;
        if canonical_hash != block_hash {
            return Ok(None);
        }
        Ok(Some(
            latest_block_number
                .saturating_sub(block_number)
                .saturating_add(1),
        ))
    }

    fn primary_endpoint(&self) -> Result<&RpcEndpoint> {
        self.endpoints
            .iter()
            .find(|endpoint| endpoint.name == "primary")
            .context("configured primary RPC is unavailable; refusing to broadcast")
    }

    #[cfg(test)]
    pub(crate) fn local_test_client(
        url: &str,
        miner: Address,
        miner_runtime_hash: B256,
        token: Address,
        token_runtime_hash: B256,
        token_decimals: u8,
    ) -> Result<Self> {
        Self::local_test_client_with_nodes(
            url,
            &[(1, miner, miner_runtime_hash)],
            token,
            token_runtime_hash,
            token_decimals,
        )
    }

    #[cfg(test)]
    pub(crate) fn local_test_client_with_nodes(
        url: &str,
        miners: &[(u8, Address, B256)],
        token: Address,
        token_runtime_hash: B256,
        token_decimals: u8,
    ) -> Result<Self> {
        let endpoint = RpcEndpoint {
            name: "primary".to_owned(),
            url: Url::parse(url).context("parse local Anvil URL")?,
            client: reqwest::Client::builder()
                .timeout(RPC_TIMEOUT)
                .build()
                .context("create local Anvil RPC client")?,
        };
        let manifest = DeploymentManifest {
            schema_version: 1,
            network: crate::cli::Network::Testnet,
            chain_id: 1439,
            native_symbol: "INJ".to_owned(),
            native_decimals: 18,
            primary_rpc: url.to_owned(),
            archival_rpc: None,
            mining_enabled: true,
            solidity_source: None,
            reference_snapshot: None,
            ast_token: Some(TokenPin {
                address: format!("{token:#x}"),
                decimals: token_decimals,
                runtime_code_hash: format!("{token_runtime_hash:#x}"),
            }),
            nodes: miners
                .iter()
                .map(|(id, address, runtime_hash)| NodePin {
                    id: *id,
                    address: format!("{address:#x}"),
                    runtime_code_hash: format!("{runtime_hash:#x}"),
                })
                .collect(),
        };
        Ok(Self {
            manifest,
            endpoints: vec![endpoint],
            diagnostics: None,
            verification: DeploymentVerification {
                token_verified: true,
                reference_snapshot_verified: false,
                nodes: miners
                    .iter()
                    .map(|(id, _, _)| {
                        (
                            *id,
                            ContractPinStatus {
                                runtime_verified: true,
                                abi_verified: true,
                                error: None,
                            },
                        )
                    })
                    .collect(),
            },
        })
    }

    async fn verify_deployment(&mut self) -> Result<()> {
        let (endpoints, block) = self.best_block().await?;
        let endpoint = &endpoints[0];
        self.verification.reference_snapshot_verified = self.verify_reference_snapshot().await;
        if self.manifest.reference_snapshot.is_some()
            && !self.verification.reference_snapshot_verified
        {
            self.report_diagnostic(
                "Historical reference block was unavailable or did not match; live runtime pins are still required."
                    .to_owned(),
            );
        }

        if let Some(token) = &self.manifest.ast_token {
            self.verification.token_verified =
                self.verify_token_pin(endpoint, block.number, token).await;
        }

        for pin in self.manifest.nodes.clone() {
            self.verification
                .nodes
                .insert(pin.id, self.verify_node_pin(endpoint, &block, &pin).await);
        }
        Ok(())
    }

    async fn verify_reference_snapshot(&self) -> bool {
        let Some(snapshot) = &self.manifest.reference_snapshot else {
            return false;
        };
        let Ok(expected_hash) = parse_hash(&snapshot.block_hash) else {
            return false;
        };
        for endpoint in &self.endpoints {
            if let Ok(block) = block_at(endpoint, snapshot.block_number).await
                && block.hash == expected_hash
            {
                return true;
            }
        }
        false
    }

    async fn verify_token_pin(
        &self,
        endpoint: &RpcEndpoint,
        block: u64,
        token: &crate::deployment::TokenPin,
    ) -> bool {
        let check = async {
            let address = parse_address(&token.address)?;
            let expected_hash = parse_hash(&token.runtime_code_hash)?;
            let code = get_code(endpoint, address, block).await?;
            if code.is_empty() || keccak256(code) != expected_hash {
                bail!("AST token runtime hash does not match the deployment pin");
            }
            let decimals =
                call_contract(endpoint, address, IERC20Read::decimalsCall {}, block).await?;
            if decode_return::<u64>(&decimals)? != u64::from(token.decimals) {
                bail!("AST token decimals do not match the deployment pin");
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        match check {
            Ok(()) => true,
            Err(error) => {
                self.report_diagnostic(format!("AST token is unverified: {error:#}"));
                false
            }
        }
    }

    async fn verify_node_pin(
        &self,
        endpoint: &RpcEndpoint,
        block: &BlockSnapshot,
        pin: &NodePin,
    ) -> ContractPinStatus {
        let runtime_check = async {
            let address = parse_address(&pin.address)?;
            let expected_hash = parse_hash(&pin.runtime_code_hash)?;
            let code = get_code(endpoint, address, block.number)
                .await
                .with_context(|| format!("eth_getCode(node {})", pin.id))?;
            if code.is_empty() || keccak256(code) != expected_hash {
                bail!("runtime code hash does not match the deployment pin");
            }
            Ok::<Address, anyhow::Error>(address)
        }
        .await;
        let address = match runtime_check {
            Ok(address) => address,
            Err(error) => {
                return ContractPinStatus {
                    runtime_verified: false,
                    abi_verified: false,
                    error: Some(format!("{error:#}")),
                };
            }
        };

        let abi_check = async {
            let state = fetch_node(endpoint, &self.manifest, address, block).await?;
            let has_best_bytes = call_contract(
                endpoint,
                address,
                AstatineMinerRead::hasBestCall {},
                block.number,
            )
            .await?;
            if decode_return::<bool>(&has_best_bytes)? != state.candidate.is_some() {
                bail!("candidateSummary and hasBest disagree");
            }
            if let Some(token) = &self.manifest.ast_token {
                let token_bytes = call_contract(
                    endpoint,
                    address,
                    AstatineMinerRead::astTokenCall {},
                    block.number,
                )
                .await?;
                if decode_return::<Address>(&token_bytes)? != parse_address(&token.address)? {
                    bail!("miner AST token does not match its deployment manifest");
                }
            }
            let domain_bytes = call_contract(
                endpoint,
                address,
                AstatineMinerRead::WORK_DOMAIN_V2Call {},
                block.number,
            )
            .await?;
            if decode_return::<B256>(&domain_bytes)? != work_domain_v2() {
                bail!("WORK_DOMAIN_V2 does not match the canonical Rust codec");
            }
            if state.work.started && !state.work.ended {
                let context = WorkContext {
                    chain_id: self.manifest.chain_id,
                    contract: address,
                    window_id: state.work.window_id,
                    seed: state.work.seed,
                    miner: Address::ZERO,
                    header: Vec::new(),
                };
                let nonce = ABI_PROBE_NONCE;
                let local_hash = WorkHasher::new(&context)?.hash(nonce);
                let remote_bytes = call_contract(
                    endpoint,
                    address,
                    AstatineMinerRead::computeWorkHashCall {
                        miner: Address::ZERO,
                        nonce,
                        header: Bytes::new(),
                    },
                    block.number,
                )
                .await?;
                if decode_return::<B256>(&remote_bytes)? != local_hash {
                    bail!("computeWorkHash disagrees with the canonical Rust implementation");
                }
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;

        match abi_check {
            Ok(()) => ContractPinStatus {
                runtime_verified: true,
                abi_verified: true,
                error: None,
            },
            Err(error) => ContractPinStatus {
                runtime_verified: true,
                abi_verified: false,
                error: Some(format!("ABI/protocol verification failed: {error:#}")),
            },
        }
    }

    pub async fn snapshot(&self, wallet: Option<Address>) -> Result<ReadSnapshot> {
        let (endpoints, block) = self.best_block().await?;
        let endpoint = endpoints[0].clone();
        let mut node_jobs = JoinSet::new();
        for pin in self.manifest.nodes.clone() {
            let endpoints = endpoints.clone();
            let pin_status = self
                .verification
                .nodes
                .get(&pin.id)
                .cloned()
                .unwrap_or_else(|| ContractPinStatus {
                    runtime_verified: false,
                    abi_verified: false,
                    error: Some("runtime verification did not complete".to_owned()),
                });
            let manifest = self.manifest.clone();
            let block = block.clone();
            node_jobs.spawn(async move {
                fetch_node_from_endpoints(&endpoints, &manifest, pin, pin_status, block).await
            });
        }

        let mut nodes = Vec::with_capacity(self.manifest.nodes.len());
        while let Some(joined) = node_jobs.join_next().await {
            match joined {
                Ok(node) => nodes.push(node),
                Err(error) => self.report_diagnostic(format!("node reader task failed: {error}")),
            }
        }
        nodes.sort_by_key(|node| node.id);

        let (native_balance, native_balance_error) = if let Some(address) = wallet {
            match get_balance(&endpoint, address, block.number).await {
                Ok(balance) => (Some(balance), None),
                Err(error) => (None, Some(format!("{error:#}"))),
            }
        } else {
            (None, None)
        };
        let (ast_balance, ast_balance_error) = match (&self.manifest.ast_token, wallet) {
            (Some(token), Some(address)) if self.verification.token_verified => {
                let token_address = parse_address(&token.address)?;
                match call_contract(
                    &endpoint,
                    token_address,
                    IERC20Read::balanceOfCall { account: address },
                    block.number,
                )
                .await
                {
                    Ok(value) => match decode_return::<U256>(&value) {
                        Ok(balance) => (Some(balance), None),
                        Err(error) => (None, Some(error.to_string())),
                    },
                    Err(error) => (None, Some(format!("{error:#}"))),
                }
            }
            (Some(_), Some(_)) => (
                None,
                Some("AST token runtime pin is not verified".to_owned()),
            ),
            _ => (None, None),
        };

        for source in &endpoints {
            let current = block_at(source, block.number).await?;
            if current.hash != block.hash {
                bail!(
                    "RPC {} changed block {} while reading; discarding stale snapshot",
                    source.name,
                    block.number
                );
            }
        }

        Ok(ReadSnapshot {
            block,
            native_balance,
            native_balance_error,
            ast_balance,
            ast_balance_error,
            nodes,
        })
    }

    async fn best_block(&self) -> Result<(Vec<RpcEndpoint>, BlockSnapshot)> {
        let mut candidates = Vec::new();
        let mut errors = Vec::new();
        for endpoint in &self.endpoints {
            match endpoint_block(endpoint).await {
                Ok((number, block)) => candidates.push((endpoint.clone(), number, block)),
                Err(error) => errors.push(format!("{}: {error:#}", endpoint.name)),
            }
        }
        candidates.sort_by_key(|(_, number, _)| std::cmp::Reverse(*number));
        let Some((best_endpoint, best_number, best_block)) = candidates.first().cloned() else {
            bail!("all configured RPCs failed: {}", errors.join("; "));
        };
        for (_, number, other_block) in &candidates {
            if *number == best_number && other_block.hash != best_block.hash {
                bail!(
                    "RPC endpoints disagree on block {best_number}; refusing potentially forked work"
                );
            }
        }
        let mut snapshot_endpoints = Vec::with_capacity(candidates.len());
        for (candidate, number, candidate_block) in candidates {
            if number == best_number && candidate_block.hash == best_block.hash {
                snapshot_endpoints.push(candidate);
                continue;
            }
            match block_at(&candidate, best_number).await {
                Ok(block) if block.hash == best_block.hash => snapshot_endpoints.push(candidate),
                Ok(_) => self.report_diagnostic(format!(
                    "RPC {} disagrees with snapshot block {}; excluding it for this read.",
                    candidate.name, best_number
                )),
                Err(error) => self.report_diagnostic(format!(
                    "RPC {} cannot serve snapshot block {}: {error:#}",
                    candidate.name, best_number
                )),
            }
        }
        if snapshot_endpoints.is_empty() {
            bail!("no RPC endpoint can serve the selected canonical snapshot block");
        }
        // Keep the newest endpoint first for balances and final reorg validation.
        if let Some(index) = snapshot_endpoints
            .iter()
            .position(|candidate| candidate.name == best_endpoint.name)
        {
            snapshot_endpoints.swap(0, index);
        }
        Ok((snapshot_endpoints, best_block))
    }
}

fn receipts_agree(left: &TransactionReceipt, right: &TransactionReceipt) -> bool {
    left.transaction_hash == right.transaction_hash
        && left.status == right.status
        && left.gas_used == right.gas_used
        && left.block_number == right.block_number
        && left.block_hash == right.block_hash
        && (left.effective_gas_price.is_none()
            || right.effective_gas_price.is_none()
            || left.effective_gas_price == right.effective_gas_price)
        && left.logs == right.logs
}

fn parse_rpc_log(log: ReceiptLogJson) -> Result<RpcLog> {
    let topics = log
        .topics
        .iter()
        .map(|topic| parse_hash(topic))
        .collect::<Result<Vec<_>>>()?;
    let data = log
        .data
        .strip_prefix("0x")
        .context("receipt log data has no 0x prefix")?;
    Ok(RpcLog {
        address: parse_address(&log.address)?,
        topics,
        data: Bytes::from(hex::decode(data).context("decode receipt log data")?),
        block_number: log
            .block_number
            .as_deref()
            .map(parse_hex_quantity)
            .transpose()?,
        block_hash: log.block_hash.as_deref().map(parse_hash).transpose()?,
    })
}

async fn window_finalization_logs_at(
    endpoint: &RpcEndpoint,
    address: Address,
    token: Address,
    window_id: u64,
    from_block: u64,
) -> Result<Vec<RpcLog>> {
    let latest = rpc_request::<String>(endpoint, "eth_blockNumber", serde_json::json!([]))
        .await
        .and_then(|value| parse_hex_quantity(&value))?;
    if latest < from_block {
        return Ok(Vec::new());
    }
    let window_topic = B256::from(U256::from(window_id).to_be_bytes::<32>());
    let topics = serde_json::json!([
        [
            format!("{:#x}", AstatineMinerRead::WindowFinalized::SIGNATURE_HASH),
            format!("{:#x}", AstatineMinerRead::RewardPaid::SIGNATURE_HASH),
        ],
        format!("{window_topic:#x}"),
    ]);
    let mut from_topic = [0_u8; 32];
    from_topic[12..].copy_from_slice(address.as_slice());
    let transfer_topics = serde_json::json!([
        format!("{:#x}", IERC20Read::Transfer::SIGNATURE_HASH),
        format!("{:#x}", B256::from(from_topic)),
    ]);
    let mut results = Vec::new();
    let mut start = from_block;
    loop {
        let end = start.saturating_add(MAX_LOG_QUERY_RANGE - 1).min(latest);
        let logs = rpc_request::<Vec<ReceiptLogJson>>(
            endpoint,
            "eth_getLogs",
            serde_json::json!([{
                "address": format!("{address:#x}"),
                "fromBlock": format!("0x{start:x}"),
                "toBlock": format!("0x{end:x}"),
                "topics": topics,
            }]),
        )
        .await
        .with_context(|| format!("query finalization logs for node window {window_id}"))?;
        results.extend(
            logs.into_iter()
                .map(parse_rpc_log)
                .collect::<Result<Vec<_>>>()?,
        );
        let transfers = rpc_request::<Vec<ReceiptLogJson>>(
            endpoint,
            "eth_getLogs",
            serde_json::json!([{
                "address": format!("{token:#x}"),
                "fromBlock": format!("0x{start:x}"),
                "toBlock": format!("0x{end:x}"),
                "topics": transfer_topics,
            }]),
        )
        .await
        .with_context(|| format!("query AST Transfer logs for node window {window_id}"))?;
        results.extend(
            transfers
                .into_iter()
                .map(parse_rpc_log)
                .collect::<Result<Vec<_>>>()?,
        );
        if end == latest {
            break;
        }
        start = end
            .checked_add(1)
            .context("log query block range overflow")?;
    }
    Ok(results)
}

async fn connect_endpoint(name: &str, url: &str) -> Result<RpcEndpoint> {
    let url = Url::parse(url).context("parse RPC endpoint URL")?;
    if url.scheme() != "https" {
        bail!("refusing non-HTTPS RPC endpoint");
    }
    let client = reqwest::Client::builder()
        .timeout(RPC_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("create HTTPS JSON-RPC client")?;
    Ok(RpcEndpoint {
        name: name.to_owned(),
        url,
        client,
    })
}

async fn endpoint_block(endpoint: &RpcEndpoint) -> Result<(u64, BlockSnapshot)> {
    let number = rpc_request::<String>(endpoint, "eth_blockNumber", serde_json::json!([]))
        .await
        .and_then(|value| parse_hex_quantity(&value))
        .with_context(|| format!("read latest block from {}", endpoint.name))?;
    Ok((number, block_at(endpoint, number).await?))
}

async fn block_at(endpoint: &RpcEndpoint, number: u64) -> Result<BlockSnapshot> {
    let tag = format!("0x{number:x}");
    let block = rpc_request::<serde_json::Value>(
        endpoint,
        "eth_getBlockByNumber",
        serde_json::json!([tag, false]),
    )
    .await?;
    let timestamp = parse_hex_quantity(
        block
            .get("timestamp")
            .and_then(serde_json::Value::as_str)
            .context("block response has no timestamp")?,
    )?;
    let observed_number = parse_hex_quantity(
        block
            .get("number")
            .and_then(serde_json::Value::as_str)
            .context("block response has no number")?,
    )?;
    if observed_number != number {
        bail!("RPC returned block {observed_number} for requested block {number}");
    }
    let hash = parse_hash(
        block
            .get("hash")
            .and_then(serde_json::Value::as_str)
            .context("block response has no hash")?,
    )?;
    Ok(BlockSnapshot {
        number,
        timestamp,
        hash,
    })
}

#[derive(Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct RpcResponse<T> {
    #[serde(default)]
    result: RpcResult<T>,
    error: Option<RpcError>,
}

#[derive(Default)]
enum RpcResult<T> {
    #[default]
    Missing,
    Present(T),
}

impl<'de, T> Deserialize<'de> for RpcResult<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        T::deserialize(deserializer).map(Self::Present)
    }
}

impl<T> RpcResponse<T> {
    fn result(self) -> Option<T> {
        match self.result {
            RpcResult::Missing => None,
            RpcResult::Present(result) => Some(result),
        }
    }
}

#[derive(Debug)]
struct ReceiptStatusUnavailable {
    details: String,
}

impl std::fmt::Display for ReceiptStatusUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "receipt status unavailable: {}", self.details)
    }
}

impl std::error::Error for ReceiptStatusUnavailable {}

pub fn is_transient_receipt_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<ReceiptStatusUnavailable>().is_some())
}

#[derive(Deserialize)]
struct RpcError {
    code: i64,
    message: String,
}

async fn rpc_request<T: DeserializeOwned>(
    endpoint: &RpcEndpoint,
    method: &str,
    params: serde_json::Value,
) -> Result<T> {
    let mut response = endpoint
        .client
        .post(endpoint.url.clone())
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .with_context(|| format!("send {method} JSON-RPC request to {}", endpoint.name))?
        .error_for_status()
        .with_context(|| format!("{method} returned an HTTP error from {}", endpoint.name))?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES as u64)
    {
        bail!(
            "{method} response from {} exceeds the 2 MiB limit",
            endpoint.name
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("read {method} JSON-RPC response from {}", endpoint.name))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RPC_RESPONSE_BYTES {
            bail!(
                "{method} response from {} exceeds the 2 MiB limit",
                endpoint.name
            );
        }
        body.extend_from_slice(&chunk);
    }
    let response: RpcResponse<T> = serde_json::from_slice(&body)
        .with_context(|| format!("decode {method} JSON-RPC response from {}", endpoint.name))?;
    if let Some(error) = response.error {
        bail!("{method} JSON-RPC error {}: {}", error.code, error.message);
    }
    response
        .result()
        .with_context(|| format!("{method} JSON-RPC response has no result"))
}

async fn get_code(endpoint: &RpcEndpoint, address: Address, block: u64) -> Result<Bytes> {
    let result = rpc_request::<String>(
        endpoint,
        "eth_getCode",
        serde_json::json!([format!("{address:#x}"), format!("0x{block:x}")]),
    )
    .await?;
    let digits = result
        .strip_prefix("0x")
        .context("eth_getCode returned a value without a 0x prefix")?;
    Ok(Bytes::from(
        hex::decode(digits).context("eth_getCode returned malformed hex")?,
    ))
}

async fn get_balance(endpoint: &RpcEndpoint, address: Address, block: u64) -> Result<U256> {
    let result = rpc_request::<String>(
        endpoint,
        "eth_getBalance",
        serde_json::json!([format!("{address:#x}"), format!("0x{block:x}")]),
    )
    .await?;
    parse_hex_u256(&result)
}

async fn fetch_node_from_endpoints(
    endpoints: &[RpcEndpoint],
    manifest: &DeploymentManifest,
    pin: NodePin,
    pin_status: ContractPinStatus,
    block: BlockSnapshot,
) -> NodeView {
    let address = match parse_address(&pin.address) {
        Ok(address) => address,
        Err(error) => {
            return NodeView::unavailable(pin.id, Address::ZERO, pin_status, error.to_string());
        }
    };
    if !pin_status.runtime_verified || !pin_status.abi_verified {
        return NodeView::unavailable(
            pin.id,
            address,
            pin_status.clone(),
            pin_status
                .error
                .clone()
                .unwrap_or_else(|| "runtime or ABI pin is not trusted".to_owned()),
        );
    }

    let mut last_error = None;
    for endpoint in endpoints {
        match fetch_node(endpoint, manifest, address, &block).await {
            Ok(state) => {
                return NodeView {
                    id: pin.id,
                    address,
                    pin: pin_status,
                    state: Some(state),
                    error: None,
                };
            }
            Err(error) => last_error = Some(format!("{}: {error:#}", endpoint.name)),
        }
    }
    NodeView::unavailable(
        pin.id,
        address,
        pin_status,
        last_error.unwrap_or_else(|| "no verified RPC endpoint".to_owned()),
    )
}

impl NodeView {
    fn unavailable(id: u8, address: Address, pin: ContractPinStatus, error: String) -> Self {
        Self {
            id,
            address,
            pin,
            state: None,
            error: Some(error),
        }
    }
}

async fn fetch_node(
    endpoint: &RpcEndpoint,
    manifest: &DeploymentManifest,
    address: Address,
    block: &BlockSnapshot,
) -> Result<NodeState> {
    let (work_bytes, candidate_bytes, mining_bytes, paused_bytes) = tokio::try_join!(
        call_contract(
            endpoint,
            address,
            AstatineMinerRead::workCall {},
            block.number
        ),
        call_contract(
            endpoint,
            address,
            AstatineMinerRead::candidateSummaryCall {},
            block.number
        ),
        call_contract(
            endpoint,
            address,
            AstatineMinerRead::miningStateCall {},
            block.number
        ),
        call_contract(
            endpoint,
            address,
            AstatineMinerRead::miningPausedCall {},
            block.number
        ),
    )?;
    let work = decode_work(&work_bytes)?;
    let candidate = decode_candidate(&candidate_bytes)?;
    let mining = decode_mining(&mining_bytes)?;
    let mining_paused = decode_return::<bool>(&paused_bytes)?;
    validate_coherent_state(&work, &mining)?;
    if work.submission_fee != U256::from(SUBMISSION_FEE_WEI) {
        bail!("on-chain submission fee does not match the 0.01 INJ protocol constant");
    }
    if let Some(candidate) = &candidate {
        if candidate.header.len() > work.max_header_length as usize {
            bail!("incumbent header exceeds the on-chain maximum header length");
        }
        let context = WorkContext {
            chain_id: manifest.chain_id,
            contract: address,
            window_id: work.window_id,
            seed: work.seed,
            miner: candidate.miner,
            header: candidate.header.to_vec(),
        };
        let local_hash = WorkHasher::new(&context)?.hash(candidate.nonce);
        if local_hash != candidate.work_hash || !meets_target(local_hash, work.target) {
            bail!("incumbent candidate does not match the current seed/target state");
        }
    }
    let eligible = work.started
        && !work.ended
        && !mining_paused
        && block.timestamp <= work.window_expiry_time
        && !work.remaining_allocation.is_zero();
    let finalizable =
        work.started && !work.ended && !mining_paused && block.timestamp > work.window_expiry_time;
    let eligibility_reason = if !work.started {
        "not started"
    } else if work.ended || work.remaining_allocation.is_zero() {
        "ended or allocation exhausted"
    } else if mining_paused {
        "paused"
    } else if block.timestamp > work.window_expiry_time {
        "window expired; awaiting permissionless finalization"
    } else {
        "eligible"
    };
    Ok(NodeState {
        work,
        candidate,
        mining_paused,
        eligible,
        finalizable,
        eligibility_reason,
    })
}

fn validate_coherent_state(work: &WorkInfo, mining: &MiningInfo) -> Result<()> {
    if work.started != mining.started
        || work.ended != mining.ended
        || work.window_id != mining.window_id
        || work.seed != mining.seed
        || work.prev_hash != mining.prev_hash
        || work.target != mining.target
        || work.reward_per_window != mining.reward_per_window
    {
        bail!("work() and miningState() disagree at the same block");
    }
    if work.window_expiry_time < work.window_start_time
        || work.max_header_length == 0
        || work.max_header_length as usize > crate::protocol::MAX_HEADER_LENGTH
    {
        bail!("miner returned invalid window/header bounds");
    }
    Ok(())
}

async fn call_contract<C: SolCall>(
    endpoint: &RpcEndpoint,
    address: Address,
    call: C,
    block: u64,
) -> Result<Bytes> {
    let input = format!("0x{}", hex::encode(call.abi_encode()));
    let output = rpc_request::<String>(
        endpoint,
        "eth_call",
        serde_json::json!([
            { "to": format!("{address:#x}"), "data": input },
            format!("0x{block:x}")
        ]),
    )
    .await
    .with_context(|| format!("read contract {address:#x}"))?;
    let digits = output
        .strip_prefix("0x")
        .context("eth_call returned a value without a 0x prefix")?;
    Ok(Bytes::from(
        hex::decode(digits).context("eth_call returned malformed hex")?,
    ))
}

fn decode_work(data: &[u8]) -> Result<WorkInfo> {
    type Return = (
        bool,
        bool,
        u64,
        u64,
        u64,
        B256,
        B256,
        U256,
        U256,
        U256,
        u32,
        U256,
    );
    let (
        started,
        ended,
        window_id,
        window_start_time,
        window_expiry_time,
        seed,
        prev_hash,
        target,
        reward_per_window,
        remaining_allocation,
        max_header_length,
        submission_fee,
    ) = <Return as SolValue>::abi_decode_validate(data).context("decode work() ABI return")?;
    Ok(WorkInfo {
        started,
        ended,
        window_id,
        window_start_time,
        window_expiry_time,
        seed,
        prev_hash,
        target,
        reward_per_window,
        remaining_allocation,
        max_header_length,
        submission_fee,
    })
}

fn decode_candidate(data: &[u8]) -> Result<Option<CandidateInfo>> {
    let summary = AstatineMinerRead::candidateSummaryCall::abi_decode_returns_validate(data)
        .context("decode candidateSummary() ABI return")?;
    if !summary.exists {
        if summary.header.is_empty() {
            return Ok(None);
        }
        bail!("empty candidate state contains a nonempty header");
    }
    Ok(Some(CandidateInfo {
        miner: summary.miner,
        nonce: summary.nonce,
        work_hash: summary.workHash,
        submitted_at: summary.submittedAt,
        header: summary.header,
        first_valid_solve_secs: summary.firstValidSolveSecs,
    }))
}

fn decode_mining(data: &[u8]) -> Result<MiningInfo> {
    type Return = (
        bool,
        bool,
        u64,
        u64,
        u64,
        u16,
        U256,
        U256,
        U256,
        U256,
        B256,
        B256,
    );
    let (
        started,
        ended,
        window_id,
        _last_retarget_window_id,
        _ema_solve_secs,
        _halving_index,
        reward_per_window,
        _total_distributed,
        _next_halving_threshold,
        target,
        seed,
        prev_hash,
    ) = <Return as SolValue>::abi_decode_validate(data)
        .context("decode miningState() ABI return")?;
    Ok(MiningInfo {
        started,
        ended,
        window_id,
        reward_per_window,
        target,
        seed,
        prev_hash,
    })
}

fn decode_return<T>(data: &[u8]) -> Result<T>
where
    T: SolValue + From<<T::SolType as SolType>::RustType>,
{
    T::abi_decode_validate(data).context("decode Solidity view return")
}

fn parse_hex_quantity(value: &str) -> Result<u64> {
    let digits = value
        .strip_prefix("0x")
        .context("RPC quantity has no 0x prefix")?;
    u64::from_str_radix(digits, 16).context("RPC quantity is outside uint64")
}

fn parse_hex_u256(value: &str) -> Result<U256> {
    let digits = value
        .strip_prefix("0x")
        .context("RPC quantity has no 0x prefix")?;
    U256::from_str_radix(digits, 16).context("RPC quantity is outside uint256")
}

#[cfg(test)]
mod tests {
    use super::{
        NetworkClient, RpcEndpoint, RpcResponse, RpcResult, SUBMISSION_FEE_WEI, decode_candidate,
        decode_mining, decode_work, is_transient_receipt_error, rpc_request,
    };
    use alloy_primitives::{Address, B256, Bytes, U256};
    use alloy_sol_types::{SolCall, SolValue};
    use reqwest::Url;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread::{self, JoinHandle},
        time::Duration,
    };

    fn mock_endpoint(name: &str, responses: Vec<(u16, String)>) -> (RpcEndpoint, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                read_http_request(&mut stream);
                let reason = if status == 200 {
                    "OK"
                } else {
                    "Service Unavailable"
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let endpoint = RpcEndpoint {
            name: name.to_owned(),
            url: Url::parse(&format!("http://{address}")).unwrap(),
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
        };
        (endpoint, server)
    }

    fn read_http_request(stream: &mut TcpStream) {
        let mut received = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let count = stream.read(&mut chunk).unwrap();
            assert_ne!(count, 0, "RPC client closed before sending its request");
            received.extend_from_slice(&chunk[..count]);
            let Some(header_end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n")
            else {
                continue;
            };
            let headers = String::from_utf8_lossy(&received[..header_end]);
            let content_length = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if received.len() >= header_end + 4 + content_length {
                return;
            }
        }
    }

    fn rpc_result(result: serde_json::Value) -> String {
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string()
    }

    fn receipt_result(hash: B256, block_hash: B256) -> String {
        rpc_result(serde_json::json!({
            "transactionHash": format!("{hash:#x}"),
            "status": "0x1",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x2",
            "blockNumber": "0x10",
            "blockHash": format!("{block_hash:#x}"),
            "logs": [],
        }))
    }

    fn network_client(endpoints: Vec<RpcEndpoint>) -> NetworkClient {
        let primary_url = endpoints
            .iter()
            .find(|endpoint| endpoint.name == "primary")
            .unwrap()
            .url
            .as_str();
        let mut client = NetworkClient::local_test_client(
            primary_url,
            Address::with_last_byte(1),
            B256::with_last_byte(2),
            Address::with_last_byte(3),
            B256::with_last_byte(4),
            9,
        )
        .unwrap();
        client.endpoints = endpoints;
        client
    }

    #[test]
    fn optional_result_distinguishes_explicit_null_from_missing_field() {
        let pending: RpcResponse<Option<serde_json::Value>> =
            serde_json::from_str(r#"{"result":null}"#).unwrap();
        assert!(matches!(pending.result, RpcResult::Present(None)));

        let missing: RpcResponse<Option<serde_json::Value>> = serde_json::from_str("{}").unwrap();
        assert!(matches!(missing.result, RpcResult::Missing));
    }

    #[tokio::test]
    async fn null_receipt_and_transaction_results_are_valid_pending_responses() {
        let hash = B256::with_last_byte(0x51);
        let (endpoint, server) = mock_endpoint(
            "primary",
            vec![(200, rpc_result(serde_json::Value::Null)); 2],
        );
        let client = network_client(vec![endpoint]);

        assert!(client.transaction_receipt(hash).await.unwrap().is_none());
        assert!(!client.transaction_known(hash).await.unwrap());
        server.join().unwrap();
    }

    #[tokio::test]
    async fn pending_receipt_transitions_to_confirmed_receipt() {
        let hash = B256::with_last_byte(0x61);
        let (endpoint, server) = mock_endpoint(
            "primary",
            vec![
                (200, rpc_result(serde_json::Value::Null)),
                (200, receipt_result(hash, B256::with_last_byte(0x71))),
            ],
        );
        let client = network_client(vec![endpoint]);

        assert!(client.transaction_receipt(hash).await.unwrap().is_none());
        let receipt = client.transaction_receipt(hash).await.unwrap().unwrap();
        assert_eq!(receipt.transaction_hash, hash);
        assert_eq!(receipt.block_hash, B256::with_last_byte(0x71));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn absent_result_is_an_error_and_json_rpc_errors_are_preserved() {
        let (endpoint, server) = mock_endpoint(
            "primary",
            vec![(200, r#"{"jsonrpc":"2.0","id":1}"#.to_owned())],
        );
        let error = rpc_request::<Option<serde_json::Value>>(
            &endpoint,
            "eth_getTransactionReceipt",
            serde_json::json!([format!("{:#x}", B256::with_last_byte(0x81))]),
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("response has no result"));
        server.join().unwrap();

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32000, "message": "temporary provider failure"},
        })
        .to_string();
        let (endpoint, server) = mock_endpoint("primary", vec![(200, body)]);
        let error = rpc_request::<Option<serde_json::Value>>(
            &endpoint,
            "eth_getTransactionByHash",
            serde_json::json!([format!("{:#x}", B256::with_last_byte(0x82))]),
        )
        .await
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("JSON-RPC error -32000"));
        assert!(message.contains("temporary provider failure"));
        server.join().unwrap();
    }

    #[tokio::test]
    async fn a_pending_null_with_a_transient_peer_error_remains_retryable() {
        let (primary, primary_server) =
            mock_endpoint("primary", vec![(200, rpc_result(serde_json::Value::Null))]);
        let (archival, archival_server) = mock_endpoint("archival", vec![(503, "{}".to_owned())]);
        let client = network_client(vec![primary, archival]);

        let error = client
            .transaction_receipt(B256::with_last_byte(0x91))
            .await
            .unwrap_err();
        assert!(is_transient_receipt_error(&error));
        assert!(format!("{error:#}").contains("returned pending"));
        primary_server.join().unwrap();
        archival_server.join().unwrap();
    }

    #[tokio::test]
    async fn all_transient_receipt_endpoint_errors_are_retryable() {
        let (primary, primary_server) = mock_endpoint("primary", vec![(503, "{}".to_owned())]);
        let client = network_client(vec![primary]);
        let error = client
            .transaction_receipt(B256::with_last_byte(0xa1))
            .await
            .unwrap_err();

        assert!(is_transient_receipt_error(&error));
        assert!(format!("{error:#}").contains("read transaction receipt"));
        primary_server.join().unwrap();
    }

    #[tokio::test]
    async fn inconsistent_receipt_endpoints_are_rejected() {
        let hash = B256::with_last_byte(0xb1);
        let (primary, primary_server) = mock_endpoint(
            "primary",
            vec![(200, receipt_result(hash, B256::with_last_byte(0xb2)))],
        );
        let (archival, archival_server) = mock_endpoint(
            "archival",
            vec![(200, receipt_result(hash, B256::with_last_byte(0xb3)))],
        );
        let client = network_client(vec![primary, archival]);
        let error = client.transaction_receipt(hash).await.unwrap_err();

        assert!(format!("{error:#}").contains("disagree on transaction receipt"));
        assert!(!is_transient_receipt_error(&error));
        primary_server.join().unwrap();
        archival_server.join().unwrap();
    }

    #[test]
    fn decodes_source_shaped_work_and_mining_tuples() {
        let work = (
            true,
            false,
            7_u64,
            100_u64,
            160_u64,
            B256::with_last_byte(1),
            B256::with_last_byte(2),
            U256::MAX,
            U256::from(3),
            U256::from(4),
            64_u32,
            U256::from(SUBMISSION_FEE_WEI),
        )
            .abi_encode();
        let decoded_work = decode_work(&work).unwrap();
        assert_eq!(decoded_work.window_id, 7);
        assert_eq!(decoded_work.window_expiry_time, 160);
        assert_eq!(decoded_work.target, U256::MAX);

        let mining = (
            true,
            false,
            7_u64,
            0_u64,
            12_u64,
            0_u16,
            U256::from(3),
            U256::from(4),
            U256::from(5),
            U256::MAX,
            B256::with_last_byte(1),
            B256::with_last_byte(2),
        )
            .abi_encode();
        let decoded_mining = decode_mining(&mining).unwrap();
        assert_eq!(decoded_mining.window_id, decoded_work.window_id);
        assert_eq!(decoded_mining.seed, decoded_work.seed);
    }

    #[test]
    fn decodes_dynamic_candidate_summary_return_shape() {
        use crate::contracts::AstatineMinerRead;

        let candidate = AstatineMinerRead::CandidateInfo {
            exists: true,
            miner: Address::with_last_byte(1),
            nonce: u128::MAX,
            workHash: B256::with_last_byte(2),
            submittedAt: 3,
            header: Bytes::from_static(b"abc"),
            firstValidSolveSecs: 4,
        };
        let encoded = AstatineMinerRead::candidateSummaryCall::abi_encode_returns(&candidate);
        let decoded = decode_candidate(&encoded).unwrap().unwrap();
        assert_eq!(decoded.nonce, u128::MAX);
        assert_eq!(decoded.header.as_ref(), b"abc");

        let empty = AstatineMinerRead::CandidateInfo {
            exists: false,
            miner: Address::ZERO,
            nonce: 0,
            workHash: B256::ZERO,
            submittedAt: 0,
            header: Bytes::new(),
            firstValidSolveSecs: 0,
        };
        let empty = AstatineMinerRead::candidateSummaryCall::abi_encode_returns(&empty);
        assert!(decode_candidate(&empty).unwrap().is_none());
    }
}
