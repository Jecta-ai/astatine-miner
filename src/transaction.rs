use crate::{
    cli::Network,
    config::{AppConfig, ConfigStore, parse_inj_wei},
    contracts::{AstatineMinerRead, IERC20Read},
    diagnostics::DiagnosticBuffer,
    history_telemetry::{HistoryCounter, HistoryDuration, HistoryTelemetry},
    proof_telemetry::{ProofAttemptGuard, ProofMetric, ProofPipelineTelemetry},
    protocol::{WorkContext, WorkHasher, beats_incumbent, meets_target},
    rpc::{
        NetworkClient, ReadSnapshot, RpcLog, TransactionReceipt, is_transient_receipt_error,
        is_transient_rpc_error, is_window_expired_revert, is_window_not_expired_revert,
    },
    wallet::signer_address,
};
use alloy_primitives::{Address, B256, Bytes, U256, hex, keccak256};
use alloy_rlp::Header;
use alloy_sol_types::{SolCall, SolEvent};
use anyhow::{Context, Result, anyhow, bail};
use bip32::secp256k1::ecdsa::SigningKey;
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    str::FromStr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    task::{JoinHandle, JoinSet},
    time::{Instant, MissedTickBehavior, interval, sleep},
};

const JOURNAL_VERSION: u32 = 4;
const ARCHIVE_VERSION: u32 = 1;
const MAX_JOURNAL_ENTRIES: usize = 4_096;
const ARCHIVE_TRIGGER_ENTRIES: usize = 64;
const ARCHIVE_BATCH_SIZE: usize = 128;
const ARCHIVE_AFTER_CONFIRMATIONS: u64 = 64;
const RECEIPT_WAIT: Duration = Duration::from_secs(90);
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_secs(2);
const REWARD_SCAN_JOBS_PER_BATCH: usize = 256;
const REWARD_SCAN_CONCURRENCY: usize = 4;
const REWARD_SCAN_BLOCK_RANGE: u64 = 10_000;
const REWARD_SCAN_RETRY_BASE: Duration = Duration::from_secs(1);
const REWARD_SCAN_RETRY_MAX: Duration = Duration::from_secs(30);
const REWARD_EMPTY_SCAN_RETRY_BASE_SECS: u64 = 60;
const REWARD_EMPTY_SCAN_RETRY_MAX_SECS: u64 = 3_600;
const SUBMISSION_FEE_WEI: u128 = 10_000_000_000_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Eip1559Request {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub gas_limit: u64,
    pub to: Address,
    pub value: U256,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct SignedTransaction {
    pub raw: Vec<u8>,
    pub hash: B256,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransactionAction {
    SubmitProof,
    FinalizeWindow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionPolicyRefusalKind {
    SessionLimitExceeded,
    InsufficientConfirmedBalance,
    SigningDisabled,
}

#[derive(Debug)]
pub struct TransactionPolicyRefusal {
    pub kind: TransactionPolicyRefusalKind,
    details: String,
}

impl std::fmt::Display for TransactionPolicyRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.details)
    }
}

impl std::error::Error for TransactionPolicyRefusal {}

#[derive(Debug)]
pub struct StaleTransactionPreflight {
    details: String,
}

#[derive(Debug)]
pub struct MinedTransactionReverted {
    pub action: TransactionAction,
    pub window_id: u64,
    details: String,
}

impl std::fmt::Display for StaleTransactionPreflight {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.details)
    }
}

impl std::error::Error for StaleTransactionPreflight {}

impl std::fmt::Display for MinedTransactionReverted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.details)
    }
}

impl std::error::Error for MinedTransactionReverted {}

pub fn transaction_policy_refusal(error: &anyhow::Error) -> Option<TransactionPolicyRefusalKind> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<TransactionPolicyRefusal>()
            .map(|refusal| refusal.kind)
    })
}

pub fn is_stale_transaction_preflight(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<StaleTransactionPreflight>().is_some())
}

pub fn mined_transaction_reverted(error: &anyhow::Error) -> Option<(TransactionAction, u64)> {
    error.chain().find_map(|cause| {
        cause
            .downcast_ref::<MinedTransactionReverted>()
            .map(|reverted| (reverted.action, reverted.window_id))
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransactionStatus {
    Prepared,
    Broadcast,
    Unknown,
    Included,
    MinedSuccess,
    MinedReverted,
}

impl TransactionStatus {
    fn is_unresolved(self) -> bool {
        matches!(
            self,
            Self::Prepared | Self::Broadcast | Self::Unknown | Self::Included
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SpendingSession {
    id: String,
    #[serde(default)]
    wallet: String,
    limit_wei: String,
    closed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TransactionEntry {
    chain_id: u64,
    contract: String,
    node_id: u8,
    window_id: u64,
    action: TransactionAction,
    session_id: String,
    #[serde(default)]
    wallet: String,
    nonce: u64,
    transaction_hash: String,
    value_wei: String,
    max_fee_per_gas_wei: String,
    gas_limit: u64,
    maximum_exposure_wei: String,
    status: TransactionStatus,
    actual_cost_wei: Option<String>,
    #[serde(default)]
    last_known_cost_wei: Option<String>,
    outcome: Option<String>,
    #[serde(default)]
    reward_outcome: Option<String>,
    #[serde(default)]
    reward_block: Option<u64>,
    #[serde(default)]
    reward_block_hash: Option<String>,
    #[serde(default)]
    reward_confirmations: u64,
    #[serde(default)]
    reward_confirmed: bool,
    proof_nonce: Option<u128>,
    proof_hash: Option<String>,
    header_hex: Option<String>,
    receipt_block: Option<u64>,
    #[serde(default)]
    receipt_block_hash: Option<String>,
    #[serde(default)]
    receipt_status: Option<bool>,
    #[serde(default)]
    confirmations: u64,
    #[serde(default)]
    confirmations_required: u8,
    created_unix_secs: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArchiveMeta {
    file_name: String,
    content_hash: String,
    entry_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RewardScanCursor {
    scanned_through: u64,
    retry_after_unix_secs: u64,
    retry_backoff_secs: u64,
    rescan_active: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RewardScanAnchor {
    block_number: u64,
    block_hash: String,
}

#[derive(Clone, Debug)]
struct RewardScanJob {
    key: String,
    candidate: RewardCandidate,
    from_block: u64,
    to_block: u64,
    rescan_active: bool,
    retry_after_unix_secs: u64,
    retry_backoff_secs: u64,
}

struct RewardScanJobOutput {
    key: String,
    cursor: Option<RewardScanCursor>,
    evidence: Vec<RewardEvidence>,
}

enum RewardScanBatchOutput {
    ReorgDetected,
    Scanned {
        snapshot: crate::rpc::BlockSnapshot,
        results: Vec<Result<RewardScanJobOutput>>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalArchive {
    version: u32,
    entries: Vec<TransactionEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalState {
    version: u32,
    active_session: Option<SpendingSession>,
    entries: Vec<TransactionEntry>,
    #[serde(default)]
    proof_attempted_through: HashMap<String, u64>,
    #[serde(default)]
    archives: Vec<ArchiveMeta>,
    #[serde(default)]
    archived_session_spending: HashMap<String, String>,
    #[serde(default = "zero_wei_string")]
    archived_total_spending_wei: String,
    #[serde(default)]
    next_archive_sequence: u64,
    #[serde(default)]
    reward_scan_cursors: HashMap<String, RewardScanCursor>,
    #[serde(default)]
    reward_scan_anchor: Option<RewardScanAnchor>,
}

impl Default for JournalState {
    fn default() -> Self {
        Self {
            version: JOURNAL_VERSION,
            active_session: None,
            entries: Vec::new(),
            proof_attempted_through: HashMap::new(),
            archives: Vec::new(),
            archived_session_spending: HashMap::new(),
            archived_total_spending_wei: "0".to_owned(),
            next_archive_sequence: 0,
            reward_scan_cursors: HashMap::new(),
            reward_scan_anchor: None,
        }
    }
}

fn zero_wei_string() -> String {
    "0".to_owned()
}

fn migrate_journal(
    mut state: JournalState,
    wallet: Address,
    confirmations_required: u8,
) -> Result<(JournalState, bool)> {
    if state.version == JOURNAL_VERSION {
        return Ok((state, false));
    }
    if state.version == 3 {
        state.version = JOURNAL_VERSION;
        return Ok((state, true));
    }
    if !matches!(state.version, 1 | 2) {
        bail!(
            "transaction journal schema version {} is unsupported",
            state.version
        );
    }

    let wallet_string = format!("{wallet:#x}");
    for entry in &mut state.entries {
        entry.confirmations_required = confirmations_required;
        if entry.action == TransactionAction::SubmitProof {
            let contract = Address::from_str(&entry.contract)
                .context("legacy journal contains an invalid miner contract")?;
            state
                .proof_attempted_through
                .entry(format!("{contract:#x}"))
                .and_modify(|window| *window = (*window).max(entry.window_id))
                .or_insert(entry.window_id);
        }
        if matches!(
            entry.status,
            TransactionStatus::Included
                | TransactionStatus::MinedSuccess
                | TransactionStatus::MinedReverted
        ) {
            // Legacy receipts were never confirmation-checked. Retain their intent and
            // maximum exposure, then recover them from the node without rebroadcasting.
            let previously_succeeded = entry
                .receipt_status
                .unwrap_or(entry.status == TransactionStatus::MinedSuccess);
            entry.status = TransactionStatus::Unknown;
            entry.last_known_cost_wei = entry.actual_cost_wei.take();
            entry.receipt_status = Some(previously_succeeded);
            entry.confirmations = 0;
            entry.reward_block_hash = None;
            entry.reward_confirmations = 0;
            entry.reward_confirmed = false;
        }
    }
    if let Some(session) = &mut state.active_session
        && session.wallet.is_empty()
        && !state
            .entries
            .iter()
            .any(|entry| entry.session_id == session.id && entry.status.is_unresolved())
    {
        session.wallet = wallet_string;
    }
    state.version = JOURNAL_VERSION;
    Ok((state, true))
}

fn proof_attempt_key(contract: Address) -> String {
    format!("{contract:#x}")
}

fn reward_scan_key(contract: Address, window_id: u64) -> String {
    format!("{contract:#x}:{window_id}")
}

pub struct TransactionJournal {
    store: ConfigStore,
    state: JournalState,
    _lock: File,
    history_telemetry: Arc<HistoryTelemetry>,
}

impl TransactionJournal {
    #[cfg(test)]
    pub fn open(store: &ConfigStore, config: &AppConfig, wallet: Address) -> Result<Self> {
        Self::open_with_history_telemetry(
            store,
            config,
            wallet,
            Arc::new(HistoryTelemetry::default()),
        )
    }

    fn open_with_history_telemetry(
        store: &ConfigStore,
        config: &AppConfig,
        wallet: Address,
        history_telemetry: Arc<HistoryTelemetry>,
    ) -> Result<Self> {
        let _open_timer = history_telemetry.timer(HistoryDuration::JournalOpen);
        if config.network != Network::Testnet {
            bail!("transaction signing is disabled outside Injective Testnet");
        }
        let limit = parse_inj_wei(&config.per_session_spending_limit_inj)?;
        let lock = store.lock_transaction_journal()?;
        let state = match store.read_transaction_journal()? {
            Some(contents) => serde_json::from_slice::<JournalState>(&contents)
                .context("decode transaction journal")?,
            None => JournalState::default(),
        };
        let (state, migrated) = migrate_journal(state, wallet, config.transaction_confirmations)?;
        validate_journal(&state)?;
        let archive_validation = {
            let _archive_validation_timer =
                history_telemetry.timer(HistoryDuration::ArchiveValidation);
            validate_archive_ledger(store, &state, Some(&history_telemetry))
        };
        if let Err(error) = archive_validation {
            history_telemetry.add(HistoryCounter::ArchiveValidationFailures, 1);
            return Err(error);
        }

        let mut journal = Self {
            store: store.clone(),
            state,
            _lock: lock,
            history_telemetry: Arc::clone(&history_telemetry),
        };
        let has_unresolved = journal.has_unresolved();
        let has_active_entries = journal
            .state
            .active_session
            .as_ref()
            .is_some_and(|session| {
                journal
                    .state
                    .entries
                    .iter()
                    .any(|entry| entry.session_id == session.id)
            });
        let mut resume_session = false;
        if limit.is_zero() {
            resume_session = journal
                .state
                .active_session
                .as_ref()
                .is_some_and(|session| !session.closed);
        } else if let Some(session) = journal
            .state
            .active_session
            .as_ref()
            .filter(|session| !session.closed)
        {
            let session_limit = parse_decimal_wei(&session.limit_wei)?;
            if has_unresolved && session_limit != limit {
                bail!("spending limit cannot change while transaction exposure is unresolved");
            }
            let wallet_matches = !session.wallet.is_empty()
                && Address::from_str(&session.wallet)
                    .context("journal session wallet address is invalid")?
                    == wallet;
            resume_session = session_limit == limit
                && (wallet_matches
                    || has_unresolved
                    || (!has_active_entries && session.wallet.is_empty()));
        }
        if resume_session {
            if !limit.is_zero()
                && let Some(session) = &mut journal.state.active_session
                && session.wallet.is_empty()
                && !has_unresolved
            {
                session.wallet = format!("{wallet:#x}");
            }
        } else if !limit.is_zero() {
            journal.state.active_session = Some(SpendingSession {
                id: new_session_id(),
                wallet: format!("{wallet:#x}"),
                limit_wei: limit.to_string(),
                closed: false,
            });
        }
        if migrated || (!limit.is_zero() && !resume_session) {
            journal.persist()?;
        }
        Ok(journal)
    }

    fn persist(&self) -> Result<()> {
        let _persist_timer = self
            .history_telemetry
            .timer(HistoryDuration::JournalPersistence);
        let contents =
            serde_json::to_vec_pretty(&self.state).context("serialize transaction journal")?;
        if let Err(error) = self.store.write_transaction_journal(&contents) {
            self.history_telemetry
                .add(HistoryCounter::JournalWriteFailures, 1);
            return Err(error);
        }
        self.history_telemetry.add(HistoryCounter::JournalWrites, 1);
        self.history_telemetry.add(
            HistoryCounter::JournalWriteBytes,
            u64::try_from(contents.len()).unwrap_or(u64::MAX),
        );
        Ok(())
    }

    pub fn has_unresolved(&self) -> bool {
        self.state
            .entries
            .iter()
            .any(|entry| entry.status.is_unresolved())
    }

    pub fn has_unverified_receipt(&self) -> bool {
        self.state.entries.iter().any(|entry| {
            entry.status == TransactionStatus::Included
                && entry.outcome.as_deref() == Some("receipt-event-unverified")
        })
    }

    pub fn pending_exposure(&self) -> Result<U256> {
        self.state
            .entries
            .iter()
            .filter(|entry| entry.status.is_unresolved())
            .try_fold(U256::ZERO, |total, entry| {
                total
                    .checked_add(parse_decimal_wei(&entry.maximum_exposure_wei)?)
                    .context("pending transaction exposure overflow")
            })
    }

    fn session_spent_or_reserved(&self) -> Result<U256> {
        let session = self
            .state
            .active_session
            .as_ref()
            .context("transaction journal has no active spending session")?;
        let archived = self
            .state
            .archived_session_spending
            .get(&session.id)
            .map(|value| parse_decimal_wei(value))
            .transpose()?
            .unwrap_or(U256::ZERO);
        self.state
            .entries
            .iter()
            .filter(|entry| entry.session_id == session.id)
            .try_fold(archived, |total, entry| {
                let amount = if entry.status.is_unresolved() {
                    parse_decimal_wei(&entry.maximum_exposure_wei)?
                } else {
                    parse_decimal_wei(
                        entry
                            .actual_cost_wei
                            .as_deref()
                            .unwrap_or(&entry.maximum_exposure_wei),
                    )?
                };
                total
                    .checked_add(amount)
                    .context("session spending total overflow")
            })
    }

    fn validate_exposure(
        &mut self,
        request: &Eip1559Request,
        intent: &TransactionIntent,
        session_limit: U256,
        minimum_reserve: U256,
        confirmed_balance: U256,
    ) -> Result<U256> {
        self.archive_settled()?;
        if self.has_unresolved() {
            bail!("an earlier transaction has unresolved broadcast status; refusing a second send");
        }
        if request.to != intent.contract || request.chain_id != 1439 {
            bail!("transaction request does not match the approved Testnet intent");
        }
        match intent.action {
            TransactionAction::SubmitProof
                if request.value != U256::from(SUBMISSION_FEE_WEI) || intent.proof.is_none() =>
            {
                bail!("proof transaction must include the canonical submission fee and proof data")
            }
            TransactionAction::FinalizeWindow
                if !request.value.is_zero() || intent.proof.is_some() =>
            {
                bail!("finalization transaction must be a zero-value call without proof data")
            }
            _ => {}
        }
        if intent.action == TransactionAction::SubmitProof
            && self
                .state
                .proof_attempted_through
                .get(&proof_attempt_key(intent.contract))
                .is_some_and(|window| intent.window_id <= *window)
        {
            bail!(
                "paid proof attempt already journaled for this node/window; refusing a second fee"
            );
        }
        let session = self
            .state
            .active_session
            .as_ref()
            .context("transaction journal has no active spending session")?;
        if parse_decimal_wei(&session.limit_wei)? != session_limit {
            bail!("active transaction journal spending limit does not match configuration");
        }
        let gas_exposure = U256::from(request.gas_limit)
            .checked_mul(request.max_fee_per_gas)
            .context("maximum gas exposure overflow")?;
        let maximum_exposure = request
            .value
            .checked_add(gas_exposure)
            .context("maximum transaction exposure overflow")?;
        let session_total = self
            .session_spent_or_reserved()?
            .checked_add(maximum_exposure)
            .context("session spending total overflow")?;
        if session_total > session_limit {
            return Err(TransactionPolicyRefusal {
                kind: TransactionPolicyRefusalKind::SessionLimitExceeded,
                details: format!(
                    "transaction maximum exposure exceeds the configured per-session limit ({} > {}) wei",
                    session_total, session_limit
                ),
            }
            .into());
        }
        let total_exposure = self
            .pending_exposure()?
            .checked_add(maximum_exposure)
            .context("combined pending transaction exposure overflow")?;
        let required_balance = minimum_reserve
            .checked_add(total_exposure)
            .context("minimum reserve plus transaction exposure overflow")?;
        if confirmed_balance < required_balance {
            return Err(TransactionPolicyRefusal {
                kind: TransactionPolicyRefusalKind::InsufficientConfirmedBalance,
                details: format!(
                    "insufficient confirmed INJ balance after reserve and pending exposure: need at least {} wei, have {} wei",
                    required_balance, confirmed_balance
                ),
            }
            .into());
        }
        if self.state.entries.len() >= MAX_JOURNAL_ENTRIES {
            bail!("transaction journal reached its entry limit; archive it before further mining");
        }
        Ok(maximum_exposure)
    }

    fn prepare(&mut self, prepared: PreparedTransaction) -> Result<()> {
        let PreparedTransaction {
            request,
            tx_hash,
            intent,
            session_limit,
            minimum_reserve,
            confirmed_balance,
            confirmations_required,
        } = prepared;
        let maximum_exposure = self.validate_exposure(
            &request,
            &intent,
            session_limit,
            minimum_reserve,
            confirmed_balance,
        )?;
        let session = self
            .state
            .active_session
            .as_ref()
            .context("transaction journal has no active spending session")?;
        let session_id = session.id.clone();
        let wallet = session.wallet.clone();

        let (proof_nonce, proof_hash, header_hex) = match intent.proof.as_ref() {
            Some(proof) => (
                Some(proof.nonce),
                Some(format!("{:#x}", proof.work_hash)),
                Some(hex::encode(&proof.header)),
            ),
            None => (None, None, None),
        };
        if intent.action == TransactionAction::SubmitProof {
            self.state
                .proof_attempted_through
                .insert(proof_attempt_key(intent.contract), intent.window_id);
        }
        self.state.entries.push(TransactionEntry {
            chain_id: request.chain_id,
            contract: format!("{:#x}", intent.contract),
            node_id: intent.node_id,
            window_id: intent.window_id,
            action: intent.action,
            session_id,
            wallet,
            nonce: request.nonce,
            transaction_hash: format!("{tx_hash:#x}"),
            value_wei: request.value.to_string(),
            max_fee_per_gas_wei: request.max_fee_per_gas.to_string(),
            gas_limit: request.gas_limit,
            maximum_exposure_wei: maximum_exposure.to_string(),
            status: TransactionStatus::Prepared,
            actual_cost_wei: None,
            last_known_cost_wei: None,
            outcome: None,
            reward_outcome: None,
            reward_block: None,
            reward_block_hash: None,
            reward_confirmations: 0,
            reward_confirmed: false,
            proof_nonce,
            proof_hash,
            header_hex,
            receipt_block: None,
            receipt_block_hash: None,
            receipt_status: None,
            confirmations: 0,
            confirmations_required,
            created_unix_secs: unix_time_secs(),
        });
        self.persist()
    }

    fn set_broadcast_state(&mut self, hash: B256, status: TransactionStatus) -> Result<()> {
        let entry = self.entry_mut(hash)?;
        if !matches!(
            entry.status,
            TransactionStatus::Prepared | TransactionStatus::Unknown
        ) {
            bail!("transaction journal broadcast state transition is invalid");
        }
        entry.status = status;
        self.persist()
    }

    fn record_included(
        &mut self,
        hash: B256,
        receipt: &TransactionReceipt,
        confirmations: u64,
        outcome: String,
    ) -> Result<()> {
        let entry = self.entry_mut(hash)?;
        let block_hash = format!("{:#x}", receipt.block_hash);
        let receipt_changed = entry.status != TransactionStatus::Included
            || entry.outcome.as_deref() != Some(outcome.as_str())
            || entry.receipt_block != Some(receipt.block_number)
            || entry.receipt_block_hash.as_deref() != Some(block_hash.as_str())
            || entry.receipt_status != Some(receipt.status)
            || entry.actual_cost_wei.is_some();
        let confirmations_changed = entry.confirmations != confirmations;
        let crossed_required_confirmations = entry.confirmations
            < u64::from(entry.confirmations_required)
            && confirmations >= u64::from(entry.confirmations_required);
        entry.status = TransactionStatus::Included;
        entry.actual_cost_wei = None;
        entry.outcome = Some(outcome);
        entry.receipt_block = Some(receipt.block_number);
        entry.receipt_block_hash = Some(block_hash);
        entry.receipt_status = Some(receipt.status);
        entry.confirmations = confirmations;
        if receipt_changed || (confirmations_changed && crossed_required_confirmations) {
            self.persist()?;
        }
        Ok(())
    }

    fn settle_receipt(
        &mut self,
        hash: B256,
        receipt: &TransactionReceipt,
        confirmations: u64,
        actual_cost: U256,
        outcome: String,
    ) -> Result<()> {
        let entry = self.entry_mut(hash)?;
        if confirmations < u64::from(entry.confirmations_required) {
            bail!("cannot settle a receipt before the configured confirmation threshold");
        }
        if receipt.status && outcome == "receipt-event-unverified" {
            bail!("cannot settle a successful receipt before its canonical event is verified");
        }
        entry.status = if receipt.status {
            TransactionStatus::MinedSuccess
        } else {
            TransactionStatus::MinedReverted
        };
        entry.actual_cost_wei = Some(actual_cost.to_string());
        entry.last_known_cost_wei = None;
        entry.outcome = Some(outcome);
        entry.receipt_block = Some(receipt.block_number);
        entry.receipt_block_hash = Some(format!("{:#x}", receipt.block_hash));
        entry.receipt_status = Some(receipt.status);
        entry.confirmations = confirmations;
        self.persist()
    }

    fn update_confirmations(&mut self, hash: B256, confirmations: u64) -> Result<bool> {
        let entry = self.entry_mut(hash)?;
        let changed = entry.confirmations != confirmations;
        if changed {
            entry.confirmations = confirmations;
        }
        Ok(changed)
    }

    fn update_reward_confirmations(
        &mut self,
        hash: B256,
        confirmations: u64,
    ) -> Result<(bool, bool)> {
        let entry = self.entry_mut(hash)?;
        if entry.reward_block_hash.is_none() {
            return Ok((false, false));
        }
        let previously_confirmed = entry.reward_confirmed;
        let previously_at_archive_threshold =
            entry.reward_confirmations >= ARCHIVE_AFTER_CONFIRMATIONS;
        let newly_confirmed =
            !entry.reward_confirmed && confirmations >= u64::from(entry.confirmations_required);
        let confirmed = confirmations >= u64::from(entry.confirmations_required);
        let crossed_archive_threshold =
            !previously_at_archive_threshold && confirmations >= ARCHIVE_AFTER_CONFIRMATIONS;
        let changed =
            entry.reward_confirmations != confirmations || entry.reward_confirmed != confirmed;
        if changed {
            entry.reward_confirmations = confirmations;
            entry.reward_confirmed = confirmed;
        }
        Ok((
            newly_confirmed,
            changed || previously_confirmed != confirmed || crossed_archive_threshold,
        ))
    }

    fn clear_reward_block_hash(&mut self, hash: B256) -> Result<()> {
        let entry = self.entry_mut(hash)?;
        if entry.reward_block_hash.take().is_some() {
            entry.reward_confirmations = 0;
            entry.reward_confirmed = false;
            self.persist()?;
        }
        Ok(())
    }

    fn mark_uncertain(&mut self, hash: B256) -> Result<()> {
        let (action, contract, window_id) = {
            let entry = self.entry_mut(hash)?;
            let data = (entry.action, entry.contract.clone(), entry.window_id);
            entry.status = TransactionStatus::Unknown;
            entry.last_known_cost_wei = entry
                .actual_cost_wei
                .take()
                .or_else(|| entry.last_known_cost_wei.clone());
            entry.confirmations = 0;
            data
        };
        let contract_address =
            Address::from_str(&contract).context("uncertain transaction contract is invalid")?;
        if action == TransactionAction::SubmitProof
            && let Some(entry) = self.state.entries.iter_mut().find(|entry| {
                entry
                    .transaction_hash
                    .eq_ignore_ascii_case(&format!("{hash:#x}"))
            })
        {
            entry.reward_block_hash = None;
            entry.reward_confirmations = 0;
            entry.reward_confirmed = false;
            self.state
                .reward_scan_cursors
                .remove(&reward_scan_key(contract_address, window_id));
        }
        if action == TransactionAction::FinalizeWindow {
            for entry in &mut self.state.entries {
                if entry.action == TransactionAction::SubmitProof
                    && entry.contract.eq_ignore_ascii_case(&contract)
                    && entry.window_id == window_id
                {
                    entry.reward_block_hash = None;
                    entry.reward_confirmations = 0;
                    entry.reward_confirmed = false;
                }
            }
            self.state
                .reward_scan_cursors
                .remove(&reward_scan_key(contract_address, window_id));
        }
        self.persist()
    }

    fn entry_mut(&mut self, hash: B256) -> Result<&mut TransactionEntry> {
        self.state
            .entries
            .iter_mut()
            .find(|entry| {
                entry
                    .transaction_hash
                    .eq_ignore_ascii_case(&format!("{hash:#x}"))
            })
            .context("transaction hash is missing from the private journal")
    }

    fn entry(&self, hash: B256) -> Result<TransactionEntry> {
        self.state
            .entries
            .iter()
            .find(|entry| {
                entry
                    .transaction_hash
                    .eq_ignore_ascii_case(&format!("{hash:#x}"))
            })
            .cloned()
            .context("transaction hash is missing from the private journal")
    }

    fn bind_legacy_wallet(&mut self, hash: B256, wallet: Address) -> Result<()> {
        if wallet.is_zero() {
            bail!("RPC returned a zero transaction sender for a legacy journal entry");
        }
        let session_id = {
            let entry = self.entry_mut(hash)?;
            if !entry.wallet.is_empty()
                && !entry.wallet.eq_ignore_ascii_case(&format!("{wallet:#x}"))
            {
                bail!("RPC transaction sender disagrees with the journaled wallet");
            }
            entry.wallet = format!("{wallet:#x}");
            entry.session_id.clone()
        };
        if let Some(session) = &mut self.state.active_session
            && session.id == session_id
        {
            if !session.wallet.is_empty()
                && !session.wallet.eq_ignore_ascii_case(&format!("{wallet:#x}"))
            {
                bail!("legacy transaction sender disagrees with its active spending session");
            }
            session.wallet = format!("{wallet:#x}");
        }
        self.persist()
    }

    fn unresolved_entries(&self) -> Vec<TransactionEntry> {
        self.state
            .entries
            .iter()
            .filter(|entry| entry.status.is_unresolved())
            .cloned()
            .collect()
    }

    fn reward_candidates(&self) -> Result<Vec<RewardCandidate>> {
        let mut groups = HashMap::<(Address, u8, u64), (u64, HashMap<Address, u8>)>::new();
        for entry in &self.state.entries {
            if entry.action != TransactionAction::SubmitProof
                || entry.status != TransactionStatus::MinedSuccess
                || entry.outcome.as_deref() != Some("candidate-updated")
                || entry.reward_block_hash.is_some()
            {
                continue;
            }
            let contract = Address::from_str(&entry.contract)
                .context("journal contract address is invalid")?;
            let wallet = Address::from_str(&entry.wallet)
                .context("journal transaction wallet address is invalid")?;
            groups
                .entry((contract, entry.node_id, entry.window_id))
                .and_modify(|(block, wallets)| {
                    *block = (*block).min(entry.receipt_block.unwrap_or_default());
                    wallets
                        .entry(wallet)
                        .and_modify(|required| {
                            *required = (*required).max(entry.confirmations_required)
                        })
                        .or_insert(entry.confirmations_required);
                })
                .or_insert_with(|| {
                    (
                        entry.receipt_block.unwrap_or_default(),
                        HashMap::from([(wallet, entry.confirmations_required)]),
                    )
                });
        }
        Ok(groups
            .into_iter()
            .map(
                |((contract, node_id, window_id), (from_block, wallets))| RewardCandidate {
                    contract,
                    node_id,
                    window_id,
                    from_block,
                    wallets: wallets.into_iter().collect(),
                },
            )
            .collect())
    }

    fn record_reward_outcome_in_memory(&mut self, evidence: RewardEvidence) -> Result<bool> {
        let RewardEvidence {
            contract,
            window_id,
            wallet,
            block,
            block_hash,
            confirmations,
            outcome,
        } = evidence;
        let contract = format!("{contract:#x}");
        let mut changed = false;
        for entry in &mut self.state.entries {
            if entry.action == TransactionAction::SubmitProof
                && entry.status == TransactionStatus::MinedSuccess
                && entry.outcome.as_deref() == Some("candidate-updated")
                && entry.contract.eq_ignore_ascii_case(&contract)
                && entry.wallet.eq_ignore_ascii_case(&format!("{wallet:#x}"))
                && entry.window_id == window_id
            {
                let reward_block_hash = format!("{block_hash:#x}");
                let reward_confirmed = confirmations >= u64::from(entry.confirmations_required);
                if entry.reward_outcome.as_deref() != Some(outcome.as_str())
                    || entry.reward_block != Some(block)
                    || entry.reward_block_hash.as_deref() != Some(reward_block_hash.as_str())
                    || entry.reward_confirmations != confirmations
                    || entry.reward_confirmed != reward_confirmed
                {
                    changed = true;
                    entry.reward_outcome = Some(outcome.clone());
                    entry.reward_block = Some(block);
                    entry.reward_block_hash = Some(reward_block_hash);
                    entry.reward_confirmations = confirmations;
                    entry.reward_confirmed = reward_confirmed;
                }
            }
        }
        if self
            .state
            .reward_scan_cursors
            .remove(&reward_scan_key(Address::from_str(&contract)?, window_id))
            .is_some()
        {
            changed = true;
        }
        Ok(changed)
    }

    fn archive_settled(&mut self) -> Result<usize> {
        if self.state.entries.len() < ARCHIVE_TRIGGER_ENTRIES {
            return Ok(0);
        }
        let indices = self
            .state
            .entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let settled = matches!(
                    entry.status,
                    TransactionStatus::MinedSuccess | TransactionStatus::MinedReverted
                ) && entry.confirmations >= ARCHIVE_AFTER_CONFIRMATIONS;
                let reward_verified = entry.action != TransactionAction::SubmitProof
                    || entry.outcome.as_deref() != Some("candidate-updated")
                    || (entry.reward_confirmed
                        && entry.reward_block_hash.is_some()
                        && entry.reward_confirmations >= ARCHIVE_AFTER_CONFIRMATIONS);
                (settled && reward_verified).then_some(index)
            })
            .take(ARCHIVE_BATCH_SIZE)
            .collect::<Vec<_>>();
        if indices.is_empty() {
            return Ok(0);
        }

        let entries = indices
            .iter()
            .map(|index| self.state.entries[*index].clone())
            .collect::<Vec<_>>();
        let record = JournalArchive {
            version: ARCHIVE_VERSION,
            entries: entries.clone(),
        };
        let contents =
            serde_json::to_vec_pretty(&record).context("serialize transaction archive")?;
        let content_hash = format!("{:#x}", keccak256(&contents));
        let file_name = format!("archive-{}.json", &content_hash[2..]);
        if let Err(error) = self.store.write_transaction_archive(&file_name, &contents) {
            self.history_telemetry
                .add(HistoryCounter::ArchiveWriteFailures, 1);
            return Err(error);
        }
        self.history_telemetry
            .add(HistoryCounter::ArchiveFilesCreated, 1);

        let mut total_spending = parse_decimal_wei(&self.state.archived_total_spending_wei)?;
        for entry in &entries {
            let actual = parse_decimal_wei(
                entry
                    .actual_cost_wei
                    .as_deref()
                    .context("settled archive entry has no actual spending amount")?,
            )?;
            total_spending = total_spending
                .checked_add(actual)
                .context("archived total spending overflow")?;
            let session_total = self
                .state
                .archived_session_spending
                .get(&entry.session_id)
                .map(|value| parse_decimal_wei(value))
                .transpose()?
                .unwrap_or(U256::ZERO)
                .checked_add(actual)
                .context("archived session spending overflow")?;
            self.state
                .archived_session_spending
                .insert(entry.session_id.clone(), session_total.to_string());
        }
        let archived_hashes = entries
            .iter()
            .map(|entry| entry.transaction_hash.clone())
            .collect::<HashSet<_>>();
        self.state
            .entries
            .retain(|entry| !archived_hashes.contains(&entry.transaction_hash));
        self.state.archived_total_spending_wei = total_spending.to_string();
        self.state.archives.push(ArchiveMeta {
            file_name,
            content_hash,
            entry_count: u32::try_from(entries.len()).context("archive entry count overflow")?,
        });
        self.state.next_archive_sequence = self
            .state
            .next_archive_sequence
            .checked_add(1)
            .context("archive sequence overflow")?;
        self.persist()?;
        Ok(entries.len())
    }

    fn close_session(&mut self) -> Result<()> {
        if self.has_unresolved() {
            bail!("cannot close the spending session while a transaction is unresolved");
        }
        if let Some(session) = &mut self.state.active_session {
            session.closed = true;
        }
        self.persist()
    }

    fn ensure_wallet_session(&mut self, wallet: Address, limit: U256) -> Result<()> {
        let matches = self.state.active_session.as_ref().is_some_and(|session| {
            !session.closed
                && session.wallet.eq_ignore_ascii_case(&format!("{wallet:#x}"))
                && parse_decimal_wei(&session.limit_wei).ok() == Some(limit)
        });
        if matches {
            return Ok(());
        }
        if self.has_unresolved() {
            bail!("cannot start a new wallet session while transaction exposure is unresolved");
        }
        self.state.active_session = Some(SpendingSession {
            id: new_session_id(),
            wallet: format!("{wallet:#x}"),
            limit_wei: limit.to_string(),
            closed: false,
        });
        self.persist()
    }

    fn require_wallet_session(&self, wallet: Address) -> Result<()> {
        let session = self
            .state
            .active_session
            .as_ref()
            .context("transaction journal has no active spending session")?;
        if session.wallet != format!("{wallet:#x}") {
            bail!("active spending session belongs to a different wallet");
        }
        Ok(())
    }
}

pub struct TransactionManager {
    pub journal: TransactionJournal,
    wallet: Address,
    ast_token: Address,
    chain_id: u64,
    session_limit: U256,
    minimum_reserve: U256,
    confirmations_required: u8,
    diagnostics: Option<DiagnosticBuffer>,
    dashboard_sink: Option<TransactionDashboardSink>,
    proof_telemetry: Option<Arc<ProofPipelineTelemetry>>,
    proof_attempt_guard: Option<Arc<ProofAttemptGuard>>,
    history_telemetry: Arc<HistoryTelemetry>,
    reward_scan_task: Option<JoinHandle<Result<RewardScanBatchOutput>>>,
    reward_scan_retry_at: Option<Instant>,
    reward_scan_retry_attempts: u8,
    receipt_reward_service_errors: u64,
    current_process_proof_hashes: HashSet<B256>,
    mined_rewards_by_window: HashMap<MinedRewardKey, U256>,
    mined_rewards_total: U256,
}

#[derive(Clone, Debug)]
pub struct ConfirmedAction {
    pub transaction_hash: B256,
    pub receipt: TransactionReceipt,
    pub outcome: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionActivityState {
    Finalizing,
    Signed,
    Confirming,
    Recovering,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransactionActivity {
    pub node_id: u8,
    pub window_id: u64,
    pub state: TransactionActivityState,
}

#[derive(Clone, Debug, Default)]
pub struct TransactionDashboardState {
    pub session_exposure: Option<U256>,
    pub mined_rewards: U256,
    pub activities: Vec<TransactionActivity>,
}

pub type TransactionDashboardSink = Arc<dyn Fn(TransactionDashboardState) + Send + Sync>;

enum ReceiptProgress {
    Settled(String),
    Pending,
    Uncertain,
}

fn receipt_wait_timeout(hash: B256, last_error: Option<&str>) -> anyhow::Error {
    match last_error {
        Some(error) => anyhow!(
            "transaction {hash:#x} was broadcast but receipt verification did not complete within {} seconds; journaled exposure remains reserved and it will not be resent; last RPC error: {error}",
            RECEIPT_WAIT.as_secs()
        ),
        None => anyhow!(
            "transaction {hash:#x} was broadcast but no receipt arrived within {} seconds; journaled exposure remains reserved and it will not be resent",
            RECEIPT_WAIT.as_secs()
        ),
    }
}

#[derive(Clone, Debug)]
struct ProofData {
    nonce: u128,
    work_hash: B256,
    header: Vec<u8>,
}

#[derive(Clone, Debug)]
struct TransactionIntent {
    contract: Address,
    node_id: u8,
    window_id: u64,
    action: TransactionAction,
    proof: Option<ProofData>,
}

struct PreparedTransaction {
    request: Eip1559Request,
    tx_hash: B256,
    intent: TransactionIntent,
    session_limit: U256,
    minimum_reserve: U256,
    confirmed_balance: U256,
    confirmations_required: u8,
}

#[derive(Clone, Debug)]
struct RewardCandidate {
    contract: Address,
    node_id: u8,
    window_id: u64,
    from_block: u64,
    wallets: Vec<(Address, u8)>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct MinedRewardKey {
    contract: Address,
    window_id: u64,
    wallet: Address,
}

struct RewardEvidence {
    contract: Address,
    window_id: u64,
    wallet: Address,
    block: u64,
    block_hash: B256,
    confirmations: u64,
    outcome: String,
}

#[derive(Clone, Debug)]
pub struct ProofSubmission {
    pub contract: Address,
    pub node_id: u8,
    pub window_id: u64,
    pub nonce: u128,
    pub header: Vec<u8>,
    pub work_hash: B256,
}

impl TransactionManager {
    #[cfg(test)]
    pub fn open(
        store: &ConfigStore,
        config: &AppConfig,
        wallet: Address,
        ast_token: Address,
    ) -> Result<Self> {
        Self::open_with_history_telemetry(
            store,
            config,
            wallet,
            ast_token,
            Arc::new(HistoryTelemetry::default()),
        )
    }

    pub(crate) fn open_with_history_telemetry(
        store: &ConfigStore,
        config: &AppConfig,
        wallet: Address,
        ast_token: Address,
        history_telemetry: Arc<HistoryTelemetry>,
    ) -> Result<Self> {
        let journal = TransactionJournal::open_with_history_telemetry(
            store,
            config,
            wallet,
            Arc::clone(&history_telemetry),
        )?;
        Ok(Self {
            journal,
            wallet,
            ast_token,
            chain_id: 1439,
            session_limit: parse_inj_wei(&config.per_session_spending_limit_inj)?,
            minimum_reserve: parse_inj_wei(&config.minimum_reserve_inj)?,
            confirmations_required: config.transaction_confirmations,
            diagnostics: None,
            dashboard_sink: None,
            proof_telemetry: None,
            proof_attempt_guard: None,
            history_telemetry,
            reward_scan_task: None,
            reward_scan_retry_at: None,
            reward_scan_retry_attempts: 0,
            receipt_reward_service_errors: 0,
            current_process_proof_hashes: HashSet::new(),
            mined_rewards_by_window: HashMap::new(),
            mined_rewards_total: U256::ZERO,
        })
    }

    pub(crate) fn history_profile_line(&self) -> String {
        let mut prepared = 0_u64;
        let mut broadcast = 0_u64;
        let mut unknown = 0_u64;
        let mut included = 0_u64;
        let mut settled_success = 0_u64;
        let mut reverted = 0_u64;
        let mut unresolved = 0_u64;
        let mut settled_canonical_pending = 0_u64;
        let mut reward_pending = 0_u64;
        for entry in &self.journal.state.entries {
            match entry.status {
                TransactionStatus::Prepared => prepared += 1,
                TransactionStatus::Broadcast => broadcast += 1,
                TransactionStatus::Unknown => unknown += 1,
                TransactionStatus::Included => included += 1,
                TransactionStatus::MinedSuccess => settled_success += 1,
                TransactionStatus::MinedReverted => reverted += 1,
            }
            if entry.status.is_unresolved() {
                unresolved += 1;
            } else if entry.confirmations < ARCHIVE_AFTER_CONFIRMATIONS
                || (entry.action == TransactionAction::SubmitProof
                    && entry.outcome.as_deref() == Some("candidate-updated")
                    && (!entry.reward_confirmed
                        || entry.reward_block_hash.is_none()
                        || entry.reward_confirmations < ARCHIVE_AFTER_CONFIRMATIONS))
            {
                settled_canonical_pending += 1;
            }
            if entry.action == TransactionAction::SubmitProof
                && entry.outcome.as_deref() == Some("candidate-updated")
                && !entry.reward_confirmed
            {
                reward_pending += 1;
            }
        }
        let archived_entries = self
            .journal
            .state
            .archives
            .iter()
            .map(|archive| u64::from(archive.entry_count))
            .sum::<u64>();
        format!(
            "history entries={} prepared={} broadcast={} unknown={} included={} settled_success={} reverted={} unresolved={} settled_canonical_pending={} reward_pending={} archives={} archived_entries={} {}",
            self.journal.state.entries.len(),
            prepared,
            broadcast,
            unknown,
            included,
            settled_success,
            reverted,
            unresolved,
            settled_canonical_pending,
            reward_pending,
            self.journal.state.archives.len(),
            archived_entries,
            self.history_telemetry.format_profile(),
        )
    }

    pub(crate) fn mined_rewards_total(&self) -> U256 {
        self.mined_rewards_total
    }

    fn set_mined_reward(&mut self, key: MinedRewardKey, payout: Option<U256>) -> Result<()> {
        let previous = self.mined_rewards_by_window.get(&key).copied();
        if previous == payout {
            return Ok(());
        }
        let total_without_previous = match previous {
            Some(previous) => self
                .mined_rewards_total
                .checked_sub(previous)
                .context("per-session mined reward total underflow")?,
            None => self.mined_rewards_total,
        };
        let total = match payout {
            Some(payout) => total_without_previous
                .checked_add(payout)
                .context("per-session mined reward total overflow")?,
            None => total_without_previous,
        };
        match payout {
            Some(payout) if !payout.is_zero() => {
                self.mined_rewards_by_window.insert(key, payout);
            }
            _ => {
                self.mined_rewards_by_window.remove(&key);
            }
        }
        self.mined_rewards_total = total;
        Ok(())
    }

    fn sync_all_mined_rewards(&mut self) -> Result<()> {
        let mut matching_keys = HashSet::new();
        let mut verified_payouts = HashMap::<MinedRewardKey, U256>::new();
        for entry in &self.journal.state.entries {
            if entry.action != TransactionAction::SubmitProof
                || !self
                    .current_process_proof_hashes
                    .contains(&entry_hash(entry)?)
            {
                continue;
            }
            let key = MinedRewardKey {
                contract: Address::from_str(&entry.contract)
                    .context("journal proof contract address is invalid")?,
                window_id: entry.window_id,
                wallet: Address::from_str(&entry.wallet)
                    .context("journal proof wallet address is invalid")?,
            };
            matching_keys.insert(key);
            if entry.status != TransactionStatus::MinedSuccess
                || entry.outcome.as_deref() != Some("candidate-updated")
                || !entry.reward_confirmed
                || entry.reward_block_hash.is_none()
            {
                continue;
            }
            let Some(payout) = entry
                .reward_outcome
                .as_deref()
                .and_then(|outcome| outcome.strip_prefix("reward-paid:"))
            else {
                continue;
            };
            let payout = parse_decimal_wei(payout)?;
            if payout.is_zero() {
                continue;
            }
            if verified_payouts
                .get(&key)
                .is_some_and(|previous| *previous != payout)
            {
                bail!("verified reward entries disagree on payout for one contract window");
            }
            verified_payouts.insert(key, payout);
        }
        let mut keys = self
            .mined_rewards_by_window
            .keys()
            .copied()
            .collect::<HashSet<_>>();
        keys.extend(matching_keys.iter().copied());
        for key in keys {
            if matching_keys.contains(&key) {
                self.set_mined_reward(key, verified_payouts.get(&key).copied())?;
            }
        }
        Ok(())
    }

    pub(crate) fn set_proof_telemetry(&mut self, telemetry: Arc<ProofPipelineTelemetry>) {
        self.proof_telemetry = Some(telemetry);
    }

    pub(crate) fn set_proof_attempt_guard(&mut self, guard: Arc<ProofAttemptGuard>) {
        self.proof_attempt_guard = Some(guard);
    }

    fn record_proof_metric(&self, node_id: u8, metric: ProofMetric) {
        if let Some(telemetry) = &self.proof_telemetry {
            telemetry.record(node_id, metric);
        }
    }

    pub fn set_diagnostics(&mut self, diagnostics: DiagnosticBuffer) {
        self.diagnostics = Some(diagnostics);
    }

    pub fn set_dashboard_sink(&mut self, sink: TransactionDashboardSink) {
        self.dashboard_sink = Some(sink);
        self.publish_dashboard_state();
    }

    pub fn dashboard_activities(&self) -> Vec<TransactionActivity> {
        self.journal
            .state
            .entries
            .iter()
            .filter(|entry| entry.status.is_unresolved())
            .map(|entry| TransactionActivity {
                node_id: entry.node_id,
                window_id: entry.window_id,
                state: if entry.status == TransactionStatus::Unknown {
                    TransactionActivityState::Recovering
                } else if entry.status == TransactionStatus::Included {
                    TransactionActivityState::Confirming
                } else if entry.status == TransactionStatus::Prepared {
                    TransactionActivityState::Signed
                } else if entry.action == TransactionAction::FinalizeWindow {
                    TransactionActivityState::Finalizing
                } else {
                    TransactionActivityState::Confirming
                },
            })
            .collect()
    }

    fn report_info(&self, message: impl Into<String>) {
        let message = message.into();
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.push(message);
        } else {
            println!("{message}");
        }
    }

    fn report_warning(&self, message: impl Into<String>) {
        let message = message.into();
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.push(message);
        } else {
            eprintln!("{message}");
        }
    }

    fn publish_dashboard_state(&self) {
        let Some(sink) = &self.dashboard_sink else {
            return;
        };
        let session_exposure = match self.session_exposure() {
            Ok(exposure) => exposure,
            Err(error) => {
                self.report_warning(format!(
                    "dashboard could not read transaction session exposure: {error:#}"
                ));
                None
            }
        };
        sink(TransactionDashboardState {
            session_exposure,
            mined_rewards: self.mined_rewards_total,
            activities: self.dashboard_activities(),
        });
    }

    pub async fn reconcile(&mut self, client: &NetworkClient) -> Result<()> {
        if client.manifest.network != Network::Testnet || client.manifest.chain_id != self.chain_id
        {
            bail!("transaction recovery is restricted to the verified Injective Testnet profile");
        }
        self.monitor(client).await?;
        let _recovery_timer = self
            .history_telemetry
            .timer(HistoryDuration::ReceiptRecovery);
        for entry in self.journal.unresolved_entries() {
            let hash = entry_hash(&entry)?;
            let known = client.transaction_known(hash).await?;
            let wallet = Address::from_str(&entry.wallet).unwrap_or(self.wallet);
            match (
                client.primary_nonce(wallet, "latest").await,
                client.pending_nonce(wallet).await,
            ) {
                (Ok(latest_nonce), Ok(pending_nonce)) => self.report_warning(format!(
                    "transaction {hash:#x} remains unresolved (known={known}, latest nonce={latest_nonce}, pending nonce={pending_nonce}, recorded nonce={}); no transaction will be resent",
                    entry.nonce
                )),
                (latest_result, pending_result) => self.report_warning(format!(
                    "transaction {hash:#x} remains unresolved (known={known}, nonce lookup unavailable: latest={:?}, pending={:?}); maximum exposure remains reserved",
                    latest_result.err(),
                    pending_result.err()
                )),
            }
        }
        Ok(())
    }

    pub async fn monitor(&mut self, client: &NetworkClient) -> Result<()> {
        if self.journal.state.entries.is_empty() {
            return Ok(());
        }
        self.history_telemetry
            .add(HistoryCounter::HistoricalHeadRequests, 1);
        let latest_snapshot = match client.latest_block_snapshot().await {
            Ok(snapshot) => snapshot,
            Err(error) if is_transient_rpc_error(&error) => {
                self.report_warning(format!(
                    "transaction monitoring deferred because the latest canonical head is temporarily unavailable; journal exposure remains reserved: {error:#}"
                ));
                return Ok(());
            }
            Err(error) => {
                return Err(error).context("read latest canonical head for transaction monitoring");
            }
        };
        self.monitor_at_snapshot(client, &latest_snapshot).await
    }

    pub async fn monitor_at_snapshot(
        &mut self,
        client: &NetworkClient,
        latest_snapshot: &crate::rpc::BlockSnapshot,
    ) -> Result<()> {
        let _monitor_timer = self
            .history_telemetry
            .timer(HistoryDuration::ReceiptMonitoring);
        let entries = self.journal.state.entries.clone();
        if entries.is_empty() {
            return Ok(());
        }
        let latest_block = latest_snapshot.number;
        let mut canonical_blocks = HashMap::from([(latest_block, latest_snapshot.hash)]);
        let mut journal_dirty = false;
        for entry in entries {
            let hash = entry_hash(&entry)?;
            if entry.status.is_unresolved() {
                let mut entry = entry;
                if entry.wallet.is_empty() {
                    match client.transaction_sender(hash).await {
                        Ok(Some(wallet)) => {
                            self.journal.bind_legacy_wallet(hash, wallet)?;
                            entry = self.journal.entry(hash)?;
                        }
                        Ok(None) => {
                            self.report_warning(format!(
                                "legacy transaction {hash:#x} has no RPC sender record yet; retaining maximum exposure"
                            ));
                            continue;
                        }
                        Err(error) => {
                            self.report_warning(format!(
                                "cannot recover legacy transaction sender for {hash:#x}; retaining maximum exposure: {error:#}"
                            ));
                            continue;
                        }
                    }
                }
                match client.transaction_receipt(hash).await {
                    Ok(Some(receipt)) => {
                        match self
                            .process_receipt(client, &entry, &receipt, latest_block)
                            .await?
                        {
                            ReceiptProgress::Settled(outcome) => {
                                self.report_info(format!(
                                    "settled recovered transaction {hash:#x}: {outcome}"
                                ));
                            }
                            ReceiptProgress::Pending => {}
                            ReceiptProgress::Uncertain => {
                                self.report_warning(format!(
                                    "transaction {hash:#x} lost canonical inclusion; maximum exposure remains reserved"
                                ));
                            }
                        }
                    }
                    Ok(None) if entry.status == TransactionStatus::Included => {
                        self.journal.mark_uncertain(hash)?;
                        self.report_warning(format!(
                            "included transaction {hash:#x} is no longer returned by RPC; maximum exposure restored"
                        ));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        let transient = is_transient_receipt_error(&error);
                        if entry.status == TransactionStatus::Included && !transient {
                            self.journal.mark_uncertain(hash)?;
                        }
                        if transient {
                            self.report_warning(format!(
                                "transaction {hash:#x} receipt recovery is temporarily unavailable; preserving journal state and maximum exposure: {error:#}"
                            ));
                        } else {
                            self.report_warning(format!(
                                "transaction {hash:#x} recovery query failed; exposure remains reserved: {error:#}"
                            ));
                        }
                    }
                }
                continue;
            }

            if entry.confirmations >= ARCHIVE_AFTER_CONFIRMATIONS {
                // The existing archive policy treats settled receipts with 64 canonical
                // confirmations as deeply settled. Keep probing a known reward event until
                // it reaches the same threshold, but do not re-fetch old receipts forever.
                if entry.action == TransactionAction::SubmitProof
                    && entry.outcome.as_deref() == Some("candidate-updated")
                    && entry.reward_block_hash.is_some()
                    && entry.reward_confirmations < ARCHIVE_AFTER_CONFIRMATIONS
                {
                    journal_dirty |= self
                        .monitor_reward_evidence(
                            client,
                            &entry,
                            latest_snapshot,
                            &mut canonical_blocks,
                        )
                        .await?;
                }
                self.history_telemetry
                    .add(HistoryCounter::DeepSettledEntriesSkipped, 1);
                continue;
            }

            self.history_telemetry
                .add(HistoryCounter::SettledCanonicalChecks, 1);

            let Some(block_number) = entry.receipt_block else {
                bail!("settled transaction has no receipt block in the journal");
            };
            let block_hash = entry
                .receipt_block_hash
                .as_deref()
                .context("settled transaction has no receipt block hash")
                .and_then(|value| B256::from_str(value).context("invalid receipt block hash"))?;
            if latest_block < block_number {
                self.journal.mark_uncertain(hash)?;
                self.report_warning(format!(
                    "latest canonical head {latest_block} is behind settled receipt block {block_number} for {hash:#x}; exposure restored for read-only reorg recovery"
                ));
                continue;
            }
            match client
                .receipt_confirmations_at_snapshot(
                    block_number,
                    block_hash,
                    latest_snapshot,
                    &mut canonical_blocks,
                )
                .await
            {
                Ok(Some(confirmations))
                    if confirmations >= u64::from(entry.confirmations_required) =>
                {
                    journal_dirty |= self.journal.update_confirmations(hash, confirmations)?;
                    journal_dirty |= self
                        .monitor_reward_evidence(
                            client,
                            &entry,
                            latest_snapshot,
                            &mut canonical_blocks,
                        )
                        .await?;
                }
                Ok(Some(_)) | Ok(None) => match client.transaction_receipt(hash).await {
                    Ok(Some(receipt)) => {
                        let progress = self
                            .process_receipt(client, &entry, &receipt, latest_block)
                            .await?;
                        if matches!(progress, ReceiptProgress::Uncertain) {
                            self.report_warning(format!(
                                "transaction {hash:#x} reorged; maximum exposure restored"
                            ));
                        }
                    }
                    Ok(None) | Err(_) => {
                        self.journal.mark_uncertain(hash)?;
                        self.report_warning(format!(
                            "settled transaction {hash:#x} is no longer canonical; maximum exposure restored"
                        ));
                    }
                },
                Err(error) => {
                    self.journal.mark_uncertain(hash)?;
                    self.report_warning(format!(
                        "cannot verify canonical block for {hash:#x}; maximum exposure restored: {error:#}"
                    ));
                }
            }
        }
        self.sync_all_mined_rewards()?;
        let archived = self.journal.archive_settled()?;
        if journal_dirty && archived == 0 {
            self.journal.persist()?;
        }
        if !self.journal.has_unresolved() && !self.session_limit.is_zero() {
            self.journal
                .ensure_wallet_session(self.wallet, self.session_limit)?;
        }
        self.publish_dashboard_state();
        Ok(())
    }

    async fn monitor_reward_evidence(
        &mut self,
        client: &NetworkClient,
        entry: &TransactionEntry,
        latest_snapshot: &crate::rpc::BlockSnapshot,
        canonical_blocks: &mut HashMap<u64, B256>,
    ) -> Result<bool> {
        let (Some(reward_block), Some(block_hash)) =
            (entry.reward_block, entry.reward_block_hash.as_deref())
        else {
            return Ok(false);
        };
        let block_hash =
            B256::from_str(block_hash).context("journal reward block hash is invalid")?;
        match client
            .receipt_confirmations_at_snapshot(
                reward_block,
                block_hash,
                latest_snapshot,
                canonical_blocks,
            )
            .await
        {
            Ok(Some(0)) => {
                self.journal.clear_reward_block_hash(entry_hash(entry)?)?;
                Ok(false)
            }
            Ok(Some(confirmations)) => {
                let (newly_confirmed, changed) = self
                    .journal
                    .update_reward_confirmations(entry_hash(entry)?, confirmations)?;
                if newly_confirmed {
                    self.report_info(format!(
                        "node {} window {} reward payout evidence reached {} confirmations: {}",
                        entry.node_id,
                        entry.window_id,
                        confirmations,
                        entry.reward_outcome.as_deref().unwrap_or("unknown")
                    ));
                }
                Ok(changed)
            }
            Ok(None) => {
                self.journal.clear_reward_block_hash(entry_hash(entry)?)?;
                self.report_warning(format!(
                    "reward event for node {} window {} is no longer canonical; reward evidence is pending revalidation",
                    entry.node_id, entry.window_id
                ));
                Ok(false)
            }
            Err(error) => {
                self.journal.clear_reward_block_hash(entry_hash(entry)?)?;
                self.report_warning(format!(
                    "reward event canonicality check failed; reward evidence is pending revalidation: {error:#}"
                ));
                Ok(false)
            }
        }
    }

    async fn process_receipt(
        &mut self,
        client: &NetworkClient,
        entry: &TransactionEntry,
        receipt: &TransactionReceipt,
        latest_block: u64,
    ) -> Result<ReceiptProgress> {
        let hash = entry_hash(entry)?;
        if receipt.transaction_hash != hash {
            bail!("RPC returned a receipt for a different transaction hash");
        }
        let confirmations = match client
            .receipt_confirmations(receipt.block_number, receipt.block_hash, latest_block)
            .await
        {
            Ok(Some(confirmations)) => confirmations,
            Ok(None) => {
                self.journal.mark_uncertain(hash)?;
                self.publish_dashboard_state();
                return Ok(ReceiptProgress::Uncertain);
            }
            Err(error) => {
                self.journal.mark_uncertain(hash)?;
                self.publish_dashboard_state();
                self.report_warning(format!(
                    "receipt canonicality check failed for {hash:#x}: {error:#}"
                ));
                return Ok(ReceiptProgress::Uncertain);
            }
        };
        let outcome = self.validate_receipt(entry, receipt);
        let stored_outcome = outcome
            .as_ref()
            .map(Clone::clone)
            .unwrap_or_else(|_| "receipt-event-unverified".to_owned());
        let inclusion_changed =
            entry.status != TransactionStatus::Included || entry.confirmations != confirmations;
        self.journal
            .record_included(hash, receipt, confirmations, stored_outcome)?;
        self.publish_dashboard_state();
        if inclusion_changed {
            self.report_info(format!(
                "transaction included node={:02} window={} action={:?} hash={hash:#x} confirmations={confirmations}",
                entry.node_id, entry.window_id, entry.action
            ));
        }
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                self.report_warning(format!(
                    "receipt event verification is pending for {hash:#x}: {error:#}"
                ));
                return Ok(ReceiptProgress::Pending);
            }
        };
        if confirmations < u64::from(entry.confirmations_required) {
            return Ok(ReceiptProgress::Pending);
        }
        let actual_cost = match receipt_cost(entry, receipt) {
            Ok(cost) => cost,
            Err(error) => {
                self.journal.record_included(
                    hash,
                    receipt,
                    confirmations,
                    "receipt-cost-unverified".to_owned(),
                )?;
                self.report_warning(format!(
                    "receipt cost remains unverified for {hash:#x}: {error:#}"
                ));
                return Ok(ReceiptProgress::Pending);
            }
        };
        self.journal
            .settle_receipt(hash, receipt, confirmations, actual_cost, outcome.clone())?;
        self.publish_dashboard_state();
        self.report_info(format!(
            "transaction confirmed node={:02} window={} action={:?} hash={hash:#x} outcome={outcome} cost_wei={actual_cost}",
            entry.node_id, entry.window_id, entry.action
        ));
        Ok(ReceiptProgress::Settled(outcome))
    }

    #[cfg(test)]
    pub async fn reconcile_rewards(
        &mut self,
        client: &NetworkClient,
        snapshot: &crate::rpc::ReadSnapshot,
    ) -> Result<()> {
        if !client.verification.token_verified {
            bail!(
                "AST token runtime is not verified; reward events will not be reported as verified"
            );
        }
        loop {
            if self.reward_scan_task.is_none()
                && !self.schedule_reward_reconciliation(client, snapshot)?
            {
                break;
            }
            let task = self
                .reward_scan_task
                .take()
                .context("reward reconciliation batch was not scheduled")?;
            let batch = task
                .await
                .context("join bounded reward reconciliation batch")??;
            if self.apply_reward_scan_batch(batch)? {
                bail!("one or more historical reward windows could not be verified");
            }
        }
        self.sync_all_mined_rewards()?;
        self.publish_dashboard_state();
        Ok(())
    }

    pub(crate) async fn service_reward_reconciliation(
        &mut self,
        client: &NetworkClient,
        snapshot: &crate::rpc::ReadSnapshot,
    ) -> Result<bool> {
        self.history_telemetry
            .add(HistoryCounter::RewardServiceCalls, 1);
        if !client.verification.token_verified {
            return Ok(false);
        }
        if self
            .reward_scan_task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            return Ok(true);
        }
        let mut deferred = false;
        if let Some(task) = self.reward_scan_task.take() {
            match task.await {
                Ok(Ok(batch)) => {
                    if self.apply_reward_scan_batch(batch)? {
                        self.defer_reward_scan();
                        deferred = true;
                    } else {
                        self.reward_scan_retry_attempts = 0;
                        self.reward_scan_retry_at = None;
                    }
                }
                Ok(Err(error)) => {
                    self.history_telemetry
                        .add(HistoryCounter::RewardScanErrors, 1);
                    self.report_warning(format!(
                        "historical reward verification is deferred; its scan cursor is preserved: {error:#}"
                    ));
                    self.defer_reward_scan();
                    deferred = true;
                }
                Err(error) => {
                    self.history_telemetry
                        .add(HistoryCounter::RewardScanErrors, 1);
                    self.report_warning(format!(
                        "historical reward verification task stopped; its scan cursor is preserved: {error}"
                    ));
                    self.defer_reward_scan();
                    deferred = true;
                }
            }
        }
        if deferred {
            return Ok(false);
        }
        self.schedule_reward_reconciliation(client, snapshot)
    }

    async fn service_reward_reconciliation_while_receipt_pending(
        &mut self,
        client: &NetworkClient,
    ) -> Result<()> {
        if !client.verification.token_verified
            || self
                .reward_scan_task
                .as_ref()
                .is_some_and(|task| !task.is_finished())
        {
            return Ok(());
        }
        let has_candidates = match self.journal.reward_candidates() {
            Ok(candidates) => !candidates.is_empty(),
            Err(error) => {
                self.report_receipt_wait_reward_warning(format!(
                    "historical rewards remain pending during receipt confirmation: {error:#}"
                ));
                return Ok(());
            }
        };
        let mut has_unsettled_session_reward = false;
        for entry in &self.journal.state.entries {
            if entry.action == TransactionAction::SubmitProof
                && entry.outcome.as_deref() == Some("candidate-updated")
                && entry.reward_block_hash.is_some()
                && entry.reward_confirmations < ARCHIVE_AFTER_CONFIRMATIONS
                && self
                    .current_process_proof_hashes
                    .contains(&entry_hash(entry)?)
            {
                has_unsettled_session_reward = true;
                break;
            }
        }
        if !has_candidates && !has_unsettled_session_reward {
            return Ok(());
        }
        let snapshot = match client.snapshot(Some(self.wallet)).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.report_receipt_wait_reward_warning(format!(
                    "historical reward snapshot failed during receipt confirmation: {error:#}"
                ));
                return Ok(());
            }
        };
        if let Err(error) = self.service_reward_reconciliation(client, &snapshot).await {
            self.report_receipt_wait_reward_warning(format!(
                "historical reward reconciliation was deferred during receipt confirmation: {error:#}"
            ));
        }
        if let Err(error) = self
            .monitor_session_reward_evidence(client, &snapshot)
            .await
        {
            self.report_receipt_wait_reward_warning(format!(
                "session reward confirmation update was deferred during receipt confirmation: {error:#}"
            ));
        }
        Ok(())
    }

    fn report_receipt_wait_reward_warning(&mut self, message: String) {
        self.receipt_reward_service_errors = self.receipt_reward_service_errors.saturating_add(1);
        if self.receipt_reward_service_errors == 1
            || self.receipt_reward_service_errors.is_multiple_of(5)
        {
            self.report_warning(message);
        }
    }

    async fn monitor_session_reward_evidence(
        &mut self,
        client: &NetworkClient,
        snapshot: &crate::rpc::ReadSnapshot,
    ) -> Result<()> {
        let entries = self.journal.state.entries.clone();
        let mut canonical_blocks = HashMap::from([(snapshot.block.number, snapshot.block.hash)]);
        let mut journal_dirty = false;
        for entry in entries {
            if entry.action != TransactionAction::SubmitProof
                || !self
                    .current_process_proof_hashes
                    .contains(&entry_hash(&entry)?)
                || entry.outcome.as_deref() != Some("candidate-updated")
                || entry.reward_block_hash.is_none()
                || entry.reward_confirmations >= ARCHIVE_AFTER_CONFIRMATIONS
            {
                continue;
            }
            journal_dirty |= self
                .monitor_reward_evidence(client, &entry, &snapshot.block, &mut canonical_blocks)
                .await?;
        }
        self.sync_all_mined_rewards()?;
        if journal_dirty {
            let archived = self.journal.archive_settled()?;
            if archived == 0 {
                self.journal.persist()?;
            }
        }
        self.publish_dashboard_state();
        Ok(())
    }

    fn defer_reward_scan(&mut self) {
        self.reward_scan_retry_attempts = self.reward_scan_retry_attempts.saturating_add(1);
        let shift = u32::from(self.reward_scan_retry_attempts.saturating_sub(1).min(5));
        let delay = REWARD_SCAN_RETRY_BASE
            .saturating_mul(1_u32 << shift)
            .min(REWARD_SCAN_RETRY_MAX);
        self.reward_scan_retry_at = Some(Instant::now() + delay);
        if self.reward_scan_retry_attempts == 1 || self.reward_scan_retry_attempts.is_multiple_of(5)
        {
            self.report_warning(format!(
                "historical reward evidence is pending; bounded verification will retry in {}s",
                delay.as_secs()
            ));
        }
    }

    fn schedule_reward_reconciliation(
        &mut self,
        client: &NetworkClient,
        snapshot: &crate::rpc::ReadSnapshot,
    ) -> Result<bool> {
        if self.reward_scan_task.is_some()
            || self
                .reward_scan_retry_at
                .is_some_and(|retry_at| Instant::now() < retry_at)
        {
            return Ok(false);
        }
        if !client.verification.token_verified {
            return Ok(false);
        }
        let mut candidates = self.journal.reward_candidates()?;
        self.history_telemetry.add(
            HistoryCounter::RewardCandidates,
            u64::try_from(candidates.len()).unwrap_or(u64::MAX),
        );
        candidates.sort_by_key(|candidate| {
            (
                self.journal
                    .state
                    .reward_scan_cursors
                    .get(&reward_scan_key(candidate.contract, candidate.window_id))
                    .map(|cursor| cursor.scanned_through)
                    .unwrap_or(candidate.from_block),
                candidate.from_block,
                candidate.node_id,
                candidate.window_id,
            )
        });
        let pending_keys = candidates
            .iter()
            .map(|candidate| reward_scan_key(candidate.contract, candidate.window_id))
            .collect::<HashSet<_>>();
        let cursor_count = self.journal.state.reward_scan_cursors.len();
        self.journal
            .state
            .reward_scan_cursors
            .retain(|key, _| pending_keys.contains(key));
        let mut changed = cursor_count != self.journal.state.reward_scan_cursors.len();
        if self.journal.state.reward_scan_cursors.is_empty()
            && self.journal.state.reward_scan_anchor.is_some()
        {
            self.journal.state.reward_scan_anchor = None;
            changed = true;
        }
        if changed {
            self.journal.persist()?;
        }

        let now = unix_time_secs();
        let mut jobs = Vec::new();
        for candidate in candidates {
            let Some(state) = snapshot
                .nodes
                .iter()
                .find(|node| node.id == candidate.node_id)
                .and_then(|node| node.state.as_ref())
            else {
                continue;
            };
            if state.work.window_id <= candidate.window_id && !state.work.ended {
                self.history_telemetry
                    .add(HistoryCounter::RewardCandidatesWaitingForWindow, 1);
                continue;
            }
            let key = reward_scan_key(candidate.contract, candidate.window_id);
            let cursor = self.journal.state.reward_scan_cursors.get(&key);
            if cursor.is_some() {
                self.history_telemetry
                    .add(HistoryCounter::RewardCursorHits, 1);
            }
            let retry_due = cursor.is_some_and(|cursor| {
                cursor.retry_after_unix_secs > 0
                    && now >= cursor.retry_after_unix_secs
                    && cursor.scanned_through >= snapshot.block.number
            });
            let rescan_active = cursor.is_none_or(|cursor| cursor.rescan_active) || retry_due;
            let start = if retry_due {
                candidate.from_block
            } else if let Some(cursor) = cursor {
                cursor.scanned_through.saturating_add(1)
            } else {
                candidate.from_block
            };
            if start > snapshot.block.number {
                continue;
            }
            let retry_backoff_secs = match (cursor, retry_due) {
                (Some(cursor), true) => cursor.retry_backoff_secs.saturating_mul(2).clamp(
                    REWARD_EMPTY_SCAN_RETRY_BASE_SECS,
                    REWARD_EMPTY_SCAN_RETRY_MAX_SECS,
                ),
                (Some(cursor), false) => cursor.retry_backoff_secs.clamp(
                    REWARD_EMPTY_SCAN_RETRY_BASE_SECS,
                    REWARD_EMPTY_SCAN_RETRY_MAX_SECS,
                ),
                (None, _) => REWARD_EMPTY_SCAN_RETRY_BASE_SECS,
            };
            let end = start
                .saturating_add(REWARD_SCAN_BLOCK_RANGE - 1)
                .min(snapshot.block.number);
            jobs.push(RewardScanJob {
                key,
                candidate,
                from_block: start,
                to_block: end,
                rescan_active,
                retry_after_unix_secs: cursor
                    .map(|cursor| cursor.retry_after_unix_secs)
                    .unwrap_or_default(),
                retry_backoff_secs,
            });
            if jobs.len() == REWARD_SCAN_JOBS_PER_BATCH {
                break;
            }
        }

        let previous_anchor = self.journal.state.reward_scan_anchor.clone();
        let anchor_needs_check = previous_anchor.as_ref().is_some_and(|anchor| {
            anchor.block_number != snapshot.block.number
                || B256::from_str(&anchor.block_hash).ok() != Some(snapshot.block.hash)
        });
        if jobs.is_empty() && !anchor_needs_check {
            return Ok(false);
        }
        self.history_telemetry
            .add(HistoryCounter::RewardScanBatches, 1);
        self.history_telemetry.add(
            HistoryCounter::RewardScanJobs,
            u64::try_from(jobs.len()).unwrap_or(u64::MAX),
        );
        self.reward_scan_task = Some(tokio::spawn(run_reward_scan_batch(
            client.clone(),
            snapshot.block.clone(),
            previous_anchor,
            jobs,
        )));
        Ok(true)
    }

    fn apply_reward_scan_batch(&mut self, batch: RewardScanBatchOutput) -> Result<bool> {
        match batch {
            RewardScanBatchOutput::ReorgDetected => {
                if !self.journal.state.reward_scan_cursors.is_empty()
                    || self.journal.state.reward_scan_anchor.is_some()
                {
                    self.journal.state.reward_scan_cursors.clear();
                    self.journal.state.reward_scan_anchor = None;
                    self.journal.persist()?;
                    self.history_telemetry
                        .add(HistoryCounter::RewardCursorResets, 1);
                }
                Ok(false)
            }
            RewardScanBatchOutput::Scanned { snapshot, results } => {
                let mut changed = false;
                let mut errors = 0_u64;
                let mut has_evidence = false;
                let mut successful_jobs = 0_u64;
                for result in results {
                    let output = match result {
                        Ok(output) => output,
                        Err(_) => {
                            errors = errors.saturating_add(1);
                            continue;
                        }
                    };
                    successful_jobs = successful_jobs.saturating_add(1);
                    if !output.evidence.is_empty() {
                        for evidence in output.evidence {
                            changed |= self.journal.record_reward_outcome_in_memory(evidence)?;
                            has_evidence = true;
                            self.history_telemetry
                                .add(HistoryCounter::RewardEvidenceVerified, 1);
                        }
                        if self
                            .journal
                            .state
                            .reward_scan_cursors
                            .remove(&output.key)
                            .is_some()
                        {
                            changed = true;
                        }
                    } else if let Some(cursor) = output.cursor {
                        if self.journal.state.reward_scan_cursors.get(&output.key) != Some(&cursor)
                        {
                            self.journal
                                .state
                                .reward_scan_cursors
                                .insert(output.key, cursor);
                            changed = true;
                        }
                    } else {
                        errors = errors.saturating_add(1);
                    }
                }
                if errors > 0 {
                    self.history_telemetry
                        .add(HistoryCounter::RewardScanErrors, errors);
                }
                if successful_jobs > 0 {
                    let anchor = RewardScanAnchor {
                        block_number: snapshot.number,
                        block_hash: format!("{:#x}", snapshot.hash),
                    };
                    if self.journal.state.reward_scan_anchor.as_ref() != Some(&anchor) {
                        self.journal.state.reward_scan_anchor = Some(anchor);
                        changed = true;
                    }
                }
                if changed {
                    self.journal.persist()?;
                    if has_evidence {
                        self.sync_all_mined_rewards()?;
                        self.publish_dashboard_state();
                    }
                }
                Ok(errors > 0)
            }
        }
    }

    pub async fn submit_proof(
        &mut self,
        client: &NetworkClient,
        signer: &SigningKey,
        submission: ProofSubmission,
    ) -> Result<ConfirmedAction> {
        if signer_address(signer) != self.wallet {
            self.record_proof_metric(submission.node_id, ProofMetric::SignerIdentityMismatch);
            bail!("unlocked signer does not match the configured wallet");
        }
        if submission.header.len() > crate::protocol::MAX_HEADER_LENGTH {
            bail!("proof header exceeds the canonical protocol limit");
        }
        let data = AstatineMinerRead::submitSolutionCall {
            header: Bytes::copy_from_slice(&submission.header),
            nonce: submission.nonce,
        }
        .abi_encode();
        self.send(
            client,
            signer,
            TransactionIntent {
                contract: submission.contract,
                node_id: submission.node_id,
                window_id: submission.window_id,
                action: TransactionAction::SubmitProof,
                proof: Some(ProofData {
                    nonce: submission.nonce,
                    work_hash: submission.work_hash,
                    header: submission.header,
                }),
            },
            U256::from(SUBMISSION_FEE_WEI),
            data,
        )
        .await
    }

    pub async fn finalize_window(
        &mut self,
        client: &NetworkClient,
        signer: &SigningKey,
        contract: Address,
        node_id: u8,
        window_id: u64,
    ) -> Result<ConfirmedAction> {
        if signer_address(signer) != self.wallet {
            bail!("unlocked signer does not match the configured wallet");
        }
        self.send(
            client,
            signer,
            TransactionIntent {
                contract,
                node_id,
                window_id,
                action: TransactionAction::FinalizeWindow,
                proof: None,
            },
            U256::ZERO,
            AstatineMinerRead::finalizeWindowCall {}.abi_encode(),
        )
        .await
    }

    pub fn close_session(&mut self) -> Result<()> {
        self.journal.close_session()
    }

    pub fn budget_remaining(&self) -> Result<U256> {
        if self.session_limit.is_zero() {
            return Ok(U256::ZERO);
        }
        self.session_limit
            .checked_sub(self.journal.session_spent_or_reserved()?)
            .context("active session exposure exceeds configured spending limit")
    }

    pub fn proof_attempted(&self, contract: Address, window_id: u64) -> bool {
        self.proof_attempted_through(contract)
            .is_some_and(|last_attempted| window_id <= last_attempted)
    }

    pub(crate) fn proof_attempted_through(&self, contract: Address) -> Option<u64> {
        self.journal
            .state
            .proof_attempted_through
            .get(&proof_attempt_key(contract))
            .copied()
    }

    pub fn session_exposure(&self) -> Result<Option<U256>> {
        if self.journal.state.active_session.is_none() {
            return Ok(None);
        }
        self.journal.session_spent_or_reserved().map(Some)
    }

    async fn send(
        &mut self,
        client: &NetworkClient,
        signer: &SigningKey,
        intent: TransactionIntent,
        value: U256,
        data: Vec<u8>,
    ) -> Result<ConfirmedAction> {
        if !client.can_broadcast() || client.manifest.chain_id != self.chain_id {
            bail!("transaction signing is disabled outside the approved Injective Testnet profile");
        }
        if self.session_limit.is_zero() {
            return Err(TransactionPolicyRefusal {
                kind: TransactionPolicyRefusalKind::SigningDisabled,
                details:
                    "transaction signing is disabled because the configured session cap is zero"
                        .to_owned(),
            }
            .into());
        }
        if self.journal.has_unresolved() {
            bail!(
                "an earlier transaction is unresolved; refusing to broadcast another transaction"
            );
        }
        self.journal.require_wallet_session(self.wallet)?;
        let pinned_address = client
            .manifest
            .nodes
            .iter()
            .find(|pin| pin.id == intent.node_id)
            .with_context(|| {
                format!(
                    "node {} is absent from the Testnet manifest",
                    intent.node_id
                )
            })?;
        if crate::deployment::parse_address(&pinned_address.address)? != intent.contract {
            bail!("selected node contract address differs from its built-in Testnet pin");
        }
        let preflight_snapshot = client.snapshot(Some(self.wallet)).await?;
        validate_fresh_state(
            &preflight_snapshot,
            client.manifest.chain_id,
            self.wallet,
            &intent,
        )?;
        let quote = match client
            .fee_quote(self.wallet, intent.contract, value, &data)
            .await
        {
            Ok(quote) => quote,
            Err(error)
                if intent.action == TransactionAction::SubmitProof
                    && is_window_expired_revert(&error) =>
            {
                return Err(StaleTransactionPreflight {
                    details: "eth_estimateGas reports WindowExpired; local proof was discarded and chain state must be refreshed"
                        .to_owned(),
                }
                .into());
            }
            Err(error)
                if intent.action == TransactionAction::FinalizeWindow
                    && is_window_not_expired_revert(&error) =>
            {
                return Err(StaleTransactionPreflight {
                    details: "eth_estimateGas reports WindowNotExpired; fresh canonical state must be checked before retrying"
                        .to_owned(),
                }
                .into());
            }
            Err(error) => return Err(error).context("quote fees for transaction preflight"),
        };
        let nonce = client.pending_nonce(self.wallet).await?;
        let pending_balance = client.pending_balance(self.wallet).await?;
        let fresh_snapshot = client.snapshot(Some(self.wallet)).await?;
        validate_fresh_state(
            &fresh_snapshot,
            client.manifest.chain_id,
            self.wallet,
            &intent,
        )?;
        let confirmed_balance = fresh_snapshot
            .native_balance
            .context("confirmed INJ balance is unavailable for reserve enforcement")?;
        let spendable_balance = confirmed_balance.min(pending_balance);
        client
            .verify_broadcast_snapshot(&fresh_snapshot.block)
            .await?;
        let runtime_contract = client
            .verify_node_runtime_at(intent.node_id, fresh_snapshot.block.number)
            .await?;
        if runtime_contract != intent.contract {
            bail!("selected node contract address differs from its built-in Testnet pin");
        }
        if client.pending_nonce(self.wallet).await? != nonce {
            return Err(StaleTransactionPreflight {
                details: "wallet pending nonce changed before transaction signing; refresh before retrying"
                    .to_owned(),
            }
            .into());
        }
        let request = Eip1559Request {
            chain_id: self.chain_id,
            nonce,
            max_priority_fee_per_gas: quote.max_priority_fee_per_gas,
            max_fee_per_gas: quote.max_fee_per_gas,
            gas_limit: quote.gas_limit,
            to: intent.contract,
            value,
            data,
        };
        let maximum_exposure = self.journal.validate_exposure(
            &request,
            &intent,
            self.session_limit,
            self.minimum_reserve,
            spendable_balance,
        )?;
        let node_id = intent.node_id;
        let window_id = intent.window_id;
        let action = intent.action;
        let signed = sign_eip1559(signer, &request)?;
        if action == TransactionAction::SubmitProof {
            self.record_proof_metric(node_id, ProofMetric::Signed);
        }
        self.journal.prepare(PreparedTransaction {
            request,
            tx_hash: signed.hash,
            intent,
            session_limit: self.session_limit,
            minimum_reserve: self.minimum_reserve,
            confirmed_balance: spendable_balance,
            confirmations_required: self.confirmations_required,
        })?;
        if action == TransactionAction::SubmitProof {
            self.current_process_proof_hashes.insert(signed.hash);
        }
        if action == TransactionAction::SubmitProof
            && let Some(guard) = &self.proof_attempt_guard
        {
            guard.record_attempt(node_id, window_id);
        }
        self.publish_dashboard_state();
        self.report_info(format!(
            "transaction prepared node={node_id:02} window={window_id} action={action:?} hash={:#x} maximum_exposure_wei={maximum_exposure}",
            signed.hash
        ));

        match client.broadcast_raw_transaction(&signed.raw).await {
            Ok(returned_hash) if returned_hash == signed.hash => {
                self.journal
                    .set_broadcast_state(signed.hash, TransactionStatus::Broadcast)?;
                if action == TransactionAction::SubmitProof {
                    self.record_proof_metric(node_id, ProofMetric::Broadcast);
                }
                self.report_info(format!(
                    "transaction broadcast node={node_id:02} window={window_id} action={action:?} hash={:#x}",
                    signed.hash
                ));
            }
            Ok(returned_hash) => {
                self.journal
                    .set_broadcast_state(signed.hash, TransactionStatus::Unknown)?;
                if action == TransactionAction::SubmitProof {
                    self.record_proof_metric(node_id, ProofMetric::BroadcastOutcomeUnknown);
                }
                self.publish_dashboard_state();
                self.report_warning(format!(
                    "transaction broadcast hash mismatch node={node_id:02} window={window_id} action={action:?} expected={:#x} returned={returned_hash:#x}",
                    signed.hash
                ));
                bail!(
                    "RPC acknowledged unexpected transaction hash {returned_hash:#x}; recorded expected hash {:#x} and will not retry",
                    signed.hash
                );
            }
            Err(error) => {
                self.journal
                    .set_broadcast_state(signed.hash, TransactionStatus::Unknown)?;
                if action == TransactionAction::SubmitProof {
                    self.record_proof_metric(node_id, ProofMetric::BroadcastOutcomeUnknown);
                }
                self.publish_dashboard_state();
                self.report_warning(format!(
                    "transaction broadcast outcome unknown node={node_id:02} window={window_id} action={action:?} hash={:#x}: {error:#}",
                    signed.hash
                ));
                return Err(error).context(format!(
                    "broadcast outcome is unknown for {:#x}; the journal prevents rebroadcast",
                    signed.hash
                ));
            }
        }
        self.publish_dashboard_state();

        let deadline = Instant::now() + RECEIPT_WAIT;
        // The mining coordinator awaits this send through receipt finality. Keep applying
        // completed reward scans here so a later pending proof cannot freeze MINED at zero.
        let mut reward_service_ticker = interval(RECEIPT_POLL_INTERVAL);
        reward_service_ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        reward_service_ticker.tick().await;
        let mut receipt_poll_errors = 0_u32;
        let mut last_receipt_error = None;
        loop {
            if Instant::now() >= deadline {
                return Err(receipt_wait_timeout(
                    signed.hash,
                    last_receipt_error.as_deref(),
                ));
            }
            let receipt_query = client.transaction_receipt(signed.hash);
            tokio::pin!(receipt_query);
            let receipt_result = loop {
                tokio::select! {
                    result = &mut receipt_query => break result,
                    _ = reward_service_ticker.tick(), if client.verification.token_verified => {
                        if let Err(error) = self
                            .service_reward_reconciliation_while_receipt_pending(client)
                            .await
                        {
                            self.report_warning(format!(
                                "session reward reconciliation is deferred while transaction {:#x} awaits receipt confirmation: {error:#}",
                                signed.hash
                            ));
                        }
                    }
                }
            };
            let (receipt, receipt_query_failed) = match receipt_result {
                Ok(receipt) => {
                    receipt_poll_errors = 0;
                    last_receipt_error = None;
                    (receipt, false)
                }
                Err(error) if is_transient_receipt_error(&error) => {
                    receipt_poll_errors = receipt_poll_errors.saturating_add(1);
                    let details = format!("{error:#}");
                    if receipt_poll_errors == 1 || receipt_poll_errors.is_multiple_of(5) {
                        self.report_warning(format!(
                            "receipt lookup temporarily failed for {:#x}; journaled exposure remains reserved and polling will retry without rebroadcasting: {details}",
                            signed.hash
                        ));
                    }
                    last_receipt_error = Some(details);
                    (None, true)
                }
                Err(error) => {
                    return Err(error).context(format!(
                        "receipt verification failed for {:#x}; journaled exposure remains reserved and the transaction will not be resent",
                        signed.hash
                    ));
                }
            };
            if let Some(receipt) = receipt {
                let latest = match client.latest_block_snapshot().await {
                    Ok(snapshot) => snapshot.number,
                    Err(error) => {
                        receipt_poll_errors = receipt_poll_errors.saturating_add(1);
                        let details = format!("read latest block for receipt finality: {error:#}");
                        if receipt_poll_errors == 1 || receipt_poll_errors.is_multiple_of(5) {
                            self.report_warning(format!(
                                "receipt finality lookup temporarily failed for {:#x}; journaled exposure remains reserved and polling will retry: {details}",
                                signed.hash
                            ));
                        }
                        last_receipt_error = Some(details);
                        tokio::select! {
                            _ = sleep(RECEIPT_POLL_INTERVAL) => {}
                            _ = reward_service_ticker.tick(), if client.verification.token_verified => {
                                if let Err(error) = self
                                    .service_reward_reconciliation_while_receipt_pending(client)
                                    .await
                                {
                                    self.report_warning(format!(
                                        "session reward reconciliation is deferred while transaction {:#x} awaits receipt confirmation: {error:#}",
                                        signed.hash
                                    ));
                                }
                            }
                        }
                        continue;
                    }
                };
                receipt_poll_errors = 0;
                last_receipt_error = None;
                match self
                    .process_receipt(client, &self.journal.entry(signed.hash)?, &receipt, latest)
                    .await?
                {
                    ReceiptProgress::Settled(outcome) => {
                        if !receipt.status {
                            let entry = self.journal.entry(signed.hash)?;
                            let actual_cost = entry.actual_cost_wei.context(
                                "settled reverted transaction has no recorded actual cost",
                            )?;
                            return Err(MinedTransactionReverted {
                                action: entry.action,
                                window_id: entry.window_id,
                                details: format!(
                                    "transaction {:#x} was mined but reverted ({actual_cost} wei) and charged gas; this transaction hash will not be resent",
                                    signed.hash
                                ),
                            }
                            .into());
                        }
                        if action == TransactionAction::SubmitProof {
                            self.record_proof_metric(node_id, ProofMetric::ReceiptConfirmed);
                            if outcome == "candidate-updated" {
                                self.record_proof_metric(node_id, ProofMetric::CandidateUpdated);
                            } else if outcome == "submission-rejected-fee-retained" {
                                self.record_proof_metric(node_id, ProofMetric::CandidateRejected);
                            }
                        }
                        return Ok(ConfirmedAction {
                            transaction_hash: signed.hash,
                            receipt,
                            outcome,
                        });
                    }
                    ReceiptProgress::Pending => {
                        let entry = self.journal.entry(signed.hash)?;
                        if entry.outcome.as_deref() == Some("receipt-event-unverified")
                            || entry.outcome.as_deref() == Some("receipt-cost-unverified")
                        {
                            bail!(
                                "transaction {:#x} is included but remains unverified; maximum exposure is reserved and no retry will be sent",
                                signed.hash
                            );
                        }
                    }
                    ReceiptProgress::Uncertain => {
                        bail!(
                            "transaction {:#x} lost canonical inclusion; maximum exposure is reserved and it will not be resent",
                            signed.hash
                        );
                    }
                }
            } else if !receipt_query_failed
                && self.journal.entry(signed.hash)?.status == TransactionStatus::Included
            {
                self.journal.mark_uncertain(signed.hash)?;
                bail!(
                    "transaction {:#x} receipt disappeared before finality; maximum exposure is reserved and it will not be resent",
                    signed.hash
                );
            }
            tokio::select! {
                _ = sleep(RECEIPT_POLL_INTERVAL) => {}
                _ = reward_service_ticker.tick(), if client.verification.token_verified => {
                    if let Err(error) = self
                        .service_reward_reconciliation_while_receipt_pending(client)
                        .await
                    {
                        self.report_warning(format!(
                            "session reward reconciliation is deferred while transaction {:#x} awaits receipt confirmation: {error:#}",
                            signed.hash
                        ));
                    }
                }
            }
        }
    }

    fn validate_receipt(
        &self,
        entry: &TransactionEntry,
        receipt: &TransactionReceipt,
    ) -> Result<String> {
        if receipt.transaction_hash != entry_hash(entry)? {
            bail!("transaction receipt hash differs from the journaled intent");
        }
        let entry_wallet = Address::from_str(&entry.wallet)
            .context("journal wallet address is not yet recoverable")?;
        if !receipt.status {
            return Ok("transaction-reverted".to_owned());
        }
        let contract =
            Address::from_str(&entry.contract).context("journal contract address is invalid")?;
        match entry.action {
            TransactionAction::SubmitProof => {
                let expected_hash = entry
                    .proof_hash
                    .as_deref()
                    .context("proof hash is missing from submission journal")?;
                let expected_hash =
                    B256::from_str(expected_hash).context("journal proof hash is invalid")?;
                let nonce = entry
                    .proof_nonce
                    .context("proof nonce is missing from journal")?;
                match verify_submission_events(
                    &receipt.logs,
                    contract,
                    entry_wallet,
                    entry.window_id,
                    expected_hash,
                    nonce,
                )? {
                    SubmissionOutcome::Accepted => Ok("candidate-updated".to_owned()),
                    SubmissionOutcome::Rejected => {
                        Ok("submission-rejected-fee-retained".to_owned())
                    }
                }
            }
            TransactionAction::FinalizeWindow => {
                let (winner, payout) = verify_finalization_events(
                    &receipt.logs,
                    contract,
                    self.ast_token,
                    entry.window_id,
                )?;
                if winner == entry_wallet && !payout.is_zero() {
                    Ok(format!("window-finalized-reward-paid:{payout}"))
                } else {
                    Ok(format!("window-finalized-winner:{winner}:payout:{payout}"))
                }
            }
        }
    }
}

impl Drop for TransactionManager {
    fn drop(&mut self) {
        if let Some(task) = self.reward_scan_task.take() {
            task.abort();
        }
    }
}

async fn run_reward_scan_batch(
    client: NetworkClient,
    snapshot: crate::rpc::BlockSnapshot,
    previous_anchor: Option<RewardScanAnchor>,
    jobs: Vec<RewardScanJob>,
) -> Result<RewardScanBatchOutput> {
    let telemetry = client.history_telemetry();
    let _reconciliation_timer = telemetry.timer(HistoryDuration::RewardReconciliation);
    if let Some(anchor) = previous_anchor {
        let previous_hash = B256::from_str(&anchor.block_hash)
            .context("persisted reward scan anchor hash is invalid")?;
        if snapshot.number < anchor.block_number {
            bail!(
                "verified head {} is behind the persisted reward scan anchor {}",
                snapshot.number,
                anchor.block_number
            );
        }
        let canonical_hash = if snapshot.number == anchor.block_number {
            snapshot.hash
        } else {
            client.canonical_block_hash(anchor.block_number).await?
        };
        if canonical_hash != previous_hash {
            return Ok(RewardScanBatchOutput::ReorgDetected);
        }
    }

    let mut jobs = jobs.into_iter();
    let mut workers = JoinSet::new();
    for _ in 0..REWARD_SCAN_CONCURRENCY {
        let Some(job) = jobs.next() else {
            break;
        };
        let client = client.clone();
        let snapshot = snapshot.clone();
        workers.spawn(async move { scan_reward_job(client, snapshot, job).await });
    }
    let mut results = Vec::new();
    while let Some(joined) = workers.join_next().await {
        match joined {
            Ok(result) => results.push(result),
            Err(error) => results.push(Err(anyhow!("reward scan worker failed: {error}"))),
        }
        if let Some(job) = jobs.next() {
            let client = client.clone();
            let snapshot = snapshot.clone();
            workers.spawn(async move { scan_reward_job(client, snapshot, job).await });
        }
    }
    Ok(RewardScanBatchOutput::Scanned { snapshot, results })
}

async fn scan_reward_job(
    client: NetworkClient,
    snapshot: crate::rpc::BlockSnapshot,
    job: RewardScanJob,
) -> Result<RewardScanJobOutput> {
    let logs = client
        .window_finalization_logs_range(
            job.candidate.contract,
            client
                .manifest
                .ast_token
                .as_ref()
                .map(|token| crate::deployment::parse_address(&token.address))
                .transpose()?
                .context("AST token pin is unavailable for reward scan")?,
            job.candidate.window_id,
            job.from_block,
            job.to_block,
        )
        .await?;
    if logs.is_empty() {
        let (retry_after_unix_secs, retry_backoff_secs, rescan_active) =
            if job.to_block < snapshot.number {
                (0, job.retry_backoff_secs, job.rescan_active)
            } else if job.rescan_active {
                (
                    unix_time_secs().saturating_add(job.retry_backoff_secs),
                    job.retry_backoff_secs,
                    false,
                )
            } else if job.retry_after_unix_secs > 0 {
                (job.retry_after_unix_secs, job.retry_backoff_secs, false)
            } else {
                (
                    unix_time_secs().saturating_add(REWARD_EMPTY_SCAN_RETRY_BASE_SECS),
                    REWARD_EMPTY_SCAN_RETRY_BASE_SECS,
                    false,
                )
            };
        return Ok(RewardScanJobOutput {
            key: job.key,
            cursor: Some(RewardScanCursor {
                scanned_through: job.to_block,
                retry_after_unix_secs,
                retry_backoff_secs,
                rescan_active,
            }),
            evidence: Vec::new(),
        });
    }

    let (winner, payout) = verify_finalization_events(
        &logs,
        job.candidate.contract,
        client
            .manifest
            .ast_token
            .as_ref()
            .map(|token| crate::deployment::parse_address(&token.address))
            .transpose()?
            .context("AST token pin is unavailable for reward verification")?,
        job.candidate.window_id,
    )?;
    let (reward_block, reward_block_hash) =
        finalization_log_position(&logs, job.candidate.contract, job.candidate.window_id)?;
    let reward_confirmations = client
        .receipt_confirmations(reward_block, reward_block_hash, snapshot.number)
        .await?
        .context("finalization reward event is not canonical at the verified snapshot")?;
    if reward_confirmations == 0 {
        bail!("finalization reward event has no verified canonical confirmation");
    }
    let evidence = job
        .candidate
        .wallets
        .into_iter()
        .map(|(wallet, _)| RewardEvidence {
            contract: job.candidate.contract,
            window_id: job.candidate.window_id,
            wallet,
            block: reward_block,
            block_hash: reward_block_hash,
            confirmations: reward_confirmations,
            outcome: if winner == wallet && !payout.is_zero() {
                format!("reward-paid:{payout}")
            } else {
                format!("not-window-winner:{winner}:payout:{payout}")
            },
        })
        .collect();
    Ok(RewardScanJobOutput {
        key: job.key,
        cursor: None,
        evidence,
    })
}

fn validate_fresh_state(
    snapshot: &ReadSnapshot,
    chain_id: u64,
    wallet: Address,
    intent: &TransactionIntent,
) -> Result<()> {
    let stale = |details: &str| {
        anyhow::Error::new(StaleTransactionPreflight {
            details: details.to_owned(),
        })
    };
    let Some(node) = snapshot.nodes.iter().find(|node| node.id == intent.node_id) else {
        return Err(stale(
            "selected node is missing from the fresh verified snapshot",
        ));
    };
    let Some(state) = node.state.as_ref() else {
        return Err(stale(
            "selected node state is unavailable or not ABI-verified",
        ));
    };
    if state.work.window_id != intent.window_id {
        return Err(stale(
            "selected node advanced to a different window before transaction signing",
        ));
    }
    match (intent.action, intent.proof.as_ref()) {
        (TransactionAction::SubmitProof, Some(proof)) => {
            if !state.eligible || proof.header.len() > state.work.max_header_length as usize {
                return Err(stale(
                    "fresh on-chain work is no longer eligible for proof submission",
                ));
            }
            let context = WorkContext {
                chain_id,
                contract: intent.contract,
                window_id: intent.window_id,
                seed: state.work.seed,
                miner: wallet,
                header: proof.header.clone(),
            };
            if WorkHasher::new(&context)?.hash(proof.nonce) != proof.work_hash
                || !meets_target(proof.work_hash, state.work.target)
                || state
                    .candidate
                    .as_ref()
                    .is_some_and(|candidate| !beats_incumbent(proof.work_hash, candidate.work_hash))
            {
                return Err(stale(
                    "fresh on-chain seed, target, or incumbent invalidated the local proof",
                ));
            }
        }
        (TransactionAction::FinalizeWindow, None) => {
            if !state.finalizable || state.mining_paused {
                return Err(stale(
                    "fresh on-chain state is not permissionlessly finalizable",
                ));
            }
        }
        _ => bail!("transaction action and proof intent do not match"),
    }
    Ok(())
}

pub fn sign_eip1559(signer: &SigningKey, request: &Eip1559Request) -> Result<SignedTransaction> {
    if request.chain_id == 0 || request.gas_limit == 0 {
        bail!("EIP-1559 transaction chain ID and gas limit must be nonzero");
    }
    if request.max_fee_per_gas < request.max_priority_fee_per_gas {
        bail!("EIP-1559 max fee must be at least the priority fee");
    }
    let unsigned_fields = transaction_fields(request);
    let mut signing_payload = vec![0x02];
    signing_payload.extend_from_slice(&encode_rlp_list(&unsigned_fields));
    let signing_hash = keccak256(signing_payload);
    let (signature, recovery_id) = signer.sign_prehash_recoverable(signing_hash.as_slice());
    if recovery_id.is_x_reduced() {
        bail!("secp256k1 recovery ID is not representable by an Ethereum typed transaction");
    }
    let signature_bytes = signature.to_bytes();
    let r = U256::from_be_slice(&signature_bytes[..32]);
    let s = U256::from_be_slice(&signature_bytes[32..]);
    let mut signed_fields = unsigned_fields;
    signed_fields.push(rlp_u64(if recovery_id.is_y_odd() { 1 } else { 0 }));
    signed_fields.push(rlp_u256(r));
    signed_fields.push(rlp_u256(s));

    let mut raw = vec![0x02];
    raw.extend_from_slice(&encode_rlp_list(&signed_fields));
    let hash = keccak256(&raw);
    Ok(SignedTransaction { raw, hash })
}

fn transaction_fields(request: &Eip1559Request) -> Vec<Vec<u8>> {
    vec![
        rlp_u64(request.chain_id),
        rlp_u64(request.nonce),
        rlp_u256(request.max_priority_fee_per_gas),
        rlp_u256(request.max_fee_per_gas),
        rlp_u64(request.gas_limit),
        rlp_bytes(request.to.as_slice()),
        rlp_u256(request.value),
        rlp_bytes(&request.data),
        encode_rlp_list(&[]),
    ]
}

fn encode_rlp_list(encoded_fields: &[Vec<u8>]) -> Vec<u8> {
    let payload_length = encoded_fields.iter().map(Vec::len).sum();
    let mut encoded = Vec::with_capacity(payload_length + 9);
    Header {
        list: true,
        payload_length,
    }
    .encode(&mut encoded);
    for field in encoded_fields {
        encoded.extend_from_slice(field);
    }
    encoded
}

fn rlp_u64(value: u64) -> Vec<u8> {
    alloy_rlp::encode(value)
}

fn rlp_u256(value: U256) -> Vec<u8> {
    let bytes = value.to_be_bytes::<32>();
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    rlp_bytes(&bytes[first_nonzero..])
}

fn rlp_bytes(value: &[u8]) -> Vec<u8> {
    alloy_rlp::encode(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubmissionOutcome {
    Accepted,
    Rejected,
}

fn verify_submission_events(
    logs: &[RpcLog],
    contract: Address,
    wallet: Address,
    window_id: u64,
    work_hash: B256,
    nonce: u128,
) -> Result<SubmissionOutcome> {
    let mut outcome = None;
    for log in logs.iter().filter(|log| log.address == contract) {
        if log.topics.first() == Some(&AstatineMinerRead::CandidateUpdated::SIGNATURE_HASH) {
            let event = AstatineMinerRead::CandidateUpdated::decode_raw_log_validate(
                log.topics.iter().copied(),
                log.data.as_ref(),
            )
            .context("decode CandidateUpdated receipt event")?;
            if event.windowId == window_id
                && event.miner == wallet
                && event.workHash == work_hash
                && event.nonce == nonce
            {
                set_submission_outcome(&mut outcome, SubmissionOutcome::Accepted)?;
            }
        } else if log.topics.first() == Some(&AstatineMinerRead::SubmissionRejected::SIGNATURE_HASH)
        {
            let event = AstatineMinerRead::SubmissionRejected::decode_raw_log_validate(
                log.topics.iter().copied(),
                log.data.as_ref(),
            )
            .context("decode SubmissionRejected receipt event")?;
            if event.windowId == window_id
                && event.miner == wallet
                && event.workHash == work_hash
                && event.fee == U256::from(SUBMISSION_FEE_WEI)
            {
                set_submission_outcome(&mut outcome, SubmissionOutcome::Rejected)?;
            }
        }
    }
    outcome.context("successful submitSolution receipt contains no matching canonical proof event")
}

fn set_submission_outcome(
    outcome: &mut Option<SubmissionOutcome>,
    next: SubmissionOutcome,
) -> Result<()> {
    if outcome.is_some_and(|previous| previous != next) {
        bail!("submission receipt contains conflicting canonical proof events");
    }
    *outcome = Some(next);
    Ok(())
}

fn verify_finalization_events(
    logs: &[RpcLog],
    contract: Address,
    token: Address,
    window_id: u64,
) -> Result<(Address, U256)> {
    let mut finalized = None;
    let mut reward = None;
    let mut miner_transfers = Vec::new();
    for log in logs {
        if log.address == contract
            && log.topics.first() == Some(&AstatineMinerRead::WindowFinalized::SIGNATURE_HASH)
        {
            let event = AstatineMinerRead::WindowFinalized::decode_raw_log_validate(
                log.topics.iter().copied(),
                log.data.as_ref(),
            )
            .context("decode WindowFinalized receipt event")?;
            if event.completedWindowId == window_id {
                if finalized.is_some() {
                    bail!("finalization receipt contains duplicate WindowFinalized events");
                }
                finalized = Some((
                    event.winner,
                    event.payout,
                    log.block_number
                        .context("WindowFinalized log has no block number")?,
                    log.block_hash
                        .context("WindowFinalized log has no block hash")?,
                ));
            }
        } else if log.address == contract
            && log.topics.first() == Some(&AstatineMinerRead::RewardPaid::SIGNATURE_HASH)
        {
            let event = AstatineMinerRead::RewardPaid::decode_raw_log_validate(
                log.topics.iter().copied(),
                log.data.as_ref(),
            )
            .context("decode RewardPaid receipt event")?;
            if event.windowId == window_id {
                if reward.is_some() {
                    bail!("finalization receipt contains duplicate RewardPaid events");
                }
                reward = Some((
                    event.winner,
                    event.amount,
                    log.block_number
                        .context("RewardPaid log has no block number")?,
                    log.block_hash.context("RewardPaid log has no block hash")?,
                ));
            }
        } else if log.address == token
            && log.topics.first() == Some(&IERC20Read::Transfer::SIGNATURE_HASH)
        {
            let event = IERC20Read::Transfer::decode_raw_log_validate(
                log.topics.iter().copied(),
                log.data.as_ref(),
            )
            .context("decode AST Transfer receipt event")?;
            if event.from == contract {
                miner_transfers.push((event.to, event.value, log.block_number, log.block_hash));
            }
        }
    }
    let (winner, payout, finalized_block, finalized_hash) = finalized
        .context("successful finalizeWindow receipt has no matching WindowFinalized event")?;
    if payout.is_zero() {
        if reward.is_some() {
            bail!("empty WindowFinalized payout unexpectedly has a RewardPaid event");
        }
        if miner_transfers.iter().any(|transfer| {
            transfer.2 == Some(finalized_block) && transfer.3 == Some(finalized_hash)
        }) {
            bail!("empty WindowFinalized unexpectedly transfers AST from the miner contract");
        }
    } else if reward != Some((winner, payout, finalized_block, finalized_hash)) {
        bail!("WindowFinalized payout does not match the canonical RewardPaid event");
    } else if miner_transfers
        .iter()
        .filter(|transfer| {
            transfer.0 == winner
                && transfer.1 == payout
                && transfer.2 == Some(finalized_block)
                && transfer.3 == Some(finalized_hash)
        })
        .count()
        != 1
    {
        bail!("RewardPaid does not match exactly one canonical AST Transfer event");
    }
    Ok((winner, payout))
}

fn finalization_log_position(
    logs: &[RpcLog],
    contract: Address,
    window_id: u64,
) -> Result<(u64, B256)> {
    let mut position = None;
    for log in logs.iter().filter(|log| {
        log.address == contract
            && log.topics.first() == Some(&AstatineMinerRead::WindowFinalized::SIGNATURE_HASH)
    }) {
        let event = AstatineMinerRead::WindowFinalized::decode_raw_log_validate(
            log.topics.iter().copied(),
            log.data.as_ref(),
        )
        .context("decode WindowFinalized reward evidence")?;
        if event.completedWindowId == window_id {
            if position.is_some() {
                bail!("multiple canonical WindowFinalized logs matched one window");
            }
            position = Some((
                log.block_number
                    .context("WindowFinalized log has no block number")?,
                log.block_hash
                    .context("WindowFinalized log has no block hash")?,
            ));
        }
    }
    position.context("no canonical WindowFinalized log position was returned")
}

fn receipt_cost(entry: &TransactionEntry, receipt: &TransactionReceipt) -> Result<U256> {
    let maximum_fee = parse_decimal_wei(&entry.max_fee_per_gas_wei)?;
    if receipt.gas_used > U256::from(entry.gas_limit) {
        bail!("receipt reports gas usage above the journaled transaction gas limit");
    }
    if receipt
        .effective_gas_price
        .is_some_and(|price| price > maximum_fee)
    {
        bail!("receipt effective gas price exceeds the journaled EIP-1559 maximum");
    }
    let fee = receipt.effective_gas_price.unwrap_or(maximum_fee);
    let gas = receipt
        .gas_used
        .checked_mul(fee)
        .context("receipt gas cost overflow")?;
    let value = if receipt.status {
        parse_decimal_wei(&entry.value_wei)?
    } else {
        U256::ZERO
    };
    let actual = gas
        .checked_add(value)
        .context("receipt native cost overflow")?;
    if actual > parse_decimal_wei(&entry.maximum_exposure_wei)? {
        bail!("receipt native cost exceeds the journaled maximum transaction exposure");
    }
    Ok(actual)
}

fn validate_journal(state: &JournalState) -> Result<()> {
    if state.version != JOURNAL_VERSION {
        bail!("transaction journal schema is unsupported");
    }
    if let Some(session) = &state.active_session {
        if session.id.is_empty() {
            bail!("transaction journal session ID is empty");
        }
        if !session.wallet.is_empty() {
            Address::from_str(&session.wallet)
                .context("journal session wallet address is invalid")?;
        } else if !state
            .entries
            .iter()
            .any(|entry| entry.session_id == session.id && entry.status.is_unresolved())
        {
            bail!("journal session has no wallet and no recoverable transaction to bind it to");
        }
        parse_decimal_wei(&session.limit_wei)
            .context("journal session spending limit is invalid")?;
    }
    for (contract, window_id) in &state.proof_attempted_through {
        Address::from_str(contract).context("journal proof-attempt contract is invalid")?;
        let _ = window_id;
    }
    if let Some(anchor) = &state.reward_scan_anchor {
        B256::from_str(&anchor.block_hash).context("journal reward-scan anchor hash is invalid")?;
    }
    for (key, cursor) in &state.reward_scan_cursors {
        let (contract, window_id) = key
            .rsplit_once(':')
            .context("journal reward-scan key is invalid")?;
        let contract = Address::from_str(contract)
            .context("journal reward-scan contract address is invalid")?;
        let window_id = window_id
            .parse::<u64>()
            .context("journal reward-scan window ID is invalid")?;
        if key != &reward_scan_key(contract, window_id) {
            bail!("journal reward-scan key is not canonical");
        }
        if state
            .reward_scan_anchor
            .as_ref()
            .is_none_or(|anchor| cursor.scanned_through > anchor.block_number)
        {
            bail!("journal reward-scan cursor is beyond its canonical anchor");
        }
        if !(REWARD_EMPTY_SCAN_RETRY_BASE_SECS..=REWARD_EMPTY_SCAN_RETRY_MAX_SECS)
            .contains(&cursor.retry_backoff_secs)
        {
            bail!("journal reward-scan retry interval is outside supported bounds");
        }
    }
    for amount in state.archived_session_spending.values() {
        parse_decimal_wei(amount).context("archived session spending total is invalid")?;
    }
    parse_decimal_wei(&state.archived_total_spending_wei)
        .context("archived total spending is invalid")?;
    for entry in &state.entries {
        if entry.chain_id != 1439 || entry.node_id == 0 || entry.node_id > 9 {
            bail!("transaction journal has an invalid node ID");
        }
        for value in [
            &entry.value_wei,
            &entry.max_fee_per_gas_wei,
            &entry.maximum_exposure_wei,
        ] {
            parse_decimal_wei(value)?;
        }
        Address::from_str(&entry.contract)
            .context("transaction journal has an invalid contract")?;
        if entry.wallet.is_empty() {
            if !entry.status.is_unresolved() {
                bail!("settled transaction journal entry has no wallet identity");
            }
        } else {
            Address::from_str(&entry.wallet)
                .context("transaction journal has an invalid wallet address")?;
        }
        if state.active_session.as_ref().is_some_and(|session| {
            session.id == entry.session_id
                && !session.wallet.is_empty()
                && !entry.wallet.is_empty()
                && session.wallet != entry.wallet
        }) {
            bail!("transaction wallet does not match its spending session");
        }
        entry_hash(entry)?;
        if let Some(hash) = &entry.proof_hash {
            B256::from_str(hash).context("transaction journal has an invalid proof hash")?;
        }
        if let Some(header) = &entry.header_hex {
            hex::decode(header).context("transaction journal has malformed proof header")?;
        }
        if let Some(actual) = &entry.actual_cost_wei {
            parse_decimal_wei(actual)?;
        }
        if let Some(last_known) = &entry.last_known_cost_wei {
            parse_decimal_wei(last_known)?;
        }
        if let Some(block_hash) = &entry.receipt_block_hash {
            B256::from_str(block_hash).context("journal receipt block hash is invalid")?;
        }
        if let Some(reward_block_hash) = &entry.reward_block_hash {
            B256::from_str(reward_block_hash).context("journal reward block hash is invalid")?;
            if entry.reward_block.is_none() {
                bail!("journal reward block hash has no block number");
            }
        }
        if entry.reward_confirmed
            && (entry.reward_block_hash.is_none()
                || entry.reward_confirmations < u64::from(entry.confirmations_required)
                || entry.reward_outcome.is_none())
        {
            bail!("journal reward confirmation flag is inconsistent with its event evidence");
        }
        if entry.confirmations_required == 0 || entry.confirmations_required > 12 {
            bail!("journal transaction confirmation threshold is invalid");
        }
        match entry.action {
            TransactionAction::SubmitProof
                if entry.proof_nonce.is_none()
                    || entry.proof_hash.is_none()
                    || entry.header_hex.is_none() =>
            {
                bail!("proof transaction journal entry is missing its proof intent")
            }
            TransactionAction::FinalizeWindow
                if entry.proof_nonce.is_some()
                    || entry.proof_hash.is_some()
                    || entry.header_hex.is_some() =>
            {
                bail!("finalization journal entry unexpectedly contains proof data")
            }
            _ => {}
        }
        match entry.status {
            TransactionStatus::Prepared | TransactionStatus::Broadcast => {
                if entry.actual_cost_wei.is_some()
                    || entry.last_known_cost_wei.is_some()
                    || entry.outcome.is_some()
                    || entry.receipt_block.is_some()
                    || entry.receipt_block_hash.is_some()
                    || entry.receipt_status.is_some()
                {
                    bail!("pre-receipt transaction contains receipt data in the journal");
                }
            }
            TransactionStatus::Unknown => {
                if entry.actual_cost_wei.is_some() {
                    bail!("uncertain transaction must reserve maximum, not settled, exposure");
                }
                if entry.receipt_block_hash.is_some() && entry.receipt_block.is_none() {
                    bail!("uncertain receipt block hash has no block number");
                }
            }
            TransactionStatus::Included => {
                if entry.actual_cost_wei.is_some()
                    || entry.receipt_block.is_none()
                    || entry.receipt_block_hash.is_none()
                    || entry.receipt_status.is_none()
                    || entry.outcome.is_none()
                {
                    bail!("included transaction is missing its unconfirmed receipt metadata");
                }
            }
            TransactionStatus::MinedSuccess | TransactionStatus::MinedReverted => {
                if entry.actual_cost_wei.is_none()
                    || entry.outcome.is_none()
                    || entry.receipt_block.is_none()
                    || entry.receipt_block_hash.is_none()
                    || entry.receipt_status.is_none()
                    || entry.confirmations < u64::from(entry.confirmations_required)
                {
                    bail!("settled transaction is missing confirmed receipt metadata");
                }
                if (entry.status == TransactionStatus::MinedSuccess)
                    != entry.receipt_status.unwrap()
                {
                    bail!("settled transaction status disagrees with receipt status");
                }
                if entry.last_known_cost_wei.is_some() {
                    bail!("settled transaction retained stale uncertain spending data");
                }
                if entry.outcome.as_deref() == Some("receipt-event-unverified")
                    || entry.outcome.as_deref() == Some("receipt-cost-unverified")
                {
                    bail!("unverified receipt cannot be marked settled");
                }
            }
        }
        if entry.action == TransactionAction::SubmitProof {
            let contract = Address::from_str(&entry.contract)?;
            if state
                .proof_attempted_through
                .get(&proof_attempt_key(contract))
                .is_none_or(|last_attempt| *last_attempt < entry.window_id)
            {
                bail!("proof attempt is missing from the persistent node/window guard");
            }
        }
    }
    Ok(())
}

fn validate_archive_ledger(
    store: &ConfigStore,
    state: &JournalState,
    telemetry: Option<&HistoryTelemetry>,
) -> Result<()> {
    let mut file_names = HashSet::new();
    let mut session_totals = HashMap::<String, U256>::new();
    let mut grand_total = U256::ZERO;
    for meta in &state.archives {
        if let Some(telemetry) = telemetry {
            telemetry.add(HistoryCounter::ArchiveFilesValidated, 1);
        }
        if !file_names.insert(meta.file_name.clone()) {
            bail!("transaction journal references a duplicate archive file");
        }
        let expected_hash =
            B256::from_str(&meta.content_hash).context("transaction archive digest is invalid")?;
        let contents = store.read_transaction_archive(&meta.file_name)?;
        if keccak256(&contents) != expected_hash {
            bail!(
                "transaction archive {} failed its journal digest",
                meta.file_name
            );
        }
        let archive: JournalArchive =
            serde_json::from_slice(&contents).context("decode transaction archive")?;
        if archive.version != ARCHIVE_VERSION || archive.entries.len() != meta.entry_count as usize
        {
            bail!("transaction archive metadata does not match its contents");
        }
        if let Some(telemetry) = telemetry {
            telemetry.add(
                HistoryCounter::ArchiveEntriesValidated,
                u64::try_from(archive.entries.len()).unwrap_or(u64::MAX),
            );
        }
        let archive_state = JournalState {
            version: JOURNAL_VERSION,
            active_session: None,
            entries: archive.entries.clone(),
            proof_attempted_through: state.proof_attempted_through.clone(),
            archives: Vec::new(),
            archived_session_spending: HashMap::new(),
            archived_total_spending_wei: "0".to_owned(),
            next_archive_sequence: 0,
            reward_scan_cursors: HashMap::new(),
            reward_scan_anchor: None,
        };
        validate_journal(&archive_state)?;
        for entry in archive.entries {
            if !matches!(
                entry.status,
                TransactionStatus::MinedSuccess | TransactionStatus::MinedReverted
            ) || entry.confirmations < ARCHIVE_AFTER_CONFIRMATIONS
            {
                bail!("transaction archive contains unsettled or shallowly confirmed exposure");
            }
            if entry.action == TransactionAction::SubmitProof
                && entry.outcome.as_deref() == Some("candidate-updated")
                && (!entry.reward_confirmed
                    || entry.reward_block_hash.is_none()
                    || entry.reward_confirmations < ARCHIVE_AFTER_CONFIRMATIONS)
            {
                bail!(
                    "transaction archive contains accepted work without sufficiently confirmed reward evidence"
                );
            }
            let actual = parse_decimal_wei(
                entry
                    .actual_cost_wei
                    .as_deref()
                    .context("archived settled transaction has no actual cost")?,
            )?;
            grand_total = grand_total
                .checked_add(actual)
                .context("archived total spending overflow")?;
            let previous = session_totals
                .get(&entry.session_id)
                .copied()
                .unwrap_or(U256::ZERO);
            session_totals.insert(
                entry.session_id,
                previous
                    .checked_add(actual)
                    .context("archived session spending overflow")?,
            );
        }
    }
    let recorded_sessions = state
        .archived_session_spending
        .iter()
        .map(|(session, total)| Ok((session.clone(), parse_decimal_wei(total)?)))
        .collect::<Result<HashMap<_, _>>>()?;
    if recorded_sessions != session_totals
        || parse_decimal_wei(&state.archived_total_spending_wei)? != grand_total
    {
        bail!("transaction archive spending totals do not match preserved receipt history");
    }
    Ok(())
}

fn entry_hash(entry: &TransactionEntry) -> Result<B256> {
    B256::from_str(&entry.transaction_hash).context("transaction journal hash is invalid")
}

fn parse_decimal_wei(value: &str) -> Result<U256> {
    U256::from_str_radix(value, 10).context("transaction journal amount is not decimal wei")
}

fn new_session_id() -> String {
    let mut bytes = [0_u8; 16];
    thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        ARCHIVE_AFTER_CONFIRMATIONS, ARCHIVE_TRIGGER_ENTRIES, Eip1559Request, HistoryCounter,
        HistoryTelemetry, JOURNAL_VERSION, PreparedTransaction, ProofData, ProofSubmission,
        REWARD_EMPTY_SCAN_RETRY_BASE_SECS, RewardScanAnchor, RewardScanBatchOutput,
        RewardScanCursor, SUBMISSION_FEE_WEI, TransactionAction, TransactionActivity,
        TransactionActivityState, TransactionDashboardState, TransactionEntry, TransactionIntent,
        TransactionJournal, TransactionManager, TransactionPolicyRefusalKind, TransactionStatus,
        encode_rlp_list, entry_hash, parse_decimal_wei, reward_scan_key, rlp_bytes, rlp_u64,
        rlp_u256, run_reward_scan_batch, sign_eip1559, transaction_policy_refusal, unix_time_secs,
        validate_archive_ledger, verify_finalization_events, verify_submission_events,
    };
    use crate::{
        cli::{MineArgs, Network},
        config::{AppConfig, ConfigStore, parse_inj_wei},
        contracts::{AstatineMinerRead, IERC20Read},
        diagnostics::DiagnosticBuffer,
        mining::{
            DashboardContext, FinalizationOptions, MiningProbe, NodeSlot, ObserverUpdate,
            finalize_initial_expired_windows, start_read_only_observer, update_slots,
        },
        proof_telemetry::{ProofMetric, ProofPipelineTelemetry},
        protocol::{WorkContext, WorkHasher, beats_incumbent, meets_target},
        rpc::{NetworkClient, RpcLog, TransactionReceipt},
        wallet::signer_address,
    };
    use alloy_primitives::{Address, B256, Bytes, U256, hex, keccak256};
    use alloy_sol_types::{SolCall, SolEvent, SolValue};
    use anyhow::Context;
    use bip32::secp256k1::ecdsa::SigningKey;
    use rand::{RngCore, thread_rng};
    use std::{
        collections::{HashMap, HashSet},
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        num::NonZeroUsize,
        path::PathBuf,
        process::{Child, Command, Stdio},
        str::FromStr,
        sync::{
            Arc, Mutex, RwLock,
            atomic::{AtomicBool, Ordering},
        },
        time::{Duration, Instant},
    };
    use tempfile::tempdir;
    use tokio::time::sleep;

    alloy_sol_types::sol! {
        interface LocalMockAST {
            function decimals() external view returns (uint8);
            function mint(address account, uint256 amount) external;
            function approve(address spender, uint256 amount) external returns (bool);
            function balanceOf(address account) external view returns (uint256);
        }

        interface LocalAstatineMiner {
            function fundAST(uint256 amount) external;
            function activateGenesis(bytes32 initialSeed) external;
        }
    }

    fn test_signer() -> SigningKey {
        let mut key = [0_u8; 32];
        loop {
            thread_rng().fill_bytes(&mut key);
            if let Ok(signer) = SigningKey::from_slice(&key) {
                return signer;
            }
        }
    }

    fn test_request() -> Eip1559Request {
        Eip1559Request {
            chain_id: 1439,
            nonce: 3,
            max_priority_fee_per_gas: U256::from(2_000_000_000_u64),
            max_fee_per_gas: U256::from(30_000_000_000_u64),
            gas_limit: 75_000,
            to: Address::with_last_byte(0x42),
            value: U256::from(10_000_000_000_000_000_u128),
            data: vec![1, 2, 3, 4],
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn settled_history_entry(
        contract: Address,
        node_id: u8,
        wallet: Address,
        session_id: &str,
        window_id: u64,
        hash: B256,
        action: TransactionAction,
        outcome: &str,
        reward_outcome: Option<String>,
        reward_confirmations: u64,
    ) -> TransactionEntry {
        let accepted_proof = action == TransactionAction::SubmitProof;
        let has_reward_evidence = reward_outcome.is_some();
        let reward_block_hash =
            has_reward_evidence.then(|| format!("{:#x}", B256::with_last_byte(0x20)));
        TransactionEntry {
            chain_id: 1439,
            contract: format!("{contract:#x}"),
            node_id,
            window_id,
            action,
            session_id: session_id.to_owned(),
            wallet: format!("{wallet:#x}"),
            nonce: window_id,
            transaction_hash: format!("{hash:#x}"),
            value_wei: if accepted_proof {
                SUBMISSION_FEE_WEI.to_string()
            } else {
                "0".to_owned()
            },
            max_fee_per_gas_wei: "1".to_owned(),
            gas_limit: 21_000,
            maximum_exposure_wei: "1000".to_owned(),
            status: TransactionStatus::MinedSuccess,
            actual_cost_wei: Some("100".to_owned()),
            last_known_cost_wei: None,
            outcome: Some(outcome.to_owned()),
            reward_outcome,
            reward_block: has_reward_evidence.then_some(20),
            reward_block_hash,
            reward_confirmations,
            reward_confirmed: has_reward_evidence && reward_confirmations >= 2,
            proof_nonce: accepted_proof.then_some(window_id as u128),
            proof_hash: accepted_proof.then(|| format!("{hash:#x}")),
            header_hex: accepted_proof.then(|| "01".to_owned()),
            receipt_block: Some(10),
            receipt_block_hash: Some(format!("{:#x}", B256::with_last_byte(0x10))),
            receipt_status: Some(true),
            confirmations: ARCHIVE_AFTER_CONFIRMATIONS,
            confirmations_required: 2,
            created_unix_secs: window_id,
        }
    }

    fn prepared_test_transaction(
        request: &Eip1559Request,
        tx_hash: B256,
        session_limit: U256,
        minimum_reserve: U256,
        confirmed_balance: U256,
        proof: Option<ProofData>,
    ) -> PreparedTransaction {
        PreparedTransaction {
            request: request.clone(),
            tx_hash,
            intent: TransactionIntent {
                contract: request.to,
                node_id: 1,
                window_id: 4,
                action: TransactionAction::SubmitProof,
                proof,
            },
            session_limit,
            minimum_reserve,
            confirmed_balance,
            confirmations_required: 2,
        }
    }

    #[test]
    fn mined_rewards_count_verified_current_process_windows_once_and_correct_reorgs() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x77);
        let contract_one = Address::with_last_byte(1);
        let contract_two = Address::with_last_byte(2);
        let mut manager =
            TransactionManager::open(&store, &config, wallet, Address::with_last_byte(0x88))
                .unwrap();
        let session_id = manager
            .journal
            .state
            .active_session
            .as_ref()
            .unwrap()
            .id
            .clone();
        let old_hash = B256::with_last_byte(1);
        let current_hash = B256::with_last_byte(2);
        let pending_hash = B256::with_last_byte(3);
        let losing_hash = B256::with_last_byte(4);
        let second_node_hash = B256::with_last_byte(5);
        let unpaid_hash = B256::with_last_byte(6);
        let payout_26k = U256::from(26_000_000_000_000_u128);
        let payout_1k = U256::from(1_000_000_000_000_u128);
        let payout_500 = U256::from(500_000_000_000_u128);
        manager.journal.state.entries = vec![
            settled_history_entry(
                contract_one,
                1,
                wallet,
                &session_id,
                1,
                old_hash,
                TransactionAction::SubmitProof,
                "candidate-updated",
                Some(format!("reward-paid:{payout_1k}")),
                ARCHIVE_AFTER_CONFIRMATIONS,
            ),
            settled_history_entry(
                contract_one,
                1,
                wallet,
                &session_id,
                2,
                current_hash,
                TransactionAction::SubmitProof,
                "candidate-updated",
                Some(format!("reward-paid:{payout_26k}")),
                ARCHIVE_AFTER_CONFIRMATIONS,
            ),
            settled_history_entry(
                contract_one,
                1,
                wallet,
                &session_id,
                3,
                pending_hash,
                TransactionAction::SubmitProof,
                "candidate-updated",
                Some(format!("reward-paid:{payout_1k}")),
                1,
            ),
            settled_history_entry(
                contract_one,
                1,
                wallet,
                &session_id,
                4,
                losing_hash,
                TransactionAction::SubmitProof,
                "candidate-updated",
                Some(format!(
                    "not-window-winner:{:#x}:payout:{payout_26k}",
                    Address::with_last_byte(0x55)
                )),
                ARCHIVE_AFTER_CONFIRMATIONS,
            ),
            settled_history_entry(
                contract_two,
                2,
                wallet,
                &session_id,
                5,
                second_node_hash,
                TransactionAction::SubmitProof,
                "candidate-updated",
                Some(format!("reward-paid:{payout_500}")),
                ARCHIVE_AFTER_CONFIRMATIONS,
            ),
            settled_history_entry(
                contract_two,
                2,
                wallet,
                &session_id,
                6,
                unpaid_hash,
                TransactionAction::SubmitProof,
                "candidate-updated",
                None,
                0,
            ),
        ];
        manager
            .journal
            .state
            .proof_attempted_through
            .insert(format!("{contract_one:#x}"), 4);
        manager
            .journal
            .state
            .proof_attempted_through
            .insert(format!("{contract_two:#x}"), 6);
        manager.current_process_proof_hashes.extend([
            current_hash,
            pending_hash,
            losing_hash,
            second_node_hash,
            unpaid_hash,
        ]);

        manager.sync_all_mined_rewards().unwrap();
        assert_eq!(manager.mined_rewards_total(), payout_26k + payout_500);
        manager.sync_all_mined_rewards().unwrap();
        assert_eq!(manager.mined_rewards_total(), payout_26k + payout_500);

        let pending_entry = manager
            .journal
            .state
            .entries
            .iter_mut()
            .find(|entry| entry_hash(entry).unwrap() == pending_hash)
            .unwrap();
        pending_entry.reward_confirmations = 2;
        pending_entry.reward_confirmed = true;
        manager.sync_all_mined_rewards().unwrap();
        assert_eq!(
            manager.mined_rewards_total(),
            payout_26k + payout_500 + payout_1k
        );

        let current_entry = manager
            .journal
            .state
            .entries
            .iter_mut()
            .find(|entry| entry_hash(entry).unwrap() == current_hash)
            .unwrap();
        current_entry.reward_block_hash = None;
        current_entry.reward_confirmed = false;
        current_entry.reward_confirmations = 0;
        manager.sync_all_mined_rewards().unwrap();
        assert_eq!(manager.mined_rewards_total(), payout_500 + payout_1k);
    }

    #[tokio::test]
    async fn reward_reorg_removes_current_process_mined_total() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x77);
        let token = Address::with_last_byte(0x88);
        let contract = Address::with_last_byte(1);
        let (url, rpc_counts, stop_server, server) = history_rpc_server(100, Duration::ZERO);
        let client = NetworkClient::local_test_client(
            &url,
            contract,
            B256::with_last_byte(1),
            token,
            B256::with_last_byte(2),
            9,
        )
        .unwrap();
        let mut manager = TransactionManager::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            token,
            client.history_telemetry(),
        )
        .unwrap();
        let session_id = manager
            .journal
            .state
            .active_session
            .as_ref()
            .unwrap()
            .id
            .clone();
        let proof_hash = B256::with_last_byte(0x52);
        let entry = settled_history_entry(
            contract,
            1,
            wallet,
            &session_id,
            7,
            proof_hash,
            TransactionAction::SubmitProof,
            "candidate-updated",
            Some("reward-paid:26000000000000".to_owned()),
            3,
        );
        manager.journal.state.entries.push(entry);
        manager
            .journal
            .state
            .proof_attempted_through
            .insert(format!("{contract:#x}"), 7);
        manager.current_process_proof_hashes.insert(proof_hash);
        manager.sync_all_mined_rewards().unwrap();
        assert_eq!(
            manager.mined_rewards_total(),
            U256::from(26_000_000_000_000_u128)
        );

        manager
            .monitor_at_snapshot(
                &client,
                &crate::rpc::BlockSnapshot {
                    number: 100,
                    timestamp: 100,
                    hash: B256::with_last_byte(0xaa),
                },
            )
            .await
            .unwrap();
        stop_server.store(true, Ordering::Release);
        server.join().unwrap();
        assert_eq!(manager.mined_rewards_total(), U256::ZERO);
        assert_eq!(
            manager.journal.state.entries[0].reward_block_hash, None,
            "noncanonical reward evidence is cleared and must be rescanned"
        );
        assert_eq!(
            rpc_counts.lock().unwrap().get("eth_getBlockByNumber"),
            Some(&1)
        );
    }

    #[test]
    fn mined_rewards_survive_archive_in_process_but_reset_after_cli_restart() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x77);
        let contract = Address::with_last_byte(1);
        let mut manager =
            TransactionManager::open(&store, &config, wallet, Address::with_last_byte(0x88))
                .unwrap();
        let session_id = manager
            .journal
            .state
            .active_session
            .as_ref()
            .unwrap()
            .id
            .clone();
        let reward_payout = U256::from(26_000_000_000_000_u128);
        let current_hash = B256::with_last_byte(1);
        let mut entries = vec![settled_history_entry(
            contract,
            1,
            wallet,
            &session_id,
            1,
            current_hash,
            TransactionAction::SubmitProof,
            "candidate-updated",
            Some(format!("reward-paid:{reward_payout}")),
            ARCHIVE_AFTER_CONFIRMATIONS,
        )];
        entries.extend((1..ARCHIVE_TRIGGER_ENTRIES).map(|index| {
            settled_history_entry(
                Address::with_last_byte((index % 9 + 1) as u8),
                (index % 9 + 1) as u8,
                wallet,
                &session_id,
                index as u64 + 1,
                B256::from(U256::from(index + 1)),
                TransactionAction::FinalizeWindow,
                "window-finalized",
                None,
                0,
            )
        }));
        manager.journal.state.entries = entries;
        manager
            .journal
            .state
            .proof_attempted_through
            .insert(format!("{contract:#x}"), 1);
        manager.current_process_proof_hashes.insert(current_hash);
        manager.sync_all_mined_rewards().unwrap();
        assert_eq!(manager.mined_rewards_total(), reward_payout);

        let archived = manager.journal.archive_settled().unwrap();
        assert_eq!(archived, ARCHIVE_TRIGGER_ENTRIES);
        assert!(manager.journal.state.entries.is_empty());
        manager.sync_all_mined_rewards().unwrap();
        assert_eq!(manager.mined_rewards_total(), reward_payout);
        drop(manager);

        let restarted =
            TransactionManager::open(&store, &config, wallet, Address::with_last_byte(0x88))
                .unwrap();
        assert_eq!(restarted.mined_rewards_total(), U256::ZERO);
        assert_eq!(restarted.journal.state.archives.len(), 1);
        assert_eq!(
            restarted.journal.state.archives[0].entry_count,
            archived as u32
        );
    }

    #[test]
    fn testnet6_v3_journal_migrates_without_resetting_receipts_or_reward_history() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x77);
        let contract = Address::with_last_byte(1);
        let mut journal = TransactionJournal::open(&store, &config, wallet).unwrap();
        let session_id = journal.state.active_session.as_ref().unwrap().id.clone();
        let hash = B256::with_last_byte(0x52);
        journal
            .state
            .proof_attempted_through
            .insert(format!("{contract:#x}"), 42);
        journal.state.entries.push(settled_history_entry(
            contract,
            1,
            wallet,
            &session_id,
            42,
            hash,
            TransactionAction::SubmitProof,
            "candidate-updated",
            Some("reward-paid:123000000000".to_owned()),
            ARCHIVE_AFTER_CONFIRMATIONS,
        ));
        journal.persist().unwrap();
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&store.read_transaction_journal().unwrap().unwrap()).unwrap();
        legacy["version"] = serde_json::Value::from(3_u64);
        legacy
            .as_object_mut()
            .unwrap()
            .remove("reward_scan_cursors");
        legacy.as_object_mut().unwrap().remove("reward_scan_anchor");
        drop(journal);
        store
            .write_transaction_journal(&serde_json::to_vec(&legacy).unwrap())
            .unwrap();

        let migrated = TransactionJournal::open(&store, &config, wallet).unwrap();
        assert_eq!(migrated.state.version, JOURNAL_VERSION);
        assert!(migrated.state.reward_scan_cursors.is_empty());
        assert!(migrated.state.reward_scan_anchor.is_none());
        assert_eq!(migrated.state.entries.len(), 1);
        assert_eq!(entry_hash(&migrated.state.entries[0]).unwrap(), hash);
        assert_eq!(
            migrated.state.entries[0].reward_outcome.as_deref(),
            Some("reward-paid:123000000000")
        );
        assert_eq!(
            migrated
                .state
                .proof_attempted_through
                .get(&format!("{contract:#x}")),
            Some(&42)
        );
    }

    type HistoryRpcCounts = Arc<Mutex<HashMap<String, u64>>>;
    type HistoryRpcServer = (
        String,
        HistoryRpcCounts,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    );

    fn history_rpc_server(latest_block: u64, response_delay: Duration) -> HistoryRpcServer {
        history_rpc_server_with_log_failures(latest_block, response_delay, 0)
    }

    fn history_rpc_server_with_log_failures(
        latest_block: u64,
        response_delay: Duration,
        log_failures: usize,
    ) -> HistoryRpcServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let counts = Arc::new(Mutex::new(HashMap::new()));
        let server_counts = Arc::clone(&counts);
        let stop_server = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop_server);
        let thread = std::thread::spawn(move || {
            let mut log_failures = log_failures;
            loop {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if server_stop.load(Ordering::Acquire) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("accept history RPC request: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let request = read_history_http_request(&mut stream);
                let method = request["method"].as_str().unwrap().to_owned();
                *server_counts
                    .lock()
                    .unwrap()
                    .entry(method.clone())
                    .or_insert(0) += 1;
                if method == "eth_getLogs" {
                    let range_start = request["params"][0]["fromBlock"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    *server_counts
                        .lock()
                        .unwrap()
                        .entry(format!("eth_getLogs_from_{range_start}"))
                        .or_insert(0) += 1;
                }
                let result = match method.as_str() {
                    "eth_blockNumber" => serde_json::Value::String(format!("0x{latest_block:x}")),
                    "eth_getBlockByNumber" => {
                        let tag = request["params"][0].as_str().unwrap();
                        let number = if tag == "latest" {
                            latest_block
                        } else {
                            u64::from_str_radix(tag.trim_start_matches("0x"), 16).unwrap()
                        };
                        serde_json::json!({
                            "number": format!("0x{number:x}"),
                            "timestamp": "0x1",
                            "hash": format!("{:#x}", B256::with_last_byte(0xaa)),
                        })
                    }
                    "eth_getLogs" => serde_json::Value::Array(Vec::new()),
                    other => panic!("unexpected history RPC method {other}"),
                };
                let response = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": result,
                })
                .to_string();
                if !response_delay.is_zero() {
                    std::thread::sleep(response_delay);
                }
                let status = if method == "eth_getLogs" && log_failures > 0 {
                    log_failures -= 1;
                    503
                } else {
                    200
                };
                write!(
                    stream,
                    "HTTP/1.1 {status} response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                    response.len()
                )
                .unwrap();
            }
        });
        (format!("http://{address}"), counts, stop_server, thread)
    }

    fn read_history_http_request(stream: &mut TcpStream) -> serde_json::Value {
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let count = match stream.read(&mut chunk) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("read history RPC request: {error}"),
            };
            assert_ne!(count, 0, "history RPC client closed before request body");
            bytes.extend_from_slice(&chunk[..count]);
            let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let body_len = headers
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + body_len {
                return serde_json::from_slice(&bytes[header_end + 4..header_end + 4 + body_len])
                    .unwrap();
            }
        }
    }

    #[tokio::test]
    async fn historical_receipt_monitor_skips_deep_settled_history() {
        for count in [10_usize, 100, 1_000] {
            let root = tempdir().unwrap();
            let store = ConfigStore::at_root(PathBuf::from(root.path()));
            let config = AppConfig {
                per_session_spending_limit_inj: "1".to_owned(),
                ..AppConfig::default()
            };
            let wallet = Address::with_last_byte(0x77);
            let token = Address::with_last_byte(0x88);
            let contract = Address::with_last_byte(0x99);
            let (url, rpc_counts, stop_server, server) = history_rpc_server(100, Duration::ZERO);
            let client = NetworkClient::local_test_client(
                &url,
                contract,
                B256::with_last_byte(0x01),
                token,
                B256::with_last_byte(0x02),
                9,
            )
            .unwrap();
            let mut manager = TransactionManager::open_with_history_telemetry(
                &store,
                &config,
                wallet,
                token,
                client.history_telemetry(),
            )
            .unwrap();
            let session_id = manager
                .journal
                .state
                .active_session
                .as_ref()
                .unwrap()
                .id
                .clone();
            manager.journal.state.entries = (0..count)
                .map(|index| TransactionEntry {
                    chain_id: 1439,
                    contract: format!("{contract:#x}"),
                    node_id: 1,
                    window_id: index as u64,
                    action: TransactionAction::FinalizeWindow,
                    session_id: session_id.clone(),
                    wallet: format!("{wallet:#x}"),
                    nonce: index as u64,
                    transaction_hash: format!("{:#x}", B256::from(U256::from(index + 1))),
                    value_wei: "0".to_owned(),
                    max_fee_per_gas_wei: "1".to_owned(),
                    gas_limit: 21_000,
                    maximum_exposure_wei: "0".to_owned(),
                    status: TransactionStatus::MinedSuccess,
                    actual_cost_wei: Some("0".to_owned()),
                    last_known_cost_wei: None,
                    outcome: Some("window-finalized".to_owned()),
                    reward_outcome: None,
                    reward_block: None,
                    reward_block_hash: None,
                    reward_confirmations: 0,
                    reward_confirmed: false,
                    proof_nonce: None,
                    proof_hash: None,
                    header_hex: None,
                    receipt_block: Some(1),
                    receipt_block_hash: Some(format!("{:#x}", B256::with_last_byte(0xaa))),
                    receipt_status: Some(true),
                    confirmations: 100,
                    confirmations_required: 2,
                    created_unix_secs: index as u64,
                })
                .collect();
            manager.journal.persist().unwrap();

            let started = Instant::now();
            let monitor_result = manager.monitor(&client).await;
            let elapsed = started.elapsed();
            stop_server.store(true, Ordering::Release);
            monitor_result.unwrap();
            server.join().unwrap();
            let counts = rpc_counts.lock().unwrap();
            assert_eq!(counts.get("eth_blockNumber"), Some(&1));
            assert_eq!(counts.get("eth_getBlockByNumber"), Some(&1));
            eprintln!(
                "history-monitor-optimized entries={count} elapsed_ms={} eth_getBlockByNumber={} profile={}",
                elapsed.as_millis(),
                counts
                    .get("eth_getBlockByNumber")
                    .copied()
                    .unwrap_or_default(),
                manager.history_profile_line()
            );
            drop(counts);
            drop(manager);
            if count >= super::ARCHIVE_TRIGGER_ENTRIES {
                let started = Instant::now();
                let reopened = TransactionManager::open_with_history_telemetry(
                    &store,
                    &config,
                    wallet,
                    token,
                    client.history_telemetry(),
                )
                .unwrap();
                eprintln!(
                    "history-archive-open entries={count} elapsed_ms={} profile={}",
                    started.elapsed().as_millis(),
                    reopened.history_profile_line()
                );
            }
        }
    }

    #[tokio::test]
    async fn settled_confirmation_updates_are_persisted_as_one_archive_safe_batch() {
        let count = 100_usize;
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x77);
        let token = Address::with_last_byte(0x88);
        let contract = Address::with_last_byte(1);
        let (url, rpc_counts, stop_server, server) = history_rpc_server(100, Duration::ZERO);
        let client = NetworkClient::local_test_client(
            &url,
            contract,
            B256::with_last_byte(1),
            token,
            B256::with_last_byte(2),
            9,
        )
        .unwrap();
        let telemetry = client.history_telemetry();
        let mut manager = TransactionManager::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            token,
            Arc::clone(&telemetry),
        )
        .unwrap();
        let session_id = manager
            .journal
            .state
            .active_session
            .as_ref()
            .unwrap()
            .id
            .clone();
        manager.journal.state.entries = (0..count)
            .map(|index| {
                let mut entry = settled_history_entry(
                    contract,
                    1,
                    wallet,
                    &session_id,
                    index as u64,
                    B256::from(U256::from(index + 1)),
                    TransactionAction::FinalizeWindow,
                    "window-finalized",
                    None,
                    0,
                );
                entry.confirmations = 2;
                entry.receipt_block = Some(10);
                entry.receipt_block_hash = Some(format!("{:#x}", B256::with_last_byte(0xaa)));
                entry
            })
            .collect();
        manager.journal.persist().unwrap();
        let writes_before_monitor = telemetry.count(HistoryCounter::JournalWrites);

        manager.monitor(&client).await.unwrap();
        stop_server.store(true, Ordering::Release);
        server.join().unwrap();
        assert_eq!(
            telemetry.count(HistoryCounter::JournalWrites),
            writes_before_monitor + 1
        );
        assert_eq!(
            telemetry.count(HistoryCounter::SettledCanonicalChecks),
            count as u64
        );
        assert_eq!(
            rpc_counts.lock().unwrap().get("eth_getBlockByNumber"),
            Some(&2)
        );
        assert!(manager.journal.state.entries.is_empty());
        assert_eq!(manager.journal.state.archives.len(), 1);
        assert_eq!(manager.journal.state.archives[0].entry_count, count as u32);
    }

    #[tokio::test]
    async fn reward_scan_cursor_prevents_repeated_historical_log_ranges() {
        for count in [10_usize, 100, 1_000] {
            let root = tempdir().unwrap();
            let store = ConfigStore::at_root(PathBuf::from(root.path()));
            let config = AppConfig {
                per_session_spending_limit_inj: "1".to_owned(),
                ..AppConfig::default()
            };
            let wallet = Address::with_last_byte(0x77);
            let token = Address::with_last_byte(0x88);
            let contract = Address::with_last_byte(0x99);
            let latest = 25_000_u64;
            let (url, rpc_counts, stop_server, server) = history_rpc_server(latest, Duration::ZERO);
            let client = NetworkClient::local_test_client(
                &url,
                contract,
                B256::with_last_byte(0x01),
                token,
                B256::with_last_byte(0x02),
                9,
            )
            .unwrap();
            let mut manager = TransactionManager::open_with_history_telemetry(
                &store,
                &config,
                wallet,
                token,
                client.history_telemetry(),
            )
            .unwrap();
            let session_id = manager
                .journal
                .state
                .active_session
                .as_ref()
                .unwrap()
                .id
                .clone();
            manager.journal.state.entries = (0..count)
                .map(|index| TransactionEntry {
                    chain_id: 1439,
                    contract: format!("{contract:#x}"),
                    node_id: 1,
                    window_id: index as u64,
                    action: TransactionAction::SubmitProof,
                    session_id: session_id.clone(),
                    wallet: format!("{wallet:#x}"),
                    nonce: index as u64,
                    transaction_hash: format!("{:#x}", B256::from(U256::from(index + 1))),
                    value_wei: SUBMISSION_FEE_WEI.to_string(),
                    max_fee_per_gas_wei: "1".to_owned(),
                    gas_limit: 21_000,
                    maximum_exposure_wei: "1".to_owned(),
                    status: TransactionStatus::MinedSuccess,
                    actual_cost_wei: Some("1".to_owned()),
                    last_known_cost_wei: None,
                    outcome: Some("candidate-updated".to_owned()),
                    reward_outcome: None,
                    reward_block: None,
                    reward_block_hash: None,
                    reward_confirmations: 0,
                    reward_confirmed: false,
                    proof_nonce: Some(index as u128),
                    proof_hash: Some(format!("{:#x}", B256::from(U256::from(index + 1)))),
                    header_hex: Some("01".to_owned()),
                    receipt_block: Some(1),
                    receipt_block_hash: Some(format!("{:#x}", B256::with_last_byte(0xaa))),
                    receipt_status: Some(true),
                    confirmations: 100,
                    confirmations_required: 2,
                    created_unix_secs: index as u64,
                })
                .collect();
            manager
                .journal
                .state
                .proof_attempted_through
                .insert(format!("{contract:#x}"), count.saturating_sub(1) as u64);
            manager.journal.persist().unwrap();
            let snapshot = crate::rpc::ReadSnapshot {
                block: crate::rpc::BlockSnapshot {
                    number: latest,
                    timestamp: 25_000,
                    hash: B256::with_last_byte(0xaa),
                },
                native_balance: None,
                native_balance_error: None,
                ast_balance: None,
                ast_balance_error: None,
                nodes: vec![crate::rpc::NodeView {
                    id: 1,
                    address: contract,
                    pin: crate::rpc::ContractPinStatus {
                        runtime_verified: true,
                        abi_verified: true,
                        error: None,
                    },
                    state: Some(crate::rpc::NodeState {
                        work: crate::rpc::WorkInfo {
                            started: true,
                            ended: false,
                            window_id: count as u64,
                            window_start_time: 1,
                            window_expiry_time: 50_000,
                            seed: B256::with_last_byte(1),
                            prev_hash: B256::ZERO,
                            target: U256::MAX,
                            reward_per_window: U256::ZERO,
                            remaining_allocation: U256::from(1),
                            max_header_length: 128,
                            submission_fee: U256::from(SUBMISSION_FEE_WEI),
                        },
                        candidate: None,
                        mining_paused: false,
                        eligible: true,
                        finalizable: false,
                        eligibility_reason: "eligible",
                    }),
                    error: None,
                }],
            };

            let started = Instant::now();
            let reconcile_result = manager.reconcile_rewards(&client, &snapshot).await;
            let elapsed = started.elapsed();
            reconcile_result.unwrap();
            {
                let counts = rpc_counts.lock().unwrap();
                assert_eq!(
                    counts.get("eth_blockNumber").copied().unwrap_or_default(),
                    0
                );
                assert_eq!(counts.get("eth_getLogs"), Some(&(count as u64 * 6)));
                assert_eq!(
                    manager
                        .history_telemetry
                        .count(super::HistoryCounter::BlockRangesScanned),
                    count as u64 * 3
                );
                eprintln!(
                    "reward-reconcile-initial-scan candidates={count} elapsed_ms={} eth_getLogs={} ranges={} profile={}",
                    elapsed.as_millis(),
                    counts.get("eth_getLogs").copied().unwrap_or_default(),
                    count as u64 * 3,
                    manager.history_profile_line()
                );
            }
            let log_calls_before_repeat = manager
                .history_telemetry
                .count(super::HistoryCounter::GetLogsRequests);
            manager.reconcile_rewards(&client, &snapshot).await.unwrap();
            assert_eq!(
                manager
                    .history_telemetry
                    .count(super::HistoryCounter::GetLogsRequests),
                log_calls_before_repeat,
                "a repeated reconcile at the same verified head must not rescan completed ranges"
            );
            if count == 10 {
                let key = reward_scan_key(contract, 0);
                manager
                    .journal
                    .state
                    .reward_scan_cursors
                    .get_mut(&key)
                    .unwrap()
                    .retry_after_unix_secs = unix_time_secs().saturating_sub(1);
                manager.journal.persist().unwrap();
                manager.reconcile_rewards(&client, &snapshot).await.unwrap();
                assert_eq!(
                    manager
                        .history_telemetry
                        .count(super::HistoryCounter::GetLogsRequests),
                    log_calls_before_repeat + 6,
                    "an empty historical scan must be revisited after its bounded retry interval"
                );
            }
            stop_server.store(true, Ordering::Release);
            server.join().unwrap();
        }
    }

    #[tokio::test]
    async fn background_reward_scan_returns_without_blocking_live_work() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x77);
        let token = Address::with_last_byte(0x88);
        let contract = Address::with_last_byte(0x99);
        let latest = 25_000_u64;
        let (url, rpc_counts, stop_server, server) =
            history_rpc_server(latest, Duration::from_millis(150));
        let client = NetworkClient::local_test_client(
            &url,
            contract,
            B256::with_last_byte(0x01),
            token,
            B256::with_last_byte(0x02),
            9,
        )
        .unwrap();
        let mut manager = TransactionManager::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            token,
            client.history_telemetry(),
        )
        .unwrap();
        let session_id = manager
            .journal
            .state
            .active_session
            .as_ref()
            .unwrap()
            .id
            .clone();
        manager
            .journal
            .state
            .proof_attempted_through
            .insert(format!("{contract:#x}"), 0);
        manager.journal.state.entries.push(TransactionEntry {
            chain_id: 1439,
            contract: format!("{contract:#x}"),
            node_id: 1,
            window_id: 0,
            action: TransactionAction::SubmitProof,
            session_id,
            wallet: format!("{wallet:#x}"),
            nonce: 1,
            transaction_hash: format!("{:#x}", B256::with_last_byte(0x11)),
            value_wei: SUBMISSION_FEE_WEI.to_string(),
            max_fee_per_gas_wei: "1".to_owned(),
            gas_limit: 21_000,
            maximum_exposure_wei: "1".to_owned(),
            status: TransactionStatus::MinedSuccess,
            actual_cost_wei: Some("1".to_owned()),
            last_known_cost_wei: None,
            outcome: Some("candidate-updated".to_owned()),
            reward_outcome: None,
            reward_block: None,
            reward_block_hash: None,
            reward_confirmations: 0,
            reward_confirmed: false,
            proof_nonce: Some(1),
            proof_hash: Some(format!("{:#x}", B256::with_last_byte(0x12))),
            header_hex: Some("01".to_owned()),
            receipt_block: Some(1),
            receipt_block_hash: Some(format!("{:#x}", B256::with_last_byte(0xaa))),
            receipt_status: Some(true),
            confirmations: 100,
            confirmations_required: 2,
            created_unix_secs: 1,
        });
        manager.journal.persist().unwrap();
        let snapshot = crate::rpc::ReadSnapshot {
            block: crate::rpc::BlockSnapshot {
                number: latest,
                timestamp: latest,
                hash: B256::with_last_byte(0xaa),
            },
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![crate::rpc::NodeView {
                id: 1,
                address: contract,
                pin: crate::rpc::ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(crate::rpc::NodeState {
                    work: crate::rpc::WorkInfo {
                        started: true,
                        ended: false,
                        window_id: 1,
                        window_start_time: 1,
                        window_expiry_time: latest + 10,
                        seed: B256::with_last_byte(1),
                        prev_hash: B256::ZERO,
                        target: U256::MAX,
                        reward_per_window: U256::ZERO,
                        remaining_allocation: U256::from(1),
                        max_header_length: 128,
                        submission_fee: U256::from(SUBMISSION_FEE_WEI),
                    },
                    candidate: None,
                    mining_paused: false,
                    eligible: true,
                    finalizable: false,
                    eligibility_reason: "eligible",
                }),
                error: None,
            }],
        };

        let started = Instant::now();
        assert!(
            manager
                .service_reward_reconciliation(&client, &snapshot)
                .await
                .unwrap()
        );
        assert!(started.elapsed() < Duration::from_millis(100));
        assert!(
            manager
                .reward_scan_task
                .as_ref()
                .is_some_and(|task| !task.is_finished())
        );

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            manager
                .service_reward_reconciliation(&client, &snapshot)
                .await
                .unwrap();
            if manager.reward_scan_task.is_none()
                && manager
                    .journal
                    .state
                    .reward_scan_cursors
                    .get(&reward_scan_key(contract, 0))
                    .is_some_and(|cursor| cursor.scanned_through == latest)
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
        assert!(manager.reward_scan_task.is_none());
        assert_eq!(
            manager.journal.state.reward_scan_cursors[&reward_scan_key(contract, 0)]
                .scanned_through,
            latest
        );
        let log_requests = client
            .history_telemetry()
            .count(HistoryCounter::GetLogsRequests);
        assert_eq!(log_requests, 6);
        assert!(
            !manager
                .service_reward_reconciliation(&client, &snapshot)
                .await
                .unwrap()
        );
        assert_eq!(
            client
                .history_telemetry()
                .count(HistoryCounter::GetLogsRequests),
            log_requests
        );
        stop_server.store(true, Ordering::Release);
        server.join().unwrap();
        assert_eq!(rpc_counts.lock().unwrap().get("eth_getLogs"), Some(&6));
    }

    #[tokio::test]
    async fn reward_scan_http_503_keeps_cursor_and_retries_the_same_range() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x77);
        let token = Address::with_last_byte(0x88);
        let contract = Address::with_last_byte(0x99);
        let latest = 100_u64;
        let (url, rpc_counts, stop_server, server) =
            history_rpc_server_with_log_failures(latest, Duration::ZERO, 1);
        let client = NetworkClient::local_test_client(
            &url,
            contract,
            B256::with_last_byte(0x01),
            token,
            B256::with_last_byte(0x02),
            9,
        )
        .unwrap();
        let mut manager = TransactionManager::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            token,
            client.history_telemetry(),
        )
        .unwrap();
        let session_id = manager
            .journal
            .state
            .active_session
            .as_ref()
            .unwrap()
            .id
            .clone();
        manager.journal.state.entries.push(settled_history_entry(
            contract,
            1,
            wallet,
            &session_id,
            0,
            B256::with_last_byte(0x61),
            TransactionAction::SubmitProof,
            "candidate-updated",
            None,
            0,
        ));
        manager
            .journal
            .state
            .proof_attempted_through
            .insert(format!("{contract:#x}"), 0);
        manager.journal.persist().unwrap();
        let snapshot = crate::rpc::ReadSnapshot {
            block: crate::rpc::BlockSnapshot {
                number: latest,
                timestamp: latest,
                hash: B256::with_last_byte(0xaa),
            },
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![crate::rpc::NodeView {
                id: 1,
                address: contract,
                pin: crate::rpc::ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(crate::rpc::NodeState {
                    work: crate::rpc::WorkInfo {
                        started: true,
                        ended: false,
                        window_id: 1,
                        window_start_time: 1,
                        window_expiry_time: latest + 10,
                        seed: B256::with_last_byte(1),
                        prev_hash: B256::ZERO,
                        target: U256::MAX,
                        reward_per_window: U256::ZERO,
                        remaining_allocation: U256::from(1),
                        max_header_length: 128,
                        submission_fee: U256::from(SUBMISSION_FEE_WEI),
                    },
                    candidate: None,
                    mining_paused: false,
                    eligible: true,
                    finalizable: false,
                    eligibility_reason: "eligible",
                }),
                error: None,
            }],
        };

        assert!(
            manager
                .service_reward_reconciliation(&client, &snapshot)
                .await
                .unwrap()
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while manager.reward_scan_retry_attempts == 0 && Instant::now() < deadline {
            manager
                .service_reward_reconciliation(&client, &snapshot)
                .await
                .unwrap();
            sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(manager.reward_scan_retry_attempts, 1);
        assert!(manager.journal.state.reward_scan_cursors.is_empty());
        assert_eq!(
            client
                .history_telemetry()
                .count(HistoryCounter::RewardScanErrors),
            1
        );

        manager.reward_scan_retry_at = Some(tokio::time::Instant::now() - Duration::from_secs(1));
        assert!(
            manager
                .service_reward_reconciliation(&client, &snapshot)
                .await
                .unwrap()
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while manager.reward_scan_task.is_some() && Instant::now() < deadline {
            manager
                .service_reward_reconciliation(&client, &snapshot)
                .await
                .unwrap();
            sleep(Duration::from_millis(5)).await;
        }
        assert!(manager.reward_scan_task.is_none());
        assert_eq!(
            manager.journal.state.reward_scan_cursors[&reward_scan_key(contract, 0)]
                .scanned_through,
            latest
        );
        stop_server.store(true, Ordering::Release);
        server.join().unwrap();
        let counts = rpc_counts.lock().unwrap();
        assert_eq!(counts.get("eth_getLogs"), Some(&3));
        assert_eq!(counts.get("eth_getLogs_from_0xa"), Some(&3));
    }

    #[tokio::test]
    async fn reward_scan_restart_resumes_after_the_durable_range_cursor() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x77);
        let token = Address::with_last_byte(0x88);
        let contract = Address::with_last_byte(1);
        let latest = 25_000_u64;
        let snapshot = crate::rpc::ReadSnapshot {
            block: crate::rpc::BlockSnapshot {
                number: latest,
                timestamp: latest,
                hash: B256::with_last_byte(0xaa),
            },
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![crate::rpc::NodeView {
                id: 1,
                address: contract,
                pin: crate::rpc::ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(crate::rpc::NodeState {
                    work: crate::rpc::WorkInfo {
                        started: true,
                        ended: false,
                        window_id: 1,
                        window_start_time: 1,
                        window_expiry_time: latest + 10,
                        seed: B256::with_last_byte(1),
                        prev_hash: B256::ZERO,
                        target: U256::MAX,
                        reward_per_window: U256::ZERO,
                        remaining_allocation: U256::from(1),
                        max_header_length: 128,
                        submission_fee: U256::from(SUBMISSION_FEE_WEI),
                    },
                    candidate: None,
                    mining_paused: false,
                    eligible: true,
                    finalizable: false,
                    eligibility_reason: "eligible",
                }),
                error: None,
            }],
        };
        let (first_url, first_counts, first_stop, first_server) =
            history_rpc_server(latest, Duration::ZERO);
        let first_client = NetworkClient::local_test_client(
            &first_url,
            contract,
            B256::with_last_byte(1),
            token,
            B256::with_last_byte(2),
            9,
        )
        .unwrap();
        let mut manager = TransactionManager::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            token,
            first_client.history_telemetry(),
        )
        .unwrap();
        let session_id = manager
            .journal
            .state
            .active_session
            .as_ref()
            .unwrap()
            .id
            .clone();
        manager.journal.state.entries.push(settled_history_entry(
            contract,
            1,
            wallet,
            &session_id,
            0,
            B256::with_last_byte(0x61),
            TransactionAction::SubmitProof,
            "candidate-updated",
            None,
            0,
        ));
        manager
            .journal
            .state
            .proof_attempted_through
            .insert(format!("{contract:#x}"), 0);
        manager.journal.persist().unwrap();
        assert!(
            manager
                .schedule_reward_reconciliation(&first_client, &snapshot)
                .unwrap()
        );
        let first_batch = manager
            .reward_scan_task
            .take()
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        manager.apply_reward_scan_batch(first_batch).unwrap();
        assert_eq!(
            manager.journal.state.reward_scan_cursors[&reward_scan_key(contract, 0)]
                .scanned_through,
            10 + super::REWARD_SCAN_BLOCK_RANGE - 1
        );
        first_stop.store(true, Ordering::Release);
        first_server.join().unwrap();
        assert_eq!(first_counts.lock().unwrap().get("eth_getLogs"), Some(&2));
        drop(manager);

        let (second_url, second_counts, second_stop, second_server) =
            history_rpc_server(latest, Duration::ZERO);
        let second_client = NetworkClient::local_test_client(
            &second_url,
            contract,
            B256::with_last_byte(1),
            token,
            B256::with_last_byte(2),
            9,
        )
        .unwrap();
        let mut recovered = TransactionManager::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            token,
            second_client.history_telemetry(),
        )
        .unwrap();
        assert!(
            recovered
                .service_reward_reconciliation(&second_client, &snapshot)
                .await
                .unwrap()
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while !recovered
            .reward_scan_task
            .as_ref()
            .is_some_and(|task| task.is_finished())
            && Instant::now() < deadline
        {
            sleep(Duration::from_millis(5)).await;
        }
        assert!(
            recovered
                .reward_scan_task
                .as_ref()
                .is_some_and(|task| task.is_finished())
        );
        second_stop.store(true, Ordering::Release);
        second_server.join().unwrap();
        let counts = second_counts.lock().unwrap();
        assert_eq!(counts.get("eth_getLogs"), Some(&2));
        assert_eq!(counts.get("eth_getLogs_from_0x271a"), Some(&2));
        drop(counts);
    }

    #[tokio::test]
    async fn reward_scan_anchor_reorg_resets_only_scan_cursors() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x77);
        let token = Address::with_last_byte(0x88);
        let contract = Address::with_last_byte(1);
        let client = NetworkClient::local_test_client(
            "http://127.0.0.1:8545",
            contract,
            B256::with_last_byte(1),
            token,
            B256::with_last_byte(2),
            9,
        )
        .unwrap();
        let mut manager = TransactionManager::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            token,
            client.history_telemetry(),
        )
        .unwrap();
        manager.journal.state.reward_scan_anchor = Some(RewardScanAnchor {
            block_number: 100,
            block_hash: format!("{:#x}", B256::with_last_byte(0xaa)),
        });
        manager.journal.state.reward_scan_cursors.insert(
            reward_scan_key(contract, 7),
            RewardScanCursor {
                scanned_through: 90,
                retry_after_unix_secs: unix_time_secs() + 60,
                retry_backoff_secs: REWARD_EMPTY_SCAN_RETRY_BASE_SECS,
                rescan_active: false,
            },
        );
        let historical_entry = settled_history_entry(
            contract,
            1,
            wallet,
            &manager.journal.state.active_session.as_ref().unwrap().id,
            7,
            B256::with_last_byte(0x77),
            TransactionAction::SubmitProof,
            "candidate-updated",
            None,
            0,
        );
        manager.journal.state.entries.push(historical_entry);
        manager
            .journal
            .state
            .proof_attempted_through
            .insert(format!("{contract:#x}"), 7);
        manager.journal.persist().unwrap();

        let batch = run_reward_scan_batch(
            client,
            crate::rpc::BlockSnapshot {
                number: 100,
                timestamp: 100,
                hash: B256::with_last_byte(0xbb),
            },
            manager.journal.state.reward_scan_anchor.clone(),
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(matches!(batch, RewardScanBatchOutput::ReorgDetected));
        manager.apply_reward_scan_batch(batch).unwrap();
        assert!(manager.journal.state.reward_scan_cursors.is_empty());
        assert!(manager.journal.state.reward_scan_anchor.is_none());
        assert_eq!(manager.journal.state.entries.len(), 1);
        assert_eq!(manager.journal.state.entries[0].window_id, 7);
        assert_eq!(
            manager
                .journal
                .state
                .proof_attempted_through
                .get(&format!("{contract:#x}")),
            Some(&7)
        );
    }

    #[tokio::test]
    async fn reward_scan_restart_resumes_from_persisted_block_cursor() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x77);
        let token = Address::with_last_byte(0x88);
        let contract = Address::with_last_byte(1);
        let latest = 25_000_u64;
        let snapshot = crate::rpc::ReadSnapshot {
            block: crate::rpc::BlockSnapshot {
                number: latest,
                timestamp: latest,
                hash: B256::with_last_byte(0xaa),
            },
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![crate::rpc::NodeView {
                id: 1,
                address: contract,
                pin: crate::rpc::ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(crate::rpc::NodeState {
                    work: crate::rpc::WorkInfo {
                        started: true,
                        ended: false,
                        window_id: 1,
                        window_start_time: 1,
                        window_expiry_time: latest + 10,
                        seed: B256::with_last_byte(1),
                        prev_hash: B256::ZERO,
                        target: U256::MAX,
                        reward_per_window: U256::ZERO,
                        remaining_allocation: U256::from(1),
                        max_header_length: 128,
                        submission_fee: U256::from(SUBMISSION_FEE_WEI),
                    },
                    candidate: None,
                    mining_paused: false,
                    eligible: true,
                    finalizable: false,
                    eligibility_reason: "eligible",
                }),
                error: None,
            }],
        };
        let (first_url, first_counts, first_stop, first_server) =
            history_rpc_server(latest, Duration::ZERO);
        let first_client = NetworkClient::local_test_client(
            &first_url,
            contract,
            B256::with_last_byte(1),
            token,
            B256::with_last_byte(2),
            9,
        )
        .unwrap();
        let mut first_manager = TransactionManager::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            token,
            first_client.history_telemetry(),
        )
        .unwrap();
        let session_id = first_manager
            .journal
            .state
            .active_session
            .as_ref()
            .unwrap()
            .id
            .clone();
        let proof_hash = B256::with_last_byte(0x71);
        first_manager
            .journal
            .state
            .entries
            .push(settled_history_entry(
                contract,
                1,
                wallet,
                &session_id,
                0,
                proof_hash,
                TransactionAction::SubmitProof,
                "candidate-updated",
                None,
                0,
            ));
        first_manager
            .journal
            .state
            .proof_attempted_through
            .insert(format!("{contract:#x}"), 0);
        first_manager.journal.persist().unwrap();

        assert!(
            first_manager
                .schedule_reward_reconciliation(&first_client, &snapshot)
                .unwrap()
        );
        let first_batch = first_manager
            .reward_scan_task
            .take()
            .unwrap()
            .await
            .unwrap()
            .unwrap();
        first_manager.apply_reward_scan_batch(first_batch).unwrap();
        first_stop.store(true, Ordering::Release);
        first_server.join().unwrap();
        assert_eq!(first_counts.lock().unwrap().get("eth_getLogs"), Some(&2));
        assert_eq!(
            first_manager.journal.state.reward_scan_cursors[&reward_scan_key(contract, 0)]
                .scanned_through,
            10 + super::REWARD_SCAN_BLOCK_RANGE - 1
        );
        drop(first_manager);

        let (second_url, second_counts, second_stop, second_server) =
            history_rpc_server(latest, Duration::ZERO);
        let second_client = NetworkClient::local_test_client(
            &second_url,
            contract,
            B256::with_last_byte(1),
            token,
            B256::with_last_byte(2),
            9,
        )
        .unwrap();
        let mut recovered = TransactionManager::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            token,
            second_client.history_telemetry(),
        )
        .unwrap();
        assert!(
            recovered
                .service_reward_reconciliation(&second_client, &snapshot)
                .await
                .unwrap()
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while !recovered
            .reward_scan_task
            .as_ref()
            .is_some_and(|task| task.is_finished())
            && Instant::now() < deadline
        {
            sleep(Duration::from_millis(5)).await;
        }
        assert!(
            recovered
                .reward_scan_task
                .as_ref()
                .is_some_and(|task| task.is_finished())
        );
        second_stop.store(true, Ordering::Release);
        second_server.join().unwrap();
        let counts = second_counts.lock().unwrap();
        assert_eq!(counts.get("eth_getLogs"), Some(&2));
        assert_eq!(counts.get("eth_getLogs_from_0x271a"), Some(&2));
        drop(counts);
    }

    #[test]
    fn dashboard_sink_uses_journaled_session_exposure_and_pending_activity() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x99);
        let mut manager =
            TransactionManager::open(&store, &config, wallet, Address::with_last_byte(0x88))
                .unwrap();
        let latest = Arc::new(Mutex::new(None::<TransactionDashboardState>));
        let sink_latest = Arc::clone(&latest);
        manager.set_dashboard_sink(Arc::new(move |state| {
            *sink_latest
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(state);
        }));
        assert_eq!(
            latest
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|state| state.session_exposure),
            Some(U256::ZERO)
        );

        let request = test_request();
        let tx_hash = B256::with_last_byte(0x42);
        manager
            .journal
            .prepare(prepared_test_transaction(
                &request,
                tx_hash,
                U256::from(1_000_000_000_000_000_000_u128),
                U256::from(100_000_000_000_000_000_u128),
                U256::from(2_000_000_000_000_000_000_u128),
                Some(ProofData {
                    nonce: 7,
                    work_hash: B256::with_last_byte(7),
                    header: b"test-header".to_vec(),
                }),
            ))
            .unwrap();
        manager.publish_dashboard_state();

        let state = latest.lock().unwrap().clone().unwrap();
        let maximum_exposure =
            request.value + U256::from(request.gas_limit) * request.max_fee_per_gas;
        assert_eq!(state.session_exposure, Some(maximum_exposure));
        assert_eq!(
            state.activities,
            [TransactionActivity {
                node_id: 1,
                window_id: 4,
                state: TransactionActivityState::Signed,
            }]
        );

        manager
            .journal
            .set_broadcast_state(tx_hash, TransactionStatus::Broadcast)
            .unwrap();
        manager.publish_dashboard_state();
        assert_eq!(
            latest.lock().unwrap().as_ref().unwrap().activities,
            [TransactionActivity {
                node_id: 1,
                window_id: 4,
                state: TransactionActivityState::Confirming,
            }],
            "CONFIRMING is shown only after the journal records an acknowledged broadcast"
        );
    }

    #[test]
    fn typed_transaction_signature_hash_and_raw_hash_are_consistent() {
        let signed = sign_eip1559(&test_signer(), &test_request()).unwrap();
        assert_eq!(signed.raw[0], 0x02);
        assert_eq!(signed.hash, keccak256(&signed.raw));
        assert!(signed.raw.len() > 100);
    }

    #[test]
    fn rlp_integer_and_list_encodings_are_canonical() {
        assert_eq!(rlp_u64(0), [0x80]);
        assert_eq!(rlp_u64(1), [0x01]);
        assert_eq!(rlp_u256(U256::ZERO), [0x80]);
        assert_eq!(rlp_bytes(&[0x01]), [0x01]);
        assert_eq!(encode_rlp_list(&[]), [0xc0]);
    }

    #[test]
    fn testnet_session_journal_reserves_fee_and_exposure_without_raw_transaction() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let mut config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        config.network = Network::Testnet;
        let journal_wallet = Address::with_last_byte(0x99);
        let mut journal = TransactionJournal::open(&store, &config, journal_wallet).unwrap();
        let request = test_request();
        let hash = sign_eip1559(&test_signer(), &request).unwrap().hash;
        journal
            .prepare(prepared_test_transaction(
                &request,
                hash,
                U256::from(1_000_000_000_000_000_000_u128),
                U256::from(100_000_000_000_000_000_u128),
                U256::from(2_000_000_000_000_000_000_u128),
                Some(ProofData {
                    nonce: 8,
                    work_hash: B256::with_last_byte(7),
                    header: b"header".to_vec(),
                }),
            ))
            .unwrap();
        assert!(journal.has_unresolved());
        assert!(journal.pending_exposure().unwrap() > request.value);

        let bytes = store.read_transaction_journal().unwrap().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["entries"][0].get("raw").is_none());
        assert!(json["entries"][0].get("signed_transaction").is_none());
        let session_id = journal.state.active_session.as_ref().unwrap().id.clone();
        assert!(TransactionJournal::open(&store, &config, journal_wallet).is_err());
        assert!(
            journal
                .prepare(prepared_test_transaction(
                    &request,
                    B256::with_last_byte(8),
                    U256::from(1_000_000_000_000_000_000_u128),
                    U256::ZERO,
                    U256::MAX,
                    None,
                ))
                .is_err()
        );
        assert_ne!(
            journal.state.active_session.as_ref().unwrap().limit_wei,
            "0"
        );
        assert_eq!(journal.state.entries[0].status, TransactionStatus::Prepared);
        drop(journal);
        let recovery =
            TransactionJournal::open(&store, &config, Address::with_last_byte(0x98)).unwrap();
        assert!(recovery.has_unresolved());
        drop(recovery);
        let resumed = TransactionJournal::open(&store, &config, journal_wallet).unwrap();
        assert_eq!(
            resumed.state.active_session.as_ref().unwrap().id,
            session_id,
            "an interrupted session must not reset its spending budget"
        );
        assert!(resumed.has_unresolved());
        assert_eq!(
            resumed
                .state
                .proof_attempted_through
                .get(&format!("{:#x}", request.to)),
            Some(&4),
            "the paid-proof guard survives process restart"
        );
    }

    #[test]
    fn settled_proof_attempt_guard_survives_restart() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x99);
        let request = test_request();
        let hash = sign_eip1559(&test_signer(), &request).unwrap().hash;
        let intent = TransactionIntent {
            contract: request.to,
            node_id: 1,
            window_id: 4,
            action: TransactionAction::SubmitProof,
            proof: Some(ProofData {
                nonce: 8,
                work_hash: B256::with_last_byte(7),
                header: b"header".to_vec(),
            }),
        };
        let mut journal = TransactionJournal::open(&store, &config, wallet).unwrap();
        journal
            .prepare(prepared_test_transaction(
                &request,
                hash,
                U256::from(1_000_000_000_000_000_000_u128),
                U256::ZERO,
                U256::MAX,
                intent.proof.clone(),
            ))
            .unwrap();
        let entry = &mut journal.state.entries[0];
        entry.status = TransactionStatus::MinedSuccess;
        entry.actual_cost_wei = Some("100".to_owned());
        entry.outcome = Some("candidate-updated".to_owned());
        entry.receipt_block = Some(10);
        entry.receipt_block_hash = Some(format!("{:#x}", B256::with_last_byte(10)));
        entry.receipt_status = Some(true);
        entry.confirmations = 2;
        journal.persist().unwrap();
        drop(journal);

        let mut resumed = TransactionJournal::open(&store, &config, wallet).unwrap();
        let error = resumed
            .validate_exposure(
                &request,
                &intent,
                U256::from(1_000_000_000_000_000_000_u128),
                U256::ZERO,
                U256::MAX,
            )
            .unwrap_err();
        assert!(format!("{error:#}").contains("paid proof attempt already journaled"));
    }

    #[test]
    fn proof_attempt_guard_only_suppresses_the_same_contract_through_the_attempted_window() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = signer_address(&test_signer());
        let contract = Address::with_last_byte(0x42);
        let mut manager =
            TransactionManager::open(&store, &config, wallet, Address::with_last_byte(0x88))
                .unwrap();
        let intent = TransactionIntent {
            contract,
            node_id: 1,
            window_id: 4,
            action: TransactionAction::SubmitProof,
            proof: Some(ProofData {
                nonce: 8,
                work_hash: B256::with_last_byte(7),
                header: b"header".to_vec(),
            }),
        };
        let mut request = test_request();
        request.to = contract;
        let tx_hash = sign_eip1559(&test_signer(), &request).unwrap().hash;
        manager
            .journal
            .prepare(PreparedTransaction {
                request,
                tx_hash,
                intent: intent.clone(),
                session_limit: U256::from(1_000_000_000_000_000_000_u128),
                minimum_reserve: U256::ZERO,
                confirmed_balance: U256::MAX,
                confirmations_required: 1,
            })
            .unwrap();

        assert!(manager.proof_attempted(contract, 4));
        assert!(manager.proof_attempted(contract, 3));
        assert!(!manager.proof_attempted(contract, 5));
        assert!(!manager.proof_attempted(Address::with_last_byte(0x43), 4));
    }

    #[tokio::test]
    async fn proof_submission_rejects_wrong_wallet_before_rpc_or_journal_attempt() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            wallet_address: Some(format!("{:#x}", Address::with_last_byte(0x99))),
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x99);
        let token = Address::with_last_byte(0x88);
        let contract = Address::with_last_byte(1);
        let network = NetworkClient::local_test_client(
            "http://127.0.0.1:1",
            contract,
            B256::with_last_byte(2),
            token,
            B256::with_last_byte(3),
            9,
        )
        .unwrap();
        let mut manager = TransactionManager::open(&store, &config, wallet, token).unwrap();
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        manager.set_proof_telemetry(Arc::clone(&telemetry));
        let error = manager
            .submit_proof(
                &network,
                &test_signer(),
                ProofSubmission {
                    contract,
                    node_id: 1,
                    window_id: 0,
                    nonce: 1,
                    header: Vec::new(),
                    work_hash: B256::with_last_byte(4),
                },
            )
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("does not match the configured wallet"));
        assert_eq!(telemetry.count(1, ProofMetric::SignerIdentityMismatch), 1);
        assert!(manager.journal.state.entries.is_empty());
        assert!(!manager.proof_attempted(contract, 0));
    }

    #[test]
    fn legacy_unverified_receipt_migrates_to_recoverable_reserved_exposure() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x99);
        let request = test_request();
        let tx_hash = sign_eip1559(&test_signer(), &request).unwrap().hash;
        let mut journal = TransactionJournal::open(&store, &config, wallet).unwrap();
        journal
            .prepare(prepared_test_transaction(
                &request,
                tx_hash,
                U256::from(1_000_000_000_000_000_000_u128),
                U256::ZERO,
                U256::MAX,
                Some(ProofData {
                    nonce: 8,
                    work_hash: B256::with_last_byte(7),
                    header: b"legacy".to_vec(),
                }),
            ))
            .unwrap();
        let legacy_entry = &mut journal.state.entries[0];
        legacy_entry.status = TransactionStatus::MinedSuccess;
        legacy_entry.actual_cost_wei = Some("12345".to_owned());
        legacy_entry.outcome = Some("receipt-event-unverified".to_owned());
        legacy_entry.receipt_block = Some(99);
        legacy_entry.receipt_status = Some(true);
        legacy_entry.confirmations = 0;
        journal.state.version = 1;
        journal
            .state
            .active_session
            .as_mut()
            .unwrap()
            .wallet
            .clear();
        journal.state.proof_attempted_through.clear();
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&journal.state).unwrap()).unwrap();
        let state = legacy.as_object_mut().unwrap();
        state.remove("proof_attempted_through");
        state.remove("archives");
        state.remove("archived_session_spending");
        state.remove("archived_total_spending_wei");
        state.remove("next_archive_sequence");
        state["active_session"]
            .as_object_mut()
            .unwrap()
            .remove("wallet");
        let entry = state["entries"][0].as_object_mut().unwrap();
        for key in [
            "wallet",
            "last_known_cost_wei",
            "reward_block",
            "reward_block_hash",
            "reward_confirmations",
            "reward_confirmed",
            "receipt_block_hash",
            "receipt_status",
            "confirmations",
            "confirmations_required",
        ] {
            entry.remove(key);
        }
        drop(journal);
        store
            .write_transaction_journal(&serde_json::to_vec(&legacy).unwrap())
            .unwrap();

        let migrated = TransactionJournal::open(&store, &config, wallet).unwrap();
        assert_eq!(migrated.state.version, super::JOURNAL_VERSION);
        assert!(migrated.has_unresolved());
        let entry = &migrated.state.entries[0];
        assert_eq!(entry.status, TransactionStatus::Unknown);
        assert_eq!(entry.last_known_cost_wei.as_deref(), Some("12345"));
        assert_eq!(entry.outcome.as_deref(), Some("receipt-event-unverified"));
        assert_eq!(entry.receipt_block, Some(99));
        assert!(migrated.pending_exposure().unwrap() > request.value);
        assert_eq!(
            migrated
                .state
                .proof_attempted_through
                .get(&format!("{:#x}", request.to)),
            Some(&4)
        );
        drop(migrated);

        let read_only_config = AppConfig {
            per_session_spending_limit_inj: "0".to_owned(),
            ..config
        };
        let read_only = TransactionJournal::open(&store, &read_only_config, wallet).unwrap();
        assert!(read_only.has_unresolved());
        assert!(read_only.pending_exposure().unwrap() > request.value);
    }

    #[test]
    fn archives_only_deeply_confirmed_settled_entries_and_keeps_spending_totals() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x99);
        let mut journal = TransactionJournal::open(&store, &config, wallet).unwrap();
        let session_id = journal.state.active_session.as_ref().unwrap().id.clone();
        journal.state.entries = (0..super::ARCHIVE_TRIGGER_ENTRIES)
            .map(|index| TransactionEntry {
                chain_id: 1439,
                contract: format!("{:#x}", Address::with_last_byte(1)),
                node_id: 1,
                window_id: index as u64,
                action: TransactionAction::FinalizeWindow,
                session_id: session_id.clone(),
                wallet: format!("{wallet:#x}"),
                nonce: index as u64,
                transaction_hash: format!("{:#x}", B256::with_last_byte(index as u8)),
                value_wei: "0".to_owned(),
                max_fee_per_gas_wei: "10".to_owned(),
                gas_limit: 10,
                maximum_exposure_wei: "100".to_owned(),
                status: TransactionStatus::MinedSuccess,
                actual_cost_wei: Some("100".to_owned()),
                last_known_cost_wei: None,
                outcome: Some("window-finalized-winner:0x0:payout:0".to_owned()),
                reward_outcome: None,
                reward_block: None,
                reward_block_hash: None,
                reward_confirmations: 0,
                reward_confirmed: false,
                proof_nonce: None,
                proof_hash: None,
                header_hex: None,
                receipt_block: Some(index as u64 + 1),
                receipt_block_hash: Some(format!(
                    "{:#x}",
                    B256::with_last_byte((index as u8).wrapping_add(1))
                )),
                receipt_status: Some(true),
                confirmations: super::ARCHIVE_AFTER_CONFIRMATIONS,
                confirmations_required: 2,
                created_unix_secs: index as u64,
            })
            .collect();
        let archived = journal.archive_settled().unwrap();
        assert_eq!(
            archived,
            super::ARCHIVE_TRIGGER_ENTRIES.min(super::ARCHIVE_BATCH_SIZE)
        );
        assert_eq!(
            journal.state.entries.len(),
            super::ARCHIVE_TRIGGER_ENTRIES - archived
        );
        assert_eq!(journal.state.archives.len(), 1);
        assert_eq!(
            journal.state.archived_total_spending_wei,
            (archived as u64 * 100).to_string()
        );
        assert_eq!(
            journal.session_spent_or_reserved().unwrap(),
            U256::from((super::ARCHIVE_TRIGGER_ENTRIES as u64) * 100)
        );
        validate_archive_ledger(&store, &journal.state, None).unwrap();
        drop(journal);
        let reopened = TransactionJournal::open(&store, &config, wallet).unwrap();
        assert_eq!(
            reopened.state.entries.len(),
            super::ARCHIVE_TRIGGER_ENTRIES - archived
        );
        assert_eq!(
            reopened.session_spent_or_reserved().unwrap(),
            U256::from((super::ARCHIVE_TRIGGER_ENTRIES as u64) * 100)
        );
    }

    #[test]
    fn corrupted_archive_is_rejected_without_discarding_journal_history() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x99);
        let contract = Address::with_last_byte(1);
        let telemetry = Arc::new(HistoryTelemetry::default());
        let mut journal = TransactionJournal::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            Arc::clone(&telemetry),
        )
        .unwrap();
        let session_id = journal.state.active_session.as_ref().unwrap().id.clone();
        journal.state.entries = (0..ARCHIVE_TRIGGER_ENTRIES)
            .map(|index| {
                settled_history_entry(
                    contract,
                    1,
                    wallet,
                    &session_id,
                    index as u64,
                    B256::from(U256::from(index + 1)),
                    TransactionAction::FinalizeWindow,
                    "window-finalized",
                    None,
                    0,
                )
            })
            .collect();
        assert_eq!(journal.archive_settled().unwrap(), ARCHIVE_TRIGGER_ENTRIES);
        let archive = journal.state.archives[0].file_name.clone();
        drop(journal);

        let archive_path = root
            .path()
            .join("transactions")
            .join("archives")
            .join(archive);
        let mut contents = std::fs::read(&archive_path).unwrap();
        contents[0] ^= 1;
        std::fs::write(&archive_path, contents).unwrap();
        let open_error = match TransactionJournal::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            Arc::clone(&telemetry),
        ) {
            Ok(_) => panic!("modified archive should fail digest validation"),
            Err(error) => error,
        };
        assert!(open_error.to_string().contains("failed its journal digest"));
        assert_eq!(
            telemetry.count(HistoryCounter::ArchiveValidationFailures),
            1
        );
        assert!(store.read_transaction_journal().unwrap().is_some());
    }

    #[test]
    fn journal_and_archive_write_failures_are_reported_without_losing_active_entries() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let wallet = Address::with_last_byte(0x99);
        let contract = Address::with_last_byte(1);
        let telemetry = Arc::new(HistoryTelemetry::default());
        let mut journal = TransactionJournal::open_with_history_telemetry(
            &store,
            &config,
            wallet,
            Arc::clone(&telemetry),
        )
        .unwrap();
        let session_id = journal.state.active_session.as_ref().unwrap().id.clone();
        journal.state.entries = (0..ARCHIVE_TRIGGER_ENTRIES)
            .map(|index| {
                settled_history_entry(
                    contract,
                    1,
                    wallet,
                    &session_id,
                    index as u64,
                    B256::from(U256::from(index + 1)),
                    TransactionAction::FinalizeWindow,
                    "window-finalized",
                    None,
                    0,
                )
            })
            .collect();

        let archives_path = root.path().join("transactions").join("archives");
        std::fs::write(&archives_path, b"blocking archive directory").unwrap();
        let before_entries = journal.state.entries.len();
        assert!(journal.archive_settled().is_err());
        assert_eq!(journal.state.entries.len(), before_entries);
        assert_eq!(telemetry.count(HistoryCounter::ArchiveWriteFailures), 1);

        std::fs::remove_file(archives_path).unwrap();
        let journal_path = root.path().join("transactions").join("journal.json");
        std::fs::remove_file(&journal_path).unwrap();
        std::fs::create_dir(&journal_path).unwrap();
        assert!(journal.persist().is_err());
        assert_eq!(telemetry.count(HistoryCounter::JournalWriteFailures), 1);
        assert_eq!(journal.state.entries.len(), before_entries);
    }

    #[test]
    fn maximum_exposure_and_minimum_reserve_are_enforced_before_journaling() {
        let request = test_request();
        let hash = sign_eip1559(&test_signer(), &request).unwrap().hash;

        let capped_root = tempdir().unwrap();
        let capped_store = ConfigStore::at_root(PathBuf::from(capped_root.path()));
        let capped_config = AppConfig {
            per_session_spending_limit_inj: "0.01".to_owned(),
            minimum_reserve_inj: "0".to_owned(),
            ..AppConfig::default()
        };
        let journal_wallet = Address::with_last_byte(0x99);
        let mut capped =
            TransactionJournal::open(&capped_store, &capped_config, journal_wallet).unwrap();
        let cap_error = capped
            .prepare(prepared_test_transaction(
                &request,
                hash,
                U256::from(10_000_000_000_000_000_u128),
                U256::ZERO,
                U256::MAX,
                Some(ProofData {
                    nonce: 8,
                    work_hash: B256::with_last_byte(7),
                    header: b"header".to_vec(),
                }),
            ))
            .unwrap_err();
        assert!(format!("{cap_error:#}").contains("maximum exposure exceeds"));
        assert_eq!(
            transaction_policy_refusal(&cap_error),
            Some(TransactionPolicyRefusalKind::SessionLimitExceeded)
        );
        assert!(!capped.has_unresolved());

        let reserve_root = tempdir().unwrap();
        let reserve_store = ConfigStore::at_root(PathBuf::from(reserve_root.path()));
        let reserve_config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        let mut reserve =
            TransactionJournal::open(&reserve_store, &reserve_config, journal_wallet).unwrap();
        let reserve_error = reserve
            .prepare(prepared_test_transaction(
                &request,
                hash,
                U256::from(1_000_000_000_000_000_000_u128),
                U256::from(100_000_000_000_000_000_u128),
                U256::from(110_000_000_000_000_000_u128),
                Some(ProofData {
                    nonce: 8,
                    work_hash: B256::with_last_byte(7),
                    header: b"header".to_vec(),
                }),
            ))
            .unwrap_err();
        assert!(format!("{reserve_error:#}").contains("insufficient confirmed INJ balance"));
        assert_eq!(
            transaction_policy_refusal(&reserve_error),
            Some(TransactionPolicyRefusalKind::InsufficientConfirmedBalance)
        );
        assert!(!reserve.has_unresolved());
    }

    #[test]
    fn zero_limit_opens_read_only_while_mainnet_cannot_open_a_journal() {
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(root.path()));
        let wallet = Address::with_last_byte(0x99);
        let readonly = TransactionJournal::open(&store, &AppConfig::default(), wallet).unwrap();
        assert!(readonly.state.active_session.is_none());
        assert!(!readonly.has_unresolved());
        drop(readonly);
        let mainnet_config = AppConfig {
            network: Network::Mainnet,
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        assert!(TransactionJournal::open(&store, &mainnet_config, wallet).is_err());
    }

    #[test]
    fn submission_receipt_requires_matching_canonical_event() {
        let wallet = signer_address(&test_signer());
        let contract = Address::with_last_byte(0x42);
        let work_hash = B256::with_last_byte(7);
        let event = AstatineMinerRead::CandidateUpdated {
            windowId: 12,
            miner: wallet,
            workHash: work_hash,
            nonce: 8,
            submittedAt: 123,
            firstValidSolveSecs: 4,
        };
        let log = RpcLog {
            address: contract,
            topics: event.encode_topics().into_iter().map(Into::into).collect(),
            data: Bytes::from(event.encode_data()),
            block_number: None,
            block_hash: None,
        };
        assert_eq!(
            verify_submission_events(
                std::slice::from_ref(&log),
                contract,
                wallet,
                12,
                work_hash,
                8
            )
            .unwrap(),
            super::SubmissionOutcome::Accepted
        );
        assert!(
            verify_submission_events(
                std::slice::from_ref(&log),
                contract,
                wallet,
                13,
                work_hash,
                8
            )
            .is_err()
        );

        let rejected = AstatineMinerRead::SubmissionRejected {
            windowId: 12,
            miner: wallet,
            workHash: work_hash,
            reason: 1,
            fee: U256::from(SUBMISSION_FEE_WEI),
        };
        let rejected_log = RpcLog {
            address: contract,
            topics: rejected
                .encode_topics()
                .into_iter()
                .map(Into::into)
                .collect(),
            data: Bytes::from(rejected.encode_data()),
            block_number: None,
            block_hash: None,
        };
        assert_eq!(
            verify_submission_events(
                std::slice::from_ref(&rejected_log),
                contract,
                wallet,
                12,
                work_hash,
                8,
            )
            .unwrap(),
            super::SubmissionOutcome::Rejected
        );
    }

    #[test]
    fn finalization_receipt_requires_reward_and_window_events_to_match() {
        let contract = Address::with_last_byte(0x42);
        let token = Address::with_last_byte(0x55);
        let winner = Address::with_last_byte(0x31);
        let payout = U256::from(777);
        let reward = AstatineMinerRead::RewardPaid {
            windowId: 9,
            winner,
            amount: payout,
            totalDistributed: payout,
        };
        let finalized = AstatineMinerRead::WindowFinalized {
            completedWindowId: 9,
            nextWindowId: 10,
            winner,
            virtualBlockHash: B256::with_last_byte(2),
            payout,
            targetAfter: U256::MAX,
            seedAfter: B256::with_last_byte(3),
            emaAfter: 60,
            ended: false,
        };
        let transfer = IERC20Read::Transfer {
            from: contract,
            to: winner,
            value: payout,
        };
        let logs = [
            RpcLog {
                address: contract,
                topics: reward.encode_topics().into_iter().map(Into::into).collect(),
                data: Bytes::from(reward.encode_data()),
                block_number: Some(20),
                block_hash: Some(B256::with_last_byte(0x20)),
            },
            RpcLog {
                address: contract,
                topics: finalized
                    .encode_topics()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                data: Bytes::from(finalized.encode_data()),
                block_number: Some(20),
                block_hash: Some(B256::with_last_byte(0x20)),
            },
            RpcLog {
                address: token,
                topics: transfer
                    .encode_topics()
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                data: Bytes::from(transfer.encode_data()),
                block_number: Some(20),
                block_hash: Some(B256::with_last_byte(0x20)),
            },
        ];
        assert_eq!(
            verify_finalization_events(&logs, contract, token, 9).unwrap(),
            (winner, payout)
        );
        assert!(verify_finalization_events(&logs[..2], contract, token, 9).is_err());
    }

    #[test]
    fn receipt_cost_tracks_success_value_and_excludes_reverted_value() {
        let entry = super::TransactionEntry {
            chain_id: 1439,
            contract: format!("{:#x}", Address::with_last_byte(1)),
            node_id: 1,
            window_id: 1,
            action: TransactionAction::SubmitProof,
            session_id: "x".into(),
            wallet: format!("{:#x}", signer_address(&test_signer())),
            nonce: 0,
            transaction_hash: format!("{:#x}", B256::with_last_byte(1)),
            value_wei: "100".into(),
            max_fee_per_gas_wei: "10".into(),
            gas_limit: 10,
            maximum_exposure_wei: "200".into(),
            status: TransactionStatus::Broadcast,
            actual_cost_wei: None,
            last_known_cost_wei: None,
            outcome: None,
            reward_outcome: None,
            reward_block: None,
            reward_block_hash: None,
            reward_confirmations: 0,
            reward_confirmed: false,
            proof_nonce: Some(1),
            proof_hash: Some(format!("{:#x}", B256::with_last_byte(2))),
            header_hex: Some(String::new()),
            receipt_block: None,
            receipt_block_hash: None,
            receipt_status: None,
            confirmations: 0,
            confirmations_required: 2,
            created_unix_secs: 0,
        };
        let receipt = TransactionReceipt {
            transaction_hash: B256::with_last_byte(1),
            status: true,
            gas_used: U256::from(3),
            effective_gas_price: Some(U256::from(7)),
            block_number: 1,
            block_hash: B256::with_last_byte(1),
            logs: Vec::new(),
        };
        assert_eq!(
            super::receipt_cost(&entry, &receipt).unwrap(),
            U256::from(121)
        );
        let reverted = TransactionReceipt {
            status: false,
            ..receipt
        };
        assert_eq!(
            super::receipt_cost(&entry, &reverted).unwrap(),
            U256::from(21)
        );
    }

    #[tokio::test]
    #[ignore = "requires local Forge and Anvil; run with ASTATINE_EVM_ROOT set"]
    async fn autonomous_startup_finalizes_nine_expired_windows_then_submits_signed_proof() {
        let root = std::env::var_os("ASTATINE_EVM_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .join("astatineEVM")
                    .join("evm")
            });
        assert!(
            root.join("src/AstatineMiner.sol").is_file(),
            "invalid ASTATINE_EVM_ROOT"
        );
        let build = Command::new("forge")
            .args(["build", "--root"])
            .arg(&root)
            .output()
            .expect("Forge must be installed for the local EVM lifecycle test");
        assert!(
            build.status.success(),
            "Forge build failed:\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );

        let port_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = port_listener.local_addr().unwrap().port();
        drop(port_listener);
        let mut process = Command::new("anvil")
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--chain-id",
                "1439",
                "--accounts",
                "3",
                "--silent",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Anvil must be installed for the local EVM lifecycle test");
        let _process_guard = AnvilGuard(&mut process);
        let endpoint = format!("http://127.0.0.1:{port}");
        let client = reqwest::Client::new();
        wait_for_anvil(&client, &endpoint).await;

        let signer = test_signer();
        let account = signer_address(&signer);
        let unlocked_accounts =
            rpc_request_local(&client, &endpoint, "eth_accounts", serde_json::json!([]))
                .await
                .unwrap();
        let deployment_wallet = Address::from_str(unlocked_accounts[0].as_str().unwrap()).unwrap();
        let test_inj_balance = U256::from(1_000_u64) * U256::from(10_u8).pow(U256::from(18));
        rpc_request_local(
            &client,
            &endpoint,
            "anvil_setBalance",
            serde_json::json!([format!("{account:#x}"), format!("{test_inj_balance:#x}")]),
        )
        .await
        .unwrap();

        let token_artifact = read_artifact(&root.join("out/MockAST.sol/MockAST.json"));
        let miner_artifact = read_artifact(&root.join("out/AstatineMiner.sol/AstatineMiner.json"));
        let token_decimals = 9_u8;
        let token_unit = U256::from(10_u8).pow(U256::from(token_decimals));
        let allocation = U256::from(1_000_u64) * token_unit;
        let reward = U256::from(100_u64) * token_unit;
        let total_allocation = allocation * U256::from(9);
        let mut token_init = artifact_bytecode(&token_artifact);
        token_init.extend_from_slice(&abi_uint8_word(token_decimals));
        let token = deploy_unlocked(&client, &endpoint, deployment_wallet, &token_init).await;
        let mint = LocalMockAST::mintCall {
            account: deployment_wallet,
            amount: total_allocation,
        }
        .abi_encode();
        send_unlocked(
            &client,
            &endpoint,
            deployment_wallet,
            Some(token),
            &mint,
            U256::ZERO,
        )
        .await;
        let miner_bytecode = artifact_bytecode(&miner_artifact);
        let mut node_addresses = Vec::with_capacity(9);
        for node_id in 1..=9_u8 {
            let seed = B256::with_last_byte(0x70 + node_id);
            let miner = deploy_local_miner(LocalMinerDeployment {
                client: &client,
                endpoint: &endpoint,
                deployment_wallet,
                token,
                token_decimals,
                allocation,
                reward,
                miner_bytecode: &miner_bytecode,
                initial_target: U256::MAX,
                retarget_interval: 3,
                window_secs: 60,
            })
            .await;
            let approve = LocalMockAST::approveCall {
                spender: miner,
                amount: allocation,
            }
            .abi_encode();
            send_unlocked(
                &client,
                &endpoint,
                deployment_wallet,
                Some(token),
                &approve,
                U256::ZERO,
            )
            .await;
            let fund = LocalAstatineMiner::fundASTCall { amount: allocation }.abi_encode();
            send_unlocked(
                &client,
                &endpoint,
                deployment_wallet,
                Some(miner),
                &fund,
                U256::ZERO,
            )
            .await;
            let activate =
                LocalAstatineMiner::activateGenesisCall { initialSeed: seed }.abi_encode();
            send_unlocked(
                &client,
                &endpoint,
                deployment_wallet,
                Some(miner),
                &activate,
                U256::ZERO,
            )
            .await;
            node_addresses.push((
                node_id,
                miner,
                local_code_hash(&client, &endpoint, miner).await,
            ));
        }
        rpc_request_local(
            &client,
            &endpoint,
            "evm_increaseTime",
            serde_json::json!([120]),
        )
        .await
        .unwrap();
        rpc_request_local(&client, &endpoint, "evm_mine", serde_json::json!([]))
            .await
            .unwrap();

        let network = NetworkClient::local_test_client_with_nodes(
            &endpoint,
            &node_addresses,
            token,
            local_code_hash(&client, &endpoint, token).await,
            token_decimals,
        )
        .unwrap();
        assert_eq!(network.manifest.chain_id, 1439);
        assert_eq!(network.manifest.nodes.len(), 9);
        let mut snapshot = network.snapshot(Some(account)).await.unwrap();
        assert_eq!(snapshot.nodes.len(), 9);
        assert!(snapshot.nodes.iter().all(|node| {
            node.state
                .as_ref()
                .is_some_and(|state| state.finalizable && !state.eligible)
        }));

        let app_root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(app_root.path()));
        let config = AppConfig {
            network: Network::Testnet,
            minimum_reserve_inj: "0.1".to_owned(),
            per_session_spending_limit_inj: "20".to_owned(),
            transaction_confirmations: 1,
            ..AppConfig::default()
        };
        let mut manager = TransactionManager::open(&store, &config, account, token).unwrap();
        let selected = HashSet::from_iter(1..=9_u8);
        let pending_sync = Arc::new(std::sync::RwLock::new(HashMap::new()));
        let finalization_state = Arc::new(std::sync::RwLock::new(HashMap::new()));
        assert!(
            finalize_initial_expired_windows(
                &network,
                &selected,
                &mut manager,
                &signer,
                account,
                &mut snapshot,
                FinalizationOptions {
                    finalization_state: &finalization_state,
                    dashboard: &None,
                    pending_sync: &pending_sync,
                },
            )
            .await
            .unwrap()
        );

        let finalizations = manager
            .journal
            .state
            .entries
            .iter()
            .filter(|entry| entry.action == TransactionAction::FinalizeWindow)
            .collect::<Vec<_>>();
        assert_eq!(finalizations.len(), 9);
        assert!(finalizations.iter().all(|entry| {
            entry.status == TransactionStatus::MinedSuccess
                && entry.confirmations >= u64::from(config.transaction_confirmations)
        }));
        assert!(snapshot.nodes.iter().all(|node| {
            node.state
                .as_ref()
                .is_some_and(|state| state.eligible && !state.finalizable)
        }));
        assert!(!manager.journal.has_unresolved());

        let node = snapshot.nodes.iter().find(|node| node.id == 1).unwrap();
        let state = node.state.as_ref().unwrap();
        let header = b"all-nine-expired-autonomous-startup-proof";
        let context = WorkContext {
            chain_id: network.manifest.chain_id,
            contract: node.address,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner: account,
            header: header.to_vec(),
        };
        let nonce = 0_u128;
        let work_hash = WorkHasher::new(&context).unwrap().hash(nonce);
        assert!(meets_target(work_hash, state.work.target));
        let submitted = manager
            .submit_proof(
                &network,
                &signer,
                ProofSubmission {
                    contract: node.address,
                    node_id: node.id,
                    window_id: state.work.window_id,
                    nonce,
                    header: header.to_vec(),
                    work_hash,
                },
            )
            .await
            .expect("eligible post-finalization proof should be signed and submitted");
        assert!(submitted.receipt.status);
        assert_eq!(submitted.outcome, "candidate-updated");
        assert!(!manager.journal.has_unresolved());
    }

    #[tokio::test]
    #[ignore = "requires local Forge and Anvil; run with ASTATINE_EVM_ROOT set"]
    async fn autonomous_runtime_mines_and_finalizes_across_three_consecutive_windows() {
        let root = std::env::var_os("ASTATINE_EVM_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .join("astatineEVM")
                    .join("evm")
            });
        assert!(root.join("src/AstatineMiner.sol").is_file());
        let build = Command::new("forge")
            .args(["build", "--root"])
            .arg(&root)
            .output()
            .expect("Forge is required for the autonomous local lifecycle test");
        assert!(
            build.status.success(),
            "Forge build failed:\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );

        tokio::time::timeout(Duration::from_secs(90), async {
            let port_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = port_listener.local_addr().unwrap().port();
            drop(port_listener);
            let mut process = Command::new("anvil")
                .args([
                    "--host",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                    "--chain-id",
                    "1439",
                    "--accounts",
                    "3",
                    "--silent",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("Anvil is required for the autonomous local lifecycle test");
            let _process_guard = AnvilGuard(&mut process);
            let endpoint = format!("http://127.0.0.1:{port}");
            let rpc = reqwest::Client::new();
            wait_for_anvil(&rpc, &endpoint).await;

            let signer = test_signer();
            let account = signer_address(&signer);
            let accounts =
                rpc_request_local(&rpc, &endpoint, "eth_accounts", serde_json::json!([]))
                    .await
                    .unwrap();
            let deployment_wallet = Address::from_str(accounts[0].as_str().unwrap()).unwrap();
            let funded_balance = U256::from(1_000_u64) * U256::from(10_u8).pow(U256::from(18));
            rpc_request_local(
                &rpc,
                &endpoint,
                "anvil_setBalance",
                serde_json::json!([format!("{account:#x}"), format!("{funded_balance:#x}")]),
            )
            .await
            .unwrap();

            let token_artifact = read_artifact(&root.join("out/MockAST.sol/MockAST.json"));
            let miner_artifact =
                read_artifact(&root.join("out/AstatineMiner.sol/AstatineMiner.json"));
            let miner_bytecode = artifact_bytecode(&miner_artifact);
            let decimals = 9_u8;
            let token_unit = U256::from(10_u8).pow(U256::from(decimals));
            let allocation = U256::from(1_000_u64) * token_unit;
            let total_allocation = allocation * U256::from(9_u8);
            let reward = U256::from(100_u64) * token_unit;
            let mut token_init = artifact_bytecode(&token_artifact);
            token_init.extend_from_slice(&abi_uint8_word(decimals));
            let token = deploy_unlocked(&rpc, &endpoint, deployment_wallet, &token_init).await;
            let mint = LocalMockAST::mintCall {
                account: deployment_wallet,
                amount: total_allocation,
            }
            .abi_encode();
            send_unlocked(
                &rpc,
                &endpoint,
                deployment_wallet,
                Some(token),
                &mint,
                U256::ZERO,
            )
            .await;
            let mut miners = Vec::with_capacity(9);
            for node_id in 1..=9_u8 {
                let miner = deploy_local_miner(LocalMinerDeployment {
                    client: &rpc,
                    endpoint: &endpoint,
                    deployment_wallet,
                    token,
                    token_decimals: decimals,
                    allocation,
                    reward,
                    miner_bytecode: &miner_bytecode,
                    initial_target: U256::MAX,
                    retarget_interval: 3,
                    window_secs: 60,
                })
                .await;
                let approve = LocalMockAST::approveCall {
                    spender: miner,
                    amount: allocation,
                }
                .abi_encode();
                send_unlocked(
                    &rpc,
                    &endpoint,
                    deployment_wallet,
                    Some(token),
                    &approve,
                    U256::ZERO,
                )
                .await;
                let fund = LocalAstatineMiner::fundASTCall { amount: allocation }.abi_encode();
                send_unlocked(
                    &rpc,
                    &endpoint,
                    deployment_wallet,
                    Some(miner),
                    &fund,
                    U256::ZERO,
                )
                .await;
                let activate = LocalAstatineMiner::activateGenesisCall {
                    initialSeed: B256::with_last_byte(0x40 + node_id),
                }
                .abi_encode();
                send_unlocked(
                    &rpc,
                    &endpoint,
                    deployment_wallet,
                    Some(miner),
                    &activate,
                    U256::ZERO,
                )
                .await;
                miners.push((
                    node_id,
                    miner,
                    local_code_hash(&rpc, &endpoint, miner).await,
                ));
                if node_id == 1 {
                    rpc_request_local(&rpc, &endpoint, "evm_increaseTime", serde_json::json!([30]))
                        .await
                        .unwrap();
                    rpc_request_local(&rpc, &endpoint, "evm_mine", serde_json::json!([]))
                        .await
                        .unwrap();
                }
            }
            rpc_request_local(&rpc, &endpoint, "evm_increaseTime", serde_json::json!([30]))
                .await
                .unwrap();
            rpc_request_local(&rpc, &endpoint, "evm_mine", serde_json::json!([]))
                .await
                .unwrap();

            let network = NetworkClient::local_test_client_with_nodes(
                &endpoint,
                &miners,
                token,
                local_code_hash(&rpc, &endpoint, token).await,
                decimals,
            )
            .unwrap();
            network.fail_next_finalization_fee_quote_once();
            network.delay_next_finalization_fee_quote(Duration::from_millis(250));
            let expired = network.snapshot(Some(account)).await.unwrap();
            assert_eq!(expired.nodes.len(), 9);
            assert!(
                expired.nodes.iter().any(|node| {
                    node.id == 1
                        && node
                            .state
                            .as_ref()
                            .is_some_and(|state| state.finalizable && !state.eligible)
                }),
                "node1 snapshot at block {} timestamp {}: {:?}",
                expired.block.number,
                expired.block.timestamp,
                expired
                    .nodes
                    .iter()
                    .find(|node| node.id == 1)
                    .and_then(|node| node.state.as_ref())
            );
            assert!(expired.nodes.iter().any(|node| {
                node.id == 3
                    && node
                        .state
                        .as_ref()
                        .is_some_and(|state| state.eligible && !state.finalizable)
            }));
            let temp = tempdir().unwrap();
            let store = ConfigStore::at_root(temp.path().to_path_buf());
            let config = AppConfig {
                network: Network::Testnet,
                wallet_address: Some(format!("{account:#x}")),
                cpu_threads: 32,
                minimum_reserve_inj: "0".to_owned(),
                per_session_spending_limit_inj: "1".to_owned(),
                transaction_confirmations: 1,
                ..AppConfig::default()
            };
            store.save(&config).unwrap();
            let run_store = store.clone();
            let run_config = config.clone();
            let run_network = network.clone();
            let run_signer = clone_signer(&signer);
            let args = MineArgs {
                compute_only: false,
                threads: NonZeroUsize::new(32),
                nodes: vec![1, 3],
            };
            let (probe_tx, probe_rx) = tokio::sync::oneshot::channel();
            let mut runtime = tokio::spawn(async move {
                crate::mining::run_with_client(
                    &run_store,
                    run_config,
                    args,
                    run_network,
                    Some(run_signer),
                    Some(probe_tx),
                )
                .await
            });
            let probe = match tokio::time::timeout(Duration::from_secs(5), probe_rx).await {
                Ok(Ok(probe)) => probe,
                Ok(Err(_)) => panic!(
                    "mining runtime exited before worker startup: {:?}",
                    runtime.await
                ),
                Err(_) => panic!("production mining runtime did not start within five seconds"),
            };
            assert_eq!(probe.worker_threads, 32);
            assert_eq!(
                probe
                    .transaction_state
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .mined_rewards,
                U256::ZERO,
                "the session MINED total starts at zero"
            );
            probe.proof_processing_gate.send_replace(false);
            let initial_finalization = tokio::select! {
                entry = wait_for_journal_entry_for_window(
                    &store,
                    1,
                    TransactionAction::FinalizeWindow,
                    0,
                    TransactionStatus::MinedSuccess,
                ) => entry,
                result = &mut runtime => panic!("production runtime exited before startup window finalized: {result:?}"),
            };
            assert_eq!(initial_finalization.window_id, 0);
            assert!(network.fee_quote_delays_started() >= 1);
            let _node1_window1 = wait_for_eligible_window(&network, 1, 1).await;
            let node3_window0 = wait_for_eligible_window(&network, 3, 0).await;
            wait_for_active_probe(&probe, 1, 1).await;
            wait_for_active_probe(&probe, 3, 0).await;
            wait_for_hash_increase(&probe, 1, 0).await;
            wait_for_hash_increase(&probe, 3, 0).await;
            let proof = wait_for_journal_entry_for_window(
                &store,
                1,
                TransactionAction::SubmitProof,
                1,
                TransactionStatus::MinedSuccess,
            )
            .await;
            assert_eq!(proof.outcome.as_deref(), Some("candidate-updated"));
            let _active_snapshot = wait_for_candidate(&network, 1, 1, account).await;
            let node3_proof = wait_for_journal_entry_for_window(
                &store,
                3,
                TransactionAction::SubmitProof,
                0,
                TransactionStatus::MinedSuccess,
            )
            .await;
            assert_eq!(node3_proof.outcome.as_deref(), Some("candidate-updated"));
            let _node3_candidate = wait_for_candidate(&network, 3, 0, account).await;
            for node_id in [1, 3] {
                for metric in [
                    ProofMetric::TargetValidHashes,
                    ProofMetric::QueuedCandidates,
                    ProofMetric::MainLoopReceived,
                    ProofMetric::Signed,
                    ProofMetric::Broadcast,
                    ProofMetric::ReceiptConfirmed,
                    ProofMetric::CandidateUpdated,
                ] {
                    assert!(
                        probe.proof_telemetry.count(node_id, metric) > 0,
                        "node {node_id:02} lifecycle metric {metric:?} must be recorded"
                    );
                }
            }
            let node1_hashes = probe.slots[0].completed_hashes();
            assert!(!runtime.is_finished());
            wait_for_no_unresolved_transactions(&store).await;

            let mut observed_updates = probe.observer_updates.clone();
            let _ = observed_updates.borrow_and_update();
            rpc_request_local(
                &rpc,
                &endpoint,
                "anvil_setAutomine",
                serde_json::json!([false]),
            )
            .await
            .unwrap();
            advance_window_past_expiry(&rpc, &endpoint, &network, 3, &node3_window0).await;
            let while_node3_finalizing = network.snapshot(None).await.unwrap();
            assert!(while_node3_finalizing.nodes.iter().any(|node| {
                node.id == 1
                    && node
                        .state
                        .as_ref()
                        .is_some_and(|state| state.work.window_id == 1 && state.eligible)
            }));
            let pending_node3_finalization = wait_for_journal_entry_for_window(
                &store,
                3,
                TransactionAction::FinalizeWindow,
                0,
                TransactionStatus::Broadcast,
            )
            .await;
            let pending_hash = entry_hash(&pending_node3_finalization).unwrap();
            assert!(
                network
                    .transaction_receipt(pending_hash)
                    .await
                    .unwrap()
                    .is_none()
            );
            let observed = wait_for_observer_snapshot(
                &mut observed_updates,
                while_node3_finalizing.block.number,
            )
            .await;
            assert!(observed.nodes.iter().any(|node| {
                node.id == 1
                    && node
                        .state
                        .as_ref()
                        .is_some_and(|state| state.work.window_id == 1 && state.eligible)
            }));
            wait_for_hash_increase(&probe, 1, node1_hashes).await;
            assert!(!runtime.is_finished());
            rpc_request_local(&rpc, &endpoint, "evm_mine", serde_json::json!([]))
                .await
                .unwrap();
            rpc_request_local(
                &rpc,
                &endpoint,
                "anvil_setAutomine",
                serde_json::json!([true]),
            )
            .await
            .unwrap();
            let node3_finalized = wait_for_journal_entry_for_window(
                &store,
                3,
                TransactionAction::FinalizeWindow,
                0,
                TransactionStatus::MinedSuccess,
            )
            .await;
            assert!(node3_finalized.receipt_status.unwrap());
            wait_for_active_probe(&probe, 3, 1).await;

            let node1_window1 = wait_for_eligible_window(&network, 1, 1).await;
            advance_window_past_expiry(&rpc, &endpoint, &network, 1, &node1_window1).await;
            let first_rewarding_finalization = wait_for_journal_entry_for_window(
                &store,
                1,
                TransactionAction::FinalizeWindow,
                1,
                TransactionStatus::MinedSuccess,
            )
            .await;
            assert!(first_rewarding_finalization.receipt_status.unwrap());
            wait_for_verified_reward(&store, 1, 1, &probe.history_telemetry).await;
            let rewarded_snapshot = network.snapshot(Some(account)).await.unwrap();
            assert!(rewarded_snapshot.ast_balance.is_some_and(|balance| balance >= reward));
            wait_for_dashboard_mined_reward(&probe.transaction_state, reward).await;
            let second_window = wait_for_eligible_window(&network, 1, 2).await;
            wait_for_active_probe(&probe, 1, 2).await;
            wait_for_hash_increase(&probe, 1, node1_hashes).await;
            assert!(!runtime.is_finished());
            let node1_window2_proof = wait_for_journal_entry_for_window(
                &store,
                1,
                TransactionAction::SubmitProof,
                2,
                TransactionStatus::MinedSuccess,
            )
            .await;
            assert_eq!(
                node1_window2_proof.outcome.as_deref(),
                Some("candidate-updated")
            );
            let _node1_window2_candidate = wait_for_candidate(&network, 1, 2, account).await;
            let node3_window1_proof = wait_for_journal_entry_for_window(
                &store,
                3,
                TransactionAction::SubmitProof,
                1,
                TransactionStatus::MinedSuccess,
            )
            .await;
            assert_eq!(
                node3_window1_proof.outcome.as_deref(),
                Some("candidate-updated")
            );
            let _node3_window1_candidate = wait_for_candidate(&network, 3, 1, account).await;
            wait_for_no_unresolved_transactions(&store).await;

            rpc_request_local(
                &rpc,
                &endpoint,
                "anvil_setAutomine",
                serde_json::json!([false]),
            )
            .await
            .unwrap();
            advance_window_past_expiry(&rpc, &endpoint, &network, 1, &second_window).await;
            let pending_node1_finalization = wait_for_journal_entry_for_window(
                &store,
                1,
                TransactionAction::FinalizeWindow,
                2,
                TransactionStatus::Broadcast,
            )
            .await;
            assert!(
                network
                    .transaction_receipt(entry_hash(&pending_node1_finalization).unwrap())
                    .await
                    .unwrap()
                    .is_none()
            );
            rpc_request_local(&rpc, &endpoint, "evm_mine", serde_json::json!([]))
                .await
                .unwrap();
            let second_finalization = wait_for_journal_entry_for_window(
                &store,
                1,
                TransactionAction::FinalizeWindow,
                2,
                TransactionStatus::MinedSuccess,
            )
            .await;
            assert!(second_finalization.receipt_status.unwrap());

            let node3_after_node1_finalization = network.snapshot(None).await.unwrap();
            let node3_finalization_window = node3_after_node1_finalization
                .nodes
                .iter()
                .find(|node| node.id == 3)
                .and_then(|node| node.state.as_ref())
                .expect("node 03 should remain verified")
                .work
                .window_id;
            if node3_after_node1_finalization
                .nodes
                .iter()
                .any(|node| node.id == 3 && node.state.as_ref().is_some_and(|state| state.eligible))
            {
                advance_window_past_expiry(
                    &rpc,
                    &endpoint,
                    &network,
                    3,
                    &node3_after_node1_finalization,
                )
                .await;
            }
            let pending_node3_finalization = wait_for_journal_entry_for_window(
                &store,
                3,
                TransactionAction::FinalizeWindow,
                node3_finalization_window,
                TransactionStatus::Broadcast,
            )
            .await;
            assert!(
                network
                    .transaction_receipt(entry_hash(&pending_node3_finalization).unwrap())
                    .await
                    .unwrap()
                    .is_none()
            );
            rpc_request_local(&rpc, &endpoint, "evm_mine", serde_json::json!([]))
                .await
                .unwrap();
            let node3_second_finalization = wait_for_journal_entry_for_window(
                &store,
                3,
                TransactionAction::FinalizeWindow,
                node3_finalization_window,
                TransactionStatus::MinedSuccess,
            )
            .await;
            assert!(node3_second_finalization.receipt_status.unwrap());
            wait_for_verified_reward(&store, 1, 2, &probe.history_telemetry).await;
            wait_for_verified_reward(
                &store,
                3,
                node3_finalization_window,
                &probe.history_telemetry,
            )
            .await;
            let rewarded_journal = store.read_transaction_journal().unwrap().unwrap();
            let rewarded_journal: super::JournalState =
                serde_json::from_slice(&rewarded_journal).unwrap();
            let mut rewarded_windows = HashSet::new();
            let expected_session_mined = rewarded_journal
                .entries
                .iter()
                .filter(|entry| {
                    entry.action == TransactionAction::SubmitProof
                        && entry.reward_confirmed
                        && entry
                            .reward_outcome
                            .as_deref()
                            .is_some_and(|outcome| outcome.starts_with("reward-paid:"))
                })
                .try_fold(U256::ZERO, |total, entry| {
                    let key = (
                        entry.contract.clone(),
                        entry.window_id,
                        entry.wallet.clone(),
                    );
                    if !rewarded_windows.insert(key) {
                        return Ok(total);
                    }
                    let amount = entry
                        .reward_outcome
                        .as_deref()
                        .and_then(|outcome| outcome.strip_prefix("reward-paid:"))
                        .context("verified proof entry must retain its payout")
                        .and_then(parse_decimal_wei)?;
                    total
                        .checked_add(amount)
                        .context("local lifecycle reward total overflow")
                })
                .unwrap();
            assert_eq!(rewarded_windows.len(), 4);
            assert_eq!(expected_session_mined, reward * U256::from(4));
            assert_eq!(
                wait_for_dashboard_mined_reward(&probe.transaction_state, expected_session_mined)
                    .await,
                expected_session_mined,
                "the live dashboard must show every verified winning window from this invocation"
            );
            let cumulative_balance = network.snapshot(Some(account)).await.unwrap();
            assert_eq!(cumulative_balance.ast_balance, Some(expected_session_mined));
            let third_window = wait_for_eligible_window(&network, 1, 3).await;
            wait_for_active_probe(&probe, 1, 3).await;
            let node3_third_window =
                wait_for_eligible_window(&network, 3, node3_finalization_window + 1).await;
            wait_for_active_probe(&probe, 3, node3_finalization_window + 1).await;
            let hashes_after_second_finalization = probe.slots[0].completed_hashes();
            wait_for_hash_increase(&probe, 1, hashes_after_second_finalization).await;
            assert!(third_window.block.number >= second_window.block.number);
            assert!(node3_third_window.block.number >= third_window.block.number);
            assert!(!runtime.is_finished());

            let mut observer_updates = probe.observer_updates.clone();
            let _ = observer_updates.borrow_and_update();
            let pending_proof = wait_for_pending_proof(&store).await;
            assert!(matches!(pending_proof.node_id, 1 | 3));
            let pending_hash = entry_hash(&pending_proof).unwrap();
            assert!(network.transaction_known(pending_hash).await.unwrap());
            assert!(
                network
                    .transaction_receipt(pending_hash)
                    .await
                    .unwrap()
                    .is_none()
            );
            let nonce_with_pending = local_pending_nonce(&rpc, &endpoint, account).await;
            assert!(nonce_with_pending > pending_proof.nonce);

            probe.stop_signal.request_stop();
            let first_stop = tokio::time::timeout(Duration::from_secs(10), &mut runtime)
                .await
                .expect("Ctrl+C-equivalent stop must complete while receipt is pending")
                .expect("runtime task must join cleanly");
            assert!(first_stop.is_ok());
            let journal_after_stop: super::JournalState =
                serde_json::from_slice(&store.read_transaction_journal().unwrap().unwrap())
                    .unwrap();
            let retained_pending = journal_after_stop
                .entries
                .iter()
                .find(|entry| entry_hash(entry).unwrap() == pending_hash)
                .unwrap();
            assert_eq!(retained_pending.status, TransactionStatus::Broadcast);
            assert!(U256::from_str(&retained_pending.maximum_exposure_wei).unwrap() > U256::ZERO);
            let entry_count_before_recovery = journal_after_stop.entries.len();
            let nonce_before_recovery = local_pending_nonce(&rpc, &endpoint, account).await;

            let recovery_store = store.clone();
            let recovery_config = config.clone();
            let recovery_network = network.clone();
            let recovery_signer = clone_signer(&signer);
            let recovery_args = MineArgs {
                compute_only: false,
                threads: NonZeroUsize::new(1),
                nodes: vec![pending_proof.node_id],
            };
            let (recovery_probe_tx, recovery_probe_rx) = tokio::sync::oneshot::channel();
            let mut recovery_runtime = tokio::spawn(async move {
                crate::mining::run_with_client(
                    &recovery_store,
                    recovery_config,
                    recovery_args,
                    recovery_network,
                    Some(recovery_signer),
                    Some(recovery_probe_tx),
                )
                .await
            });
            let recovery_probe = tokio::time::timeout(Duration::from_secs(5), recovery_probe_rx)
                .await
                .expect("recovery runtime must start")
                .expect("recovery runtime probe must remain connected");
            assert_eq!(
                recovery_probe
                    .transaction_state
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .mined_rewards,
                U256::ZERO,
                "recovered rewards from a previous CLI invocation do not enter the new session total"
            );
            recovery_probe
                .proof_processing_gate
                .send_replace(false);
            wait_for_active_probe(
                &recovery_probe,
                pending_proof.node_id,
                pending_proof.window_id,
            )
            .await;
            let mut recovery_updates = recovery_probe.observer_updates.clone();
            let _ = recovery_updates.borrow_and_update();
            let recovery_head = network.latest_block_snapshot().await.unwrap();
            let observed_during_recovery =
                wait_for_observer_snapshot(&mut recovery_updates, recovery_head.number).await;
            assert!(observed_during_recovery.nodes.iter().any(|node| {
                node.id == pending_proof.node_id
                    && node
                        .state
                        .as_ref()
                        .is_some_and(|state| state.work.window_id == pending_proof.window_id)
            }));
            let recovery_hashes =
                recovery_probe.slots[usize::from(pending_proof.node_id - 1)].completed_hashes();
            tokio::time::sleep(Duration::from_millis(150)).await;
            assert_eq!(
                local_pending_nonce(&rpc, &endpoint, account).await,
                nonce_before_recovery
            );
            wait_for_hash_increase(&recovery_probe, pending_proof.node_id, recovery_hashes).await;
            let journal_during_recovery: super::JournalState =
                serde_json::from_slice(&store.read_transaction_journal().unwrap().unwrap())
                    .unwrap();
            assert_eq!(
                journal_during_recovery.entries.len(),
                entry_count_before_recovery
            );
            assert!(journal_during_recovery.entries.iter().any(|entry| {
                entry_hash(entry).unwrap() == pending_hash
                    && entry.status == TransactionStatus::Broadcast
            }));
            assert!(
                network
                    .transaction_receipt(pending_hash)
                    .await
                    .unwrap()
                    .is_none()
            );
            rpc_request_local(&rpc, &endpoint, "evm_mine", serde_json::json!([]))
                .await
                .unwrap();
            rpc_request_local(
                &rpc,
                &endpoint,
                "anvil_setAutomine",
                serde_json::json!([true]),
            )
            .await
            .unwrap();
            let settled_pending = wait_for_journal_entry_for_window(
                &store,
                pending_proof.node_id,
                TransactionAction::SubmitProof,
                pending_proof.window_id,
                TransactionStatus::MinedSuccess,
            )
            .await;
            assert_eq!(
                settled_pending.outcome.as_deref(),
                Some("candidate-updated")
            );
            let _recovered_candidate = wait_for_candidate(
                &network,
                pending_proof.node_id,
                pending_proof.window_id,
                account,
            )
            .await;
            assert_eq!(
                local_pending_nonce(&rpc, &endpoint, account).await,
                nonce_before_recovery
            );

            recovery_probe.stop_signal.request_stop();
            let recovery_stop =
                tokio::time::timeout(Duration::from_secs(10), &mut recovery_runtime)
                    .await
                    .expect("recovered runtime should stop cleanly")
                    .expect("recovered runtime task should join cleanly");
            assert!(recovery_stop.is_ok());
        })
        .await
        .expect("autonomous miner must finalize, reopen, hash and submit across three windows");
    }

    #[tokio::test]
    #[ignore = "requires local Forge and Anvil; run with ASTATINE_EVM_ROOT set"]
    async fn current_session_rewards_survive_external_finalization_and_exclude_losing_proofs() {
        let root = std::env::var_os("ASTATINE_EVM_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .join("astatineEVM")
                    .join("evm")
            });
        assert!(root.join("src/AstatineMiner.sol").is_file());
        let build = Command::new("forge")
            .args(["build", "--root"])
            .arg(&root)
            .output()
            .expect("Forge must be installed for the verified session reward lifecycle test");
        assert!(
            build.status.success(),
            "Forge build failed:\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut process = Command::new("anvil")
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--chain-id",
                "1439",
                "--accounts",
                "3",
                "--silent",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Anvil must be installed for the verified session reward lifecycle test");
        let _process_guard = AnvilGuard(&mut process);
        let endpoint = format!("http://127.0.0.1:{port}");
        let rpc = reqwest::Client::new();
        wait_for_anvil(&rpc, &endpoint).await;

        let signer = test_signer();
        let wallet = signer_address(&signer);
        let unlocked_accounts =
            rpc_request_local(&rpc, &endpoint, "eth_accounts", serde_json::json!([]))
                .await
                .unwrap();
        let deployment_wallet = Address::from_str(unlocked_accounts[0].as_str().unwrap()).unwrap();
        let external_finalizer = Address::from_str(unlocked_accounts[2].as_str().unwrap()).unwrap();
        assert_ne!(wallet, deployment_wallet);
        assert_ne!(wallet, external_finalizer);

        let funded_inj = U256::from(1_000_u64) * U256::from(10_u8).pow(U256::from(18));
        rpc_request_local(
            &rpc,
            &endpoint,
            "anvil_setBalance",
            serde_json::json!([format!("{wallet:#x}"), format!("{funded_inj:#x}")]),
        )
        .await
        .unwrap();

        let token_artifact = read_artifact(&root.join("out/MockAST.sol/MockAST.json"));
        let miner_artifact = read_artifact(&root.join("out/AstatineMiner.sol/AstatineMiner.json"));
        let decimals = 9_u8;
        let ast_unit = U256::from(10_u8).pow(U256::from(decimals));
        let allocation = U256::from(1_000_u64) * ast_unit;
        let reward = U256::from(100_u64) * ast_unit;
        let mut token_init = artifact_bytecode(&token_artifact);
        token_init.extend_from_slice(&abi_uint8_word(decimals));
        let token = deploy_unlocked(&rpc, &endpoint, deployment_wallet, &token_init).await;
        let mint = LocalMockAST::mintCall {
            account: deployment_wallet,
            amount: allocation,
        }
        .abi_encode();
        send_unlocked(
            &rpc,
            &endpoint,
            deployment_wallet,
            Some(token),
            &mint,
            U256::ZERO,
        )
        .await;
        let miner = deploy_local_miner(LocalMinerDeployment {
            client: &rpc,
            endpoint: &endpoint,
            deployment_wallet,
            token,
            token_decimals: decimals,
            allocation,
            reward,
            miner_bytecode: &artifact_bytecode(&miner_artifact),
            initial_target: U256::MAX,
            retarget_interval: 3,
            window_secs: 60,
        })
        .await;
        let approve = LocalMockAST::approveCall {
            spender: miner,
            amount: allocation,
        }
        .abi_encode();
        send_unlocked(
            &rpc,
            &endpoint,
            deployment_wallet,
            Some(token),
            &approve,
            U256::ZERO,
        )
        .await;
        let fund = LocalAstatineMiner::fundASTCall { amount: allocation }.abi_encode();
        send_unlocked(
            &rpc,
            &endpoint,
            deployment_wallet,
            Some(miner),
            &fund,
            U256::ZERO,
        )
        .await;
        let seed = B256::with_last_byte(0x91);
        let activate = LocalAstatineMiner::activateGenesisCall { initialSeed: seed }.abi_encode();
        send_unlocked(
            &rpc,
            &endpoint,
            deployment_wallet,
            Some(miner),
            &activate,
            U256::ZERO,
        )
        .await;

        let network = NetworkClient::local_test_client(
            &endpoint,
            miner,
            local_code_hash(&rpc, &endpoint, miner).await,
            token,
            local_code_hash(&rpc, &endpoint, token).await,
            decimals,
        )
        .unwrap();
        let root_dir = tempdir().unwrap();
        let store = ConfigStore::at_root(root_dir.path().to_path_buf());
        let config = AppConfig {
            network: Network::Testnet,
            minimum_reserve_inj: "0".to_owned(),
            per_session_spending_limit_inj: "20".to_owned(),
            transaction_confirmations: 2,
            ..AppConfig::default()
        };
        let dashboard_state = Arc::new(RwLock::new(TransactionDashboardState::default()));
        let dashboard_sink_state = Arc::clone(&dashboard_state);
        let mut manager = TransactionManager::open(&store, &config, wallet, token).unwrap();
        manager.set_dashboard_sink(Arc::new(move |state| {
            *dashboard_sink_state
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = state;
        }));
        assert_eq!(manager.mined_rewards_total(), U256::ZERO);
        assert_eq!(
            network.snapshot(Some(wallet)).await.unwrap().ast_balance,
            Some(U256::ZERO)
        );

        let first_snapshot = network.snapshot(Some(wallet)).await.unwrap();
        let first_node = first_snapshot
            .nodes
            .iter()
            .find(|node| node.id == 1)
            .unwrap();
        let first_work = first_node.state.as_ref().unwrap();
        let first_header = b"session-earned-by-cli-window-zero";
        let first_context = WorkContext {
            chain_id: network.manifest.chain_id,
            contract: miner,
            window_id: first_work.work.window_id,
            seed: first_work.work.seed,
            miner: wallet,
            header: first_header.to_vec(),
        };
        let first_nonce = 0_u128;
        let first_hash = WorkHasher::new(&first_context).unwrap().hash(first_nonce);
        assert!(meets_target(first_hash, first_work.work.target));
        let (next_manager, first_action) = submit_local_proof_with_confirmation(
            manager,
            network.clone(),
            clone_signer(&signer),
            ProofSubmission {
                contract: miner,
                node_id: 1,
                window_id: first_work.work.window_id,
                nonce: first_nonce,
                header: first_header.to_vec(),
                work_hash: first_hash,
            },
            &store,
            &rpc,
            &endpoint,
        )
        .await;
        manager = next_manager;
        assert_eq!(first_action.outcome, "candidate-updated");
        assert_eq!(manager.mined_rewards_total(), U256::ZERO);

        let expired_window_zero = network.snapshot(None).await.unwrap();
        advance_window_past_expiry(&rpc, &endpoint, &network, 1, &expired_window_zero).await;
        let finalize = AstatineMinerRead::finalizeWindowCall {}.abi_encode();
        send_unlocked(
            &rpc,
            &endpoint,
            deployment_wallet,
            Some(miner),
            &finalize,
            U256::ZERO,
        )
        .await;
        rpc_request_local(&rpc, &endpoint, "evm_mine", serde_json::json!([]))
            .await
            .unwrap();
        let paid_snapshot = network.snapshot(Some(wallet)).await.unwrap();
        assert_eq!(paid_snapshot.ast_balance, Some(reward));
        assert_eq!(manager.mined_rewards_total(), U256::ZERO);
        assert_eq!(
            service_until_mined_reward(&mut manager, &network, wallet, reward).await,
            reward
        );
        assert_eq!(
            dashboard_state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .mined_rewards,
            reward,
            "the current-run winning proof must be counted although a different account finalized it"
        );
        let first_reward_entry = manager
            .journal
            .state
            .entries
            .iter()
            .find(|entry| entry.action == TransactionAction::SubmitProof && entry.window_id == 0)
            .unwrap();
        assert!(first_reward_entry.reward_confirmed);
        assert!(
            first_reward_entry
                .reward_outcome
                .as_deref()
                .is_some_and(|outcome| outcome.starts_with("reward-paid:"))
        );
        assert_eq!(manager.mined_rewards_total(), reward);

        let second_snapshot = network.snapshot(Some(wallet)).await.unwrap();
        let second_work = second_snapshot
            .nodes
            .iter()
            .find(|node| node.id == 1)
            .unwrap()
            .state
            .as_ref()
            .unwrap();
        assert_eq!(second_work.work.window_id, 1);
        let second_header = b"session-losing-cli-window-one";
        let second_context = WorkContext {
            chain_id: network.manifest.chain_id,
            contract: miner,
            window_id: second_work.work.window_id,
            seed: second_work.work.seed,
            miner: wallet,
            header: second_header.to_vec(),
        };
        let second_nonce = 0_u128;
        let second_hash = WorkHasher::new(&second_context).unwrap().hash(second_nonce);
        assert!(meets_target(second_hash, second_work.work.target));
        let (next_manager, second_action) = submit_local_proof_with_confirmation(
            manager,
            network.clone(),
            clone_signer(&signer),
            ProofSubmission {
                contract: miner,
                node_id: 1,
                window_id: second_work.work.window_id,
                nonce: second_nonce,
                header: second_header.to_vec(),
                work_hash: second_hash,
            },
            &store,
            &rpc,
            &endpoint,
        )
        .await;
        manager = next_manager;
        assert_eq!(second_action.outcome, "candidate-updated");

        let winner_snapshot = network.snapshot(None).await.unwrap();
        let winner_state = winner_snapshot
            .nodes
            .iter()
            .find(|node| node.id == 1)
            .and_then(|node| node.state.as_ref())
            .unwrap();
        let incumbent = winner_state.candidate.as_ref().unwrap().work_hash;
        let challenger_header = b"external-contender-wins-window-one";
        let challenger_context = WorkContext {
            chain_id: network.manifest.chain_id,
            contract: miner,
            window_id: winner_state.work.window_id,
            seed: winner_state.work.seed,
            miner: deployment_wallet,
            header: challenger_header.to_vec(),
        };
        let challenger_hasher = WorkHasher::new(&challenger_context).unwrap();
        let (challenger_nonce, challenger_hash) = (0..10_000_u128)
            .find_map(|nonce| {
                let hash = challenger_hasher.hash(nonce);
                (meets_target(hash, winner_state.work.target) && beats_incumbent(hash, incumbent))
                    .then_some((nonce, hash))
            })
            .expect("local external wallet should find a proof better than the CLI incumbent");
        let challenger_call = AstatineMinerRead::submitSolutionCall {
            header: Bytes::copy_from_slice(challenger_header),
            nonce: challenger_nonce,
        }
        .abi_encode();
        send_unlocked(
            &rpc,
            &endpoint,
            deployment_wallet,
            Some(miner),
            &challenger_call,
            U256::from(SUBMISSION_FEE_WEI),
        )
        .await;
        let replaced_candidate = network.snapshot(None).await.unwrap();
        assert_eq!(
            replaced_candidate
                .nodes
                .iter()
                .find(|node| node.id == 1)
                .and_then(|node| node.state.as_ref())
                .and_then(|state| state.candidate.as_ref())
                .map(|candidate| candidate.miner),
            Some(deployment_wallet)
        );
        assert_eq!(
            replaced_candidate
                .nodes
                .iter()
                .find(|node| node.id == 1)
                .and_then(|node| node.state.as_ref())
                .and_then(|state| state.candidate.as_ref())
                .map(|candidate| candidate.work_hash),
            Some(challenger_hash)
        );

        let expired_window_one = network.snapshot(None).await.unwrap();
        advance_window_past_expiry(&rpc, &endpoint, &network, 1, &expired_window_one).await;
        let balance_before_losing_finalization = network
            .snapshot(Some(deployment_wallet))
            .await
            .unwrap()
            .ast_balance
            .unwrap();
        send_unlocked(
            &rpc,
            &endpoint,
            external_finalizer,
            Some(miner),
            &finalize,
            U256::ZERO,
        )
        .await;
        rpc_request_local(&rpc, &endpoint, "evm_mine", serde_json::json!([]))
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let snapshot = network.snapshot(Some(wallet)).await.unwrap();
                manager
                    .service_reward_reconciliation(&network, &snapshot)
                    .await
                    .unwrap();
                let losing_entry = manager.journal.state.entries.iter().find(|entry| {
                    entry.action == TransactionAction::SubmitProof && entry.window_id == 1
                });
                if losing_entry.is_some_and(|entry| {
                    entry.reward_confirmed
                        && entry
                            .reward_outcome
                            .as_deref()
                            .is_some_and(|outcome| outcome.starts_with("not-window-winner:"))
                }) {
                    return;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("the CLI proof that lost to the external contender must be reconciled");

        let current_wallet_balance = network.snapshot(Some(wallet)).await.unwrap();
        assert_eq!(current_wallet_balance.ast_balance, Some(reward));
        let external_winner_balance = network
            .snapshot(Some(deployment_wallet))
            .await
            .unwrap()
            .ast_balance
            .unwrap();
        assert_eq!(
            external_winner_balance - balance_before_losing_finalization,
            reward
        );
        assert_eq!(manager.mined_rewards_total(), reward);
        assert_eq!(
            dashboard_state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .mined_rewards,
            reward,
            "external transfers and losing proofs must not change the dashboard session total"
        );

        drop(manager);
        let restarted = TransactionManager::open(&store, &config, wallet, token).unwrap();
        assert_eq!(restarted.mined_rewards_total(), U256::ZERO);
        assert!(restarted.journal.state.entries.iter().any(|entry| {
            entry.action == TransactionAction::SubmitProof
                && entry.window_id == 0
                && entry.reward_confirmed
                && entry
                    .reward_outcome
                    .as_deref()
                    .is_some_and(|outcome| outcome.starts_with("reward-paid:"))
        }));
        assert!(restarted.journal.state.entries.iter().any(|entry| {
            entry.action == TransactionAction::SubmitProof
                && entry.window_id == 1
                && entry.reward_confirmed
                && entry
                    .reward_outcome
                    .as_deref()
                    .is_some_and(|outcome| outcome.starts_with("not-window-winner:"))
        }));
    }

    #[tokio::test]
    #[ignore = "requires local Forge and Anvil; run with ASTATINE_EVM_ROOT set"]
    async fn production_worker_submits_real_one_in_sixty_million_proof_after_head_updates() {
        let root = std::env::var_os("ASTATINE_EVM_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .join("astatineEVM")
                    .join("evm")
            });
        assert!(root.join("src/AstatineMiner.sol").is_file());
        let build = Command::new("forge")
            .args(["build", "--root"])
            .arg(&root)
            .output()
            .expect("Forge must be installed for the high-difficulty worker test");
        assert!(
            build.status.success(),
            "Forge build failed:\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );

        tokio::time::timeout(Duration::from_secs(240), async {
            let port_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = port_listener.local_addr().unwrap().port();
            drop(port_listener);
            let mut process = Command::new("anvil")
                .args([
                    "--host",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                    "--chain-id",
                    "1439",
                    "--accounts",
                    "3",
                    "--silent",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("Anvil must be installed for the high-difficulty worker test");
            let _process_guard = AnvilGuard(&mut process);
            let endpoint = format!("http://127.0.0.1:{port}");
            let rpc = reqwest::Client::new();
            wait_for_anvil(&rpc, &endpoint).await;

            let signer = test_signer();
            let account = signer_address(&signer);
            let accounts =
                rpc_request_local(&rpc, &endpoint, "eth_accounts", serde_json::json!([]))
                    .await
                    .unwrap();
            let deployment_wallet = Address::from_str(accounts[0].as_str().unwrap()).unwrap();
            let funded_balance = U256::from(1_000_u64) * U256::from(10_u8).pow(U256::from(18));
            rpc_request_local(
                &rpc,
                &endpoint,
                "anvil_setBalance",
                serde_json::json!([format!("{account:#x}"), format!("{funded_balance:#x}")]),
            )
            .await
            .unwrap();

            let token_artifact = read_artifact(&root.join("out/MockAST.sol/MockAST.json"));
            let miner_artifact =
                read_artifact(&root.join("out/AstatineMiner.sol/AstatineMiner.json"));
            let miner_bytecode = artifact_bytecode(&miner_artifact);
            let decimals = 9_u8;
            let token_unit = U256::from(10_u8).pow(U256::from(decimals));
            let allocation = U256::from(1_000_u64) * token_unit;
            let total_allocation = allocation * U256::from(9_u8);
            let reward = U256::from(100_u64) * token_unit;
            let mut token_init = artifact_bytecode(&token_artifact);
            token_init.extend_from_slice(&abi_uint8_word(decimals));
            let token = deploy_unlocked(&rpc, &endpoint, deployment_wallet, &token_init).await;
            let mint = LocalMockAST::mintCall {
                account: deployment_wallet,
                amount: total_allocation,
            }
            .abi_encode();
            send_unlocked(
                &rpc,
                &endpoint,
                deployment_wallet,
                Some(token),
                &mint,
                U256::ZERO,
            )
            .await;

            let target = U256::MAX / U256::from(60_000_000_u64);
            let easier_target = U256::MAX / U256::from(50_000_000_u64);
            let harder_target = U256::MAX / U256::from(70_000_000_u64);
            assert!(target < easier_target && target > harder_target);
            let mut miners = Vec::with_capacity(9);
            for node_id in 1..=9_u8 {
                let initial_target = if node_id == 1 { target } else { U256::MAX };
                let miner = deploy_local_miner(LocalMinerDeployment {
                    client: &rpc,
                    endpoint: &endpoint,
                    deployment_wallet,
                    token,
                    token_decimals: decimals,
                    allocation,
                    reward,
                    miner_bytecode: &miner_bytecode,
                    initial_target,
                    retarget_interval: 100,
                    window_secs: 600,
                })
                .await;
                let approve = LocalMockAST::approveCall {
                    spender: miner,
                    amount: allocation,
                }
                .abi_encode();
                send_unlocked(
                    &rpc,
                    &endpoint,
                    deployment_wallet,
                    Some(token),
                    &approve,
                    U256::ZERO,
                )
                .await;
                let fund = LocalAstatineMiner::fundASTCall { amount: allocation }.abi_encode();
                send_unlocked(
                    &rpc,
                    &endpoint,
                    deployment_wallet,
                    Some(miner),
                    &fund,
                    U256::ZERO,
                )
                .await;
                miners.push((
                    node_id,
                    miner,
                    local_code_hash(&rpc, &endpoint, miner).await,
                ));
            }
            for (node_id, miner, _) in miners.iter().filter(|(node_id, _, _)| *node_id != 1) {
                let activate = LocalAstatineMiner::activateGenesisCall {
                    initialSeed: B256::with_last_byte(0x50 + *node_id),
                }
                .abi_encode();
                send_unlocked(
                    &rpc,
                    &endpoint,
                    deployment_wallet,
                    Some(*miner),
                    &activate,
                    U256::ZERO,
                )
                .await;
            }
            let miner = miners
                .iter()
                .find(|(node_id, _, _)| *node_id == 1)
                .unwrap()
                .1;
            let seed = B256::with_last_byte(0x51);
            let activate =
                LocalAstatineMiner::activateGenesisCall { initialSeed: seed }.abi_encode();
            send_unlocked(
                &rpc,
                &endpoint,
                deployment_wallet,
                Some(miner),
                &activate,
                U256::ZERO,
            )
            .await;
            let network = NetworkClient::local_test_client_with_nodes(
                &endpoint,
                &miners,
                token,
                local_code_hash(&rpc, &endpoint, token).await,
                decimals,
            )
            .unwrap();
            let initial = network.snapshot(Some(account)).await.unwrap();
            let state = initial
                .nodes
                .iter()
                .find(|node| node.id == 1)
                .unwrap()
                .state
                .as_ref()
                .unwrap();
            assert!(state.eligible && !state.finalizable);
            assert_eq!(state.work.target, target);
            let context = WorkContext {
                chain_id: network.manifest.chain_id,
                contract: miner,
                window_id: state.work.window_id,
                seed: state.work.seed,
                miner: account,
                header: Vec::new(),
            };
            let (nonce, expected_hash) =
                first_target_valid_nonce_parallel(&context, target, 32, 1_200_000_000)
                    .expect("parallel deterministic fixture search should find 1-in-60M work");
            assert_eq!(
                WorkHasher::new(&context).unwrap().hash(nonce),
                expected_hash
            );
            assert!(meets_target(expected_hash, target));
            network.set_test_proof_nonce_start(1, state.work.window_id, state.work.seed, nonce);
            network.delay_next_proof_fee_quote(Duration::from_secs(1));
            network.fail_next_proof_fee_quote_once();

            let temp = tempdir().unwrap();
            let store = ConfigStore::at_root(temp.path().to_path_buf());
            let config = AppConfig {
                network: Network::Testnet,
                wallet_address: Some(format!("{account:#x}")),
                cpu_threads: 32,
                minimum_reserve_inj: "0".to_owned(),
                per_session_spending_limit_inj: "1".to_owned(),
                transaction_confirmations: 1,
                ..AppConfig::default()
            };
            store.save(&config).unwrap();
            let run_store = store.clone();
            let run_config = config.clone();
            let run_network = network.clone();
            let run_signer = clone_signer(&signer);
            let args = MineArgs {
                compute_only: false,
                threads: NonZeroUsize::new(32),
                nodes: vec![1],
            };
            let (probe_tx, probe_rx) = tokio::sync::oneshot::channel();
            let runtime = tokio::spawn(async move {
                crate::mining::run_with_client(
                    &run_store,
                    run_config,
                    args,
                    run_network,
                    Some(run_signer),
                    Some(probe_tx),
                )
                .await
            });
            let probe = match tokio::time::timeout(Duration::from_secs(5), probe_rx).await {
                Ok(Ok(probe)) => probe,
                Ok(Err(_)) => panic!(
                    "high-difficulty runtime exited before workers started: {:?}",
                    runtime.await
                ),
                Err(_) => panic!("32-worker runtime must start within five seconds"),
            };
            assert_eq!(probe.worker_threads, 32);
            let mut observed_updates = probe.observer_updates.clone();
            let _ = observed_updates.borrow_and_update();
            wait_for_proof_metric(&probe, 1, ProofMetric::TargetValidHashes, 1).await;
            wait_for_proof_metric(&probe, 1, ProofMetric::QueuedCandidates, 1).await;
            wait_for_proof_metric(&probe, 1, ProofMetric::MainLoopReceived, 1).await;
            assert_eq!(
                probe
                    .proof_telemetry
                    .count(1, ProofMetric::PreflightStarted),
                0
            );

            let mut refreshed_block = initial.block.number;
            let generation_before_head_updates = probe.slots[0].generation();
            for _ in 0..3 {
                rpc_request_local(&rpc, &endpoint, "evm_increaseTime", serde_json::json!([3]))
                    .await
                    .unwrap();
                rpc_request_local(&rpc, &endpoint, "evm_mine", serde_json::json!([]))
                    .await
                    .unwrap();
                refreshed_block += 1;
                probe.observer_refresh.force_refresh();
                let refreshed =
                    wait_for_observer_snapshot(&mut observed_updates, refreshed_block).await;
                let refreshed_state = refreshed.nodes[0].state.as_ref().unwrap();
                assert_eq!(refreshed_state.work.window_id, state.work.window_id);
                assert!(refreshed_state.eligible && !refreshed_state.finalizable);
                assert_eq!(refreshed_state.work.target, target);
            }
            assert!(
                probe.slots[0].generation() > generation_before_head_updates,
                "verified same-window deadline updates must invalidate old workers"
            );
            assert_eq!(
                probe
                    .proof_telemetry
                    .count(1, ProofMetric::GenerationMismatchRevalidated),
                0,
                "the main-loop receive is deliberately held until after the verified heads"
            );
            probe.proof_processing_gate.send_replace(false);
            wait_for_proof_metric(&probe, 1, ProofMetric::GenerationMismatchRevalidated, 1).await;
            wait_for_proof_metric(&probe, 1, ProofMetric::PreflightStarted, 1).await;
            tokio::time::timeout(Duration::from_secs(5), async {
                while network.fee_quote_delays_started() == 0 {
                    sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("proof fee-quote delay hook must be reached");
            rpc_request_local(&rpc, &endpoint, "evm_increaseTime", serde_json::json!([2]))
                .await
                .unwrap();
            rpc_request_local(&rpc, &endpoint, "evm_mine", serde_json::json!([]))
                .await
                .unwrap();
            refreshed_block += 1;
            probe.observer_refresh.force_refresh();
            let after_preflight_head =
                wait_for_observer_snapshot(&mut observed_updates, refreshed_block).await;
            assert!(
                after_preflight_head.nodes[0]
                    .state
                    .as_ref()
                    .is_some_and(|state| state.work.window_id == 0 && state.eligible)
            );

            let accepted = wait_for_journal_entry_for_window(
                &store,
                1,
                TransactionAction::SubmitProof,
                0,
                TransactionStatus::MinedSuccess,
            )
            .await;
            assert_eq!(accepted.outcome.as_deref(), Some("candidate-updated"));
            assert_eq!(accepted.value_wei, SUBMISSION_FEE_WEI.to_string());
            let candidate = wait_for_candidate(&network, 1, 0, account).await;
            assert!(
                candidate.nodes[0]
                    .state
                    .as_ref()
                    .unwrap()
                    .candidate
                    .is_some()
            );
            for metric in [
                ProofMetric::Signed,
                ProofMetric::Broadcast,
                ProofMetric::ReceiptConfirmed,
                ProofMetric::CandidateUpdated,
            ] {
                assert_eq!(probe.proof_telemetry.count(1, metric), 1, "{metric:?}");
            }
            assert_eq!(
                probe
                    .proof_telemetry
                    .count(1, ProofMetric::PreflightStarted),
                2
            );
            assert_eq!(
                probe
                    .proof_telemetry
                    .count(1, ProofMetric::PreflightRpcFailure),
                1
            );
            let journal: serde_json::Value =
                serde_json::from_slice(&store.read_transaction_journal().unwrap().unwrap())
                    .unwrap();
            let proof_entries = journal["entries"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|entry| {
                    entry["action"] == "submit_proof"
                        && entry["node_id"] == 1
                        && entry["window_id"] == 0
                })
                .count();
            assert_eq!(
                proof_entries, 1,
                "one paid attempt is authorized per node/window"
            );

            probe.stop_signal.request_stop();
            tokio::time::timeout(Duration::from_secs(5), runtime)
                .await
                .expect("high-difficulty runtime should stop cleanly")
                .unwrap()
                .unwrap();
            let stopped_journal: super::JournalState =
                serde_json::from_slice(&store.read_transaction_journal().unwrap().unwrap())
                    .unwrap();
            assert!(
                stopped_journal
                    .entries
                    .iter()
                    .filter(|entry| {
                        entry.action == TransactionAction::SubmitProof
                            && entry.node_id == 1
                            && entry.window_id == 0
                    })
                    .all(|entry| entry.status == TransactionStatus::MinedSuccess)
            );
            assert!(
                !stopped_journal
                    .entries
                    .iter()
                    .any(|entry| entry.status.is_unresolved())
            );
            assert!(
                stopped_journal
                    .active_session
                    .as_ref()
                    .is_some_and(|session| session.closed)
            );
        })
        .await
        .expect("high-difficulty CPU-to-CandidateUpdated lifecycle must not hang");
    }

    #[tokio::test]
    #[ignore = "requires local Forge and Anvil; run with ASTATINE_EVM_ROOT set"]
    async fn transaction_manager_local_anvil_lifecycle_recovery_reorg_and_spending_cap() {
        let root = std::env::var_os("ASTATINE_EVM_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap()
                    .join("astatineEVM")
                    .join("evm")
            });
        assert!(
            root.join("src/AstatineMiner.sol").is_file(),
            "invalid ASTATINE_EVM_ROOT"
        );
        let build = Command::new("forge")
            .args(["build", "--root"])
            .arg(&root)
            .output()
            .expect("Forge must be installed for the local EVM lifecycle test");
        assert!(
            build.status.success(),
            "Forge build failed:\n{}\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr)
        );

        let port_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = port_listener.local_addr().unwrap().port();
        drop(port_listener);
        let mut process = Command::new("anvil")
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--chain-id",
                "1439",
                "--accounts",
                "3",
                "--silent",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Anvil must be installed for the local EVM lifecycle test");
        let _process_guard = AnvilGuard(&mut process);
        let endpoint = format!("http://127.0.0.1:{port}");
        let client = reqwest::Client::new();
        wait_for_anvil(&client, &endpoint).await;

        let signer = test_signer();
        let account = signer_address(&signer);
        let unlocked_accounts =
            rpc_request_local(&client, &endpoint, "eth_accounts", serde_json::json!([]))
                .await
                .unwrap();
        let deployment_wallet = Address::from_str(unlocked_accounts[0].as_str().unwrap()).unwrap();
        let test_inj_balance = U256::from(1_000_u64) * U256::from(10_u8).pow(U256::from(18));
        rpc_request_local(
            &client,
            &endpoint,
            "anvil_setBalance",
            serde_json::json!([format!("{account:#x}"), format!("{test_inj_balance:#x}")]),
        )
        .await
        .unwrap();

        let token_artifact = read_artifact(&root.join("out/MockAST.sol/MockAST.json"));
        let miner_artifact = read_artifact(&root.join("out/AstatineMiner.sol/AstatineMiner.json"));
        let token_bytecode = artifact_bytecode(&token_artifact);
        let miner_bytecode = artifact_bytecode(&miner_artifact);
        let token_decimals = 9_u8;
        let mut token_init = token_bytecode;
        token_init.extend_from_slice(&abi_uint8_word(token_decimals));
        let token = deploy_unlocked(&client, &endpoint, deployment_wallet, &token_init).await;

        let token_unit = U256::from(10_u8).pow(U256::from(token_decimals));
        let allocation = U256::from(1_000_u64) * token_unit;
        let reward = U256::from(100_u64) * token_unit;
        let mut miner_init = miner_bytecode;
        let constructor = [
            token.abi_encode(),
            u64::from(token_decimals).abi_encode(),
            allocation.abi_encode(),
            reward.abi_encode(),
            U256::MAX.abi_encode(),
            U256::from(1).abi_encode(),
            U256::MAX.abi_encode(),
            60_u64.abi_encode(),
            60_u64.abi_encode(),
            200_u16.abi_encode(),
            100_u64.abi_encode(),
            3_u64.abi_encode(),
            2_u64.abi_encode(),
            256_u32.abi_encode(),
            120_u64.abi_encode(),
            deployment_wallet.abi_encode(),
            Address::with_last_byte(0x22).abi_encode(),
            Address::with_last_byte(0x33).abi_encode(),
        ]
        .concat();
        miner_init.extend_from_slice(&constructor);
        let miner = deploy_unlocked(&client, &endpoint, deployment_wallet, &miner_init).await;

        let mint = LocalMockAST::mintCall {
            account: deployment_wallet,
            amount: allocation,
        }
        .abi_encode();
        send_unlocked(
            &client,
            &endpoint,
            deployment_wallet,
            Some(token),
            &mint,
            U256::ZERO,
        )
        .await;
        let approve = LocalMockAST::approveCall {
            spender: miner,
            amount: allocation,
        }
        .abi_encode();
        send_unlocked(
            &client,
            &endpoint,
            deployment_wallet,
            Some(token),
            &approve,
            U256::ZERO,
        )
        .await;
        let fund = LocalAstatineMiner::fundASTCall { amount: allocation }.abi_encode();
        send_unlocked(
            &client,
            &endpoint,
            deployment_wallet,
            Some(miner),
            &fund,
            U256::ZERO,
        )
        .await;
        let seed = B256::with_last_byte(0x77);
        let activate = LocalAstatineMiner::activateGenesisCall { initialSeed: seed }.abi_encode();
        send_unlocked(
            &client,
            &endpoint,
            deployment_wallet,
            Some(miner),
            &activate,
            U256::ZERO,
        )
        .await;

        type WorkReturn = (
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
        let work_bytes = local_call(
            &client,
            &endpoint,
            miner,
            &AstatineMinerRead::workCall {}.abi_encode(),
        )
        .await;
        let work = <WorkReturn as SolValue>::abi_decode_validate(&work_bytes).unwrap();
        assert!(work.0 && !work.1);
        assert_eq!(work.2, 0);
        assert_eq!(work.5, seed);

        let network = Arc::new(
            NetworkClient::local_test_client(
                &endpoint,
                miner,
                local_code_hash(&client, &endpoint, miner).await,
                token,
                local_code_hash(&client, &endpoint, token).await,
                token_decimals,
            )
            .unwrap(),
        );
        let decimals_bytes = local_call(
            &client,
            &endpoint,
            token,
            &LocalMockAST::decimalsCall {}.abi_encode(),
        )
        .await;
        assert_eq!(
            U256::abi_decode_validate(&decimals_bytes).unwrap(),
            U256::from(token_decimals)
        );
        let app_root = tempdir().unwrap();
        let store = ConfigStore::at_root(PathBuf::from(app_root.path()));
        let config = AppConfig {
            network: Network::Testnet,
            minimum_reserve_inj: "0.1".to_owned(),
            per_session_spending_limit_inj: "1".to_owned(),
            transaction_confirmations: 2,
            ..AppConfig::default()
        };

        let header = b"transaction-manager-local-anvil-lifecycle";
        let context = WorkContext {
            chain_id: 1439,
            contract: miner,
            window_id: work.2,
            seed: work.5,
            miner: account,
            header: header.to_vec(),
        };
        let nonce = 0_u128;
        let work_hash = WorkHasher::new(&context).unwrap().hash(nonce);
        assert!(meets_target(work_hash, work.7));
        let submission = ProofSubmission {
            contract: miner,
            node_id: 1,
            window_id: work.2,
            nonce,
            header: header.to_vec(),
            work_hash,
        };
        rpc_request_local(
            &client,
            &endpoint,
            "anvil_setAutomine",
            serde_json::json!([false]),
        )
        .await
        .unwrap();
        let submit_store = store.clone();
        let submit_network = Arc::clone(&network);
        let submit_signer = clone_signer(&signer);
        let submit_config = config.clone();
        let mut submit_task = tokio::spawn(async move {
            let mut manager =
                TransactionManager::open(&submit_store, &submit_config, account, token).unwrap();
            manager
                .submit_proof(&submit_network, &submit_signer, submission)
                .await
        });
        let broadcast_proof = tokio::select! {
            entry = wait_for_journal_entry(
                &store,
                TransactionAction::SubmitProof,
                TransactionStatus::Broadcast,
            ) => entry,
            result = &mut submit_task => panic!("proof manager task ended before the broadcast could be observed: {result:?}"),
        };
        assert_eq!(broadcast_proof.confirmations, 0);
        let observer_slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
        let observer_schedule = Arc::new(RwLock::new(Vec::new()));
        let observer_selected = HashSet::from([1_u8, 3, 7]);
        let observer_node_hash = local_code_hash(&client, &endpoint, miner).await;
        let observer_token_hash = local_code_hash(&client, &endpoint, token).await;
        let observer_network = NetworkClient::local_test_client_with_nodes(
            &endpoint,
            &[
                (1, miner, observer_node_hash),
                (3, miner, observer_node_hash),
                (7, miner, observer_node_hash),
            ],
            token,
            observer_token_hash,
            token_decimals,
        )
        .unwrap();
        let observer_context = DashboardContext {
            network: Network::Testnet,
            chain_id: 1439,
            address: account,
            threads: 2,
            spending_limit: parse_inj_wei(&config.per_session_spending_limit_inj).unwrap(),
            transaction_mode: true,
            compute_only: false,
            workers_started: Arc::new(AtomicBool::new(true)),
            total_hashes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            selected: observer_selected.clone(),
            slots: Arc::clone(&observer_slots),
            schedule: Arc::clone(&observer_schedule),
            transaction_state: Arc::new(RwLock::new(TransactionDashboardState {
                session_exposure: Some(
                    parse_decimal_wei(&broadcast_proof.maximum_exposure_wei).unwrap(),
                ),
                mined_rewards: U256::ZERO,
                activities: vec![TransactionActivity {
                    node_id: 1,
                    window_id: broadcast_proof.window_id,
                    state: TransactionActivityState::Confirming,
                }],
            })),
            pending_sync: Arc::new(RwLock::new(HashMap::new())),
            finalization_state: Arc::new(RwLock::new(HashMap::new())),
        };
        let observer_seed = observer_network.snapshot(Some(account)).await.unwrap();
        update_slots(
            &observer_slots,
            &observer_schedule,
            &observer_network.manifest,
            account,
            &observer_selected,
            &observer_seed,
        )
        .unwrap();
        let observer_seed_block = observer_seed.block.number;
        let mut observer = start_read_only_observer(
            observer_network.clone(),
            observer_context,
            observer_seed,
            None,
            DiagnosticBuffer::default(),
        );
        let mut observed_updates = observer.updates.clone();
        let _ = observed_updates.borrow_and_update();
        observer.force_refresh();
        tokio::time::timeout(Duration::from_secs(5), observed_updates.changed())
            .await
            .expect("observer should refresh while transaction confirmation is pending")
            .expect("observer update channel should remain open");
        assert!(observer.latest_snapshot().unwrap().block.number >= observer_seed_block);
        assert_eq!(
            *observer_schedule
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [0, 2, 6]
        );
        assert!(
            !submit_task.is_finished(),
            "read-only observation must progress while the proof receipt is pending"
        );
        assert!(broadcast_proof.actual_cost_wei.is_none());
        assert!(
            parse_decimal_wei(&broadcast_proof.maximum_exposure_wei).unwrap()
                > U256::from(SUBMISSION_FEE_WEI)
        );
        assert!(
            store
                .read_transaction_journal()
                .unwrap()
                .unwrap()
                .windows(b"signed_transaction".len())
                .all(|window| window != b"signed_transaction")
        );
        let proof_hash = entry_hash(&broadcast_proof).unwrap();
        assert!(network.transaction_known(proof_hash).await.unwrap());
        assert!(
            network
                .transaction_receipt(proof_hash)
                .await
                .unwrap()
                .is_none()
        );
        let pending_nonce_before_recovery = local_pending_nonce(&client, &endpoint, account).await;
        assert_eq!(pending_nonce_before_recovery, broadcast_proof.nonce + 1);
        submit_task.abort();
        let _ = submit_task.await;

        let mut recovered = TransactionManager::open(&store, &config, account, token).unwrap();
        recovered.reconcile(&network).await.unwrap();
        let pending_recovered = recovered
            .journal
            .state
            .entries
            .iter()
            .find(|entry| entry.action == TransactionAction::SubmitProof)
            .unwrap();
        assert_eq!(pending_recovered.status, TransactionStatus::Broadcast);
        assert!(recovered.journal.pending_exposure().unwrap() > U256::ZERO);
        assert_eq!(
            local_pending_nonce(&client, &endpoint, account).await,
            pending_nonce_before_recovery,
            "restart recovery must not submit a duplicate transaction"
        );

        rpc_request_local(&client, &endpoint, "evm_mine", serde_json::json!([]))
            .await
            .unwrap();
        recovered.reconcile(&network).await.unwrap();
        let included_proof = recovered
            .journal
            .state
            .entries
            .iter()
            .find(|entry| entry.action == TransactionAction::SubmitProof)
            .unwrap();
        assert_eq!(included_proof.status, TransactionStatus::Included);
        assert_eq!(included_proof.confirmations, 1);

        rpc_request_local(&client, &endpoint, "evm_mine", serde_json::json!([]))
            .await
            .unwrap();
        rpc_request_local(
            &client,
            &endpoint,
            "anvil_setAutomine",
            serde_json::json!([true]),
        )
        .await
        .unwrap();
        recovered.reconcile(&network).await.unwrap();
        let accepted = recovered
            .journal
            .state
            .entries
            .iter()
            .find(|entry| entry.action == TransactionAction::SubmitProof)
            .unwrap()
            .clone();
        assert_eq!(accepted.status, TransactionStatus::MinedSuccess);
        assert!(accepted.confirmations >= u64::from(config.transaction_confirmations));
        assert_eq!(accepted.outcome.as_deref(), Some("candidate-updated"));
        assert_eq!(
            recovered
                .journal
                .state
                .proof_attempted_through
                .get(&format!("{miner:#x}")),
            Some(&0)
        );

        observer.force_refresh();
        tokio::time::timeout(Duration::from_secs(5), observed_updates.changed())
            .await
            .expect("observer should refresh the accepted candidate after receipt confirmation")
            .expect("observer update channel should remain open");
        let observed = observer.latest_snapshot().unwrap();
        let observed_candidate = observed
            .nodes
            .iter()
            .find(|node| node.id == 1)
            .and_then(|node| node.state.as_ref())
            .and_then(|state| state.candidate.as_ref())
            .expect("verified snapshot should expose the accepted candidate");
        assert_eq!(observed_candidate.miner, account);
        assert_eq!(
            observed.nodes[0].state.as_ref().unwrap().work.window_id,
            work.2
        );
        observer.stop().await.unwrap();

        let mut replacement = None;
        for nonce in 1..10_000_u128 {
            let hash = WorkHasher::new(&context).unwrap().hash(nonce);
            if hash < work_hash {
                replacement = Some((nonce, hash));
                break;
            }
        }
        let (replacement_nonce, replacement_hash) = replacement.unwrap();
        let nonce_before_rejected_attempt = local_pending_nonce(&client, &endpoint, account).await;
        let duplicate = recovered
            .submit_proof(
                &network,
                &signer,
                ProofSubmission {
                    contract: miner,
                    node_id: 1,
                    window_id: work.2,
                    nonce: replacement_nonce,
                    header: header.to_vec(),
                    work_hash: replacement_hash,
                },
            )
            .await
            .unwrap_err();
        assert!(format!("{duplicate:#}").contains("paid proof attempt already journaled"));
        assert_eq!(
            local_pending_nonce(&client, &endpoint, account).await,
            nonce_before_rejected_attempt,
            "one-attempt guard must reject before signing or broadcasting another paid proof"
        );

        let low_root = tempdir().unwrap();
        let low_store = ConfigStore::at_root(PathBuf::from(low_root.path()));
        let low_config = AppConfig {
            network: Network::Testnet,
            minimum_reserve_inj: "0".to_owned(),
            per_session_spending_limit_inj: "0.000000000000000001".to_owned(),
            transaction_confirmations: 2,
            ..AppConfig::default()
        };
        let mut low_cap_manager =
            TransactionManager::open(&low_store, &low_config, account, token).unwrap();
        let over_cap = low_cap_manager
            .submit_proof(
                &network,
                &signer,
                ProofSubmission {
                    contract: miner,
                    node_id: 1,
                    window_id: work.2,
                    nonce: replacement_nonce,
                    header: header.to_vec(),
                    work_hash: replacement_hash,
                },
            )
            .await
            .unwrap_err();
        assert!(format!("{over_cap:#}").contains("maximum exposure exceeds"));
        let low_journal: super::JournalState =
            serde_json::from_slice(&low_store.read_transaction_journal().unwrap().unwrap())
                .unwrap();
        assert!(low_journal.entries.is_empty());
        assert_eq!(
            local_pending_nonce(&client, &endpoint, account).await,
            nonce_before_rejected_attempt,
            "maximum exposure must be rejected before a raw transaction is sent"
        );
        rpc_request_local(
            &client,
            &endpoint,
            "evm_increaseTime",
            serde_json::json!([61]),
        )
        .await
        .unwrap();
        rpc_request_local(&client, &endpoint, "evm_mine", serde_json::json!([]))
            .await
            .unwrap();
        let nonce_before_finalization_cap = local_pending_nonce(&client, &endpoint, account).await;
        let finalization_over_cap = low_cap_manager
            .finalize_window(&network, &signer, miner, 1, work.2)
            .await
            .unwrap_err();
        assert!(format!("{finalization_over_cap:#}").contains("maximum exposure exceeds"));
        assert_eq!(
            local_pending_nonce(&client, &endpoint, account).await,
            nonce_before_finalization_cap,
            "empty-window finalization gas must fit the configured spending cap"
        );
        let low_journal: super::JournalState =
            serde_json::from_slice(&low_store.read_transaction_journal().unwrap().unwrap())
                .unwrap();
        assert!(low_journal.entries.is_empty());
        drop(low_cap_manager);
        let pre_finalize_snapshot =
            rpc_request_local(&client, &endpoint, "evm_snapshot", serde_json::json!([]))
                .await
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
        drop(recovered);

        let finalize_store = store.clone();
        let finalize_network = Arc::clone(&network);
        let finalize_signer = clone_signer(&signer);
        let finalize_config = config.clone();
        let finalize_task = tokio::spawn(async move {
            let mut manager =
                TransactionManager::open(&finalize_store, &finalize_config, account, token)
                    .unwrap();
            manager
                .finalize_window(&finalize_network, &finalize_signer, miner, 1, work.2)
                .await
        });
        let included_finalization = wait_for_journal_entry(
            &store,
            TransactionAction::FinalizeWindow,
            TransactionStatus::Included,
        )
        .await;
        assert!(included_finalization.confirmations < 2);
        finalize_task.abort();
        let _ = finalize_task.await;
        rpc_request_local(&client, &endpoint, "evm_mine", serde_json::json!([]))
            .await
            .unwrap();

        let mut manager = TransactionManager::open(&store, &config, account, token).unwrap();
        manager.reconcile(&network).await.unwrap();
        let snapshot = network.snapshot(Some(account)).await.unwrap();
        manager
            .reconcile_rewards(&network, &snapshot)
            .await
            .unwrap();
        let finalization_entry = manager
            .journal
            .state
            .entries
            .iter()
            .find(|entry| entry.action == TransactionAction::FinalizeWindow)
            .unwrap()
            .clone();
        assert_eq!(finalization_entry.status, TransactionStatus::MinedSuccess);
        assert!(finalization_entry.confirmations >= 2);
        assert!(
            finalization_entry
                .outcome
                .as_deref()
                .unwrap()
                .contains("window-finalized-reward-paid")
        );
        let accepted = manager
            .journal
            .state
            .entries
            .iter()
            .find(|entry| entry.action == TransactionAction::SubmitProof)
            .unwrap();
        assert!(
            accepted
                .reward_outcome
                .as_deref()
                .unwrap()
                .starts_with("reward-paid:")
        );
        assert!(accepted.reward_block_hash.is_some());
        let balance_bytes = local_call(
            &client,
            &endpoint,
            token,
            &LocalMockAST::balanceOfCall { account }.abi_encode(),
        )
        .await;
        assert_eq!(U256::abi_decode_validate(&balance_bytes).unwrap(), reward);

        let reverted = rpc_request_local(
            &client,
            &endpoint,
            "evm_revert",
            serde_json::json!([pre_finalize_snapshot]),
        )
        .await
        .unwrap();
        assert_eq!(reverted, serde_json::Value::Bool(true));
        manager.monitor(&network).await.unwrap();
        let finalization_entry = manager
            .journal
            .state
            .entries
            .iter()
            .find(|entry| entry.action == TransactionAction::FinalizeWindow)
            .unwrap();
        assert_eq!(finalization_entry.status, TransactionStatus::Unknown);
        assert!(finalization_entry.last_known_cost_wei.is_some());
        assert!(manager.journal.pending_exposure().unwrap() > U256::ZERO);
        let accepted = manager
            .journal
            .state
            .entries
            .iter()
            .find(|entry| entry.action == TransactionAction::SubmitProof)
            .unwrap();
        assert!(accepted.reward_block_hash.is_none());
        assert_eq!(
            local_pending_nonce(&client, &endpoint, account).await,
            finalization_entry.nonce,
            "reorg recovery must reserve exposure without rebroadcasting"
        );
    }

    struct AnvilGuard<'a>(&'a mut Child);

    impl Drop for AnvilGuard<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    async fn wait_for_anvil(client: &reqwest::Client, endpoint: &str) {
        for _ in 0..100 {
            if rpc_request_local(client, endpoint, "eth_chainId", serde_json::json!([]))
                .await
                .is_ok()
            {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("Anvil did not become ready");
    }

    fn read_artifact(path: &std::path::Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).expect("read Forge contract artifact"))
            .expect("decode Forge contract artifact")
    }

    fn artifact_bytecode(artifact: &serde_json::Value) -> Vec<u8> {
        let bytecode = artifact["bytecode"]["object"]
            .as_str()
            .expect("artifact creation bytecode is present");
        let bytecode = bytecode.strip_prefix("0x").unwrap_or(bytecode);
        hex::decode(bytecode).expect("decode artifact creation bytecode")
    }

    async fn deploy_unlocked(
        client: &reqwest::Client,
        endpoint: &str,
        from: Address,
        init_code: &[u8],
    ) -> Address {
        let hash = rpc_request_local(
            client,
            endpoint,
            "eth_sendTransaction",
            serde_json::json!([{
                "from": format!("{from:#x}"),
                "data": format!("0x{}", hex::encode(init_code)),
                "gas": "0x989680",
            }]),
        )
        .await
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
        let receipt = wait_for_receipt(client, endpoint, &hash).await;
        assert_eq!(receipt["status"], "0x1", "contract deployment reverted");
        Address::from_str(receipt["contractAddress"].as_str().unwrap()).unwrap()
    }

    struct LocalMinerDeployment<'a> {
        client: &'a reqwest::Client,
        endpoint: &'a str,
        deployment_wallet: Address,
        token: Address,
        token_decimals: u8,
        allocation: U256,
        reward: U256,
        miner_bytecode: &'a [u8],
        initial_target: U256,
        retarget_interval: u64,
        window_secs: u64,
    }

    async fn deploy_local_miner(deployment: LocalMinerDeployment<'_>) -> Address {
        let LocalMinerDeployment {
            client,
            endpoint,
            deployment_wallet,
            token,
            token_decimals,
            allocation,
            reward,
            miner_bytecode,
            initial_target,
            retarget_interval,
            window_secs,
        } = deployment;
        let constructor = [
            token.abi_encode(),
            u64::from(token_decimals).abi_encode(),
            allocation.abi_encode(),
            reward.abi_encode(),
            initial_target.abi_encode(),
            U256::from(1).abi_encode(),
            U256::MAX.abi_encode(),
            window_secs.abi_encode(),
            60_u64.abi_encode(),
            200_u16.abi_encode(),
            100_u64.abi_encode(),
            retarget_interval.abi_encode(),
            2_u64.abi_encode(),
            256_u32.abi_encode(),
            window_secs.saturating_add(60).abi_encode(),
            deployment_wallet.abi_encode(),
            Address::with_last_byte(0x22).abi_encode(),
            Address::with_last_byte(0x33).abi_encode(),
        ]
        .concat();
        let mut init_code = miner_bytecode.to_vec();
        init_code.extend_from_slice(&constructor);
        deploy_unlocked(client, endpoint, deployment_wallet, &init_code).await
    }

    async fn send_unlocked(
        client: &reqwest::Client,
        endpoint: &str,
        from: Address,
        to: Option<Address>,
        data: &[u8],
        value: U256,
    ) {
        let mut transaction = serde_json::json!({
            "from": format!("{from:#x}"),
            "data": format!("0x{}", hex::encode(data)),
            "value": format!("{value:#x}"),
            "gas": "0x989680",
        });
        if let Some(to) = to {
            transaction["to"] = serde_json::Value::String(format!("{to:#x}"));
        }
        let hash = rpc_request_local(
            client,
            endpoint,
            "eth_sendTransaction",
            serde_json::json!([transaction]),
        )
        .await
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
        let receipt = wait_for_receipt(client, endpoint, &hash).await;
        assert_eq!(receipt["status"], "0x1", "setup transaction reverted");
    }

    async fn wait_for_receipt(
        client: &reqwest::Client,
        endpoint: &str,
        hash: &str,
    ) -> serde_json::Value {
        for _ in 0..100 {
            if let Ok(value) = rpc_request_local(
                client,
                endpoint,
                "eth_getTransactionReceipt",
                serde_json::json!([hash]),
            )
            .await
                && !value.is_null()
            {
                return value;
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("transaction {hash} was not mined");
    }

    async fn local_call(
        client: &reqwest::Client,
        endpoint: &str,
        to: Address,
        data: &[u8],
    ) -> Vec<u8> {
        let value = rpc_request_local(
            client,
            endpoint,
            "eth_call",
            serde_json::json!([{
                "to": format!("{to:#x}"),
                "data": format!("0x{}", hex::encode(data)),
            }, "latest"]),
        )
        .await
        .unwrap();
        hex::decode(value.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
    }

    async fn local_code_hash(client: &reqwest::Client, endpoint: &str, address: Address) -> B256 {
        let code = rpc_request_local(
            client,
            endpoint,
            "eth_getCode",
            serde_json::json!([format!("{address:#x}"), "latest"]),
        )
        .await
        .unwrap();
        let code = hex::decode(code.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap();
        keccak256(code)
    }

    async fn local_pending_nonce(client: &reqwest::Client, endpoint: &str, wallet: Address) -> u64 {
        let nonce = rpc_request_local(
            client,
            endpoint,
            "eth_getTransactionCount",
            serde_json::json!([format!("{wallet:#x}"), "pending"]),
        )
        .await
        .unwrap();
        parse_rpc_quantity(nonce.as_str().unwrap())
    }

    fn clone_signer(signer: &SigningKey) -> SigningKey {
        SigningKey::from_slice(signer.to_bytes().as_slice()).unwrap()
    }

    async fn wait_for_journal_entry(
        store: &ConfigStore,
        action: TransactionAction,
        status: TransactionStatus,
    ) -> super::TransactionEntry {
        for _ in 0..400 {
            if let Some(contents) = store.read_transaction_journal().unwrap() {
                let state: super::JournalState = serde_json::from_slice(&contents).unwrap();
                if let Some(entry) = state
                    .entries
                    .into_iter()
                    .find(|entry| entry.action == action && entry.status == status)
                {
                    return entry;
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("transaction journal did not reach {status:?} for {action:?}");
    }

    async fn wait_for_journal_entry_for_window(
        store: &ConfigStore,
        node_id: u8,
        action: TransactionAction,
        window_id: u64,
        status: TransactionStatus,
    ) -> super::TransactionEntry {
        tokio::time::timeout(Duration::from_secs(25), async {
            loop {
                if let Some(contents) = store.read_transaction_journal().unwrap() {
                    let state: super::JournalState = serde_json::from_slice(&contents).unwrap();
                    if let Some(entry) = state.entries.into_iter().find(|entry| {
                        entry.node_id == node_id
                            && entry.action == action
                            && entry.window_id == window_id
                    }) {
                        if entry.status == TransactionStatus::MinedReverted {
                            panic!(
                                "{action:?} for window {window_id} reverted: {:?}",
                                entry.outcome
                            );
                        }
                        if entry.status == status {
                            return entry;
                        }
                    }
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "journal did not reach {status:?} for node {node_id} {action:?} window {window_id}"
            )
        })
    }

    async fn wait_for_eligible_window(
        network: &NetworkClient,
        node_id: u8,
        window_id: u64,
    ) -> crate::rpc::ReadSnapshot {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let snapshot = network.snapshot(None).await.unwrap();
                if snapshot.nodes.iter().any(|node| {
                    node.id == node_id
                        && node.state.as_ref().is_some_and(|state| {
                            state.work.window_id == window_id && state.eligible
                        })
                }) {
                    return snapshot;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("node {node_id:02} did not become eligible in window {window_id}")
        })
    }

    async fn wait_for_candidate(
        network: &NetworkClient,
        node_id: u8,
        window_id: u64,
        expected_miner: Address,
    ) -> crate::rpc::ReadSnapshot {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let snapshot = network.snapshot(None).await.unwrap();
                if snapshot.nodes.iter().any(|node| {
                    node.id == node_id
                        && node.state.as_ref().is_some_and(|state| {
                            state.work.window_id == window_id
                                && state
                                    .candidate
                                    .as_ref()
                                    .is_some_and(|candidate| candidate.miner == expected_miner)
                        })
                }) {
                    return snapshot;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("on-chain candidate was not verified for node {node_id:02} window {window_id}")
        })
    }

    async fn wait_for_hash_increase(probe: &MiningProbe, node_id: u8, previous: u64) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while probe.slots[usize::from(node_id - 1)].completed_hashes() <= previous {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("CPU worker hash counter for node {node_id:02} must increase"));
    }

    async fn wait_for_proof_metric(
        probe: &MiningProbe,
        node_id: u8,
        metric: ProofMetric,
        minimum: u64,
    ) {
        tokio::time::timeout(Duration::from_secs(20), async {
            while probe.proof_telemetry.count(node_id, metric) < minimum {
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("proof telemetry {metric:?} for node {node_id:02} did not reach {minimum}")
        });
    }

    async fn wait_for_active_probe(probe: &MiningProbe, node_id: u8, window_id: u64) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let scheduled = probe
                    .schedule
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&usize::from(node_id - 1));
                if scheduled
                    && probe.slots[usize::from(node_id - 1)].active_window_id() == Some(window_id)
                {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("production runtime did not schedule node {node_id:02} window {window_id}")
        });
    }

    async fn wait_for_observer_snapshot(
        updates: &mut tokio::sync::watch::Receiver<ObserverUpdate>,
        minimum_block: u64,
    ) -> crate::rpc::ReadSnapshot {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                updates.changed().await.unwrap();
                let update = { updates.borrow().clone() };
                if let ObserverUpdate::Snapshot(snapshot) = update
                    && snapshot.block.number >= minimum_block
                {
                    return snapshot;
                }
            }
        })
        .await
        .expect("read-only observer did not publish a verified snapshot")
    }

    async fn wait_for_pending_proof(store: &ConfigStore) -> super::TransactionEntry {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(contents) = store.read_transaction_journal().unwrap() {
                    let state: super::JournalState = serde_json::from_slice(&contents).unwrap();
                    if let Some(entry) = state.entries.into_iter().find(|entry| {
                        entry.action == TransactionAction::SubmitProof
                            && entry.status == TransactionStatus::Broadcast
                    }) {
                        return entry;
                    }
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("proof transaction did not reach journaled Broadcast state")
    }

    async fn wait_for_no_unresolved_transactions(store: &ConfigStore) {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let unresolved = store
                    .read_transaction_journal()
                    .unwrap()
                    .map(|contents| {
                        let journal: super::JournalState =
                            serde_json::from_slice(&contents).unwrap();
                        journal
                            .entries
                            .iter()
                            .any(|entry| entry.status.is_unresolved())
                    })
                    .unwrap_or(false);
                if !unresolved {
                    return;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("journaled transaction should settle before the next test action");
    }

    fn first_target_valid_nonce_parallel(
        context: &WorkContext,
        target: U256,
        worker_count: usize,
        nonce_limit: u64,
    ) -> Option<(u128, B256)> {
        let found = std::sync::atomic::AtomicU64::new(u64::MAX);
        std::thread::scope(|scope| {
            for worker_id in 0..worker_count {
                let context = context.clone();
                let found = &found;
                scope.spawn(move || {
                    let hasher = WorkHasher::new(&context).unwrap();
                    let mut nonce = worker_id as u64;
                    while nonce < nonce_limit && found.load(Ordering::Acquire) == u64::MAX {
                        let hash = hasher.hash(u128::from(nonce));
                        if meets_target(hash, target) {
                            let _ = found.compare_exchange(
                                u64::MAX,
                                nonce,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            );
                            break;
                        }
                        nonce = nonce.saturating_add(worker_count as u64);
                    }
                });
            }
        });
        let nonce = found.load(Ordering::Acquire);
        if nonce == u64::MAX {
            return None;
        }
        let nonce = u128::from(nonce);
        let hash = WorkHasher::new(context).unwrap().hash(nonce);
        Some((nonce, hash))
    }

    async fn advance_window_past_expiry(
        rpc: &reqwest::Client,
        endpoint: &str,
        network: &NetworkClient,
        node_id: u8,
        snapshot: &crate::rpc::ReadSnapshot,
    ) {
        let state = snapshot
            .nodes
            .iter()
            .find(|node| node.id == node_id)
            .unwrap()
            .state
            .as_ref()
            .unwrap();
        let expected_window = state.work.window_id;
        let remaining = state
            .work
            .window_expiry_time
            .saturating_sub(snapshot.block.timestamp);
        rpc_request_local(
            rpc,
            endpoint,
            "evm_increaseTime",
            serde_json::json!([remaining.saturating_add(1)]),
        )
        .await
        .unwrap();
        rpc_request_local(rpc, endpoint, "evm_mine", serde_json::json!([]))
            .await
            .unwrap();
        let expired = network.snapshot(None).await.unwrap();
        assert!(
            expired.nodes.iter().any(|node| {
                node.id == node_id
                    && node.state.as_ref().is_some_and(|state| {
                        state.work.window_id == expected_window
                            && expired.block.timestamp > state.work.window_expiry_time
                            && state.finalizable
                            && !state.eligible
                    })
            }),
            "fresh verified canonical snapshot must confirm actual expiry"
        );
    }

    async fn wait_for_verified_reward(
        store: &ConfigStore,
        node_id: u8,
        window_id: u64,
        telemetry: &HistoryTelemetry,
    ) {
        let verified = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Some(contents) = store.read_transaction_journal().unwrap() {
                    let journal: super::JournalState = serde_json::from_slice(&contents).unwrap();
                    if journal.entries.iter().any(|entry| {
                        entry.action == TransactionAction::SubmitProof
                            && entry.node_id == node_id
                            && entry.window_id == window_id
                            && entry.reward_confirmed
                            && entry
                                .reward_outcome
                                .as_deref()
                                .is_some_and(|outcome| outcome.starts_with("reward-paid:"))
                    }) {
                        return;
                    }
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await;
        if verified.is_err() {
            let journal = store.read_transaction_journal().unwrap().unwrap();
            let journal: super::JournalState = serde_json::from_slice(&journal).unwrap();
            let entry = journal.entries.iter().find(|entry| {
                entry.action == TransactionAction::SubmitProof
                    && entry.node_id == node_id
                    && entry.window_id == window_id
            });
            let cursor = entry
                .and_then(|entry| Address::from_str(&entry.contract).ok())
                .and_then(|contract| {
                    journal
                        .reward_scan_cursors
                        .get(&super::reward_scan_key(contract, window_id))
                });
            panic!(
                "reward event for node {node_id} window {window_id} must be verified: entry={:?}, cursor={cursor:?}, anchor={:?}, {}",
                entry.map(|entry| (
                    entry.status,
                    entry.confirmations,
                    entry.reward_outcome.as_deref(),
                    entry.reward_confirmations,
                    entry.reward_block_hash.is_some(),
                )),
                journal.reward_scan_anchor,
                telemetry.format_profile(),
            )
        }
    }

    async fn wait_for_dashboard_mined_reward(
        transaction_state: &Arc<RwLock<TransactionDashboardState>>,
        minimum: U256,
    ) -> U256 {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let mined = transaction_state
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .mined_rewards;
                if mined >= minimum {
                    return mined;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("verified current-session rewards must reach the live dashboard state")
    }

    async fn service_until_mined_reward(
        manager: &mut TransactionManager,
        client: &NetworkClient,
        wallet: Address,
        minimum: U256,
    ) -> U256 {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let snapshot = client.snapshot(Some(wallet)).await.unwrap();
                manager
                    .service_reward_reconciliation(client, &snapshot)
                    .await
                    .unwrap();
                let mined = manager.mined_rewards_total();
                if mined >= minimum {
                    return mined;
                }
                sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("background reward reconciliation must update the current session total")
    }

    async fn submit_local_proof_with_confirmation(
        manager: TransactionManager,
        network: NetworkClient,
        signer: SigningKey,
        submission: ProofSubmission,
        store: &ConfigStore,
        rpc: &reqwest::Client,
        endpoint: &str,
    ) -> (TransactionManager, super::ConfirmedAction) {
        let node_id = submission.node_id;
        let window_id = submission.window_id;
        let submission_task = tokio::spawn(async move {
            let mut manager = manager;
            let result = manager.submit_proof(&network, &signer, submission).await;
            (manager, result)
        });
        let _included = wait_for_journal_entry_for_window(
            store,
            node_id,
            TransactionAction::SubmitProof,
            window_id,
            TransactionStatus::Included,
        )
        .await;
        rpc_request_local(rpc, endpoint, "evm_mine", serde_json::json!([]))
            .await
            .unwrap();
        let (manager, result) = submission_task
            .await
            .expect("proof submission task should join after confirmation");
        (
            manager,
            result.expect("local winning proof should be confirmed"),
        )
    }

    async fn rpc_request_local(
        client: &reqwest::Client,
        endpoint: &str,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let response: serde_json::Value = client
            .post(endpoint)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": method,
                "params": params,
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        if let Some(error) = response.get("error") {
            anyhow::bail!("{method} returned JSON-RPC error: {error}");
        }
        Ok(response["result"].clone())
    }

    fn parse_rpc_quantity(value: &str) -> u64 {
        u64::from_str_radix(value.strip_prefix("0x").unwrap(), 16).unwrap()
    }

    fn abi_uint8_word(value: u8) -> [u8; 32] {
        let mut word = [0_u8; 32];
        word[31] = value;
        word
    }
}
