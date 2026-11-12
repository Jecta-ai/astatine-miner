use crate::{
    cli::{DeviceChoice, MineArgs},
    config::{ConfigStore, parse_inj_wei},
    dashboard::{
        Dashboard, DashboardEventKind, DashboardModel, DashboardNode, DashboardSignal,
        DashboardUpdater, NodeStatus, WindowCountdown,
    },
    deployment::DeploymentManifest,
    diagnostics::DiagnosticBuffer,
    gpu::{
        GPU_BATCH_SIZE, GpuBackendEngine, GpuBatchIdentity, GpuDeviceInfo, PendingGpuDispatch,
        benchmark_cpu_reference,
    },
    proof_telemetry::{ProofMetric, ProofPipelineTelemetry},
    protocol::{WorkContext, WorkHasher, beats_incumbent, meets_target},
    rpc::{BlockSnapshot, NetworkClient, NodeState, ReadSnapshot, is_transient_rpc_error},
    shutdown::{ShutdownSignal, race_with_shutdown},
    startup::StartupProgress,
    transaction::{
        AUTOMATIC_REWARD_FORWARDING_DISABLED, ConfirmedAction, ProofSubmission, RunSessionBudget,
        RunSessionLimitChanged, SessionJournalSnapshot, TransactionAction,
        TransactionActivityState, TransactionDashboardState, TransactionManager,
        TransactionPolicyRefusalKind, is_proof_quote_unavailable, is_stale_transaction_preflight,
        mined_transaction_reverted, transaction_policy_refusal,
    },
    wallet::{selected_address, unlock_selected_interactive},
};
use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result, anyhow, bail};
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io::{self, Write},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{
    sync::{mpsc, watch},
    time,
};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const GENESIS_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);
const REWARD_SCAN_SERVICE_INTERVAL: Duration = Duration::from_millis(250);
const IDLE_INTERVAL: Duration = Duration::from_millis(20);
const NONCE_BATCH_SIZE: usize = GPU_BATCH_SIZE;
const PENDING_PROOF_CANDIDATE_CAPACITY: usize = 9;
const PROOF_WAKE_CAPACITY: usize = 1;
const WORK_EXPIRY_SAFETY_SECS: u64 = 2;
const STALE_PREFLIGHT_RETRY: Duration = Duration::from_secs(1);
const OBSERVER_STALL_TIMEOUT: Duration = Duration::from_secs(45);
// Once a submission has crossed the durable Prepared boundary, shutdown,
// operator stop, or a terminal dashboard failure must not drop the future
// before its single first-broadcast attempt can finish. This grace exceeds the
// eight-second JSON-RPC client timeout plus margin.
const PREPARED_BROADCAST_STOP_GRACE: Duration = Duration::from_secs(12);
const MAX_PROOF_PREFLIGHT_RETRIES: u8 = 2;
const MAX_PROOF_REFRESH_REQUESTS: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
struct HashingContext {
    chain_id: u64,
    contract: Address,
    window_id: u64,
    seed: B256,
    miner: Address,
    header: Vec<u8>,
}

impl HashingContext {
    fn work_context(&self) -> WorkContext {
        WorkContext {
            chain_id: self.chain_id,
            contract: self.contract,
            window_id: self.window_id,
            seed: self.seed,
            miner: self.miner,
            header: self.header.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkFingerprint {
    hashing_context: HashingContext,
    target: U256,
    incumbent: Option<B256>,
    window_expiry_time: u64,
    max_header_length: u32,
}

struct WorkJob {
    fingerprint: WorkFingerprint,
    generation: u64,
    hasher: WorkHasher,
    target: U256,
    incumbent: Option<B256>,
    valid_until: Instant,
}

struct NonceAllocator {
    next: Option<u128>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LocalBestUpdate {
    NewBest,
    NotBetter,
    StaleGeneration,
    ExpiredDeadline,
}

impl Default for NonceAllocator {
    fn default() -> Self {
        Self { next: Some(0) }
    }
}

impl NonceAllocator {
    fn reserve(&mut self, requested: usize) -> Option<(u128, usize)> {
        let start = self.next?;
        let requested = requested as u128;
        let remaining = u128::MAX - start;
        if remaining >= requested {
            self.next = start.checked_add(requested);
            Some((start, requested as usize))
        } else {
            self.next = None;
            Some((start, (remaining + 1) as usize))
        }
    }
}

pub(crate) struct NodeSlot {
    id: u8,
    generation: AtomicU64,
    work: RwLock<Option<Arc<WorkJob>>>,
    suspended_work: Mutex<Option<Arc<WorkJob>>>,
    last_observed_head: Mutex<Option<(u64, B256)>>,
    completed_hashes: AtomicU64,
    nonces: Mutex<NonceAllocator>,
    local_best: Mutex<Option<B256>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ActiveBackend {
    Cpu { threads: usize },
    Gpu(GpuDeviceInfo),
}

impl ActiveBackend {
    fn label(&self) -> &'static str {
        match self {
            Self::Cpu { .. } => "CPU",
            Self::Gpu(_) => "GPU",
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Cpu { threads } => format!("{threads} Threads"),
            Self::Gpu(info) => {
                let backend = if info.backend == "CUDA Driver API" {
                    format!("{} · CUDA · {}", info.name, info.driver_info)
                } else {
                    format!("{} · {}", info.name, info.backend)
                };
                if info.tuned_hashes_per_second == 0 {
                    format!(
                        "{backend} · batch {} · WG{} · CPU verify",
                        info.batch_size, info.workgroup_size
                    )
                } else if info.cpu_comparison_threads > 0 {
                    format!(
                        "{backend} · batch {} · WG{} · auto GPU {:.1}/CPU {:.1} MH/s",
                        info.batch_size,
                        info.workgroup_size,
                        info.tuned_hashes_per_second as f64 / 1_000_000.0,
                        info.cpu_comparison_hashes_per_second as f64 / 1_000_000.0,
                    )
                } else {
                    format!(
                        "{backend} · batch {} · WG{} · {:.2} MH/s · CPU verify",
                        info.batch_size,
                        info.workgroup_size,
                        info.tuned_hashes_per_second as f64 / 1_000_000.0,
                    )
                }
            }
        }
    }
}

fn gpu_is_meaningfully_faster(gpu_hashes_per_second: u64, cpu_hashes_per_second: u64) -> bool {
    u128::from(gpu_hashes_per_second) * 100 > u128::from(cpu_hashes_per_second) * 110
}

impl NodeSlot {
    pub(crate) fn new(id: u8) -> Self {
        Self {
            id,
            generation: AtomicU64::new(0),
            work: RwLock::new(None),
            suspended_work: Mutex::new(None),
            last_observed_head: Mutex::new(None),
            completed_hashes: AtomicU64::new(0),
            nonces: Mutex::new(NonceAllocator::default()),
            local_best: Mutex::new(None),
        }
    }

    fn current_work(&self) -> Option<Arc<WorkJob>> {
        self.current_work_at(Instant::now())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn active_window_id(&self) -> Option<u64> {
        self.current_work()
            .map(|work| work.fingerprint.hashing_context.window_id)
    }

    pub(crate) fn completed_hashes(&self) -> u64 {
        self.completed_hashes.load(Ordering::Relaxed)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn set_test_nonce_start(&self, nonce: u128) {
        *self
            .nonces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            NonceAllocator { next: Some(nonce) };
    }

    fn current_work_at(&self, now: Instant) -> Option<Arc<WorkJob>> {
        let work = self
            .work
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()?;
        (now < work.valid_until).then_some(work)
    }

    fn diagnostic_work(&self) -> (bool, bool, Option<Instant>, Option<u64>) {
        let current = self
            .work
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let active = current
            .as_ref()
            .is_some_and(|work| Instant::now() < work.valid_until);
        if let Some(work) = current {
            return (
                active,
                false,
                Some(work.valid_until),
                Some(work.fingerprint.hashing_context.window_id),
            );
        }
        let suspended = self
            .suspended_work
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        suspended.map_or((false, false, None, None), |work| {
            (
                false,
                true,
                Some(work.valid_until),
                Some(work.fingerprint.hashing_context.window_id),
            )
        })
    }

    fn is_generation_current(&self, generation: u64) -> bool {
        self.generation.load(Ordering::Acquire) == generation
    }

    fn reserve_nonces(&self, requested: usize) -> Option<(u128, usize)> {
        self.nonces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reserve(requested)
    }

    fn update_local_best(
        &self,
        generation: u64,
        valid_until: Instant,
        hash: B256,
    ) -> LocalBestUpdate {
        let mut best = self
            .local_best
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.is_generation_current(generation) {
            return LocalBestUpdate::StaleGeneration;
        }
        if Instant::now() >= valid_until {
            return LocalBestUpdate::ExpiredDeadline;
        }
        if best.is_some_and(|previous| hash >= previous) {
            return LocalBestUpdate::NotBetter;
        }
        *best = Some(hash);
        LocalBestUpdate::NewBest
    }

    fn set_work(
        &self,
        network: &DeploymentManifest,
        miner: Address,
        contract: Address,
        state: Option<&NodeState>,
        block: &BlockSnapshot,
    ) -> Result<bool> {
        self.set_work_at(network, miner, contract, state, block, Instant::now())
    }

    fn set_work_at(
        &self,
        network: &DeploymentManifest,
        miner: Address,
        contract: Address,
        state: Option<&NodeState>,
        block: &BlockSnapshot,
        now: Instant,
    ) -> Result<bool> {
        let head = (block.number, block.hash);
        let head_advanced = {
            let mut last_head = self
                .last_observed_head
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let advanced = last_head.is_some_and(|previous| previous != head);
            *last_head = Some(head);
            advanced
        };
        let next = if let Some(state) = state.filter(|state| state.eligible) {
            if state.work.max_header_length == 0 {
                bail!(
                    "node {} returned a zero-byte maximum header length",
                    self.id
                );
            }
            let hashing_context = HashingContext {
                chain_id: network.chain_id,
                contract,
                window_id: state.work.window_id,
                seed: state.work.seed,
                miner,
                header: Vec::new(),
            };
            let fingerprint = WorkFingerprint {
                hashing_context,
                target: state.work.target,
                incumbent: state
                    .candidate
                    .as_ref()
                    .map(|candidate| candidate.work_hash),
                window_expiry_time: state.work.window_expiry_time,
                max_header_length: state.work.max_header_length,
            };
            Some((
                fingerprint,
                state.work.target,
                state
                    .candidate
                    .as_ref()
                    .map(|candidate| candidate.work_hash),
            ))
        } else {
            None
        };

        let mut current = self
            .work
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((fingerprint, target, incumbent)) = next else {
            let Some(previous) = current.take() else {
                return Ok(false);
            };
            self.generation.fetch_add(1, Ordering::AcqRel);
            *self
                .local_best
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            *self
                .suspended_work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(previous);
            return Ok(true);
        };

        let current_job = current.clone();
        let suspended_job = self
            .suspended_work
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let previous = current_job.as_ref().or(suspended_job.as_ref());
        let context_unchanged = previous.is_some_and(|existing| {
            existing.fingerprint.hashing_context == fingerprint.hashing_context
        });
        let same_expiry = previous.is_some_and(|existing| {
            existing.fingerprint.window_expiry_time == fingerprint.window_expiry_time
        });
        let deadline_source = previous.filter(|_| context_unchanged && same_expiry);

        let remaining = fingerprint
            .window_expiry_time
            .saturating_sub(block.timestamp)
            .saturating_sub(WORK_EXPIRY_SAFETY_SECS);
        let proposed_deadline = now
            .checked_add(Duration::from_secs(remaining))
            .unwrap_or(now);

        if let Some(existing) = current_job.as_ref()
            && existing.fingerprint == fingerprint
        {
            let valid_until = if existing.valid_until > now {
                existing.valid_until.min(proposed_deadline)
            } else if head_advanced {
                proposed_deadline
            } else {
                existing.valid_until
            };
            if valid_until == existing.valid_until {
                return Ok(false);
            }
            let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
            if existing.valid_until <= now && head_advanced {
                *self
                    .local_best
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            }
            *current = Some(Arc::new(WorkJob {
                fingerprint,
                generation,
                hasher: existing.hasher.clone(),
                target,
                incumbent,
                valid_until,
            }));
            *self
                .suspended_work
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
            return Ok(true);
        }

        let hasher = if let Some(previous) = deadline_source {
            previous.hasher.clone()
        } else {
            WorkHasher::new(&fingerprint.hashing_context.work_context())?
        };
        let valid_until = match deadline_source {
            Some(previous) if previous.valid_until > now => {
                previous.valid_until.min(proposed_deadline)
            }
            Some(previous) if !head_advanced => previous.valid_until,
            Some(_) | None => proposed_deadline,
        };

        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        if !context_unchanged {
            *self
                .nonces
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = NonceAllocator::default();
            *self
                .local_best
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
        *current = Some(Arc::new(WorkJob {
            fingerprint,
            generation,
            hasher,
            target,
            incumbent,
            valid_until,
        }));
        *self
            .suspended_work
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        Ok(true)
    }
}

#[derive(Clone, Debug)]
struct ProofFound {
    node_id: u8,
    generation: u64,
    context: HashingContext,
    nonce: u128,
    hash: B256,
    target: U256,
    incumbent: Option<B256>,
    batch_identity: Option<GpuBatchIdentity>,
    queued_at: Instant,
    preflight_retries: u8,
}

#[derive(Clone, Debug)]
struct RefreshPublication {
    epoch: u64,
    sequence: u64,
    snapshot: ReadSnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RefreshRequestIdentity {
    epoch: u64,
    after_sequence: u64,
}

#[derive(Clone, Debug)]
struct PendingProofRefresh {
    proof: ProofFound,
    requested_epoch: u64,
    requested_after_sequence: u64,
    valid_until: Instant,
    refresh_requests: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingProofDecision {
    Waiting,
    RetryQueued,
    Parked,
    SnapshotUnavailable,
    VerifiedStale(ProofRevalidationFailure),
    LocallyExpired,
}

impl PendingProofRefresh {
    fn request_followup_refresh(
        &mut self,
        refresh: &ObserverRefreshHandle,
        latest_publication: Option<&RefreshPublication>,
    ) -> bool {
        if self.refresh_requests < MAX_PROOF_REFRESH_REQUESTS {
            self.refresh_requests += 1;
            let identity = refresh.request_refresh();
            self.requested_epoch = identity.epoch;
            self.requested_after_sequence = identity.after_sequence;
            true
        } else {
            if let Some(publication) = latest_publication {
                // Periodic full snapshots keep this candidate eligible for revalidation,
                // without issuing an unbounded stream of forced RPC requests.
                self.requested_epoch = publication.epoch;
                self.requested_after_sequence = publication.sequence;
            }
            false
        }
    }

    fn on_publication(
        &mut self,
        publication: Option<&RefreshPublication>,
        latest_snapshot_available: bool,
        manifest: &DeploymentManifest,
        wallet: Address,
        now: Instant,
        telemetry: &ProofPipelineTelemetry,
    ) -> PendingProofDecision {
        if now >= self.valid_until {
            return PendingProofDecision::LocallyExpired;
        }
        if !latest_snapshot_available {
            return PendingProofDecision::Waiting;
        }
        let Some(publication) = publication.filter(|publication| {
            publication.epoch >= self.requested_epoch
                && publication.sequence > self.requested_after_sequence
        }) else {
            return PendingProofDecision::Waiting;
        };

        match revalidate_proof_snapshot(
            manifest,
            wallet,
            &publication.snapshot,
            &self.proof,
            now,
            telemetry,
        ) {
            ProofSnapshotValidation::Unavailable => PendingProofDecision::SnapshotUnavailable,
            ProofSnapshotValidation::VerifiedStale(reason) => {
                PendingProofDecision::VerifiedStale(reason)
            }
            ProofSnapshotValidation::Valid
                if self.proof.preflight_retries < MAX_PROOF_PREFLIGHT_RETRIES =>
            {
                self.proof.preflight_retries += 1;
                PendingProofDecision::RetryQueued
            }
            ProofSnapshotValidation::Valid => {
                // Keep the candidate bounded in memory but stop quoting it again. A later
                // verified snapshot may establish that the work changed; local expiry also
                // releases it. Periodic publications reuse the refresh epoch, so correlate
                // parked work using the publication sequence as well. Provider text alone
                // never makes this transition.
                self.requested_epoch = publication.epoch;
                self.requested_after_sequence = publication.sequence;
                PendingProofDecision::Parked
            }
        }
    }
}

enum ProofObserverUpdate<'a> {
    Failed,
    Snapshot {
        publication: Option<&'a RefreshPublication>,
        latest_snapshot_available: bool,
        now: Instant,
    },
}

enum ProofRefreshEventAction {
    NoPending,
    Waiting,
    SnapshotUnavailable,
    RetryQueued,
    VerifiedStale {
        proof: ProofFound,
        reason: ProofRevalidationFailure,
    },
    LocallyExpired {
        proof: ProofFound,
    },
}

struct ProofRefreshTurn {
    action: ProofRefreshEventAction,
    retry_queued_this_snapshot: bool,
}

#[derive(Clone, Copy)]
struct ProofPreflightRetryConditions {
    session_limit_reached: bool,
    authorization_unchanged: bool,
    has_new_unresolved: bool,
    signing_blocked_by_unresolved: bool,
    has_unverified_receipt: bool,
}

fn should_retain_proof_after_preflight_failure(
    error: &anyhow::Error,
    conditions: ProofPreflightRetryConditions,
) -> bool {
    !conditions.session_limit_reached
        && conditions.authorization_unchanged
        && !conditions.has_new_unresolved
        && !conditions.signing_blocked_by_unresolved
        && !conditions.has_unverified_receipt
        && (is_proof_quote_unavailable(error)
            || is_stale_transaction_preflight(error)
            || is_transient_rpc_error(error))
}

#[derive(Default)]
struct ProofRefreshEventLoop {
    pending: Option<PendingProofRefresh>,
}

impl ProofRefreshEventLoop {
    fn retain_after_preflight_failure(
        &mut self,
        proof: ProofFound,
        valid_until: Instant,
        refresh: &ObserverRefreshHandle,
    ) -> RefreshRequestIdentity {
        assert!(self.pending.is_none(), "only one proof may await refresh");
        let identity = refresh.request_refresh();
        self.pending = Some(PendingProofRefresh {
            proof,
            requested_epoch: identity.epoch,
            requested_after_sequence: identity.after_sequence,
            valid_until,
            refresh_requests: 1,
        });
        identity
    }

    fn handle_observer_update(
        &mut self,
        update: ProofObserverUpdate<'_>,
        manifest: &DeploymentManifest,
        wallet: Address,
        refresh: &ObserverRefreshHandle,
        proof_receiver: &ProofInboxReceiver,
        telemetry: &ProofPipelineTelemetry,
    ) -> ProofRefreshTurn {
        let ProofObserverUpdate::Snapshot {
            publication,
            latest_snapshot_available,
            now,
        } = update
        else {
            return ProofRefreshTurn {
                action: if self.pending.is_some() {
                    ProofRefreshEventAction::Waiting
                } else {
                    ProofRefreshEventAction::NoPending
                },
                retry_queued_this_snapshot: false,
            };
        };
        let Some(pending) = self.pending.as_mut() else {
            return ProofRefreshTurn {
                action: ProofRefreshEventAction::NoPending,
                retry_queued_this_snapshot: false,
            };
        };
        let decision = pending.on_publication(
            publication,
            latest_snapshot_available,
            manifest,
            wallet,
            now,
            telemetry,
        );
        let mut turn = ProofRefreshTurn {
            action: ProofRefreshEventAction::Waiting,
            retry_queued_this_snapshot: false,
        };
        match decision {
            PendingProofDecision::Waiting | PendingProofDecision::Parked => {}
            PendingProofDecision::SnapshotUnavailable => {
                let _ = self
                    .pending
                    .as_mut()
                    .is_some_and(|pending| pending.request_followup_refresh(refresh, publication));
                turn.action = ProofRefreshEventAction::SnapshotUnavailable;
            }
            PendingProofDecision::RetryQueued => {
                let proof = self
                    .pending
                    .as_ref()
                    .expect("pending proof must remain present")
                    .proof
                    .clone();
                let queued = proof_receiver.requeue(proof, telemetry);
                let candidate_released = queued || !proof_receiver.sender.wake.is_closed();
                if candidate_released {
                    self.pending = None;
                    turn.retry_queued_this_snapshot = true;
                }
                turn.action = ProofRefreshEventAction::RetryQueued;
            }
            PendingProofDecision::VerifiedStale(reason) => {
                let pending = self
                    .pending
                    .take()
                    .expect("pending proof must remain present");
                turn.action = ProofRefreshEventAction::VerifiedStale {
                    proof: pending.proof,
                    reason,
                };
            }
            PendingProofDecision::LocallyExpired => {
                let pending = self
                    .pending
                    .take()
                    .expect("pending proof must remain present");
                turn.action = ProofRefreshEventAction::LocallyExpired {
                    proof: pending.proof,
                };
            }
        }
        turn
    }

    fn on_timeout(&mut self, now: Instant) -> Option<ProofFound> {
        self.pending
            .as_ref()
            .is_some_and(|pending| now >= pending.valid_until)
            .then(|| {
                self.pending
                    .take()
                    .expect("expired pending proof disappeared")
                    .proof
            })
    }

    fn take_for_spending_limit(&mut self) -> Option<ProofFound> {
        self.pending.take().map(|pending| pending.proof)
    }

    fn take_for_shutdown(&mut self) -> Option<ProofFound> {
        self.pending.take().map(|pending| pending.proof)
    }

    fn can_receive_proof(&self) -> bool {
        self.pending.is_none()
    }

    fn can_finalize(&self, retry_queued_this_snapshot: bool) -> bool {
        self.pending.is_none() && !retry_queued_this_snapshot
    }

    #[cfg(test)]
    fn has_pending(&self) -> bool {
        self.pending.is_some()
    }
}

enum ProofSnapshotValidation {
    Valid,
    Unavailable,
    VerifiedStale(ProofRevalidationFailure),
}

#[derive(Clone)]
struct ProofInboxSender {
    pending: Arc<Mutex<[Option<ProofFound>; PENDING_PROOF_CANDIDATE_CAPACITY]>>,
    wake: mpsc::Sender<()>,
}

struct ProofInboxReceiver {
    pending: Arc<Mutex<[Option<ProofFound>; PENDING_PROOF_CANDIDATE_CAPACITY]>>,
    wake: mpsc::Receiver<()>,
    paused: Arc<AtomicBool>,
    pause_latched: Arc<AtomicBool>,
    sender: ProofInboxSender,
}

fn proof_inbox(initially_paused: bool) -> (ProofInboxSender, ProofInboxReceiver) {
    let pending = Arc::new(Mutex::new(std::array::from_fn(|_| None)));
    let paused = Arc::new(AtomicBool::new(initially_paused));
    let pause_latched = Arc::new(AtomicBool::new(false));
    let (wake, wake_receiver) = mpsc::channel(PROOF_WAKE_CAPACITY);
    let sender = ProofInboxSender {
        pending: Arc::clone(&pending),
        wake,
    };
    (
        sender.clone(),
        ProofInboxReceiver {
            pending,
            wake: wake_receiver,
            paused,
            pause_latched,
            sender,
        },
    )
}

impl ProofInboxSender {
    fn deliver(&self, proof: ProofFound, telemetry: &ProofPipelineTelemetry) -> bool {
        let Some(index) = proof
            .node_id
            .checked_sub(1)
            .map(usize::from)
            .filter(|index| *index < PENDING_PROOF_CANDIDATE_CAPACITY)
        else {
            return false;
        };
        if self.wake.is_closed() {
            telemetry.record(proof.node_id, ProofMetric::QueueReceiverClosed);
            return false;
        }

        let accepted = {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match pending[index].as_ref() {
                None => {
                    pending[index] = Some(proof.clone());
                    true
                }
                Some(existing) => {
                    telemetry.record(proof.node_id, ProofMetric::QueueFullCoalesced);
                    let replace = if existing.context == proof.context {
                        let replace = proof.hash < existing.hash;
                        telemetry.record(
                            proof.node_id,
                            if replace {
                                ProofMetric::QueueReplacedByBetter
                            } else {
                                ProofMetric::QueueCandidateSuperseded
                            },
                        );
                        replace
                    } else {
                        let replace = proof.generation > existing.generation;
                        telemetry.record(
                            proof.node_id,
                            if replace {
                                ProofMetric::QueueReplacedByNewContext
                            } else {
                                ProofMetric::QueueCandidateSuperseded
                            },
                        );
                        replace
                    };
                    if replace {
                        let mut proof = proof.clone();
                        proof.queued_at = existing.queued_at;
                        pending[index] = Some(proof);
                    }
                    replace
                }
            }
        };
        if !accepted {
            return false;
        }
        telemetry.record(proof.node_id, ProofMetric::QueuedCandidates);
        match self.wake.try_send(()) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(())) => {
                telemetry.record(proof.node_id, ProofMetric::QueueWakeCoalesced);
            }
            Err(mpsc::error::TrySendError::Closed(())) => {
                let mut pending = self
                    .pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if pending[index].as_ref().is_some_and(|queued| {
                    queued.node_id == proof.node_id && queued.nonce == proof.nonce
                }) {
                    pending[index] = None;
                }
                telemetry.record(proof.node_id, ProofMetric::QueueReceiverClosed);
                return false;
            }
        }
        true
    }
}

impl ProofInboxReceiver {
    fn has_pending(&self) -> bool {
        !self.paused.load(Ordering::Acquire)
            && self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .any(Option::is_some)
    }

    fn set_paused(&self, paused: bool) {
        let paused = paused || self.pause_latched.load(Ordering::Acquire);
        let was_paused = self.paused.swap(paused, Ordering::AcqRel);
        if was_paused && !paused {
            let _ = self.sender.wake.try_send(());
        }
    }

    fn latch_paused(&self) {
        self.pause_latched.store(true, Ordering::Release);
        self.set_paused(true);
    }

    fn requeue(&self, proof: ProofFound, telemetry: &ProofPipelineTelemetry) -> bool {
        self.sender.deliver(proof, telemetry)
    }

    fn take_next(&self) -> Option<ProofFound> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let index = pending
            .iter()
            .enumerate()
            .filter_map(|(index, proof)| proof.as_ref().map(|proof| (index, proof.queued_at)))
            .min_by_key(|(_, queued_at)| *queued_at)
            .map(|(index, _)| index)?;
        pending[index].take()
    }

    fn drain_pending(&self) -> Vec<ProofFound> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.iter_mut().filter_map(Option::take).collect()
    }

    fn discard_pending(&self, telemetry: &ProofPipelineTelemetry, reason: ProofMetric) {
        for proof in self.drain_pending() {
            telemetry.record(proof.node_id, reason);
        }
    }

    async fn recv(&mut self) -> Option<ProofFound> {
        loop {
            if !self.paused.load(Ordering::Acquire)
                && let Some(proof) = self.take_next()
            {
                return Some(proof);
            }
            self.wake.recv().await?;
        }
    }
}

struct MiningWorkers {
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
    has_gpu_controller: bool,
}

#[derive(Clone)]
struct MiningWorkerContext {
    slots: Arc<Vec<NodeSlot>>,
    schedule: Arc<RwLock<Vec<usize>>>,
    stop: Arc<AtomicBool>,
    cursor: Arc<AtomicUsize>,
    total_hashes: Arc<AtomicU64>,
    proofs: ProofInboxSender,
    telemetry: Arc<ProofPipelineTelemetry>,
}

#[derive(Clone, Copy)]
struct HashedCandidate {
    nonce: u128,
    hash: B256,
    reported_gpu_hash: Option<B256>,
    batch_identity: Option<GpuBatchIdentity>,
}

struct PendingGpuWorkBatch {
    slot_index: usize,
    work: Arc<WorkJob>,
    identity: GpuBatchIdentity,
    pending: PendingGpuDispatch,
}

enum BackendEvent {
    Activated(ActiveBackend),
    FallbackNotice(String),
    Failed(String),
}

struct StartupControl<'a> {
    shutdown: &'a mut ShutdownSignal,
    progress: Option<&'a StartupProgress>,
    new_session_authorized: bool,
}

#[derive(Default)]
struct RuntimeTestOptions {
    #[cfg(test)]
    skip_workers: bool,
    #[cfg(test)]
    pre_trigger_shutdown: bool,
    #[cfg(test)]
    fail_dashboard_start: bool,
    #[cfg(test)]
    fail_reconcile: bool,
    #[cfg(test)]
    preflight_failures: Arc<Mutex<HashMap<u128, anyhow::Error>>>,
    #[cfg(test)]
    lifecycle: Arc<RuntimeLifecycleObservation>,
}

#[cfg(test)]
#[derive(Default)]
pub(crate) struct RuntimeLifecycleObservation {
    pending_proof: AtomicBool,
    proof_receive_allowed: AtomicBool,
    finalization_allowed: AtomicBool,
    snapshot_turns: AtomicUsize,
    observer_failures: AtomicUsize,
    injected_preflight_failures: AtomicUsize,
    terminal_dashboard_failures: AtomicUsize,
}

impl MiningWorkers {
    fn stop_and_join(&mut self) -> bool {
        self.stop.store(true, Ordering::Release);
        let mut failed = false;
        for worker in self.workers.drain(..) {
            if self.has_gpu_controller {
                let deadline = Instant::now() + Duration::from_secs(10);
                while !worker.is_finished() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(10));
                }
                if !worker.is_finished() {
                    eprintln!(
                        "astatine: GPU worker did not stop within 10 seconds; detaching the driver thread"
                    );
                    failed = true;
                    continue;
                }
            }
            failed |= worker.join().is_err();
        }
        failed
    }
}

impl Drop for MiningWorkers {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

#[derive(Clone)]
pub(crate) struct DashboardContext {
    pub(crate) network: crate::cli::Network,
    pub(crate) chain_id: u64,
    pub(crate) address: Address,
    pub(crate) active_backend: Arc<RwLock<ActiveBackend>>,
    pub(crate) spending_limit: U256,
    pub(crate) transaction_mode: bool,
    pub(crate) compute_only: bool,
    pub(crate) workers_started: Arc<AtomicBool>,
    pub(crate) total_hashes: Arc<AtomicU64>,
    pub(crate) selected: HashSet<u8>,
    pub(crate) slots: Arc<Vec<NodeSlot>>,
    pub(crate) schedule: Arc<RwLock<Vec<usize>>>,
    pub(crate) transaction_state: Arc<RwLock<TransactionDashboardState>>,
    pub(crate) pending_sync: Arc<RwLock<HashMap<u8, PendingDashboardSync>>>,
    pub(crate) finalization_state: Arc<RwLock<HashMap<u8, FinalizationState>>>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingDashboardSync {
    window_id: u64,
    receipt_block: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FinalizationState {
    Retrying {
        window_id: u64,
        attempts: u8,
        retry_at: Instant,
        reason: String,
    },
    Blocked {
        window_id: u64,
        reason: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) enum ObserverUpdate {
    Snapshot(ReadSnapshot),
    RpcError { message: String, report: bool },
    GenesisPollError { message: String, report: bool },
    Fatal(String),
}

enum ObserverWake {
    FullRefresh,
    GenesisProbe(Vec<u8>),
}

pub(crate) struct ReadOnlyObserver {
    shutdown: watch::Sender<bool>,
    pub(crate) updates: watch::Receiver<ObserverUpdate>,
    force_refresh: mpsc::Sender<()>,
    refresh_epoch: Arc<AtomicU64>,
    publications: watch::Receiver<Option<RefreshPublication>>,
    refresh_gate: Arc<Mutex<()>>,
    last_publication_at: Arc<Mutex<Instant>>,
    #[cfg(test)]
    test_publications_paused: Arc<AtomicBool>,
    #[cfg(test)]
    test_pause_acknowledged: Arc<AtomicBool>,
    #[cfg(test)]
    test_updates_sender: Arc<Mutex<Option<watch::Sender<ObserverUpdate>>>>,
    #[cfg(test)]
    test_publications_sender: watch::Sender<Option<RefreshPublication>>,
    #[cfg(test)]
    test_publication_sequence: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(test)]
#[derive(Clone)]
pub(crate) struct ObserverTestControls {
    test_publications_paused: Arc<AtomicBool>,
    test_pause_acknowledged: Arc<AtomicBool>,
    last_publication_at: Arc<Mutex<Instant>>,
    test_updates_sender: Arc<Mutex<Option<watch::Sender<ObserverUpdate>>>>,
    publications_sender: watch::Sender<Option<RefreshPublication>>,
    publication_sequence: Arc<AtomicU64>,
    refresh_epoch: Arc<AtomicU64>,
    refresh_gate: Arc<Mutex<()>>,
    task_abort: tokio::task::AbortHandle,
}

#[cfg(test)]
impl ObserverTestControls {
    pub(crate) fn pause_publications(&self) {
        self.test_publications_paused.store(true, Ordering::Release);
    }

    pub(crate) fn resume_publications(&self) {
        self.test_publications_paused
            .store(false, Ordering::Release);
    }

    fn current_refresh_epoch(&self) -> u64 {
        self.refresh_epoch.load(Ordering::Acquire)
    }

    pub(crate) fn pause_acknowledged(&self) -> bool {
        self.test_pause_acknowledged.load(Ordering::Acquire)
    }

    pub(crate) fn backdate_last_publication(&self, age: Duration) {
        *self
            .last_publication_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now() - age;
    }

    pub(crate) fn publish_update(&self, update: ObserverUpdate) {
        if let Some(sender) = self
            .test_updates_sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            sender.send_replace(update);
        }
    }

    fn publish_snapshot_at(&self, epoch: u64, snapshot: ReadSnapshot) -> bool {
        let updates = self
            .test_updates_sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .cloned();
        let Some(updates) = updates else {
            return false;
        };
        let _commit = self
            .refresh_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sequence = self
            .publication_sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |sequence| {
                sequence.checked_add(1)
            })
            .expect("observer publication sequence exhausted")
            + 1;
        self.publications_sender
            .send_replace(Some(RefreshPublication {
                epoch,
                sequence,
                snapshot: snapshot.clone(),
            }));
        updates.send_replace(ObserverUpdate::Snapshot(snapshot));
        *self
            .last_publication_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
        true
    }

    pub(crate) fn inject_fatal_and_stop(&self, message: String) {
        self.publish_update(ObserverUpdate::Fatal(message));
        self.task_abort.abort();
    }

    pub(crate) fn close_and_stop(&self) {
        self.test_updates_sender
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        self.task_abort.abort();
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct MiningProbe {
    pub(crate) slots: Arc<Vec<NodeSlot>>,
    pub(crate) schedule: Arc<RwLock<Vec<usize>>>,
    pub(crate) observer_updates: watch::Receiver<ObserverUpdate>,
    pub(crate) observer_refresh: ObserverRefreshHandle,
    pub(crate) stop_signal: DashboardSignal,
    pub(crate) proof_telemetry: Arc<ProofPipelineTelemetry>,
    pub(crate) cpu_worker_threads: usize,
    pub(crate) active_backend: ActiveBackend,
    #[cfg(test)]
    pub(crate) transaction_state: Arc<RwLock<TransactionDashboardState>>,
    #[cfg(test)]
    pub(crate) history_telemetry: Arc<crate::history_telemetry::HistoryTelemetry>,
    #[cfg(test)]
    pub(crate) session_limit_reached: Arc<AtomicBool>,
    #[cfg(test)]
    pub(crate) worker_stop: Arc<AtomicBool>,
    #[cfg(test)]
    workers_started: Arc<AtomicBool>,
    #[cfg(test)]
    pub(crate) proof_delivery_paused: Arc<AtomicBool>,
    #[cfg(test)]
    pub(crate) proof_processing_gate: watch::Sender<bool>,
    #[cfg(test)]
    pub(crate) observer_test_controls: ObserverTestControls,
    #[cfg(test)]
    pub(crate) observer_monitoring_degraded: Arc<AtomicBool>,
    #[cfg(test)]
    pub(crate) initial_snapshot_unavailable: bool,
    #[cfg(test)]
    test_proof_sender: ProofInboxSender,
    #[cfg(test)]
    test_preflight_failures: Arc<Mutex<HashMap<u128, anyhow::Error>>>,
    #[cfg(test)]
    pub(crate) runtime_lifecycle: Arc<RuntimeLifecycleObservation>,
}

#[cfg(test)]
impl MiningProbe {
    fn schedule_preflight_failure(&self, nonce: u128, error: anyhow::Error) {
        self.test_preflight_failures
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(nonce, error);
    }

    fn inject_proof_with_preflight_failure(&self, proof: ProofFound, error: anyhow::Error) -> bool {
        let nonce = proof.nonce;
        self.schedule_preflight_failure(nonce, error);
        let delivered = self.test_proof_sender.deliver(proof, &self.proof_telemetry);
        if !delivered {
            self.test_preflight_failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&nonce);
        }
        delivered
    }
}

#[derive(Clone)]
pub(crate) struct ObserverRefreshHandle {
    sender: mpsc::Sender<()>,
    epoch: Arc<AtomicU64>,
    publications: watch::Receiver<Option<RefreshPublication>>,
    gate: Arc<Mutex<()>>,
}

impl ObserverRefreshHandle {
    fn request_refresh(&self) -> RefreshRequestIdentity {
        let _commit = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let previous = self
            .epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                epoch.checked_add(1)
            })
            .expect("observer refresh identity exhausted");
        let epoch = previous + 1;
        let after_sequence = self
            .publications
            .borrow()
            .as_ref()
            .map_or(0, |publication| publication.sequence);
        let _ = self.sender.try_send(());
        RefreshRequestIdentity {
            epoch,
            after_sequence,
        }
    }

    pub(crate) fn force_refresh(&self) -> u64 {
        self.request_refresh().epoch
    }

    fn latest_publication(&self) -> Option<RefreshPublication> {
        let _commit = self
            .gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.publications.borrow().clone()
    }
}

impl ReadOnlyObserver {
    pub(crate) fn force_refresh(&self) -> u64 {
        self.refresh_handle().force_refresh()
    }

    fn refresh_handle(&self) -> ObserverRefreshHandle {
        ObserverRefreshHandle {
            sender: self.force_refresh.clone(),
            epoch: Arc::clone(&self.refresh_epoch),
            publications: self.publications.clone(),
            gate: Arc::clone(&self.refresh_gate),
        }
    }

    fn latest_publication(&self) -> Option<RefreshPublication> {
        self.refresh_handle().latest_publication()
    }

    #[cfg(test)]
    fn test_controls(&self) -> ObserverTestControls {
        ObserverTestControls {
            test_publications_paused: Arc::clone(&self.test_publications_paused),
            test_pause_acknowledged: Arc::clone(&self.test_pause_acknowledged),
            last_publication_at: Arc::clone(&self.last_publication_at),
            test_updates_sender: Arc::clone(&self.test_updates_sender),
            publications_sender: self.test_publications_sender.clone(),
            publication_sequence: Arc::clone(&self.test_publication_sequence),
            refresh_epoch: Arc::clone(&self.refresh_epoch),
            refresh_gate: Arc::clone(&self.refresh_gate),
            task_abort: self.task.abort_handle(),
        }
    }

    pub(crate) fn latest_snapshot(&self) -> Option<ReadSnapshot> {
        match &*self.updates.borrow() {
            ObserverUpdate::Snapshot(snapshot) => Some(snapshot.clone()),
            ObserverUpdate::RpcError { .. }
            | ObserverUpdate::GenesisPollError { .. }
            | ObserverUpdate::Fatal(_) => None,
        }
    }

    pub(crate) fn publication_age(&self) -> Duration {
        self.last_publication_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .elapsed()
    }

    pub(crate) async fn stop(&mut self) -> Result<()> {
        self.shutdown.send_replace(true);
        self.task.abort();
        match (&mut self.task).await {
            Ok(()) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error).context("join read-only chain observer"),
        }
    }
}

impl Drop for ReadOnlyObserver {
    fn drop(&mut self) {
        self.shutdown.send_replace(true);
        self.task.abort();
    }
}

#[cfg(test)]
pub(crate) async fn run(store: &ConfigStore, args: MineArgs) -> Result<()> {
    if args.new_session {
        bail!(
            "`--new-session` requires explicit spending authorization through the interactive CLI"
        );
    }
    let mut shutdown = ShutdownSignal::new().context("install shutdown signal handlers")?;
    run_with_session_confirmation(store, args, false, &mut shutdown).await
}

pub(crate) async fn run_with_session_confirmation(
    store: &ConfigStore,
    args: MineArgs,
    new_session_authorized: bool,
    shutdown: &mut ShutdownSignal,
) -> Result<()> {
    if args.new_session && !new_session_authorized {
        bail!("a new spending session requires explicit interactive authorization");
    }
    if args.send_rewards_to.is_some() {
        bail!("{AUTOMATIC_REWARD_FORWARDING_DISABLED}");
    }
    let progress = StartupProgress::start();
    progress.begin("Loading configuration");
    let config = match store.load() {
        Ok(config) => config,
        Err(error) => {
            progress.fail(format!("Configuration loading failed: {error:#}"));
            return Err(error);
        }
    };
    let session = if args.compute_only {
        SessionJournalSnapshot::default()
    } else {
        match crate::transaction::TransactionJournal::inspect_session(store, &config) {
            Ok(session) => session,
            Err(error) => {
                progress.fail(format!("Transaction session inspection failed: {error:#}"));
                return Err(error).context("inspect transaction session before mining");
            }
        }
    };
    if !args.compute_only && session.pending_transition.is_some() {
        progress.fail(
            "An init spending-session change is interrupted; run astatine init to resolve it",
        );
        bail!(
            "an init spending-session change is interrupted; run `astatine init` to resolve it before mining"
        );
    }
    if !args.compute_only && config.network != crate::cli::Network::Testnet {
        progress.fail("Autonomous transaction signing is disabled outside Injective Testnet");
        bail!("autonomous transaction signing is disabled outside Injective Testnet");
    }
    let configured_limit = parse_inj_wei(&config.per_session_spending_limit_inj)?;
    if !args.compute_only && !configured_limit.is_zero() {
        if config.per_run_sessions_enabled() {
            let wallet = selected_address(&config)?;
            if !session
                .per_run_policy_approval
                .as_ref()
                .map(|approval| approval.matches_config(&config, wallet))
                .transpose()?
                .unwrap_or(false)
            {
                bail!(
                    "authenticated per-run spending approval does not match the selected wallet, network, ceiling, or reserve; run `astatine init` to approve the current policy"
                );
            }
        } else if session.per_run_policy_approval.is_some() {
            bail!(
                "journal has an authenticated per-run policy; run `astatine init` to explicitly change authorization modes"
            );
        }
    }
    if unresolved_session_blocks_mining(
        args.compute_only,
        !session.unresolved.is_empty(),
        config.per_run_sessions_enabled(),
    ) {
        progress
            .fail("An unresolved transaction requires read-only recovery; wallet remains locked");
        eprintln!("RECOVERY REQUIRED • WALLET LOCKED • mining paused");
        for entry in &session.unresolved {
            eprintln!(
                "  {} • node {:02} window {} • {}",
                crate::diagnostics::terminal_text(&entry.hash),
                entry.node_id,
                entry.window_id,
                crate::diagnostics::terminal_text(&entry.status)
            );
        }
        bail!(
            "run `astatine recover`; after it completes, start a fresh `astatine mine` process to unlock the wallet"
        );
    }
    progress.complete("Configuration loaded");
    progress.set_network(match config.network {
        crate::cli::Network::Testnet => "Injective EVM Testnet",
        crate::cli::Network::Mainnet => "Injective EVM Mainnet",
    });
    if !args.compute_only && config.network != crate::cli::Network::Testnet {
        progress.fail("Autonomous transaction signing is disabled outside Injective Testnet");
        bail!("autonomous transaction signing is disabled outside Injective Testnet");
    }
    if new_session_authorized
        && (args.compute_only || parse_inj_wei(&config.per_session_spending_limit_inj)?.is_zero())
    {
        bail!("new spending-session authorization requires transaction mode and a positive cap");
    }
    progress.begin("Checking selected wallet");
    if let Err(error) = selected_address(&config) {
        progress.fail(format!("Selected wallet check failed: {error:#}"));
        return Err(error);
    }
    progress.complete("Selected wallet checked");
    progress.begin("Connecting to RPC · validating Chain ID");
    let connected = race_with_shutdown(
        NetworkClient::connect_with_progress(
            config.network,
            config.rpc_override(config.network),
            Some(&progress),
        ),
        shutdown,
    )
    .await?;
    let Some(client) = connected else {
        progress.cancel();
        return Ok(());
    };
    let client = client?;
    run_runtime(
        store,
        config,
        args,
        client,
        None,
        None,
        StartupControl {
            shutdown,
            progress: Some(&progress),
            new_session_authorized,
        },
        RuntimeTestOptions::default(),
    )
    .await
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PaidRunSessionOpenLimits {
    configured_ceiling: U256,
    approved_limit: U256,
}

/// Maps the runtime's saved configured ceiling and approved (possibly reduced)
/// limit onto the argument order expected by `open_paid_per_run_session`.
fn paid_run_session_open_limits(
    configured_limit: U256,
    approved_limit: U256,
) -> PaidRunSessionOpenLimits {
    PaidRunSessionOpenLimits {
        configured_ceiling: configured_limit,
        approved_limit,
    }
}

#[derive(Default)]
struct ReducedLimitPrompt {
    #[cfg(test)]
    scripted_approvals: std::collections::VecDeque<bool>,
}

impl ReducedLimitPrompt {
    #[cfg(test)]
    fn scripted(approvals: Vec<bool>) -> Self {
        Self {
            scripted_approvals: approvals.into(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn approve(
        &mut self,
        startup: Option<&StartupProgress>,
        wallet: Address,
        configured_ceiling: U256,
        confirmed_balance: U256,
        minimum_reserve: U256,
        pending_exposure: U256,
        available: U256,
        suggested: U256,
    ) -> Result<bool> {
        #[cfg(test)]
        if let Some(approved) = self.scripted_approvals.pop_front() {
            return Ok(approved);
        }
        if startup.is_some() {
            prompt_reduced_run_limit(
                wallet,
                configured_ceiling,
                confirmed_balance,
                minimum_reserve,
                pending_exposure,
                available,
                suggested,
                startup,
            )
        } else {
            Ok(false)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_paid_per_run_session(
    store: &ConfigStore,
    config: &crate::config::AppConfig,
    wallet: Address,
    ast_token: Address,
    client: &NetworkClient,
    configured_ceiling: U256,
    mut approved_limit: U256,
    reduced_limit_prompt: &mut ReducedLimitPrompt,
    history_telemetry: Arc<crate::history_telemetry::HistoryTelemetry>,
    startup: Option<&StartupProgress>,
) -> Result<Option<(TransactionManager, U256)>> {
    let minimum_reserve = parse_inj_wei(&config.minimum_reserve_inj)?;
    loop {
        let (session, journal_lock) =
            crate::transaction::TransactionJournal::inspect_session_and_lock(store, config)?;
        if session.pending_transition.is_some() {
            bail!(
                "an interrupted spending-session change must be resolved by `astatine init` before mining"
            );
        }
        let pending_exposure = session
            .pending_exposure_wei
            .as_deref()
            .map(|value| {
                U256::from_str_radix(value, 10).context("journal pending exposure is invalid")
            })
            .transpose()?
            .unwrap_or(U256::ZERO);
        let confirmed_balance = match client.confirmed_balance(wallet).await {
            Ok(balance) => balance,
            Err(error) => {
                drop(journal_lock);
                eprintln!(
                    "ASTATINE — CONFIRMED BALANCE UNAVAILABLE\nUnable to revalidate wallet balance and unresolved liabilities; no paid session was created.\n{}",
                    crate::diagnostics::terminal_text(&format!("{error:#}"))
                );
                if let Some(startup) = startup {
                    startup.cancel();
                }
                return Ok(None);
            }
        };
        let available = confirmed_balance
            .checked_sub(minimum_reserve)
            .and_then(|remaining| remaining.checked_sub(pending_exposure))
            .unwrap_or(U256::ZERO);
        let safe_ceiling = configured_ceiling.min(available);
        if safe_ceiling < approved_limit {
            drop(journal_lock);
            let Some(suggested) = suggested_session_limit(configured_ceiling, safe_ceiling) else {
                print_wallet_needs_funding(
                    wallet,
                    confirmed_balance,
                    minimum_reserve,
                    pending_exposure,
                );
                if let Some(startup) = startup {
                    startup.cancel();
                }
                return Ok(None);
            };
            let accepted = reduced_limit_prompt.approve(
                startup,
                wallet,
                configured_ceiling,
                confirmed_balance,
                minimum_reserve,
                pending_exposure,
                available,
                suggested,
            )?;
            let Some(approved) = approved_session_limit(configured_ceiling, safe_ceiling, accepted)
            else {
                eprintln!(
                    "Locked journal/balance recheck requires a lower session limit; no session was created without approval."
                );
                if let Some(startup) = startup {
                    startup.cancel();
                }
                return Ok(None);
            };
            debug_assert_eq!(approved, suggested);
            approved_limit = approved;
            continue;
        }

        let budget = RunSessionBudget {
            ceiling_wei: configured_ceiling,
            approved_limit_wei: approved_limit,
            confirmed_balance_wei: confirmed_balance,
            minimum_reserve_wei: minimum_reserve,
        };
        match TransactionManager::open_for_per_run_session_with_lock(
            store,
            config,
            wallet,
            ast_token,
            Arc::clone(&history_telemetry),
            journal_lock,
            budget,
        ) {
            Ok(manager) => {
                eprintln!(
                    "Session limit: {} INJ (configured ceiling {} INJ; confirmed balance and unresolved liabilities revalidated under the journal lock).",
                    format_token_units(Some(approved_limit), 18),
                    format_token_units(Some(configured_ceiling), 18),
                );
                return Ok(Some((manager, approved_limit)));
            }
            Err(error) => {
                let Some(changed) = error.downcast_ref::<RunSessionLimitChanged>() else {
                    return Err(error);
                };
                let safe = changed.safe_limit_wei.min(approved_limit);
                let Some(suggested) = suggested_session_limit(configured_ceiling, safe) else {
                    print_wallet_needs_funding(
                        wallet,
                        changed.confirmed_balance_wei,
                        minimum_reserve,
                        changed.pending_exposure_wei,
                    );
                    if let Some(startup) = startup {
                        startup.cancel();
                    }
                    return Ok(None);
                };
                let available = changed
                    .confirmed_balance_wei
                    .checked_sub(minimum_reserve)
                    .and_then(|remaining| remaining.checked_sub(changed.pending_exposure_wei))
                    .unwrap_or(U256::ZERO);
                let accepted = reduced_limit_prompt.approve(
                    startup,
                    wallet,
                    configured_ceiling,
                    changed.confirmed_balance_wei,
                    minimum_reserve,
                    changed.pending_exposure_wei,
                    available,
                    suggested,
                )?;
                let Some(approved) = approved_session_limit(configured_ceiling, safe, accepted)
                else {
                    eprintln!(
                        "Final locked-journal recheck requires a different session limit; no session was created without approval."
                    );
                    if let Some(startup) = startup {
                        startup.cancel();
                    }
                    return Ok(None);
                };
                debug_assert_eq!(approved, suggested);
                approved_limit = approved;
            }
        }
    }
}

#[cfg(test)]
pub(crate) async fn run_with_client(
    store: &ConfigStore,
    config: crate::config::AppConfig,
    args: MineArgs,
    client: NetworkClient,
    supplied_signer: Option<bip32::secp256k1::ecdsa::SigningKey>,
    probe_sender: Option<tokio::sync::oneshot::Sender<MiningProbe>>,
    new_session_authorized: bool,
) -> Result<()> {
    run_with_client_test_options(
        store,
        config,
        args,
        client,
        supplied_signer,
        probe_sender,
        new_session_authorized,
        RuntimeTestOptions::default(),
    )
    .await
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
async fn run_with_client_test_options(
    store: &ConfigStore,
    config: crate::config::AppConfig,
    args: MineArgs,
    client: NetworkClient,
    supplied_signer: Option<bip32::secp256k1::ecdsa::SigningKey>,
    probe_sender: Option<tokio::sync::oneshot::Sender<MiningProbe>>,
    new_session_authorized: bool,
    test_options: RuntimeTestOptions,
) -> Result<()> {
    if new_session_authorized && !args.compute_only && config.per_run_sessions_enabled() {
        let wallet = selected_address(&config)?;
        let snapshot = crate::transaction::TransactionJournal::inspect_session(store, &config)?;
        if !snapshot
            .per_run_policy_approval
            .as_ref()
            .map(|approval| approval.matches_config(&config, wallet))
            .transpose()?
            .unwrap_or(false)
        {
            // Local-runtime tests pass `new_session_authorized` as their explicit
            // owner approval and persist the corresponding policy before startup.
            crate::transaction::TransactionJournal::set_per_run_policy_approval(
                store,
                &config,
                Some(wallet),
            )?;
        }
    }
    let mut shutdown = ShutdownSignal::new().context("install shutdown signal handlers")?;
    #[cfg(test)]
    if test_options.pre_trigger_shutdown {
        shutdown.trigger_for_test(crate::shutdown::ShutdownReason::test_request_reason());
    }
    run_runtime(
        store,
        config,
        args,
        client,
        supplied_signer,
        probe_sender,
        StartupControl {
            shutdown: &mut shutdown,
            progress: None,
            new_session_authorized,
        },
        test_options,
    )
    .await
}

/// A shutdown, operator stop, or terminal dashboard failure must not drop a
/// submission that has already crossed the durable `Prepared` boundary before
/// its single first-broadcast attempt concludes. Wait at most `grace` for that
/// submission, returning early once the shared flag clears because the first
/// broadcast outcome is durable; receipt confirmation may continue for much
/// longer and does not need to delay shutdown. An unresolved liability is never
/// cleared or relabelled here.
async fn await_prepared_submission_with_grace<F>(
    prepared_broadcast_pending: &AtomicBool,
    mut submission: Pin<&mut F>,
    grace: Duration,
) -> Option<F::Output>
where
    F: Future,
{
    if !prepared_broadcast_pending.load(Ordering::Acquire) {
        return None;
    }
    let deadline = time::Instant::now() + grace;
    loop {
        tokio::select! {
            output = submission.as_mut() => return Some(output),
            _ = time::sleep(Duration::from_millis(25)) => {
                if !prepared_broadcast_pending.load(Ordering::Acquire) {
                    return None;
                }
                if time::Instant::now() >= deadline {
                    return None;
                }
            }
        }
    }
}

fn combine_runtime_results(
    inner: Result<()>,
    finalized: Result<Option<&'static str>>,
) -> Result<()> {
    match (inner, finalized) {
        (Ok(()), Ok(message)) => {
            if let Some(message) = message {
                println!("{}", crate::diagnostics::terminal_text(message));
            }
            Ok(())
        }
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Ok(_)) => Err(error),
        (Err(error), Err(cleanup_error)) => {
            Err(error.context(format!("runtime cleanup also failed: {cleanup_error:#}")))
        }
    }
}

struct RuntimeLifecycle {
    transactions: Option<TransactionManager>,
    worker_guard: Option<MiningWorkers>,
    observer: Option<ReadOnlyObserver>,
    dashboard: Option<Dashboard>,
    finalized: bool,
}

impl RuntimeLifecycle {
    fn new() -> Self {
        Self {
            transactions: None,
            worker_guard: None,
            observer: None,
            dashboard: None,
            finalized: false,
        }
    }

    /// Single idempotent finalizer for every post-manager exit path.
    ///
    /// It stops workers, stops the observer, closes the spending session while
    /// preserving unresolved liabilities, updates and restores the dashboard,
    /// and combines cleanup failures with the caller's original error.
    async fn finalize(
        &mut self,
        inner_error: Option<&str>,
        compute_only: bool,
        runtime_started: bool,
        per_run_sessions_enabled: bool,
        diagnostics: &DiagnosticBuffer,
    ) -> Result<Option<&'static str>> {
        if self.finalized {
            return Ok(None);
        }
        self.finalized = true;

        let mut cleanup_error: Option<anyhow::Error> = None;

        if let Some(mut workers) = self.worker_guard.take()
            && workers.stop_and_join()
        {
            report_mining_warning(
                &self.dashboard,
                "Compute worker stopped abnormally or exceeded the bounded shutdown interval.",
            );
        }

        if let Some(mut observer) = self.observer.take()
            && let Err(error) = observer.stop().await
        {
            cleanup_error = Some(match cleanup_error.take() {
                Some(existing) => existing.context(format!(
                    "also failed to stop read-only chain observer: {error:#}"
                )),
                None => error.context("stop read-only chain observer"),
            });
        }

        let stopped_message = if let Some(mut manager) = self.transactions.take() {
            let has_unresolved = manager.journal.has_unresolved();
            if has_unresolved && !per_run_sessions_enabled {
                Some(
                    "Stopped with transaction exposure reserved for read-only recovery. The session remains open in the private journal.",
                )
            } else if let Err(error) = manager.close_session() {
                cleanup_error = Some(match cleanup_error.take() {
                    Some(existing) => existing.context(format!(
                        "also failed to close transaction spending session: {error:#}"
                    )),
                    None => error.context("close transaction spending session"),
                });
                None
            } else if has_unresolved {
                Some(
                    "Stopped paid mining. This invocation's session is closed; unresolved transaction exposure remains reserved in the private journal.",
                )
            } else {
                Some(
                    "Stopped autonomous Testnet mining. Transaction journal retained without private key material.",
                )
            }
        } else if !runtime_started {
            None
        } else if compute_only {
            Some("Stopped compute-only mining. No transactions were signed or sent.")
        } else {
            Some(
                "Stopped mining. No transactions were signed or sent because the session limit is zero.",
            )
        };

        if let Some(error) = inner_error
            && let Some(dashboard) = self.dashboard.as_ref()
        {
            dashboard.update(|model| {
                model.critical_error = Some(error.to_owned());
                model.current_action = None;
            });
        }

        let restore_result = if let Some(mut dashboard) = self.dashboard.take() {
            let result = dashboard.stop().await;
            flush_dashboard_diagnostics(&dashboard);
            result
        } else {
            for message in diagnostics.drain() {
                eprintln!("astatine: {message}");
            }
            Ok(())
        };
        if let Err(error) = restore_result {
            cleanup_error = Some(match cleanup_error.take() {
                Some(existing) => existing.context(format!(
                    "also failed to restore mining dashboard terminal: {error:#}"
                )),
                None => error.context("restore mining dashboard terminal"),
            });
        }

        match cleanup_error {
            Some(error) => Err(error),
            None => Ok(stopped_message),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_runtime(
    store: &ConfigStore,
    config: crate::config::AppConfig,
    args: MineArgs,
    mut client: NetworkClient,
    supplied_signer: Option<bip32::secp256k1::ecdsa::SigningKey>,
    probe_sender: Option<tokio::sync::oneshot::Sender<MiningProbe>>,
    startup_control: StartupControl<'_>,
    test_options: RuntimeTestOptions,
) -> Result<()> {
    #[cfg(not(test))]
    let _ = test_options;
    let StartupControl {
        shutdown,
        progress: startup,
        new_session_authorized,
    } = startup_control;
    let mut shutdown_reason = None;
    let per_run_sessions_enabled = config.per_run_sessions_enabled();
    if args.send_rewards_to.is_some() {
        bail!("{AUTOMATIC_REWARD_FORWARDING_DISABLED}");
    }
    let show_history_profile =
        history_profile_enabled(std::env::var("ASTATINE_HISTORY_PROFILE").ok().as_deref());
    let probe_stop_signal = probe_sender.as_ref().map(|_| DashboardSignal::default());
    #[cfg(test)]
    let (proof_processing_gate, proof_processing_gate_receiver) = if probe_sender.is_some() {
        let (sender, receiver) = watch::channel(true);
        (Some(sender), Some(receiver))
    } else {
        (None, None)
    };
    let proof_telemetry = Arc::new(ProofPipelineTelemetry::default());
    if !args.compute_only && config.network != crate::cli::Network::Testnet {
        bail!("autonomous transaction signing is disabled outside Injective Testnet");
    }
    let address = selected_address(&config)?;
    let configured_limit = parse_inj_wei(&config.per_session_spending_limit_inj)?;
    let mut spending_limit = configured_limit;
    if args.new_session
        && !config.per_run_sessions_enabled()
        && (args.compute_only || spending_limit.is_zero())
    {
        bail!(
            "--new-session requires transaction mode and a positive per-session authorization cap"
        );
    }
    let mut transaction_mode = !args.compute_only && !spending_limit.is_zero();
    let threads = args
        .threads
        .map(NonZeroUsize::get)
        .unwrap_or(config.cpu_threads);
    #[cfg(test)]
    let skip_workers = test_options.skip_workers;
    #[cfg(not(test))]
    let skip_workers = false;
    #[cfg(test)]
    let runtime_lifecycle = Arc::clone(&test_options.lifecycle);
    if threads == 0 || threads > config.cpu_threads || threads > 256 {
        bail!(
            "requested threads ({threads}) must be within the configured CPU budget ({}; max 256)",
            config.cpu_threads
        );
    }
    let selected = selected_nodes(&args.nodes)?;
    if !client.has_mining_deployment() {
        bail!(
            "{} has no verified Astatine mining deployment; mining is disabled",
            network_label(config.network)
        );
    }
    if transaction_mode && !client.can_broadcast() {
        bail!("the verified Testnet primary RPC is unavailable; refusing to sign or broadcast");
    }
    if transaction_mode && !client.verification.token_verified {
        bail!("AST token runtime is not verified; refusing autonomous transaction signing");
    }
    if transaction_mode && per_run_sessions_enabled {
        let initial_journal =
            crate::transaction::TransactionJournal::inspect_session(store, &config)?;
        let pending_exposure = initial_journal
            .pending_exposure_wei
            .as_deref()
            .map(|value| {
                U256::from_str_radix(value, 10).context("journal pending exposure is invalid")
            })
            .transpose()?
            .unwrap_or(U256::ZERO);
        let minimum_reserve = parse_inj_wei(&config.minimum_reserve_inj)?;
        let confirmed_balance = match client.confirmed_balance(address).await {
            Ok(balance) => balance,
            Err(error) => {
                eprintln!(
                    "ASTATINE — CONFIRMED BALANCE UNAVAILABLE\nUnable to verify wallet balance and unresolved liabilities; no paid session was created and no transaction can be signed.\n{}",
                    crate::diagnostics::terminal_text(&format!("{error:#}"))
                );
                if let Some(startup) = startup {
                    startup.cancel();
                }
                return Ok(());
            }
        };
        let available = confirmed_balance
            .checked_sub(minimum_reserve)
            .and_then(|remaining| remaining.checked_sub(pending_exposure))
            .unwrap_or(U256::ZERO);
        if available < configured_limit {
            let Some(suggested) = suggested_session_limit(configured_limit, available) else {
                print_wallet_needs_funding(
                    address,
                    confirmed_balance,
                    minimum_reserve,
                    pending_exposure,
                );
                if let Some(startup) = startup {
                    startup.cancel();
                }
                return Ok(());
            };
            let accepted = if startup.is_some() {
                prompt_reduced_run_limit(
                    address,
                    configured_limit,
                    confirmed_balance,
                    minimum_reserve,
                    pending_exposure,
                    available,
                    suggested,
                    startup,
                )?
            } else {
                eprintln!(
                    "A reduced session limit requires interactive approval; no paid session was created."
                );
                false
            };
            let Some(approved_limit) =
                approved_session_limit(configured_limit, available, accepted)
            else {
                println!("Cancelled. No paid session or signing authority was created.");
                if let Some(startup) = startup {
                    startup.cancel();
                }
                return Ok(());
            };
            debug_assert_eq!(approved_limit, suggested);
            spending_limit = approved_limit;
        }
    }
    transaction_mode = !args.compute_only && !spending_limit.is_zero();
    if let Some(startup) = startup {
        startup.begin("Recovering previous transactions");
    }
    let readonly_recovery = !args.compute_only
        && config.network == crate::cli::Network::Testnet
        && spending_limit.is_zero()
        && match store.read_transaction_journal() {
            Ok(journal) => journal.is_some(),
            Err(error) => {
                if let Some(startup) = startup {
                    startup.fail(format!("Transaction journal could not be read: {error:#}"));
                }
                return Err(error).context("check for a read-only transaction recovery journal");
            }
        };
    let transaction_manager_mode =
        should_open_transaction_manager(args.compute_only, transaction_mode, readonly_recovery);
    let compute_only = args.compute_only;
    let mut runtime_started = false;
    let mut lifecycle = RuntimeLifecycle::new();
    let diagnostics = DiagnosticBuffer::default();
    let inner_result = async {
        let RuntimeLifecycle {
            transactions,
            worker_guard,
            observer,
            dashboard,
            ..
        } = &mut lifecycle;
    if transaction_manager_mode {
        let token = client
            .manifest
            .ast_token
            .as_ref()
            .context("AST token pin is missing from the Testnet manifest")?;
        let ast_token = crate::deployment::parse_address(&token.address)?;
        let manager_result =
            if transaction_mode && config.per_run_sessions_enabled() && new_session_authorized {
                // The opening function takes the saved configured ceiling first and
                // the approved (possibly reduced) limit second.
                let open_limits = paid_run_session_open_limits(configured_limit, spending_limit);
                let mut reduced_limit_prompt = ReducedLimitPrompt::default();
                open_paid_per_run_session(
                    store,
                    &config,
                    address,
                    ast_token,
                    &client,
                    open_limits.configured_ceiling,
                    open_limits.approved_limit,
                    &mut reduced_limit_prompt,
                    client.history_telemetry(),
                    startup,
                )
                .await
            } else {
                TransactionManager::open_with_session_policy(
                    store,
                    &config,
                    address,
                    ast_token,
                    client.history_telemetry(),
                    new_session_authorized,
                    args.new_session,
                )
                .map(|manager| Some((manager, spending_limit)))
            };
        let (manager, approved_limit) = match manager_result {
            Ok(Some((manager, approved_limit))) => (manager, approved_limit),
            Ok(None) => return Ok(()),
            Err(error) => {
                if let Some(startup) = startup {
                    startup.fail(format!(
                        "Transaction journal could not be opened: {error:#}"
                    ));
                }
                return Err(error).context("open transaction journal for startup recovery");
            }
        };
        *transactions = Some(manager);
        let manager = transactions
            .as_mut()
            .expect("transaction manager was just assigned");
        if config.per_run_sessions_enabled() && transaction_mode && new_session_authorized {
            spending_limit = approved_limit;
        }
        // The test probe is only supplied by local-runtime tests. Production CLI
        // entry points refuse unresolved startup sessions and route them to the
        // dedicated read-only `astatine recover` command.
        if unresolved_session_blocks_mining(
            args.compute_only,
            manager.journal.has_unresolved(),
            config.per_run_sessions_enabled(),
        ) && probe_sender.is_none()
        {
            let unresolved = manager.journal.unresolved_transactions();
            if let Some(startup) = startup {
                startup.fail(
                    "An unresolved transaction appeared during startup; wallet remains locked",
                );
            }
            eprintln!("RECOVERY REQUIRED • WALLET LOCKED • mining paused");
            for entry in unresolved {
                eprintln!(
                    "  {} • node {:02} window {} • {}",
                    crate::diagnostics::terminal_text(&entry.hash),
                    entry.node_id,
                    entry.window_id,
                    crate::diagnostics::terminal_text(&entry.status)
                );
            }
            bail!(
                "run `astatine recover`; after it completes, start a fresh `astatine mine` process to unlock the wallet"
            );
        }
        manager.configure_reward_forwarding(args.send_rewards_to)?;
        manager.set_proof_telemetry(Arc::clone(&proof_telemetry));
        #[cfg(test)]
        if test_options.fail_reconcile {
            let error = anyhow!("test-injected reconcile failure");
            if let Some(startup) = startup {
                startup.fail(format!("Transaction recovery failed: {error:#}"));
            }
            return Err(error).context("recover previous Testnet transactions");
        }
        match race_with_shutdown(manager.reconcile(&client), shutdown).await? {
            Some(Ok(())) => {
                let legacy = manager.legacy_unverified_settled_count()?;
                if legacy > 0 {
                    let message = format!(
                        "{legacy} historical transaction settlement(s) retain their recorded costs but predate RC1 trusted-RPC processing"
                    );
                    if let Some(startup) = startup {
                        startup.note(message);
                    } else {
                        eprintln!("{message}");
                    }
                }
            }
            Some(Err(error)) => {
                if let Some(startup) = startup {
                    startup.fail(format!("Transaction recovery failed: {error:#}"));
                }
                return Err(error).context("recover previous Testnet transactions");
            }
            None => {
                if let Some(startup) = startup {
                    startup.cancel();
                }
                return Ok(());
            }
        }
    }
    if let Some(manager) = transactions.as_mut() {
        manager.set_shutdown_request(shutdown.request());
    }
    if let Some(startup) = startup {
        if transaction_manager_mode {
            startup.complete("Transaction recovery complete");
        } else {
            startup.complete("No previous transactions to recover");
        }
        if let Some(manager) = transactions.as_ref()
            && let Some(profile) =
                optional_history_profile(show_history_profile, || manager.history_profile_line())
        {
            startup.note(profile);
        }
    }
    let initial_session_limit_reached = if transaction_mode {
        transactions
            .as_ref()
            .map(TransactionManager::remaining_authorization_below_submission_fee)
            .transpose()?
            .unwrap_or(false)
    } else {
        false
    };
    let session_limit_reached = Arc::new(AtomicBool::new(initial_session_limit_reached));
    let signing_ready = transactions
        .as_ref()
        .is_some_and(|manager| !manager.signing_blocked_by_unresolved());
    if transactions
        .as_ref()
        .is_some_and(|manager| manager.journal.has_unresolved())
    {
        if per_run_sessions_enabled {
            eprintln!(
                "An unresolved or underconfirmed transaction is being recovered read-only. Its maximum exposure remains reserved; this run may sign only with a distinct pending nonce and sufficient balance and cap."
            );
        } else {
            eprintln!(
                "An unresolved or underconfirmed transaction is being recovered. No further transactions will be signed until it settles; maximum exposure remains reserved."
            );
        }
    }
    let mut supplied_signer = supplied_signer;
    let signer = if initial_session_limit_reached {
        if let Some(startup) = startup {
            startup.note(
                "Session limit is below the 0.003 INJ proof fee; compute workers will not start",
            );
        }
        None
    } else if transaction_mode {
        if let Some(signer) = supplied_signer.take() {
            Some(signer)
        } else if signing_ready {
            if let Some(startup) = startup {
                startup.begin("Unlocking wallet");
                match unlock_result(|| {
                    crate::wallet::unlock_selected_interactive_with_progress(
                        store, &config, startup,
                    )
                }) {
                    Ok(UnlockOutcome::Unlocked(signer)) => {
                        startup.complete("Wallet unlocked");
                        Some(signer)
                    }
                    Ok(UnlockOutcome::Cancelled) => {
                        startup.cancel();
                        return Ok(());
                    }
                    Err(error) => {
                        startup.fail(format!("Wallet unlock failed: {error:#}"));
                        return Err(error);
                    }
                }
            } else {
                match unlock_result(|| unlock_selected_interactive(store, &config))? {
                    UnlockOutcome::Unlocked(signer) => Some(signer),
                    UnlockOutcome::Cancelled => return Ok(()),
                }
            }
        } else {
            if let Some(startup) = startup {
                startup.note("Wallet unlock deferred until previous transaction recovery settles.");
            }
            None
        }
    } else {
        if let Some(startup) = startup {
            startup.note("Wallet unlock skipped because transaction signing is disabled.");
        }
        None
    };
    if signer
        .as_ref()
        .is_some_and(|signer| crate::wallet::signer_address(signer) != address)
    {
        if let Some(startup) = startup {
            startup.fail("Unlocked signer does not match the selected wallet");
        }
        bail!("unlocked signer does not match the selected wallet");
    }
    let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
    let schedule = Arc::new(RwLock::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(initial_session_limit_reached));
    let cursor = Arc::new(AtomicUsize::new(0));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let active_backend = Arc::new(RwLock::new(ActiveBackend::Cpu { threads }));
    let transaction_state = Arc::new(RwLock::new(initial_transaction_dashboard_state(
        transactions.as_ref(),
        &diagnostics,
    )));
    let dashboard_context = DashboardContext {
        network: client.manifest.network,
        chain_id: client.manifest.chain_id,
        address,
        active_backend: Arc::clone(&active_backend),
        spending_limit,
        transaction_mode,
        compute_only: args.compute_only,
        workers_started: Arc::new(AtomicBool::new(false)),
        total_hashes: Arc::clone(&total_hashes),
        selected: selected.clone(),
        slots: Arc::clone(&slots),
        schedule: Arc::clone(&schedule),
        transaction_state: Arc::clone(&transaction_state),
        pending_sync: Arc::new(RwLock::new(HashMap::new())),
        finalization_state: Arc::new(RwLock::new(HashMap::new())),
    };
    client.set_diagnostics(diagnostics.clone());
    if let Some(manager) = transactions.as_mut() {
        manager.set_diagnostics(diagnostics.clone());
    }
    if let Some(startup) = startup {
        startup.begin("Loading latest mining work");
    }
    let mut terminal_startup_monitoring_error = None;
    let snapshot = match race_with_shutdown(client.snapshot(Some(address)), shutdown).await? {
        Some(Ok(snapshot)) => snapshot,
        Some(Err(error)) if initial_session_limit_reached => {
            let message = format!(
                "Initial read-only snapshot unavailable; no verified snapshot is available; mining remains stopped: {error:#}"
            );
            if let Some(startup) = startup {
                startup.note(message.clone());
            }
            terminal_startup_monitoring_error = Some(message.clone());
            unavailable_read_snapshot(&message)
        }
        Some(Err(error)) => {
            if let Some(startup) = startup {
                startup.fail(format!("Initial mining snapshot failed: {error:#}"));
            }
            return Err(error).context("load initial verified mining snapshot");
        }
        None => {
            if let Some(startup) = startup {
                startup.cancel();
            }
            return Ok(());
        }
    };
    let changed = match update_slots(
        &slots,
        &schedule,
        &client.manifest,
        address,
        &selected,
        &snapshot,
    ) {
        Ok(changed) => changed,
        Err(error) => {
            if let Some(startup) = startup {
                startup.fail(format!(
                    "Initial mining work could not be scheduled: {error:#}"
                ));
            }
            return Err(error).context("schedule initial verified mining work");
        }
    };
    #[cfg(test)]
    for slot in slots.iter() {
        if let Some(work) = slot.current_work()
            && let Some(nonce) = client.take_test_proof_nonce_start(
                slot.id,
                work.fingerprint.hashing_context.window_id,
                work.fingerprint.hashing_context.seed,
            )
        {
            slot.set_test_nonce_start(nonce);
        }
    }
    if let Some(startup) = startup {
        if terminal_startup_monitoring_error.is_some() {
            startup.complete("Initial snapshot unavailable; terminal read-only monitor is active");
        } else {
            startup.complete(format!(
                "Latest mining work loaded · block #{}",
                snapshot.block.number
            ));
        }
        if transactions.is_some() {
            startup.begin("Scheduling historical reward verification");
        }
    }
    if let Some(manager) = transactions.as_mut() {
        match manager
            .service_reward_reconciliation(&client, &snapshot)
            .await
        {
            Ok(scheduled) => {
                if let Some(startup) = startup {
                    startup.complete(if !client.verification.token_verified {
                        "Reward history waits for verified AST token"
                    } else if scheduled {
                        "Historical reward verification scheduled; mining continues"
                    } else {
                        "No pending historical reward evidence"
                    });
                }
            }
            Err(error) => {
                if let Some(startup) = startup {
                    startup.fail(format!(
                        "Reward reconciliation scheduling failed: {error:#}"
                    ));
                }
                return Err(error).context("schedule historical reward verification");
            }
        }
    }
    let proof_delivery_paused = transaction_mode
        && (session_limit_reached.load(Ordering::Acquire)
            || signer.is_none()
            || transactions
                .as_ref()
                .is_some_and(|manager| manager.signing_blocked_by_unresolved()));
    let (proof_sender, mut proof_receiver) = proof_inbox(proof_delivery_paused);
    if session_limit_reached.load(Ordering::Acquire) {
        proof_receiver.latch_paused();
    }
    let worker_context = MiningWorkerContext {
        slots: Arc::clone(&slots),
        schedule: Arc::clone(&schedule),
        stop: Arc::clone(&stop),
        cursor: Arc::clone(&cursor),
        total_hashes: Arc::clone(&total_hashes),
        proofs: proof_sender.clone(),
        telemetry: Arc::clone(&proof_telemetry),
    };
    if let Some(startup) = startup {
        startup.begin(if initial_session_limit_reached {
            "Checking terminal session authorization"
        } else {
            match args.device {
                DeviceChoice::Cpu => "Preparing CPU mining workers",
                DeviceChoice::Gpu => "Initializing and self-testing physical GPU",
                DeviceChoice::Auto => "Detecting and self-testing physical GPU",
            }
        });
    }
    *worker_guard = Some(MiningWorkers {
        stop: Arc::clone(&stop),
        workers: Vec::new(),
        has_gpu_controller: false,
    });
    let worker_guard = worker_guard
        .as_mut()
        .expect("worker guard was just initialized");
    let mut backend_event_receiver = None;
    if initial_session_limit_reached {
        stop.store(true, Ordering::Release);
        if let Some(startup) = startup {
            startup.complete("Session limit reached; compute workers were not started");
        }
    } else if skip_workers {
        if let Some(startup) = startup {
            startup.complete("Test runtime started without compute workers");
        }
    } else {
        match args.device {
            DeviceChoice::Cpu => {
                worker_guard.workers = start_cpu_worker_threads(threads, worker_context.clone())
                    .inspect_err(|error| {
                        if let Some(startup) = startup {
                            startup.fail(format!("Could not start CPU mining workers: {error:#}"));
                        }
                    })?;
                if let Some(startup) = startup {
                    startup.complete(format!("CPU workers ready · {threads} thread(s)"));
                }
            }
            DeviceChoice::Gpu | DeviceChoice::Auto => {
                if let Some(startup) = startup {
                    startup.update("GPU initialization includes a real WGSL SHA-256d self-test");
                }
                let (events, receiver) = mpsc::unbounded_channel();
                backend_event_receiver = Some(receiver);
                let controller_context = worker_context.clone();
                worker_guard.has_gpu_controller = true;
                let controller = thread::Builder::new()
                    .name("astatine-gpu-controller".to_owned())
                    .spawn(move || {
                        gpu_worker_controller(args.device, threads, controller_context, events);
                    })
                    .context("start GPU backend controller")?;
                worker_guard.workers.push(controller);

                let initial_event = tokio::select! {
                    event = receive_backend_event(&mut backend_event_receiver) => event,
                    signal = shutdown.recv() => {
                        if let Err(error) = signal {
                            report_mining_warning(&None, format!("shutdown signal handler failed: {error}"));
                        }
                        stop.store(true, Ordering::Release);
                        if let Some(startup) = startup { startup.cancel(); }
                        return Ok(());
                    }
                };
                match initial_event {
                    Some(BackendEvent::Activated(backend)) => {
                        *active_backend
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = backend.clone();
                        if let Some(startup) = startup {
                            startup.complete(match &backend {
                            ActiveBackend::Cpu { threads } if args.device == DeviceChoice::Auto => {
                                format!(
                                    "Auto selected CPU by measured throughput · {threads} thread(s)"
                                )
                            }
                            ActiveBackend::Cpu { threads } => {
                                format!("CPU fallback ready · {threads} thread(s)")
                            }
                            ActiveBackend::Gpu(info) => {
                                format!(
                                    "GPU self-test passed · {} · {} · batch {} · WG{}",
                                    info.name, info.backend, info.batch_size, info.workgroup_size
                                )
                            }
                        });
                        }
                    }
                    Some(BackendEvent::FallbackNotice(reason)) => {
                        diagnostics.push(format!("{reason}; using CPU fallback."));
                        *active_backend
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            ActiveBackend::Cpu { threads };
                        if let Some(startup) = startup {
                            startup.complete(format!("CPU fallback ready · {threads} thread(s)"));
                        }
                    }
                    Some(BackendEvent::Failed(message)) => {
                        stop.store(true, Ordering::Release);
                        if let Some(startup) = startup {
                            startup.fail(message.clone());
                        }
                        bail!("{message}");
                    }
                    None => {
                        stop.store(true, Ordering::Release);
                        let error = anyhow!("GPU backend stopped before initialization completed");
                        if let Some(startup) = startup {
                            startup.fail(format!("{error:#}"));
                        }
                        return Err(error);
                    }
                }
            }
        }
    }
    drop(proof_sender);
    dashboard_context.workers_started.store(
        !initial_session_limit_reached && !skip_workers,
        Ordering::Release,
    );
    if let Some(startup) = startup
        && !initial_session_limit_reached
    {
        startup.miner_ready();
    }
    let mut model = dashboard_model(&dashboard_context, &snapshot, Instant::now());
    if initial_session_limit_reached {
        model.snapshot_ready = terminal_startup_monitoring_error.is_none();
        model.monitoring_error = terminal_startup_monitoring_error.clone();
        model.latch_session_limit();
    }
    #[cfg(test)]
    if test_options.fail_dashboard_start {
        let error = anyhow!("test-injected dashboard start failure");
        if let Some(startup) = startup {
            startup.fail(format!("Mining dashboard could not start: {error:#}"));
        }
        return Err(error).context("initialize mining dashboard terminal");
    }
    *dashboard = match Dashboard::start(model, Arc::clone(&total_hashes), diagnostics.clone()) {
        Ok(dashboard) => dashboard,
        Err(error) => {
            if let Some(startup) = startup {
                startup.fail(format!("Mining dashboard could not start: {error:#}"));
            }
            return Err(error).context("initialize mining dashboard terminal");
        }
    };
    if let Some(dashboard) = dashboard.as_ref() {
        let diagnostics = dashboard.diagnostics();
        client.set_diagnostics(diagnostics.clone());
        if let Some(manager) = transactions.as_mut() {
            manager.set_diagnostics(diagnostics);
        }
    }
    let session_limit_control = transaction_mode.then(|| SessionLimitRuntimeControl {
        session_limit_reached: Arc::clone(&session_limit_reached),
        worker_stop: Arc::clone(&stop),
        total_hashes: Arc::clone(&total_hashes),
        proof_paused: Arc::clone(&proof_receiver.paused),
        proof_pause_latched: Arc::clone(&proof_receiver.pause_latched),
    });
    connect_transaction_dashboard(
        transactions,
        dashboard,
        Arc::clone(&transaction_state),
        session_limit_control,
    )?;
    let dashboard_updater = dashboard.as_ref().map(Dashboard::updater);
    let observer_monitoring_degraded = Arc::new(AtomicBool::new(false));
    let mut terminal_monitoring_error = None;
    refresh_dashboard(dashboard_updater.as_ref(), &dashboard_context, &snapshot);
    if let Some(error) = terminal_startup_monitoring_error.clone() {
        report_terminal_monitoring_degraded(
            dashboard,
            dashboard_updater.as_ref(),
            &observer_monitoring_degraded,
            &mut terminal_monitoring_error,
            error,
        );
    }
    if !client.verification.token_verified {
        report_mining_warning(
            dashboard,
            "AST token runtime pin is unavailable; mining proofs can still be computed, but AST balance is not trusted.",
        );
    }
    if dashboard.is_none() {
        for message in diagnostics.drain() {
            eprintln!("astatine: {message}");
        }
        if session_limit_reached.load(Ordering::Acquire) {
            println!("SESSION LIMIT REACHED • Press Ctrl+C to exit and run astatine mine again");
        } else if !args.compute_only && spending_limit.is_zero() {
            println!(
                "Per-session spending limit is zero; autonomous signing is disabled. Hashing continues without submissions or finalizations."
            );
        } else {
            print_startup(
                &client,
                address,
                &active_backend,
                &snapshot,
                &slots,
                &selected,
                changed,
            );
        }
    }
    *observer = Some(start_read_only_observer(
        client.clone(),
        dashboard_context.clone(),
        snapshot.clone(),
        dashboard_updater.clone(),
        diagnostics.clone(),
    ));
    let observer = observer
        .as_mut()
        .expect("read-only observer was just initialized");
    let mut observed_updates = observer.updates.clone();
    let _ = observed_updates.borrow_and_update();
    observer.force_refresh();
    if let Some(probe_sender) = probe_sender {
        let _ = probe_sender.send(MiningProbe {
            slots: Arc::clone(&slots),
            schedule: Arc::clone(&schedule),
            observer_updates: observer.updates.clone(),
            observer_refresh: observer.refresh_handle(),
            stop_signal: probe_stop_signal
                .as_ref()
                .expect("test stop signal must be initialized")
                .clone(),
            proof_telemetry: Arc::clone(&proof_telemetry),
            cpu_worker_threads: match active_backend
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
            {
                ActiveBackend::Cpu { threads } => threads,
                ActiveBackend::Gpu(_) => 0,
            },
            active_backend: active_backend
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            #[cfg(test)]
            transaction_state: Arc::clone(&transaction_state),
            #[cfg(test)]
            history_telemetry: client.history_telemetry(),
            #[cfg(test)]
            session_limit_reached: Arc::clone(&session_limit_reached),
            #[cfg(test)]
            worker_stop: Arc::clone(&stop),
            #[cfg(test)]
            workers_started: Arc::clone(&dashboard_context.workers_started),
            #[cfg(test)]
            proof_delivery_paused: Arc::clone(&proof_receiver.paused),
            #[cfg(test)]
            proof_processing_gate: proof_processing_gate
                .clone()
                .expect("test proof-processing gate must be initialized"),
            #[cfg(test)]
            observer_test_controls: observer.test_controls(),
            #[cfg(test)]
            observer_monitoring_degraded: Arc::clone(&observer_monitoring_degraded),
            #[cfg(test)]
            initial_snapshot_unavailable: terminal_startup_monitoring_error.is_some(),
            #[cfg(test)]
            test_proof_sender: worker_context.proofs.clone(),
            #[cfg(test)]
            test_preflight_failures: Arc::clone(&test_options.preflight_failures),
            #[cfg(test)]
            runtime_lifecycle: Arc::clone(&test_options.lifecycle),
        });
    }

    let mut progress_ticker = time::interval(PROGRESS_INTERVAL);
    progress_ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    progress_ticker.tick().await;
    let mut reward_scan_ticker = time::interval(REWARD_SCAN_SERVICE_INTERVAL);
    reward_scan_ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    reward_scan_ticker.tick().await;
    let mut last_progress = time::Instant::now();
    let mut last_snapshot = observer.latest_snapshot().unwrap_or(snapshot);
    let mut fatal_error = None;
    let mut budget_exhausted = false;
    let mut observer_updates_open = true;
    let mut proof_receiver_open = true;
    let mut stale_proof_warning_window = HashMap::<u8, u64>::new();
    let mut proof_refresh = ProofRefreshEventLoop::default();
    let dashboard_signal = dashboard
        .as_ref()
        .map(Dashboard::signal)
        .or_else(|| probe_stop_signal.clone());

    runtime_started = true;
    'mining_loop: loop {
        #[cfg(test)]
        let proof_processing_gate_open = proof_processing_gate_receiver
            .as_ref()
            .is_none_or(|gate| !*gate.borrow());
        #[cfg(not(test))]
        let proof_processing_gate_open = true;
        tokio::select! {
            // Fresh chain observations must not starve behind a continuously-ready proof inbox.
            biased;
            signal = shutdown.recv() => {
                match signal {
                    Ok(reason) => shutdown_reason = Some(reason),
                    Err(error) => report_mining_warning(
                        dashboard,
                        format!("shutdown signal handler failed: {error}"),
                    ),
                }
                break;
            }
            event = wait_for_dashboard_event(dashboard_signal.clone()) => {
                match event {
                    DashboardEventKind::StopRequested => break,
                    DashboardEventKind::Failure(error) => {
                        if session_limit_reached.load(Ordering::Acquire) {
                            // Keep listening: the operator may stop after this
                            // terminal failure has already been consumed.
                            let message = format!(
                                "terminal dashboard failed; paid mining remains stopped until Ctrl+C: {error}"
                            );
                            report_terminal_dashboard_failure(dashboard, message);
                            #[cfg(test)]
                            runtime_lifecycle
                                .terminal_dashboard_failures
                                .fetch_add(1, Ordering::AcqRel);
                            continue 'mining_loop;
                        } else {
                            fatal_error = Some(anyhow!("dashboard failed: {error}"));
                            break;
                        }
                    }
                }
            }
            update = observed_updates.changed(), if observer_updates_open => {
                if update.is_err() {
                    if session_limit_reached.load(Ordering::Acquire) {
                        observer_updates_open = false;
                        report_terminal_monitoring_degraded(
                            dashboard,
                            dashboard_updater.as_ref(),
                            &observer_monitoring_degraded,
                            &mut terminal_monitoring_error,
                            format!(
                                "Read-only observer channel closed — mining remains stopped; {}",
                                snapshot_freshness_description(&last_snapshot, "is stale")
                            ),
                        );
                        continue 'mining_loop;
                    }
                    fatal_error = Some(anyhow!("read-only chain observer stopped unexpectedly"));
                    break;
                }
                let update = take_observer_update(&mut observed_updates);
                match update {
                    ObserverUpdate::Snapshot(snapshot) => {
                        if session_limit_reached.load(Ordering::Acquire) {
                            clear_terminal_monitoring_degraded(
                                dashboard_updater.as_ref(),
                                &observer_monitoring_degraded,
                                &mut terminal_monitoring_error,
                            );
                        }
                        let mut snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                        // Reward reconciliation must remain live under proof-inbox pressure.
                        // The service only harvests completed scans or schedules background work;
                        // it does not wait on in-flight RPC requests.
                        if let Some(manager) = transactions.as_mut()
                            && let Err(error) = manager
                                .service_reward_reconciliation(&client, &snapshot)
                                .await
                        {
                            // Background RPC/scan failures are deferred inside the reward
                            // service; an error here is a journal/cursor integrity or
                            // persistence failure and must remain fail-closed.
                            fatal_error = Some(error.context("service historical reward verification"));
                            break 'mining_loop;
                        }
                        if let Some(manager) = transactions.as_mut()
                            && let Err(error) = manager
                                .monitor_at_snapshot(&client, &snapshot.block)
                                .await
                        {
                            // Receipt and canonical-RPC failures are retained as unresolved
                            // exposure by the monitor; errors escaping it are local journal
                            // integrity or persistence failures, which remain fail-closed.
                            fatal_error = Some(error.context("monitor transaction finality and reorg state"));
                            break;
                        }
                        if transaction_mode
                            && let Some(manager) = transactions.as_ref()
                        {
                            match manager.budget_remaining() {
                                Ok(remaining) => budget_exhausted |= remaining.is_zero(),
                                Err(error) => {
                                    fatal_error = Some(error);
                                    break;
                                }
                            }
                        }
                        if budget_exhausted {
                            proof_receiver
                                .discard_pending(&proof_telemetry, ProofMetric::RefusedSpendingLimit);
                        }
                        proof_receiver.set_paused(
                            transaction_mode
                                && (signer.is_none()
                                    || transactions
                                        .as_ref()
                                        .is_some_and(|manager| manager.signing_blocked_by_unresolved())),
                        );
                        snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                        if session_limit_reached.load(Ordering::Acquire) {
                            proof_receiver.latch_paused();
                            proof_receiver.discard_pending(
                                &proof_telemetry,
                                ProofMetric::RefusedSpendingLimit,
                            );
                            if let Some(proof) = proof_refresh.take_for_spending_limit() {
                                proof_telemetry.record(
                                    proof.node_id,
                                    ProofMetric::RefusedSpendingLimit,
                                );
                            }
                            last_snapshot = snapshot;
                            continue 'mining_loop;
                        }
                        snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                        if budget_exhausted
                            && let Some(proof) = proof_refresh.take_for_spending_limit()
                        {
                            proof_telemetry.record(
                                proof.node_id,
                                ProofMetric::RefusedSpendingLimit,
                            );
                        }
                        let publication = observer.latest_publication();
                        let refresh = observer.refresh_handle();
                        let proof_turn = proof_refresh.handle_observer_update(
                            ProofObserverUpdate::Snapshot {
                                publication: publication.as_ref(),
                                latest_snapshot_available: observer.latest_snapshot().is_some(),
                                now: Instant::now(),
                            },
                            &client.manifest,
                            address,
                            &refresh,
                            &proof_receiver,
                            &proof_telemetry,
                        );
                        let retry_queued_this_snapshot =
                            proof_turn.retry_queued_this_snapshot;
                        #[cfg(test)]
                        let can_receive_proof = proof_refresh.can_receive_proof();
                        let can_finalize =
                            proof_refresh.can_finalize(retry_queued_this_snapshot);
                        #[cfg(test)]
                        {
                            test_options
                                .lifecycle
                                .pending_proof
                                .store(proof_refresh.has_pending(), Ordering::Release);
                            test_options
                                .lifecycle
                                .proof_receive_allowed
                                .store(can_receive_proof, Ordering::Release);
                            test_options
                                .lifecycle
                                .finalization_allowed
                                .store(can_finalize, Ordering::Release);
                            test_options
                                .lifecycle
                                .snapshot_turns
                                .fetch_add(1, Ordering::AcqRel);
                        }
                        match proof_turn.action {
                            ProofRefreshEventAction::NoPending
                            | ProofRefreshEventAction::Waiting
                            | ProofRefreshEventAction::SnapshotUnavailable
                            | ProofRefreshEventAction::RetryQueued => {}
                            ProofRefreshEventAction::VerifiedStale { proof, reason } => {
                                if let Some(slot) = slots
                                    .get(usize::from(proof.node_id.saturating_sub(1)))
                                {
                                    record_proof_revalidation_drop(
                                        slot,
                                        &proof,
                                        reason,
                                        &proof_telemetry,
                                    );
                                }
                                proof_telemetry.record(
                                    proof.node_id,
                                    ProofMetric::PreflightStaleProof,
                                );
                                report_mining_warning(
                                    dashboard,
                                    format!(
                                        "a correlated verified snapshot invalidated the retained proof for node {} window {} ({reason:?}); no retry transaction was authorized",
                                        proof.node_id,
                                        proof.context.window_id
                                    ),
                                );
                            }
                            ProofRefreshEventAction::LocallyExpired { proof } => {
                                if let Some(slot) =
                                    slots.get(usize::from(proof.node_id.saturating_sub(1)))
                                {
                                    record_proof_revalidation_drop(
                                        slot,
                                        &proof,
                                        ProofRevalidationFailure::ExpiredDeadline,
                                        &proof_telemetry,
                                    );
                                }
                                report_mining_warning(
                                    dashboard,
                                    format!(
                                        "retained proof for node {} window {} reached its local safe submission deadline without a qualifying verified snapshot; no transaction was signed or broadcast",
                                        proof.node_id,
                                        proof.context.window_id
                                    ),
                                );
                            }
                        }
                        // Finalize expired nodes even while another active node has queued work.
                        if can_finalize
                            && let (Some(manager), Some(signer)) =
                            (transactions.as_mut(), signer.as_ref())
                        {
                            let finalization_prepared = manager.prepared_broadcast_pending();
                            let finalization = maybe_finalize_expired(
                                &client,
                                &selected,
                                manager,
                                signer,
                                address,
                                &snapshot,
                                FinalizationOptions {
                                    finalization_state: &dashboard_context.finalization_state,
                                    dashboard: &*dashboard,
                                    pending_sync: &dashboard_context.pending_sync,
                                },
                            );
                            tokio::pin!(finalization);
                            let finalization_result = loop {
                                tokio::select! {
                                    result = &mut finalization => break Some(result),
                                    signal = shutdown.recv() => {
                                        match signal {
                                            Ok(reason) => shutdown_reason = Some(reason),
                                            Err(error) => report_mining_warning(dashboard, format!("shutdown signal handler failed: {error}")),
                                        }
                                        let _ = await_prepared_submission_with_grace(
                                            &finalization_prepared,
                                            finalization.as_mut(),
                                            PREPARED_BROADCAST_STOP_GRACE,
                                        )
                                        .await;
                                        break None;
                                    }
                                    event = wait_for_dashboard_event(dashboard_signal.clone()) => {
                                        match event {
                                            DashboardEventKind::StopRequested => {
                                                let _ = await_prepared_submission_with_grace(
                                                    &finalization_prepared,
                                                    finalization.as_mut(),
                                                    PREPARED_BROADCAST_STOP_GRACE,
                                                )
                                                .await;
                                                break None;
                                            }
                                            DashboardEventKind::Failure(error)
                                                if session_limit_reached.load(Ordering::Acquire) =>
                                            {
                                                // Keep listening: a late operator stop
                                                // must remain observable.
                                                let message = format!(
                                                    "terminal dashboard failed; the already-authorized transaction remains in recovery and mining stays stopped: {error}"
                                                );
                                                report_terminal_dashboard_failure(dashboard, message);
                                                #[cfg(test)]
                                                runtime_lifecycle
                                                    .terminal_dashboard_failures
                                                    .fetch_add(1, Ordering::AcqRel);
                                            }
                                            DashboardEventKind::Failure(error) => {
                                                fatal_error = Some(anyhow!("dashboard failed: {error}"));
                                                let _ = await_prepared_submission_with_grace(
                                                    &finalization_prepared,
                                                    finalization.as_mut(),
                                                    PREPARED_BROADCAST_STOP_GRACE,
                                                )
                                                .await;
                                                break None;
                                            }
                                        }
                                    }
                                }
                            };
                            let Some(finalization_result) = finalization_result else {
                                break 'mining_loop;
                            };
                            match finalization_result {
                                Ok(true) => {
                                    observer.force_refresh();
                                }
                                Ok(false) => {}
                                Err(error)
                                    if session_limit_reached.load(Ordering::Acquire)
                                        && is_transient_rpc_error(&error) =>
                                {
                                    report_mining_warning(
                                        dashboard,
                                        format!(
                                            "the already-authorized finalization is not yet settled; terminal mining stays stopped and journaled liabilities remain reserved: {error:#}"
                                        ),
                                    );
                                }
                                Err(error) => {
                                    fatal_error = Some(error);
                                    break;
                                }
                            }
                        }
                        if session_limit_reached.load(Ordering::Acquire) {
                            proof_receiver.latch_paused();
                            proof_receiver.discard_pending(
                                &proof_telemetry,
                                ProofMetric::RefusedSpendingLimit,
                            );
                            last_snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                            continue 'mining_loop;
                        }
                        proof_receiver.set_paused(
                            transaction_mode
                                && (signer.is_none()
                                    || transactions
                                        .as_ref()
                                        .is_some_and(|manager| manager.signing_blocked_by_unresolved())
                                    || budget_exhausted),
                        );
                        snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                        // Harvest completed reward batches even while proof work is queued. This
                        // only awaits a scan task after it has finished; active RPC scans remain
                        // in the background and never hold up live proof processing.
                        if let Some(manager) = transactions.as_mut()
                            && let Err(error) = manager
                                .service_reward_reconciliation(&client, &snapshot)
                                .await
                        {
                            fatal_error = Some(error.context("service historical reward verification"));
                            break 'mining_loop;
                        }
                        if proof_receiver.has_pending() {
                            last_snapshot = snapshot;
                            continue 'mining_loop;
                        }
                        proof_receiver.set_paused(
                            transaction_mode
                                && (signer.is_none()
                                    || transactions
                                        .as_ref()
                                        .is_some_and(|manager| manager.signing_blocked_by_unresolved())
                                    || budget_exhausted),
                        );
                        last_snapshot = observer.latest_snapshot().unwrap_or(snapshot);
                    }
                    ObserverUpdate::RpcError { message, report } => {
                        let _ = proof_refresh.handle_observer_update(
                            ProofObserverUpdate::Failed,
                            &client.manifest,
                            address,
                            &observer.refresh_handle(),
                            &proof_receiver,
                            &proof_telemetry,
                        );
                        #[cfg(test)]
                        {
                            test_options
                                .lifecycle
                                .pending_proof
                                .store(proof_refresh.has_pending(), Ordering::Release);
                            test_options
                                .lifecycle
                                .observer_failures
                                .fetch_add(1, Ordering::AcqRel);
                        }
                        if session_limit_reached.load(Ordering::Acquire) {
                            let details = if report {
                                format!(": {message}")
                            } else {
                                String::new()
                            };
                            report_terminal_monitoring_degraded(
                                dashboard,
                                dashboard_updater.as_ref(),
                                &observer_monitoring_degraded,
                                &mut terminal_monitoring_error,
                                format!(
                                    "Read-only observer unavailable; {} — mining remains stopped{details}",
                                    snapshot_freshness_description(&last_snapshot, "may be stale")
                                ),
                            );
                        } else if report && dashboard.is_none() {
                            report_mining_warning(dashboard, message);
                        }
                        if dashboard.is_none() {
                            total_hashes.store(0, Ordering::Relaxed);
                        }
                    }
                    ObserverUpdate::GenesisPollError { message, report } => {
                        let _ = proof_refresh.handle_observer_update(
                            ProofObserverUpdate::Failed,
                            &client.manifest,
                            address,
                            &observer.refresh_handle(),
                            &proof_receiver,
                            &proof_telemetry,
                        );
                        #[cfg(test)]
                        {
                            test_options
                                .lifecycle
                                .pending_proof
                                .store(proof_refresh.has_pending(), Ordering::Release);
                            test_options
                                .lifecycle
                                .observer_failures
                                .fetch_add(1, Ordering::AcqRel);
                        }
                        if session_limit_reached.load(Ordering::Acquire) {
                            let details = if report {
                                format!(": {message}")
                            } else {
                                String::new()
                            };
                            report_terminal_monitoring_degraded(
                                dashboard,
                                dashboard_updater.as_ref(),
                                &observer_monitoring_degraded,
                                &mut terminal_monitoring_error,
                                format!(
                                    "Read-only genesis polling unavailable — mining remains stopped{details}"
                                ),
                            );
                        } else if report && dashboard.is_none() {
                            report_mining_warning(dashboard, message);
                        }
                    }
                    ObserverUpdate::Fatal(error) => {
                        if session_limit_reached.load(Ordering::Acquire) {
                            observer_updates_open = false;
                            report_terminal_monitoring_degraded(
                                dashboard,
                                dashboard_updater.as_ref(),
                                &observer_monitoring_degraded,
                                &mut terminal_monitoring_error,
                                format!(
                                    "Read-only observer unavailable — mining remains stopped; {}: {error}",
                                    snapshot_freshness_description(&last_snapshot, "is stale")
                                ),
                            );
                            continue 'mining_loop;
                        }
                        fatal_error = Some(anyhow!("read-only observer failed: {error}"));
                        break;
                    }
                }
            }
            _ = progress_ticker.tick() => {
                if let Some(proof) = proof_refresh.on_timeout(Instant::now())
                {
                    if let Some(slot) = slots
                        .get(usize::from(proof.node_id.saturating_sub(1)))
                    {
                        record_proof_revalidation_drop(
                            slot,
                            &proof,
                            ProofRevalidationFailure::ExpiredDeadline,
                            &proof_telemetry,
                        );
                    }
                    report_mining_warning(
                        dashboard,
                        format!(
                            "retained proof for node {} window {} reached its local safe submission deadline without a qualifying verified snapshot; no transaction was signed or broadcast",
                            proof.node_id,
                            proof.context.window_id
                        ),
                    );
                }
                let observer_age = observer.publication_age();
                if observer_updates_open
                    && observer_age > OBSERVER_STALL_TIMEOUT
                    && session_limit_reached.load(Ordering::Acquire)
                {
                    report_terminal_monitoring_degraded(
                        dashboard,
                        dashboard_updater.as_ref(),
                        &observer_monitoring_degraded,
                        &mut terminal_monitoring_error,
                        format!(
                            "Read-only observer stalled beyond the 45-second threshold — {}; mining remains stopped",
                            snapshot_freshness_description(&last_snapshot, "is stale")
                        ),
                    );
                } else if observer_updates_open && observer_age > OBSERVER_STALL_TIMEOUT {
                    fatal_error = Some(anyhow!(
                        "read-only chain observer has not published a snapshot or error for {} seconds; mining is stopping rather than showing healthy WAITING",
                        observer_age.as_secs()
                    ));
                    break;
                }
                let elapsed = last_progress.elapsed();
                if dashboard.is_none()
                    && !session_limit_reached.load(Ordering::Acquire)
                    && elapsed >= PROGRESS_INTERVAL
                {
                    print_progress(
                        &last_snapshot,
                        &slots,
                        total_hashes.swap(0, Ordering::Relaxed),
                        elapsed,
                    );
                    last_progress = time::Instant::now();
                }
            }
            _ = reward_scan_ticker.tick(), if transactions.is_some() => {
                if let Some(manager) = transactions.as_mut()
                    && let Err(error) = manager
                        .service_reward_reconciliation(&client, &last_snapshot)
                        .await
                {
                    fatal_error = Some(error.context("service historical reward verification"));
                    break 'mining_loop;
                }
                proof_receiver.set_paused(
                    transaction_mode
                        && (signer.is_none()
                            || transactions
                                .as_ref()
                                .is_some_and(|manager| manager.signing_blocked_by_unresolved())
                            || session_limit_reached.load(Ordering::Acquire)
                            || budget_exhausted),
                );
                if session_limit_reached.load(Ordering::Acquire) {
                    proof_receiver.latch_paused();
                    proof_receiver.discard_pending(
                        &proof_telemetry,
                        ProofMetric::RefusedSpendingLimit,
                    );
                }
            }
            event = receive_backend_event(&mut backend_event_receiver) => {
                if session_limit_reached.load(Ordering::Acquire) {
                    if let Some(BackendEvent::Failed(message) | BackendEvent::FallbackNotice(message)) = event {
                        report_mining_warning(
                            dashboard,
                            format!("Compute backend stopped after the session limit latched; mining remains stopped: {message}"),
                        );
                    }
                    // Do not activate a late backend or turn an already-stopped GPU into
                    // a CPU fallback after the terminal authorization state.
                    backend_event_receiver = None;
                    continue 'mining_loop;
                }
                match event {
                    Some(BackendEvent::Activated(backend)) => {
                        *active_backend
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = backend.clone();
                        if let Some(updater) = &dashboard_updater {
                            updater.update(|model| {
                                model.device_label = backend.label().to_owned();
                                model.device_detail = backend.detail();
                            });
                        }
                        match backend {
                            ActiveBackend::Cpu { threads } => report_mining_warning(
                                dashboard,
                                format!("GPU backend stopped; safely continuing on CPU ({threads} worker thread(s)); reserved GPU nonce ranges will not be reused."),
                            ),
                            ActiveBackend::Gpu(info) => report_mining_info(
                                dashboard,
                                format!("GPU backend active · {} · {}", info.name, info.backend),
                            ),
                        }
                    }
                    Some(BackendEvent::Failed(message)) => {
                        fatal_error = Some(anyhow!(message));
                        break 'mining_loop;
                    }
                    Some(BackendEvent::FallbackNotice(reason)) => {
                        report_mining_warning(
                            dashboard,
                            format!("{reason}; continuing with the CPU backend."),
                        );
                    }
                    None => backend_event_receiver = None,
                }
            }
            proof = proof_receiver.recv(), if proof_receiver_open && proof_processing_gate_open && proof_refresh.can_receive_proof() => {
                let Some(proof) = proof else {
                    if session_limit_reached.load(Ordering::Acquire) {
                        proof_receiver_open = false;
                        report_mining_warning(
                            dashboard,
                            "proof inbox closed after SESSION LIMIT REACHED; mining remains stopped until Ctrl+C",
                        );
                        continue 'mining_loop;
                    }
                    fatal_error = Some(anyhow!("compute proof inbox closed while mining was active"));
                    break;
                };
                proof_telemetry.record(proof.node_id, ProofMetric::MainLoopReceived);
                if session_limit_reached.load(Ordering::Acquire) {
                    proof_telemetry.record(proof.node_id, ProofMetric::RefusedSpendingLimit);
                    proof_receiver.latch_paused();
                    proof_receiver.discard_pending(
                        &proof_telemetry,
                        ProofMetric::RefusedSpendingLimit,
                    );
                    continue;
                }
                let Some(slot) = slots.get(usize::from(proof.node_id.saturating_sub(1))) else {
                    continue;
                };
                let work = match revalidate_queued_proof(slot, &proof, &proof_telemetry) {
                    Ok(work) => work,
                    Err(reason) => {
                        record_proof_revalidation_drop(slot, &proof, reason, &proof_telemetry);
                        continue;
                    }
                };
                #[cfg(test)]
                let injected_preflight_failure = test_options
                    .preflight_failures
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&proof.nonce);
                #[cfg(test)]
                if let Some(error) = injected_preflight_failure {
                    let conditions = ProofPreflightRetryConditions {
                        session_limit_reached: session_limit_reached.load(Ordering::Acquire),
                        authorization_unchanged: true,
                        has_new_unresolved: false,
                        signing_blocked_by_unresolved: false,
                        has_unverified_receipt: false,
                    };
                    if should_retain_proof_after_preflight_failure(&error, conditions) {
                        proof_telemetry.record(proof.node_id, ProofMetric::PreflightStarted);
                        if is_proof_quote_unavailable(&error)
                            || is_transient_rpc_error(&error)
                        {
                            proof_telemetry
                                .record(proof.node_id, ProofMetric::PreflightRpcFailure);
                        }
                        proof_refresh.retain_after_preflight_failure(
                            proof.clone(),
                            work.valid_until,
                            &observer.refresh_handle(),
                        );
                        test_options
                            .lifecycle
                            .pending_proof
                            .store(true, Ordering::Release);
                        test_options
                            .lifecycle
                            .proof_receive_allowed
                            .store(false, Ordering::Release);
                        test_options
                            .lifecycle
                            .finalization_allowed
                            .store(false, Ordering::Release);
                        test_options
                            .lifecycle
                            .injected_preflight_failures
                            .fetch_add(1, Ordering::AcqRel);
                        continue 'mining_loop;
                    }
                    fatal_error = Some(error.context("test-injected proof preflight failure"));
                    break 'mining_loop;
                }
                let incumbent = proof
                    .incumbent
                    .map(|hash| format!("; found against incumbent {hash:#x}"))
                    .unwrap_or_default();
                let contract = work.fingerprint.hashing_context.contract;
                let window_id = work.fingerprint.hashing_context.window_id;
                if args.compute_only {
                    report_mining_info(
                        dashboard,
                        format!(
                            "valid local proof: node={} window={} nonce={} hash={:#x} target={:#x}{}; compute-only, not submitted",
                            proof.node_id, window_id, proof.nonce, proof.hash, proof.target, incumbent
                        ),
                    );
                    continue;
                }
                let (Some(manager), Some(signer)) =
                    (transactions.as_mut(), signer.as_ref())
                else {
                    proof_telemetry.record(proof.node_id, ProofMetric::RefusedSigningDisabled);
                    continue;
                };
                let unresolved_before = manager
                    .journal
                    .unresolved_transactions()
                    .into_iter()
                    .map(|entry| entry.hash)
                    .collect::<HashSet<_>>();
                let authorization_before = manager.authorization_used()?;
                if manager.signing_blocked_by_unresolved() {
                    proof_receiver.set_paused(true);
                    let _ = proof_receiver.requeue(proof.clone(), &proof_telemetry);
                    proof_telemetry.record(
                        proof.node_id,
                        ProofMetric::DeferredUnresolvedTransaction,
                    );
                    continue;
                }
                if budget_exhausted || manager.budget_remaining()?.is_zero() {
                    budget_exhausted = true;
                    proof_telemetry.record(proof.node_id, ProofMetric::RefusedSpendingLimit);
                    proof_receiver.set_paused(true);
                    proof_receiver
                        .discard_pending(&proof_telemetry, ProofMetric::RefusedSpendingLimit);
                    continue;
                }
                let header = work.fingerprint.hashing_context.header.clone();
                mark_dashboard_nodes(
                    dashboard,
                    [proof.node_id],
                    NodeStatus::CheckingProof,
                    Some(format!(
                        "Node {:02} • Checking proof and transaction policy...",
                        proof.node_id
                    )),
                );
                proof_telemetry.record(proof.node_id, ProofMetric::PreflightStarted);
                let prepared_broadcast_pending = manager.prepared_broadcast_pending();
                let submission_result = {
                    let submission = manager.submit_proof(
                        &client,
                        signer,
                        ProofSubmission {
                            contract,
                            node_id: proof.node_id,
                            window_id,
                            nonce: proof.nonce,
                            header: header.clone(),
                            work_hash: proof.hash,
                        },
                    );
                    tokio::pin!(submission);
                    loop {
                        tokio::select! {
                            result = &mut submission => break Some(result),
                            signal = shutdown.recv() => {
                                match signal {
                                    Ok(reason) => shutdown_reason = Some(reason),
                                    Err(error) => report_mining_warning(dashboard, format!("shutdown signal handler failed: {error}")),
                                }
                                let _ = await_prepared_submission_with_grace(
                                    &prepared_broadcast_pending,
                                    submission.as_mut(),
                                    PREPARED_BROADCAST_STOP_GRACE,
                                )
                                .await;
                                break None;
                            }
                            event = wait_for_dashboard_event(dashboard_signal.clone()) => {
                                match event {
                                    DashboardEventKind::StopRequested => {
                                        let _ = await_prepared_submission_with_grace(
                                            &prepared_broadcast_pending,
                                            submission.as_mut(),
                                            PREPARED_BROADCAST_STOP_GRACE,
                                        )
                                        .await;
                                        break None;
                                    }
                                    DashboardEventKind::Failure(error)
                                        if session_limit_reached.load(Ordering::Acquire) =>
                                    {
                                        // Keep listening: a late operator stop
                                        // must remain observable.
                                        let message = format!(
                                            "terminal dashboard failed; the already-authorized transaction remains in recovery and mining stays stopped: {error}"
                                        );
                                        report_terminal_dashboard_failure(dashboard, message);
                                        #[cfg(test)]
                                        runtime_lifecycle
                                            .terminal_dashboard_failures
                                            .fetch_add(1, Ordering::AcqRel);
                                    }
                                    DashboardEventKind::Failure(error) => {
                                        fatal_error = Some(anyhow!("dashboard failed: {error}"));
                                        let _ = await_prepared_submission_with_grace(
                                            &prepared_broadcast_pending,
                                            submission.as_mut(),
                                            PREPARED_BROADCAST_STOP_GRACE,
                                        )
                                        .await;
                                        break None;
                                    }
                                }
                            }
                        }
                    }
                };
                let Some(submission_result) = submission_result else {
                    break 'mining_loop;
                };
                if session_limit_reached.load(Ordering::Acquire) {
                    proof_receiver.latch_paused();
                    proof_receiver.discard_pending(
                        &proof_telemetry,
                        ProofMetric::RefusedSpendingLimit,
                    );
                }
                let authorization_unchanged = manager.authorization_used()? == authorization_before;
                let has_new_unresolved = manager
                    .journal
                    .unresolved_transactions()
                    .iter()
                    .any(|entry| !unresolved_before.contains(&entry.hash));
                match submission_result {
                    Ok(action) => {
                        report_mining_info(
                            dashboard,
                            confirmed_action_message("proof", &action),
                        );
                        dashboard_context
                            .pending_sync
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .insert(
                                proof.node_id,
                                PendingDashboardSync {
                                    window_id,
                                    receipt_block: action.receipt.block_number,
                                },
                            );
                        mark_dashboard_nodes(
                            dashboard,
                            [proof.node_id],
                            NodeStatus::Syncing,
                            Some(format!(
                                "Node {:02} • Syncing accepted proof...",
                                proof.node_id
                            )),
                        );
                        observer.force_refresh();
                        proof_receiver.set_paused(
                            transaction_mode
                                && manager.signing_blocked_by_unresolved(),
                        );
                    }
                    Err(error)
                        if manager
                            .journal
                            .unresolved_transactions()
                            .iter()
                            .any(|entry| !unresolved_before.contains(&entry.hash))
                            || (!per_run_sessions_enabled && manager.journal.has_unresolved()) =>
                    {
                        report_mining_warning(
                            dashboard,
                            if per_run_sessions_enabled {
                                format!(
                                    "proof outcome remains journaled as unresolved; its maximum exposure and nonce remain reserved while receipt recovery continues read-only. Later transactions require a distinct pending nonce and sufficient balance/cap: {error:#}"
                                )
                            } else {
                                format!(
                                    "proof outcome remains journaled as unresolved; no further transaction will be signed, but read-only recovery and mining observation will continue: {error:#}"
                                )
                            },
                        );
                        proof_receiver.set_paused(manager.signing_blocked_by_unresolved());
                        mark_dashboard_nodes(
                            dashboard,
                            [proof.node_id],
                            NodeStatus::Recovering,
                            Some(format!(
                                "Node {:02} • recovering journaled proof outcome...",
                                proof.node_id
                            )),
                        );
                        observer.force_refresh();
                    }
                    Err(error)
                        if should_retain_proof_after_preflight_failure(
                            &error,
                            ProofPreflightRetryConditions {
                                session_limit_reached: session_limit_reached
                                    .load(Ordering::Acquire),
                                authorization_unchanged,
                                has_new_unresolved,
                                signing_blocked_by_unresolved: manager
                                    .signing_blocked_by_unresolved(),
                                has_unverified_receipt: manager.journal.has_unverified_receipt(),
                            },
                        ) =>
                    {
                        if is_proof_quote_unavailable(&error)
                            || is_transient_rpc_error(&error)
                        {
                            proof_telemetry
                                .record(proof.node_id, ProofMetric::PreflightRpcFailure);
                        }
                        proof_refresh.retain_after_preflight_failure(
                            proof.clone(),
                            work.valid_until,
                            &observer.refresh_handle(),
                        );
                        report_mining_warning(
                            dashboard,
                            format!(
                                "proof candidate for node {:02} window {window_id} is retained pending a correlated verified snapshot; no new transaction authorization was recorded: {error:#}",
                                proof.node_id
                            ),
                        );
                        mark_dashboard_nodes(
                            dashboard,
                            [proof.node_id],
                            NodeStatus::Syncing,
                            Some(format!(
                                "Node {:02} window #{window_id} • waiting for verified proof revalidation...",
                                proof.node_id
                            )),
                        );
                        continue 'mining_loop;
                    }
                    Err(error) if is_unresolved_nonce_refusal(&error) => {
                        proof_telemetry.record(
                            proof.node_id,
                            ProofMetric::DeferredUnresolvedTransaction,
                        );
                        let _ = proof_receiver.requeue(proof.clone(), &proof_telemetry);
                        proof_receiver.set_paused(true);
                        report_mining_warning(
                            dashboard,
                            format!(
                                "proof retained while an unresolved transaction owns the wallet's current pending nonce; receipt recovery remains read-only and hashing continues: {error:#}"
                            ),
                        );
                        mark_dashboard_nodes(
                            dashboard,
                            [proof.node_id],
                            NodeStatus::Recovering,
                            Some(format!(
                                "Node {:02} • waiting for an unresolved wallet nonce...",
                                proof.node_id
                            )),
                        );
                        observer.force_refresh();
                    }
                    Err(error) if is_policy_refusal(&error) => {
                        proof_telemetry.record(proof.node_id, ProofMetric::PreflightPolicyRefusal);
                        budget_exhausted |= is_session_limit_refusal(&error);
                        if budget_exhausted {
                            proof_receiver.set_paused(true);
                        }
                        report_mining_warning(
                            dashboard,
                            format!("valid proof was not submitted: {error:#}"),
                        );
                        mark_dashboard_nodes(dashboard, [proof.node_id], NodeStatus::Mining, None);
                    }
                    Err(error) if is_stale_proof(&error) => {
                        proof_telemetry.record(proof.node_id, ProofMetric::PreflightStaleProof);
                        if stale_proof_warning_window.get(&proof.node_id) != Some(&window_id) {
                            stale_proof_warning_window.insert(proof.node_id, window_id);
                            report_mining_warning(
                                dashboard,
                                format!(
                                    "discarded stale proof for node {} window {window_id}: {error:#}",
                                    proof.node_id
                                ),
                            );
                        }
                        mark_dashboard_nodes(
                            dashboard,
                            [proof.node_id],
                            NodeStatus::Syncing,
                            Some(format!(
                                "Node {:02} window #{window_id} • revalidating after stale proof...",
                                proof.node_id
                            )),
                        );
                        observer.force_refresh();
                    }
                    Err(error) if session_limit_reached.load(Ordering::Acquire) => {
                        report_mining_warning(
                            dashboard,
                            format!(
                                "the already-authorized proof did not settle successfully; terminal state remains latched and its journaled exposure is preserved: {error:#}"
                            ),
                        );
                        mark_dashboard_nodes(
                            dashboard,
                            [proof.node_id],
                            NodeStatus::Recovering,
                            Some(format!(
                                "Node {:02} • terminal session; transaction outcome remains journaled",
                                proof.node_id
                            )),
                        );
                    }
                    Err(error) => {
                        proof_telemetry.record(proof.node_id, ProofMetric::PreflightOtherFailure);
                        fatal_error = Some(error);
                        break;
                    }
                }
            }
        }
    }

    if let Some(proof) = proof_refresh.take_for_shutdown() {
        proof_telemetry.record(proof.node_id, ProofMetric::DroppedOnShutdown);
        report_mining_warning(
            dashboard,
            format!(
                "unsubmitted proof for node {} window {} was retained only in memory and is discarded on shutdown; no transaction authorization or broadcast was created for this pending proof",
                proof.node_id, proof.context.window_id
            ),
        );
    }
    for pending in proof_receiver.drain_pending() {
        proof_telemetry.record(pending.node_id, ProofMetric::DroppedOnShutdown);
    }
    if let Some(reason) = shutdown_reason {
        report_mining_info(
            dashboard,
            format!("Shutdown signal received: {}", reason.as_str()),
        );
    }
    if let Some(manager) = transactions.as_ref()
        && let Some(profile) =
            optional_history_profile(show_history_profile, || manager.history_profile_line())
    {
        report_mining_info(dashboard, profile);
    }
    for line in proof_telemetry.report_lines() {
        report_mining_info(dashboard, line);
    }
    if let Some(error) = fatal_error {
        return Err(error);
    }
    Ok(())
    }
    .await;

    let inner_error = inner_result
        .as_ref()
        .err()
        .map(|error| format!("{error:#}"));
    let finalize_result = lifecycle
        .finalize(
            inner_error.as_deref(),
            compute_only,
            runtime_started,
            per_run_sessions_enabled,
            &diagnostics,
        )
        .await;
    combine_runtime_results(inner_result, finalize_result)
}

fn take_observer_update(updates: &mut watch::Receiver<ObserverUpdate>) -> ObserverUpdate {
    let borrowed = updates.borrow_and_update();
    (*borrowed).clone()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProofRevalidationFailure {
    NoEligibleWork,
    ExpiredDeadline,
    WindowMismatch,
    WorkContextMismatch,
    HashMismatch,
    CurrentTarget,
    CurrentIncumbent,
    InvalidGpuBatchIdentity,
}

fn revalidate_queued_proof(
    slot: &NodeSlot,
    proof: &ProofFound,
    telemetry: &ProofPipelineTelemetry,
) -> std::result::Result<Arc<WorkJob>, ProofRevalidationFailure> {
    revalidate_queued_proof_at(slot, proof, telemetry, Instant::now())
}

fn revalidate_queued_proof_at(
    slot: &NodeSlot,
    proof: &ProofFound,
    telemetry: &ProofPipelineTelemetry,
    now: Instant,
) -> std::result::Result<Arc<WorkJob>, ProofRevalidationFailure> {
    let current = slot
        .work
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
        .ok_or(ProofRevalidationFailure::NoEligibleWork)?;
    if now >= current.valid_until {
        return Err(ProofRevalidationFailure::ExpiredDeadline);
    }
    if proof.batch_identity.is_some_and(|batch| {
        batch.node_id != proof.node_id
            || batch.node_id != slot.id
            || batch.generation != proof.generation
            || batch.window_id != proof.context.window_id
            || batch.nonce_count == 0
            || !batch.contains(proof.nonce)
    }) {
        return Err(ProofRevalidationFailure::InvalidGpuBatchIdentity);
    }
    if proof.context.window_id != current.fingerprint.hashing_context.window_id {
        return Err(ProofRevalidationFailure::WindowMismatch);
    }
    if proof.context != current.fingerprint.hashing_context {
        return Err(ProofRevalidationFailure::WorkContextMismatch);
    }
    let recomputed = WorkHasher::new(&current.fingerprint.hashing_context.work_context())
        .ok()
        .map(|hasher| hasher.hash(proof.nonce));
    if recomputed != Some(proof.hash) {
        return Err(ProofRevalidationFailure::HashMismatch);
    }
    if !meets_target(proof.hash, current.target) {
        return Err(ProofRevalidationFailure::CurrentTarget);
    }
    if current
        .incumbent
        .is_some_and(|incumbent| !beats_incumbent(proof.hash, incumbent))
    {
        return Err(ProofRevalidationFailure::CurrentIncumbent);
    }
    if proof.generation != current.generation {
        telemetry.record(slot.id, ProofMetric::GenerationMismatchRevalidated);
    }
    Ok(current)
}

fn revalidate_proof_snapshot(
    manifest: &DeploymentManifest,
    wallet: Address,
    snapshot: &ReadSnapshot,
    proof: &ProofFound,
    now: Instant,
    telemetry: &ProofPipelineTelemetry,
) -> ProofSnapshotValidation {
    let Some(node) = snapshot.nodes.iter().find(|node| node.id == proof.node_id) else {
        return ProofSnapshotValidation::Unavailable;
    };
    if node.error.is_some()
        || !node.pin.runtime_verified
        || !node.pin.abi_verified
        || node.address != proof.context.contract
        || proof.context.chain_id != manifest.chain_id
        || proof.context.miner != wallet
    {
        return ProofSnapshotValidation::Unavailable;
    }
    let Some(state) = node.state.as_ref() else {
        return ProofSnapshotValidation::Unavailable;
    };
    let slot = NodeSlot::new(proof.node_id);
    if slot
        .set_work_at(
            manifest,
            wallet,
            node.address,
            Some(state),
            &snapshot.block,
            now,
        )
        .is_err()
    {
        return ProofSnapshotValidation::Unavailable;
    }
    match revalidate_queued_proof_at(&slot, proof, telemetry, now) {
        Ok(_) => ProofSnapshotValidation::Valid,
        Err(reason) => ProofSnapshotValidation::VerifiedStale(reason),
    }
}

fn record_proof_revalidation_drop(
    slot: &NodeSlot,
    proof: &ProofFound,
    failure: ProofRevalidationFailure,
    telemetry: &ProofPipelineTelemetry,
) {
    if proof.generation != slot.generation.load(Ordering::Acquire) {
        telemetry.record(slot.id, ProofMetric::GenerationMismatchDropped);
    }
    let metric = match failure {
        ProofRevalidationFailure::NoEligibleWork => ProofMetric::DroppedNoEligibleWork,
        ProofRevalidationFailure::ExpiredDeadline => ProofMetric::DroppedExpiredDeadline,
        ProofRevalidationFailure::WindowMismatch => ProofMetric::DroppedWindowMismatch,
        ProofRevalidationFailure::WorkContextMismatch => ProofMetric::DroppedWorkContextMismatch,
        ProofRevalidationFailure::HashMismatch => ProofMetric::DroppedHashMismatch,
        ProofRevalidationFailure::CurrentTarget => ProofMetric::DroppedCurrentTarget,
        ProofRevalidationFailure::CurrentIncumbent => ProofMetric::DroppedCurrentIncumbent,
        ProofRevalidationFailure::InvalidGpuBatchIdentity => ProofMetric::GpuBatchIdentityRejected,
    };
    telemetry.record(slot.id, metric);
}

pub(crate) struct FinalizationOptions<'a> {
    pub finalization_state: &'a Arc<RwLock<HashMap<u8, FinalizationState>>>,
    pub dashboard: &'a Option<Dashboard>,
    pub pending_sync: &'a Arc<RwLock<HashMap<u8, PendingDashboardSync>>>,
}

async fn maybe_finalize_expired(
    client: &NetworkClient,
    selected: &HashSet<u8>,
    manager: &mut TransactionManager,
    signer: &bip32::secp256k1::ecdsa::SigningKey,
    wallet: Address,
    last_verified_snapshot: &ReadSnapshot,
    options: FinalizationOptions<'_>,
) -> Result<bool> {
    if manager.refresh_session_limit_state()? {
        return Ok(false);
    }
    if manager.signing_blocked_by_unresolved() {
        return Ok(false);
    }
    let snapshot = match client.snapshot(Some(wallet)).await {
        Ok(snapshot) => snapshot,
        Err(error) if is_transient_rpc_error(&error) => {
            for node in &last_verified_snapshot.nodes {
                let Some(state) = node
                    .state
                    .as_ref()
                    .filter(|state| selected.contains(&node.id) && state.finalizable)
                else {
                    continue;
                };
                let previous = options
                    .finalization_state
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&node.id)
                    .cloned();
                let attempts = retry_attempts(previous.as_ref()).saturating_add(1);
                let delay = finalization_retry_delay(attempts);
                record_finalization_state(
                    &options,
                    node.id,
                    FinalizationState::Retrying {
                        window_id: state.work.window_id,
                        attempts,
                        retry_at: Instant::now() + delay,
                        reason: format!("fresh finalization snapshot unavailable: {error:#}"),
                    },
                );
            }
            return Ok(false);
        }
        Err(error) => return Err(error).context("read fresh state before window finalization"),
    };
    {
        let mut states = options
            .finalization_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        states.retain(|node_id, state| {
            let Some(node) = snapshot.nodes.iter().find(|node| node.id == *node_id) else {
                return true;
            };
            let Some(work) = node.state.as_ref() else {
                return true;
            };
            let tracked_window = match state {
                FinalizationState::Retrying { window_id, .. }
                | FinalizationState::Blocked { window_id, .. } => *window_id,
            };
            work.work.window_id == tracked_window && work.finalizable && !work.mining_paused
        });
    }
    let mut finalized_any = false;
    for node in &snapshot.nodes {
        if manager.refresh_session_limit_state()? {
            return Ok(finalized_any);
        }
        if !selected.contains(&node.id) {
            continue;
        }
        let Some(state) = node
            .state
            .as_ref()
            .filter(|state| state.finalizable && !state.mining_paused)
        else {
            continue;
        };
        if manager.journal.has_unresolved_finalization(
            node.address,
            node.id,
            state.work.window_id,
        )? {
            mark_dashboard_nodes(
                options.dashboard,
                [node.id],
                NodeStatus::Recovering,
                Some(format!(
                    "Node {:02} window #{} • reconciling the existing finalization transaction...",
                    node.id, state.work.window_id
                )),
            );
            continue;
        }
        if manager.journal.has_successful_finalization(
            node.address,
            node.id,
            state.work.window_id,
        )? {
            record_finalization_state(
                &options,
                node.id,
                FinalizationState::Blocked {
                    window_id: state.work.window_id,
                    reason: "journal already records a successful canonical finalization; waiting for the node state to advance".to_owned(),
                },
            );
            continue;
        }
        let previous = options
            .finalization_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&node.id)
            .filter(|tracked| match tracked {
                FinalizationState::Retrying { window_id, .. }
                | FinalizationState::Blocked { window_id, .. } => {
                    *window_id == state.work.window_id
                }
            })
            .cloned();
        if let Some(FinalizationState::Blocked { reason, .. }) = &previous {
            mark_dashboard_nodes(
                options.dashboard,
                [node.id],
                NodeStatus::FinalizationBlocked,
                Some(format!(
                    "Node {:02} • Finalization blocked: {reason}",
                    node.id
                )),
            );
            continue;
        }
        if let Some(FinalizationState::Retrying {
            retry_at, reason, ..
        }) = &previous
            && Instant::now() < *retry_at
        {
            let seconds = retry_at
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1);
            mark_dashboard_nodes(
                options.dashboard,
                [node.id],
                NodeStatus::FinalizationRetrying,
                Some(format!(
                    "Node {:02} window #{} • Finalization retry in {seconds}s ({reason})",
                    node.id, state.work.window_id
                )),
            );
            continue;
        }
        if manager.budget_remaining()?.is_zero() {
            record_finalization_state(
                &options,
                node.id,
                FinalizationState::Blocked {
                    window_id: state.work.window_id,
                    reason: "configured session spending limit is exhausted".to_owned(),
                },
            );
            continue;
        }
        mark_dashboard_nodes(
            options.dashboard,
            [node.id],
            NodeStatus::Finalizing,
            Some(format!("Node {:02} • Finalizing window...", node.id)),
        );
        let unresolved_before = manager
            .journal
            .unresolved_transactions()
            .into_iter()
            .map(|entry| entry.hash)
            .collect::<HashSet<_>>();
        match manager
            .finalize_window(client, signer, node.address, node.id, state.work.window_id)
            .await
        {
            Ok(action) => {
                options
                    .finalization_state
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&node.id);
                report_mining_info(
                    options.dashboard,
                    confirmed_action_message("finalization", &action),
                );
                options
                    .pending_sync
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(
                        node.id,
                        PendingDashboardSync {
                            window_id: state.work.window_id,
                            receipt_block: action.receipt.block_number,
                        },
                    );
                mark_dashboard_nodes(
                    options.dashboard,
                    [node.id],
                    NodeStatus::Syncing,
                    Some(format!("Node {:02} • Syncing finalized window...", node.id)),
                );
                finalized_any = true;
            }
            Err(error)
                if manager
                    .journal
                    .unresolved_transactions()
                    .iter()
                    .any(|entry| !unresolved_before.contains(&entry.hash))
                    || manager.signing_blocked_by_unresolved() =>
            {
                report_mining_warning(
                    options.dashboard,
                    format!(
                        "node {} window {} finalization outcome remains journaled with maximum exposure reserved; no transaction will be resent: {error:#}",
                        node.id, state.work.window_id
                    ),
                );
                if manager.signing_blocked_by_unresolved() {
                    break;
                }
            }
            Err(error) => {
                if let Some(kind) = transaction_policy_refusal(&error) {
                    let reason = match kind {
                        TransactionPolicyRefusalKind::SessionLimitExceeded => {
                            format!("session cap refuses this finalization: {error:#}")
                        }
                        TransactionPolicyRefusalKind::InsufficientConfirmedBalance => {
                            format!(
                                "confirmed INJ balance/reserve refuses this finalization: {error:#}"
                            )
                        }
                        TransactionPolicyRefusalKind::SigningDisabled => {
                            format!("transaction signing is disabled: {error:#}")
                        }
                        TransactionPolicyRefusalKind::UnresolvedNonce => {
                            let attempts = retry_attempts(previous.as_ref()).saturating_add(1);
                            record_finalization_state(
                                &options,
                                node.id,
                                FinalizationState::Retrying {
                                    window_id: state.work.window_id,
                                    attempts,
                                    retry_at: Instant::now() + STALE_PREFLIGHT_RETRY,
                                    reason: format!(
                                        "waiting for an unresolved wallet nonce: {error:#}"
                                    ),
                                },
                            );
                            continue;
                        }
                        TransactionPolicyRefusalKind::DuplicateFinalization => {
                            format!("duplicate finalization refused: {error:#}")
                        }
                        TransactionPolicyRefusalKind::DuplicateProof => {
                            format!("duplicate proof refused: {error:#}")
                        }
                    };
                    record_finalization_state(
                        &options,
                        node.id,
                        FinalizationState::Blocked {
                            window_id: state.work.window_id,
                            reason,
                        },
                    );
                } else if mined_transaction_reverted(&error).is_some_and(|(action, window_id)| {
                    action == TransactionAction::FinalizeWindow && window_id == state.work.window_id
                }) {
                    match client.snapshot(Some(wallet)).await {
                        Ok(fresh) => {
                            let still_finalizable = fresh.nodes.iter().any(|fresh_node| {
                                fresh_node.id == node.id
                                    && fresh_node.state.as_ref().is_some_and(|fresh_state| {
                                        fresh_state.work.window_id == state.work.window_id
                                            && fresh_state.finalizable
                                            && !fresh_state.mining_paused
                                    })
                            });
                            if still_finalizable {
                                let attempts = retry_attempts(previous.as_ref()).saturating_add(1);
                                record_finalization_state(
                                    &options,
                                    node.id,
                                    FinalizationState::Retrying {
                                        window_id: state.work.window_id,
                                        attempts,
                                        retry_at: Instant::now() + STALE_PREFLIGHT_RETRY,
                                        reason: format!(
                                            "confirmed finalization revert revalidated against the canonical window; considering the one safe retry: {error:#}"
                                        ),
                                    },
                                );
                            } else {
                                options
                                    .finalization_state
                                    .write()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .remove(&node.id);
                                report_mining_warning(
                                    options.dashboard,
                                    format!(
                                        "node {} window {} finalization reverted; fresh canonical state has advanced and the transaction will not be resent",
                                        node.id, state.work.window_id
                                    ),
                                );
                            }
                        }
                        Err(state_error) => {
                            let attempts = retry_attempts(previous.as_ref()).saturating_add(1);
                            record_finalization_state(
                                &options,
                                node.id,
                                FinalizationState::Retrying {
                                    window_id: state.work.window_id,
                                    attempts,
                                    retry_at: Instant::now() + finalization_retry_delay(attempts),
                                    reason: format!(
                                        "fresh canonical state is unavailable after a confirmed revert; another attempt remains deferred: {state_error:#}"
                                    ),
                                },
                            );
                        }
                    }
                } else if is_stale_transaction_preflight(&error) {
                    let attempts = retry_attempts(previous.as_ref()).saturating_add(1);
                    record_finalization_state(
                        &options,
                        node.id,
                        FinalizationState::Retrying {
                            window_id: state.work.window_id,
                            attempts,
                            retry_at: Instant::now() + STALE_PREFLIGHT_RETRY,
                            reason: format!("fresh state changed; revalidating: {error:#}"),
                        },
                    );
                } else if is_transient_rpc_error(&error) {
                    let attempts = retry_attempts(previous.as_ref()).saturating_add(1);
                    let delay = finalization_retry_delay(attempts);
                    record_finalization_state(
                        &options,
                        node.id,
                        FinalizationState::Retrying {
                            window_id: state.work.window_id,
                            attempts,
                            retry_at: Instant::now() + delay,
                            reason: format!("transient RPC error: {error:#}"),
                        },
                    );
                } else {
                    record_finalization_state(
                        &options,
                        node.id,
                        FinalizationState::Blocked {
                            window_id: state.work.window_id,
                            reason: format!("permanent or unclassified failure: {error:#}"),
                        },
                    );
                }
            }
        }
        if manager.signing_blocked_by_unresolved() || manager.budget_remaining()?.is_zero() {
            break;
        }
    }
    Ok(finalized_any)
}

fn retry_attempts(previous: Option<&FinalizationState>) -> u8 {
    previous.map_or(0, |state| match state {
        FinalizationState::Retrying { attempts, .. } => *attempts,
        FinalizationState::Blocked { .. } => 0,
    })
}

fn finalization_retry_delay(attempts: u8) -> Duration {
    let exponent = attempts.saturating_sub(1).min(5);
    Duration::from_secs((1_u64 << exponent).min(MAX_POLL_INTERVAL.as_secs()))
}

fn record_finalization_state(
    options: &FinalizationOptions<'_>,
    node_id: u8,
    state: FinalizationState,
) {
    let changed = {
        let mut states = options
            .finalization_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if states.get(&node_id) == Some(&state) {
            false
        } else {
            states.insert(node_id, state.clone());
            true
        }
    };
    if !changed {
        return;
    }
    match state {
        FinalizationState::Retrying {
            window_id,
            attempts,
            retry_at,
            reason,
        } => {
            let delay = retry_at
                .saturating_duration_since(Instant::now())
                .as_secs()
                .max(1);
            let message = format!(
                "node {node_id:02} window {window_id} finalization retry {attempts} scheduled in {delay}s: {reason}"
            );
            report_mining_warning(options.dashboard, message.clone());
            mark_dashboard_nodes(
                options.dashboard,
                [node_id],
                NodeStatus::FinalizationRetrying,
                Some(message),
            );
        }
        FinalizationState::Blocked { window_id, reason } => {
            let message =
                format!("node {node_id:02} window {window_id} finalization blocked: {reason}");
            report_mining_warning(options.dashboard, message.clone());
            mark_dashboard_nodes(
                options.dashboard,
                [node_id],
                NodeStatus::FinalizationBlocked,
                Some(message),
            );
        }
    }
}

fn confirmed_action_message(label: &str, action: &ConfirmedAction) -> String {
    let effective_price = action
        .receipt
        .effective_gas_price
        .map(|price| price.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    format!(
        "{label} confirmed: tx={:#x} | {} | gas={} | effective price={} wei",
        action.transaction_hash, action.outcome, action.receipt.gas_used, effective_price
    )
}

fn is_policy_refusal(error: &anyhow::Error) -> bool {
    transaction_policy_refusal(error).is_some()
}

fn is_unresolved_nonce_refusal(error: &anyhow::Error) -> bool {
    matches!(
        transaction_policy_refusal(error),
        Some(TransactionPolicyRefusalKind::UnresolvedNonce)
    )
}

fn is_session_limit_refusal(error: &anyhow::Error) -> bool {
    matches!(
        transaction_policy_refusal(error),
        Some(
            TransactionPolicyRefusalKind::SessionLimitExceeded
                | TransactionPolicyRefusalKind::SigningDisabled
        )
    )
}

fn is_stale_proof(error: &anyhow::Error) -> bool {
    mined_transaction_reverted(error)
        .is_some_and(|(action, _)| action == TransactionAction::SubmitProof)
}

fn selected_nodes(nodes: &[u8]) -> Result<HashSet<u8>> {
    let mut selected = HashSet::new();
    for node in nodes {
        if !(1..=9).contains(node) || !selected.insert(*node) {
            bail!("node selection must contain unique IDs in the range 1..=9");
        }
    }
    if selected.is_empty() {
        selected.extend(1..=9);
    }
    Ok(selected)
}

pub(crate) fn update_slots(
    slots: &[NodeSlot],
    schedule: &RwLock<Vec<usize>>,
    manifest: &DeploymentManifest,
    miner: Address,
    selected: &HashSet<u8>,
    snapshot: &ReadSnapshot,
) -> Result<bool> {
    let mut changed = false;
    let mut active = Vec::with_capacity(slots.len());
    for (index, slot) in slots.iter().enumerate() {
        let node = snapshot.nodes.iter().find(|node| node.id == slot.id);
        let state = node.and_then(|node| {
            (selected.contains(&node.id) && node.pin.runtime_verified && node.pin.abi_verified)
                .then_some(node.state.as_ref())
                .flatten()
        });
        let contract = node.map(|node| node.address).unwrap_or(Address::ZERO);
        changed |= slot.set_work(manifest, miner, contract, state, &snapshot.block)?;
        if slot.current_work().is_some() {
            active.push(index);
        }
    }
    *schedule
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = active;
    Ok(changed)
}

fn inactive_genesis_nodes(snapshot: &ReadSnapshot, selected: &HashSet<u8>) -> Vec<u8> {
    let mut nodes = snapshot
        .nodes
        .iter()
        .filter(|node| selected.contains(&node.id))
        .filter(|node| node.pin.runtime_verified && node.pin.abi_verified)
        .filter_map(|node| {
            node.state
                .as_ref()
                .and_then(|state| (!state.work.started && !state.work.ended).then_some(node.id))
        })
        .collect::<Vec<_>>();
    nodes.sort_unstable();
    nodes
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SnapshotFreshness {
    Current,
    Reorg,
}

#[derive(Clone, Copy)]
struct ObserverProgress<'a> {
    last_snapshot: &'a ReadSnapshot,
    last_successful_read_at: Instant,
    last_head_advanced_at: Instant,
}

pub(crate) fn start_read_only_observer(
    client: NetworkClient,
    context: DashboardContext,
    initial_snapshot: ReadSnapshot,
    updater: Option<DashboardUpdater>,
    diagnostics: DiagnosticBuffer,
) -> ReadOnlyObserver {
    let (updates_tx, updates_rx) =
        watch::channel(ObserverUpdate::Snapshot(initial_snapshot.clone()));
    let (publications_tx, publications_rx) = watch::channel(None);
    #[cfg(test)]
    let test_publications_sender = publications_tx.clone();
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let (force_refresh, mut refresh_rx) = mpsc::channel(1);
    let refresh_epoch = Arc::new(AtomicU64::new(0));
    let refresh_gate = Arc::new(Mutex::new(()));
    let last_publication_at = Arc::new(Mutex::new(Instant::now()));
    let observer_refresh_epoch = Arc::clone(&refresh_epoch);
    let observer_refresh_gate = Arc::clone(&refresh_gate);
    let observer_last_publication_at = Arc::clone(&last_publication_at);
    #[cfg(test)]
    let test_publications_paused = Arc::new(AtomicBool::new(false));
    #[cfg(test)]
    let test_pause_acknowledged = Arc::new(AtomicBool::new(false));
    #[cfg(test)]
    let observer_test_publications_paused = Arc::clone(&test_publications_paused);
    #[cfg(test)]
    let observer_test_pause_acknowledged = Arc::clone(&test_pause_acknowledged);
    #[cfg(test)]
    let test_updates_sender = Arc::new(Mutex::new(Some(updates_tx.clone())));
    let publication_sequence = Arc::new(AtomicU64::new(0));
    let observer_publication_sequence = Arc::clone(&publication_sequence);
    let task = tokio::spawn(async move {
        let mut last_block = initial_snapshot.block.clone();
        let mut last_snapshot = initial_snapshot;
        let mut last_observed_at = Instant::now();
        let mut last_head_advanced_at = last_observed_at;
        let mut delay = POLL_INTERVAL;
        let mut next_full_refresh = time::Instant::now() + delay;
        let mut genesis_delay = GENESIS_POLL_INTERVAL;
        let mut next_genesis_poll = time::Instant::now() + genesis_delay;
        let mut consecutive_genesis_errors = 0_u8;
        let mut genesis_poll_error_message: Option<String> = None;
        let mut consecutive_errors = 0_u8;
        loop {
            let waiting_nodes = inactive_genesis_nodes(&last_snapshot, &context.selected);
            let wake = tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                    ObserverWake::FullRefresh
                }
                refresh = refresh_rx.recv() => {
                    if refresh.is_none() {
                        break;
                    }
                    ObserverWake::FullRefresh
                }
                _ = time::sleep_until(next_full_refresh) => ObserverWake::FullRefresh,
                _ = time::sleep_until(next_genesis_poll), if !waiting_nodes.is_empty() => {
                    ObserverWake::GenesisProbe(waiting_nodes)
                }
            };
            match wake {
                ObserverWake::FullRefresh => {}
                ObserverWake::GenesisProbe(node_ids) => {
                    match client.poll_genesis(&node_ids).await {
                        Ok(candidates) => {
                            consecutive_genesis_errors = 0;
                            genesis_delay = GENESIS_POLL_INTERVAL;
                            next_genesis_poll = time::Instant::now() + genesis_delay;
                            if let Some(message) = genesis_poll_error_message.take() {
                                clear_observer_genesis_poll_error(&updater, &node_ids, &message);
                            }
                            if candidates.is_empty() {
                                continue;
                            }
                            diagnostics.push(format!(
                                "genesis activation candidate observed for selected node(s) {candidates:?}; requesting a canonical full refresh"
                            ));
                        }
                        Err(error) => {
                            consecutive_genesis_errors =
                                consecutive_genesis_errors.saturating_add(1);
                            let message = format!(
                                "genesis status poll failed for selected node(s) {node_ids:?}: {error:#}"
                            );
                            let report = consecutive_genesis_errors == 1
                                || consecutive_genesis_errors.is_multiple_of(5);
                            if report {
                                diagnostics.push(message.clone());
                            }
                            if observer_genesis_poll_error(&updater, &node_ids, &message) {
                                genesis_poll_error_message = Some(message.clone());
                            }
                            updates_tx
                                .send_replace(ObserverUpdate::GenesisPollError { message, report });
                            *observer_last_publication_at
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Instant::now();
                            genesis_delay = next_poll_delay(genesis_delay);
                            next_genesis_poll = time::Instant::now() + genesis_delay;
                            continue;
                        }
                    }
                }
            }

            let request_epoch = observer_refresh_epoch.load(Ordering::Acquire);
            let request_started = Instant::now();
            let result = client.snapshot(Some(context.address)).await;
            if observer_refresh_epoch.load(Ordering::Acquire) != request_epoch {
                delay = Duration::ZERO;
                next_full_refresh = time::Instant::now();
                continue;
            }
            #[cfg(test)]
            if observer_test_publications_paused.load(Ordering::Acquire) {
                observer_test_pause_acknowledged.store(true, Ordering::Release);
                delay = next_poll_delay(delay);
                next_full_refresh = time::Instant::now() + delay;
                continue;
            }
            #[cfg(test)]
            observer_test_pause_acknowledged.store(false, Ordering::Release);
            match result {
                Ok(mut snapshot) => {
                    let freshness =
                        match snapshot_freshness(&client, &last_block, &snapshot.block).await {
                            Ok(SnapshotFreshness::Reorg) => client
                                .reverify_activated_nodes_after_reorg(&mut snapshot)
                                .await
                                .map(|()| SnapshotFreshness::Reorg),
                            result => result,
                        };
                    let freshness = match freshness {
                        Ok(freshness) => freshness,
                        Err(error) => {
                            client.clear_activation_work_verification();
                            let commit = observer_refresh_gate
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            if observer_refresh_epoch.load(Ordering::Acquire) != request_epoch {
                                drop(commit);
                                delay = Duration::ZERO;
                                next_full_refresh = time::Instant::now();
                                continue;
                            }
                            let message = format!("read-only snapshot rejected: {error:#}");
                            clear_observed_work(&context, &client.manifest, &last_snapshot.block);
                            observer_rpc_error(
                                &context,
                                &updater,
                                &diagnostics,
                                ObserverProgress {
                                    last_snapshot: &last_snapshot,
                                    last_successful_read_at: last_observed_at,
                                    last_head_advanced_at,
                                },
                                &message,
                                &mut consecutive_errors,
                            );
                            let report =
                                consecutive_errors == 1 || consecutive_errors.is_multiple_of(5);
                            updates_tx.send_replace(ObserverUpdate::RpcError { message, report });
                            *observer_last_publication_at
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Instant::now();
                            drop(commit);
                            delay = next_poll_delay(delay);
                            continue;
                        }
                    };
                    let commit = observer_refresh_gate
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if observer_refresh_epoch.load(Ordering::Acquire) != request_epoch {
                        drop(commit);
                        delay = Duration::ZERO;
                        continue;
                    }
                    if freshness == SnapshotFreshness::Reorg {
                        diagnostics.push(format!(
                            "canonical chain head changed during observation at block {}",
                            snapshot.block.number
                        ));
                    }

                    if let Err(error) = update_slots(
                        &context.slots,
                        &context.schedule,
                        &client.manifest,
                        context.address,
                        &context.selected,
                        &snapshot,
                    ) {
                        let message = format!("update verified mining work: {error:#}");
                        clear_observed_work(&context, &client.manifest, &last_snapshot.block);
                        if let Some(updater) = &updater {
                            let snapshot_freshness =
                                snapshot_freshness_description(&last_snapshot, "is stale");
                            let message_for_model = message.clone();
                            updater.update(|model| {
                                if model.session_limit_reached {
                                    model.monitoring_error = Some(format!(
                                        "Read-only observer unavailable — mining remains stopped; {snapshot_freshness}: {message_for_model}"
                                    ));
                                    model.connection_error = None;
                                    model.critical_error = None;
                                } else {
                                    model.critical_error = Some(message_for_model);
                                }
                            });
                        }
                        diagnostics.push(message.clone());
                        updates_tx.send_replace(ObserverUpdate::Fatal(message));
                        drop(commit);
                        break;
                    }

                    trace_snapshot_transitions(
                        &context.selected,
                        &last_snapshot,
                        &snapshot,
                        last_observed_at,
                        request_started.elapsed(),
                        &diagnostics,
                    );
                    let observed_at = Instant::now();
                    if snapshot.block.number != last_block.number
                        || snapshot.block.hash != last_block.hash
                    {
                        last_head_advanced_at = observed_at;
                    }
                    trace_node_liveness(
                        &context,
                        &snapshot,
                        last_observed_at,
                        last_head_advanced_at,
                        observed_at,
                        &diagnostics,
                    );
                    last_block = snapshot.block.clone();
                    last_snapshot = snapshot.clone();
                    last_observed_at = observed_at;
                    consecutive_errors = 0;
                    delay = POLL_INTERVAL;
                    next_full_refresh = time::Instant::now() + delay;
                    if consecutive_genesis_errors == 0 {
                        genesis_delay = GENESIS_POLL_INTERVAL;
                        if next_genesis_poll <= time::Instant::now() {
                            next_genesis_poll = time::Instant::now() + genesis_delay;
                        }
                    }
                    refresh_dashboard(updater.as_ref(), &context, &snapshot);
                    genesis_poll_error_message = None;
                    let publication_sequence = observer_publication_sequence
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |sequence| {
                            sequence.checked_add(1)
                        })
                        .expect("observer publication sequence exhausted")
                        + 1;
                    publications_tx.send_replace(Some(RefreshPublication {
                        epoch: request_epoch,
                        sequence: publication_sequence,
                        snapshot: snapshot.clone(),
                    }));
                    // A consumer awakened by the snapshot update must already be able to
                    // read the publication identity that qualifies that same snapshot.
                    updates_tx.send_replace(ObserverUpdate::Snapshot(snapshot));
                    *observer_last_publication_at
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                    drop(commit);
                }
                Err(error) => {
                    let commit = observer_refresh_gate
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if observer_refresh_epoch.load(Ordering::Acquire) != request_epoch {
                        drop(commit);
                        delay = Duration::ZERO;
                        next_full_refresh = time::Instant::now();
                        continue;
                    }
                    let message = format!("RPC refresh failed; stale work stopped: {error:#}");
                    client.clear_activation_work_verification();
                    clear_observed_work(&context, &client.manifest, &last_snapshot.block);
                    observer_rpc_error(
                        &context,
                        &updater,
                        &diagnostics,
                        ObserverProgress {
                            last_snapshot: &last_snapshot,
                            last_successful_read_at: last_observed_at,
                            last_head_advanced_at,
                        },
                        &message,
                        &mut consecutive_errors,
                    );
                    let report = consecutive_errors == 1 || consecutive_errors.is_multiple_of(5);
                    updates_tx.send_replace(ObserverUpdate::RpcError { message, report });
                    *observer_last_publication_at
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                    drop(commit);
                    delay = next_poll_delay(delay);
                    next_full_refresh = time::Instant::now() + delay;
                    genesis_delay = next_poll_delay(genesis_delay);
                    next_genesis_poll = time::Instant::now() + genesis_delay;
                }
            }
        }
    });
    ReadOnlyObserver {
        shutdown: shutdown_tx,
        updates: updates_rx,
        force_refresh,
        refresh_epoch,
        publications: publications_rx,
        refresh_gate,
        last_publication_at,
        #[cfg(test)]
        test_publications_paused,
        #[cfg(test)]
        test_pause_acknowledged,
        #[cfg(test)]
        test_updates_sender,
        #[cfg(test)]
        test_publications_sender,
        #[cfg(test)]
        test_publication_sequence: publication_sequence,
        task,
    }
}

async fn snapshot_freshness(
    client: &NetworkClient,
    previous: &crate::rpc::BlockSnapshot,
    next: &crate::rpc::BlockSnapshot,
) -> Result<SnapshotFreshness> {
    let previous_canonical = if next.number < previous.number {
        match client.canonical_block_hash(previous.number).await {
            Ok(hash) => Some(hash),
            Err(previous_error) => {
                let next_canonical = client.canonical_block_hash(next.number).await?;
                let current_head = client.latest_block_snapshot().await?;
                if next_canonical == next.hash
                    && current_head.number == next.number
                    && current_head.hash == next.hash
                {
                    // A reorging provider head may no longer serve the removed height.
                    // Accept the lower snapshot only when the selected RPC still reports it
                    // as the current canonical head.
                    return Ok(SnapshotFreshness::Reorg);
                }
                return Err(previous_error)
                    .context("cannot verify a lower snapshot after the prior block disappeared");
            }
        }
    } else {
        None
    };
    let next_canonical = if next.number == previous.number && next.hash != previous.hash {
        Some(client.canonical_block_hash(next.number).await?)
    } else {
        None
    };
    let freshness = compare_snapshot_freshness(previous, next, previous_canonical, next_canonical)?;
    if freshness == SnapshotFreshness::Reorg && next.number < previous.number {
        if client.canonical_block_hash(next.number).await? != next.hash {
            bail!(
                "selected RPC does not report lower snapshot block {} as canonical",
                next.number
            );
        }
        let current_head = client.latest_block_snapshot().await?;
        if current_head.number != next.number || current_head.hash != next.hash {
            bail!(
                "lower snapshot block {} is not the current canonical head {}",
                next.number,
                current_head.number
            );
        }
    }
    Ok(freshness)
}

fn compare_snapshot_freshness(
    previous: &crate::rpc::BlockSnapshot,
    next: &crate::rpc::BlockSnapshot,
    previous_canonical: Option<B256>,
    next_canonical: Option<B256>,
) -> Result<SnapshotFreshness> {
    if next.number < previous.number {
        match previous_canonical {
            Some(hash) if hash == previous.hash => bail!(
                "RPC returned block {} after verified block {} while the previous head remains canonical",
                next.number,
                previous.number
            ),
            Some(_) => return Ok(SnapshotFreshness::Reorg),
            None => bail!("cannot establish whether the prior chain head remains canonical"),
        }
    }
    if next.number == previous.number && next.hash != previous.hash {
        if next_canonical != Some(next.hash) {
            bail!(
                "selected RPC does not report snapshot block {} as canonical",
                next.number
            );
        }
        return Ok(SnapshotFreshness::Reorg);
    }
    Ok(SnapshotFreshness::Current)
}

fn trace_snapshot_transitions(
    selected: &HashSet<u8>,
    previous: &ReadSnapshot,
    current: &ReadSnapshot,
    previous_observed_at: Instant,
    request_elapsed: Duration,
    diagnostics: &DiagnosticBuffer,
) {
    for node_id in selected {
        let before = previous.nodes.iter().find(|node| node.id == *node_id);
        let after = current.nodes.iter().find(|node| node.id == *node_id);
        let before_trusted =
            before.is_some_and(|node| node.pin.runtime_verified && node.pin.abi_verified);
        let after_trusted =
            after.is_some_and(|node| node.pin.runtime_verified && node.pin.abi_verified);
        let before_state = before
            .filter(|_| before_trusted)
            .and_then(|node| node.state.as_ref());
        let after_state = after
            .filter(|_| after_trusted)
            .and_then(|node| node.state.as_ref());
        let before_window = before_state.map(|state| state.work.window_id);
        let after_window = after_state.map(|state| state.work.window_id);
        let before_status = traced_node_status(before_state, before_trusted);
        let after_status = traced_node_status(after_state, after_trusted);
        let before_candidate = before_state
            .and_then(|state| state.candidate.as_ref().map(|candidate| candidate.miner));
        let after_candidate =
            after_state.and_then(|state| state.candidate.as_ref().map(|candidate| candidate.miner));
        let before_expiry = before_state.map(|state| state.work.window_expiry_time);
        let after_expiry = after_state.map(|state| state.work.window_expiry_time);
        if before_window == after_window
            && before_status == after_status
            && before_candidate == after_candidate
            && before_expiry == after_expiry
        {
            continue;
        }
        let observation_interval_ms = Instant::now()
            .saturating_duration_since(previous_observed_at)
            .as_millis();
        let message = format!(
            "state-transition node={node_id:02} block={}..{} hash={:#x}->{:#x} window={before_window:?}->{after_window:?} status={before_status}->{after_status} candidate={}->{} expiry={before_expiry:?}->{after_expiry:?} chain_ts={} observation_interval_ms={} rpc_ms={}",
            previous.block.number,
            current.block.number,
            previous.block.hash,
            current.block.hash,
            display_candidate(before_candidate),
            display_candidate(after_candidate),
            current.block.timestamp,
            observation_interval_ms,
            request_elapsed.as_millis(),
        );
        diagnostics.push(message);
    }
}

fn trace_node_liveness(
    context: &DashboardContext,
    snapshot: &ReadSnapshot,
    last_successful_read_at: Instant,
    last_head_advanced_at: Instant,
    observed_at: Instant,
    diagnostics: &DiagnosticBuffer,
) {
    let schedule = context
        .schedule
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let activities = context
        .transaction_state
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let finalization = context
        .finalization_state
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let worker_enabled = context.workers_started.load(Ordering::Acquire);
    let authorization_used = activities
        .authorization_used
        .map(|amount| amount.to_string())
        .unwrap_or_else(|| "unavailable".to_owned());
    for node_id in &context.selected {
        let node = snapshot.nodes.iter().find(|node| node.id == *node_id);
        let trusted = node.is_some_and(|node| node.pin.runtime_verified && node.pin.abi_verified);
        let state = node
            .filter(|_| trusted)
            .and_then(|node| node.state.as_ref());
        let slot = &context.slots[usize::from(*node_id - 1)];
        let (slot_active, slot_suspended, deadline, slot_window) = slot.diagnostic_work();
        let scheduled = schedule.contains(&usize::from(*node_id - 1));
        let local_deadline_expired = deadline.is_some_and(|deadline| observed_at >= deadline);
        let transaction = activities
            .activities
            .iter()
            .find(|activity| activity.node_id == *node_id)
            .map(|activity| format!("{:?}@{}", activity.state, activity.window_id))
            .unwrap_or_else(|| "none".to_owned());
        let finalization_state = finalization
            .get(node_id)
            .map(|state| format!("{state:?}"))
            .unwrap_or_else(|| "none".to_owned());
        let (eligible, finalizable, paused, ended, chain_window) =
            state.map_or((false, false, false, false, None), |state| {
                (
                    state.eligible,
                    state.finalizable,
                    state.mining_paused,
                    state.work.ended,
                    Some(state.work.window_id),
                )
            });
        let deadline_state = deadline.map_or_else(
            || "none".to_owned(),
            |deadline| {
                format!(
                    "{}ms_remaining",
                    deadline.saturating_duration_since(observed_at).as_millis()
                )
            },
        );
        diagnostics.push(format!(
            "node-liveness node={node_id:02} window={chain_window:?} block={} hash={:#x} verified={trusted} eligible={eligible} finalizable={finalizable} paused={paused} ended={ended} local_slot={slot_active} suspended={slot_suspended} slot_window={slot_window:?} scheduled={scheduled} workers_enabled={worker_enabled} deadline={deadline_state} deadline_expired={local_deadline_expired} head_progress_age_ms={} successful_rpc_age_ms={} node_hashes={} hashes_total={} tx={transaction} authorization_used_wei={authorization_used} finalization={finalization_state}",
            snapshot.block.number,
            snapshot.block.hash,
            observed_at
                .saturating_duration_since(last_head_advanced_at)
                .as_millis(),
            observed_at
                .saturating_duration_since(last_successful_read_at)
                .as_millis(),
            slot.completed_hashes(),
            context.total_hashes.load(Ordering::Relaxed),
        ));
    }
}

fn traced_node_status(state: Option<&NodeState>, trusted: bool) -> &'static str {
    if !trusted || state.is_none() {
        return "RPC ERROR";
    }
    let state = state.expect("checked above");
    if state.work.ended {
        "ENDED"
    } else if !state.work.started {
        "WAIT GENESIS"
    } else if state.work.remaining_allocation.is_zero() {
        "ENDED"
    } else if state.mining_paused {
        "PAUSED"
    } else if state.finalizable {
        "FINALIZING"
    } else if state.eligible {
        "MINING"
    } else {
        "WAITING"
    }
}

fn display_candidate(candidate: Option<Address>) -> String {
    candidate
        .map(|address| format!("{address:#x}"))
        .unwrap_or_else(|| "None".to_owned())
}

fn clear_observed_work(
    context: &DashboardContext,
    manifest: &DeploymentManifest,
    block: &BlockSnapshot,
) {
    for slot in context.slots.iter() {
        let _ = slot.set_work(manifest, context.address, Address::ZERO, None, block);
    }
    *context
        .schedule
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Vec::new();
}

fn observer_rpc_error(
    context: &DashboardContext,
    updater: &Option<DashboardUpdater>,
    diagnostics: &DiagnosticBuffer,
    progress: ObserverProgress<'_>,
    message: &str,
    consecutive_errors: &mut u8,
) {
    *consecutive_errors = consecutive_errors.saturating_add(1);
    if *consecutive_errors == 1 || consecutive_errors.is_multiple_of(5) {
        diagnostics.push(format!(
            "{message}; last_verified_block={} hash={:#x} last_successful_read_age_ms={} last_head_advance_age_ms={}",
            progress.last_snapshot.block.number,
            progress.last_snapshot.block.hash,
            Instant::now()
                .saturating_duration_since(progress.last_successful_read_at)
                .as_millis(),
            Instant::now()
                .saturating_duration_since(progress.last_head_advanced_at)
                .as_millis(),
        ));
    }
    if let Some(updater) = updater {
        let activities = context
            .transaction_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .activities
            .clone();
        let snapshot_freshness =
            snapshot_freshness_description(progress.last_snapshot, "may be stale");
        let message = message.to_owned();
        updater.update(|model| {
            if model.session_limit_reached {
                model.monitoring_error = Some(format!(
                    "Read-only observer unavailable — {snapshot_freshness}; mining remains stopped: {message}"
                ));
                model.connection_error = None;
                model.critical_error = None;
            } else {
                model.connection_error = Some(message.clone());
            }
            for node in &mut model.selected_nodes {
                if let Some(activity) = activities
                    .iter()
                    .find(|item| item.node_id == node.id && node.window_id == Some(item.window_id))
                {
                    node.status = match activity.state {
                        TransactionActivityState::Finalizing => NodeStatus::Finalizing,
                        TransactionActivityState::Signed => NodeStatus::Signed,
                        TransactionActivityState::Confirming => NodeStatus::Confirming,
                        TransactionActivityState::Recovering => NodeStatus::Recovering,
                    };
                } else {
                    node.status = NodeStatus::RpcError;
                    node.mining_deadline = None;
                }
            }
        });
    }
}

fn observer_genesis_poll_error(
    updater: &Option<DashboardUpdater>,
    node_ids: &[u8],
    message: &str,
) -> bool {
    let Some(updater) = updater else {
        return false;
    };
    let mut installed = false;
    updater.update(|model| installed = apply_genesis_poll_error(model, node_ids, message));
    installed
}

fn apply_genesis_poll_error(model: &mut DashboardModel, node_ids: &[u8], message: &str) -> bool {
    if model.session_limit_reached {
        model.monitoring_error = Some(format!(
            "Read-only genesis polling unavailable — mining remains stopped: {message}"
        ));
        model.connection_error = None;
        return true;
    }
    if model.connection_error.is_some() {
        return false;
    }
    model.connection_error = Some(message.to_owned());
    for node in &mut model.selected_nodes {
        if node_ids.contains(&node.id) && node.status == NodeStatus::WaitingForGenesis {
            node.status = NodeStatus::RpcError;
            node.mining_deadline = None;
        }
    }
    true
}

fn clear_observer_genesis_poll_error(
    updater: &Option<DashboardUpdater>,
    node_ids: &[u8],
    message: &str,
) {
    let Some(updater) = updater else {
        return;
    };
    updater.update(|model| {
        clear_genesis_poll_error(model, node_ids, message);
    });
}

fn clear_genesis_poll_error(model: &mut DashboardModel, node_ids: &[u8], message: &str) -> bool {
    if model.session_limit_reached
        && model
            .monitoring_error
            .as_deref()
            .is_some_and(|error| error.contains(message))
    {
        model.monitoring_error = None;
        return true;
    }
    if model.connection_error.as_deref() != Some(message) {
        return false;
    }
    model.connection_error = None;
    for node in &mut model.selected_nodes {
        if node_ids.contains(&node.id) && node.status == NodeStatus::RpcError {
            node.status = NodeStatus::WaitingForGenesis;
        }
    }
    true
}

fn unavailable_read_snapshot(message: &str) -> ReadSnapshot {
    ReadSnapshot {
        block: BlockSnapshot {
            number: 0,
            timestamp: 0,
            hash: B256::ZERO,
        },
        native_balance: None,
        native_balance_error: Some(message.to_owned()),
        ast_balance: None,
        ast_balance_error: Some(message.to_owned()),
        nodes: Vec::new(),
    }
}

fn snapshot_freshness_description(snapshot: &ReadSnapshot, state: &str) -> String {
    if snapshot.block.hash == B256::ZERO {
        "no verified snapshot is available".to_owned()
    } else {
        format!("last verified block #{} {state}", snapshot.block.number)
    }
}

fn dashboard_model(
    context: &DashboardContext,
    snapshot: &ReadSnapshot,
    observed_at: Instant,
) -> DashboardModel {
    let mut selected_ids = context.selected.iter().copied().collect::<Vec<_>>();
    selected_ids.sort_unstable();
    let transaction_state = context
        .transaction_state
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let active_backend = context
        .active_backend
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let pending_sync = context
        .pending_sync
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let finalization_state = context
        .finalization_state
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let mut nodes = Vec::with_capacity(selected_ids.len());
    let mut first_error = None;
    for id in selected_ids {
        let view = snapshot.nodes.iter().find(|node| node.id == id);
        let trusted = view.is_some_and(|node| node.pin.runtime_verified && node.pin.abi_verified);
        let state = view
            .filter(|_| trusted)
            .and_then(|node| node.state.as_ref());
        let activity = transaction_state.activities.iter().find(|activity| {
            activity.node_id == id
                && state.is_some_and(|state| state.work.window_id == activity.window_id)
        });
        let slot_work = context.slots[usize::from(id - 1)].current_work();
        let mut status = dashboard_node_status(
            state,
            trusted,
            context.workers_started.load(Ordering::Acquire) && slot_work.is_some(),
            context.workers_started.load(Ordering::Acquire),
            activity.map(|activity| activity.state),
        );
        if activity.is_none()
            && let Some(state) = state
            && let Some(finalization) = finalization_state.get(&id)
        {
            status = match finalization {
                FinalizationState::Retrying { window_id, .. }
                    if *window_id == state.work.window_id =>
                {
                    NodeStatus::FinalizationRetrying
                }
                FinalizationState::Blocked { window_id, .. }
                    if *window_id == state.work.window_id =>
                {
                    NodeStatus::FinalizationBlocked
                }
                _ => status,
            };
        }
        let pending = pending_sync.get(&id).copied();
        let syncing = pending.is_some_and(|pending| {
            activity.is_none()
                && (snapshot.block.number < pending.receipt_block
                    || !trusted
                    || state.is_none()
                    || state.is_some_and(|state| state.work.window_id < pending.window_id))
        });
        if syncing {
            status = NodeStatus::Syncing;
        }
        if first_error.is_none() {
            first_error = view
                .and_then(|node| node.error.as_deref().or(node.pin.error.as_deref()))
                .map(str::to_owned);
        }
        let candidate = (!syncing && trusted)
            .then(|| {
                state.and_then(|state| state.candidate.as_ref().map(|candidate| candidate.miner))
            })
            .flatten();
        let reward = trusted
            .then(|| state.map(|state| state.work.reward_per_window))
            .flatten();
        nodes.push(DashboardNode {
            id,
            window_id: state.map(|state| state.work.window_id),
            status,
            expiry_timestamp: state.map(|state| state.work.window_expiry_time),
            mining_deadline: slot_work.map(|work| work.valid_until),
            countdown: state.map(|state| {
                WindowCountdown::from_snapshot(
                    state.work.window_id,
                    state.work.window_expiry_time,
                    snapshot.block.timestamp,
                    observed_at,
                )
            }),
            candidate,
            reward,
        });
    }
    let selected_windows_expired = !nodes.is_empty()
        && nodes.iter().all(|node| {
            matches!(
                node.status,
                NodeStatus::FinalizationRequired
                    | NodeStatus::FinalizationRetrying
                    | NodeStatus::FinalizationBlocked
                    | NodeStatus::Finalizing
                    | NodeStatus::Syncing
            )
        });
    let detail_action = nodes.iter().find_map(|node| {
        let window_id = node.window_id?;
        match (node.status, finalization_state.get(&node.id)) {
            (
                NodeStatus::FinalizationRetrying,
                Some(FinalizationState::Retrying {
                    window_id: tracked,
                    retry_at,
                    reason,
                    ..
                }),
            ) if *tracked == window_id => {
                let seconds = retry_at
                    .saturating_duration_since(Instant::now())
                    .as_secs()
                    .max(1);
                Some(format!(
                    "Node {:02} window #{window_id} • retrying finalization in {seconds}s: {reason}",
                    node.id
                ))
            }
            (
                NodeStatus::FinalizationBlocked,
                Some(FinalizationState::Blocked {
                    window_id: tracked,
                    reason,
                }),
            ) if *tracked == window_id => Some(format!(
                "Node {:02} window #{window_id} • finalization blocked: {reason}",
                node.id
            )),
            (NodeStatus::FinalizationRequired, _) => Some(format!(
                "Node {:02} window #{window_id} • finalization required{}",
                node.id,
                if context.compute_only || !context.transaction_mode {
                    "; Testnet transaction signing is disabled"
                } else {
                    "; verifying transaction budget and canonical state"
                }
            )),
            (NodeStatus::WaitingForChain, _) => Some(format!(
                "Node {:02} window #{window_id} • local work stopped at its safety deadline; waiting for a newer canonical block",
                node.id
            )),
            _ => None,
        }
    });
    let current_action = if selected_windows_expired {
        Some(match detail_action {
            Some(action) => format!("0 H/s expected • all selected windows expired • {action}"),
            None => "0 H/s expected • all selected windows expired".to_owned(),
        })
    } else {
        detail_action
    };
    DashboardModel {
        network: context.network,
        chain_id: context.chain_id,
        wallet: context.address,
        inj_balance: snapshot.native_balance,
        ast_balance: snapshot.ast_balance,
        mined_rewards: transaction_state.mined_rewards,
        device_label: active_backend.label().to_owned(),
        device_detail: active_backend.detail(),
        session_limit: Some(context.spending_limit),
        authorization_used: transaction_state.authorization_used,
        actual_rpc_cost: transaction_state.actual_rpc_cost,
        block_number: snapshot.block.number,
        block_hash: snapshot.block.hash,
        snapshot_observed_at: observed_at,
        last_block_advanced_at: observed_at,
        snapshot_ready: snapshot.block.hash != B256::ZERO,
        selected_nodes: nodes,
        compute_only: context.compute_only,
        signing_enabled: context.transaction_mode,
        recovering: transaction_state
            .activities
            .iter()
            .any(|activity| activity.state == TransactionActivityState::Recovering),
        stopping: false,
        session_limit_reached: false,
        monitoring_error: None,
        hashrate: 0.0,
        current_action,
        connection_error: first_error,
        critical_error: None,
    }
}

fn dashboard_node_status(
    state: Option<&NodeState>,
    trusted: bool,
    has_current_work: bool,
    workers_started: bool,
    activity: Option<TransactionActivityState>,
) -> NodeStatus {
    if let Some(activity) = activity {
        return match activity {
            TransactionActivityState::Finalizing => NodeStatus::Finalizing,
            TransactionActivityState::Signed => NodeStatus::Signed,
            TransactionActivityState::Confirming => NodeStatus::Confirming,
            TransactionActivityState::Recovering => NodeStatus::Recovering,
        };
    }
    if !trusted || state.is_none() {
        return NodeStatus::RpcError;
    }
    let state = state.expect("checked above");
    if state.work.ended {
        NodeStatus::Ended
    } else if !state.work.started {
        NodeStatus::WaitingForGenesis
    } else if state.work.remaining_allocation.is_zero() {
        NodeStatus::Ended
    } else if state.mining_paused {
        NodeStatus::Paused
    } else if state.finalizable {
        NodeStatus::FinalizationRequired
    } else if state.eligible && has_current_work {
        NodeStatus::Mining
    } else if state.eligible && workers_started {
        NodeStatus::WaitingForChain
    } else {
        NodeStatus::Waiting
    }
}

fn refresh_dashboard(
    updater: Option<&DashboardUpdater>,
    context: &DashboardContext,
    snapshot: &ReadSnapshot,
) {
    let Some(updater) = updater else {
        return;
    };
    let observed_at = Instant::now();
    {
        let mut pending = context
            .pending_sync
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.retain(|node_id, action| {
            snapshot.block.number < action.receipt_block
                || !snapshot.nodes.iter().any(|node| {
                    node.id == *node_id
                        && node.pin.runtime_verified
                        && node.pin.abi_verified
                        && node
                            .state
                            .as_ref()
                            .is_some_and(|state| state.work.window_id >= action.window_id)
                })
        });
    }
    let mut updated = dashboard_model(context, snapshot, observed_at);
    let chain_timestamp = snapshot.block.timestamp;
    updater.update(|model| {
        let hashrate = model.hashrate;
        let head_advanced = reconcile_head_progress(model, &mut updated, observed_at);
        if !head_advanced
            && let Some(node) = updated
                .selected_nodes
                .iter()
                .find(|node| node.status == NodeStatus::WaitingForChain)
        {
            let age = observed_at
                .saturating_duration_since(updated.last_block_advanced_at)
                .as_secs();
            updated.current_action = Some(format!(
                "Node {:02} window #{} • waiting for a new canonical block ({age}s); stale work is stopped",
                node.id,
                node.window_id.unwrap_or_default()
            ));
        }
        for node in &mut updated.selected_nodes {
            let Some(previous) = model.selected_nodes.iter().find(|old| old.id == node.id) else {
                continue;
            };
            if node.window_id.is_some() && node.window_id == previous.window_id {
                if let (Some(previous_clock), Some(new_clock)) =
                    (previous.countdown.as_ref(), node.countdown.as_ref())
                {
                    node.countdown = Some(previous_clock.reconcile_same_window(
                        new_clock.expiry_timestamp,
                        chain_timestamp,
                        observed_at,
                    ));
                }
            } else if node.status == NodeStatus::RpcError && node.window_id.is_none() {
                node.window_id = previous.window_id;
                node.expiry_timestamp = previous.expiry_timestamp;
                node.countdown = previous
                    .countdown
                    .as_ref()
                    .map(|countdown| countdown.reanchor(observed_at));
                node.candidate = previous.candidate;
                node.reward = previous.reward;
            }
        }
        *model = updated;
        model.hashrate = hashrate;
        let transaction_state = context
            .transaction_state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        apply_transaction_state_to_model(model, &transaction_state);
    });
}

fn reconcile_head_progress(
    previous: &DashboardModel,
    next: &mut DashboardModel,
    observed_at: Instant,
) -> bool {
    let advanced = !previous.snapshot_ready
        || next.block_number != previous.block_number
        || next.block_hash != previous.block_hash;
    next.last_block_advanced_at = if advanced {
        observed_at
    } else {
        previous.last_block_advanced_at
    };
    advanced
}

fn mark_dashboard_nodes(
    dashboard: &Option<Dashboard>,
    node_ids: impl IntoIterator<Item = u8>,
    status: NodeStatus,
    action: Option<String>,
) {
    let Some(dashboard) = dashboard else {
        return;
    };
    let node_ids = node_ids.into_iter().collect::<HashSet<_>>();
    dashboard.update(|model| {
        for node in &mut model.selected_nodes {
            if node_ids.contains(&node.id) {
                node.status = status;
                if status == NodeStatus::Syncing {
                    node.candidate = None;
                }
            }
        }
        model.current_action = action;
    });
}

struct SessionLimitRuntimeControl {
    session_limit_reached: Arc<AtomicBool>,
    worker_stop: Arc<AtomicBool>,
    total_hashes: Arc<AtomicU64>,
    proof_paused: Arc<AtomicBool>,
    proof_pause_latched: Arc<AtomicBool>,
}

fn connect_transaction_dashboard(
    transactions: &mut Option<TransactionManager>,
    dashboard: &Option<Dashboard>,
    transaction_state: Arc<RwLock<TransactionDashboardState>>,
    session_limit_control: Option<SessionLimitRuntimeControl>,
) -> Result<()> {
    let Some(manager) = transactions.as_mut() else {
        return Ok(());
    };
    let updater = dashboard.as_ref().map(Dashboard::updater);
    manager.set_dashboard_sink(Arc::new(move |state| {
        *transaction_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state.clone();
        if let Some(updater) = &updater {
            updater.update(|model| apply_transaction_state_to_model(model, &state));
        }
    }));
    if let Some(session_limit_control) = session_limit_control {
        let updater = dashboard.as_ref().map(Dashboard::updater);
        manager.set_session_limit_reached_sink(Arc::new(move || {
            let first_latch = session_limit_control
                .session_limit_reached
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok();
            session_limit_control
                .worker_stop
                .store(true, Ordering::Release);
            session_limit_control
                .proof_pause_latched
                .store(true, Ordering::Release);
            session_limit_control
                .proof_paused
                .store(true, Ordering::Release);
            session_limit_control
                .total_hashes
                .store(0, Ordering::Relaxed);
            if let Some(updater) = &updater {
                updater.update(DashboardModel::latch_session_limit);
            } else if first_latch {
                eprintln!(
                    "SESSION LIMIT REACHED • Press Ctrl+C to exit and run astatine mine again"
                );
            }
        }))?;
    }
    Ok(())
}

fn apply_transaction_state_to_model(model: &mut DashboardModel, state: &TransactionDashboardState) {
    model.authorization_used = state.authorization_used;
    model.actual_rpc_cost = state.actual_rpc_cost;
    model.mined_rewards = state.mined_rewards;
    model.recovering = state
        .activities
        .iter()
        .any(|activity| activity.state == TransactionActivityState::Recovering);
    for activity in &state.activities {
        let Some(node) = model
            .selected_nodes
            .iter_mut()
            .find(|node| node.id == activity.node_id)
        else {
            continue;
        };
        if node.window_id == Some(activity.window_id) {
            node.status = match activity.state {
                TransactionActivityState::Finalizing => NodeStatus::Finalizing,
                TransactionActivityState::Signed => NodeStatus::Signed,
                TransactionActivityState::Confirming => NodeStatus::Confirming,
                TransactionActivityState::Recovering => NodeStatus::Recovering,
            };
        }
    }
    let transaction_action = state.activities.first().map(|activity| {
        let action = match activity.state {
            TransactionActivityState::Finalizing => "Finalizing window",
            TransactionActivityState::Signed => "Signed; awaiting RPC broadcast",
            TransactionActivityState::Confirming => "Confirming transaction",
            TransactionActivityState::Recovering => "Recovering transaction",
        };
        let chain_window = model
            .selected_nodes
            .iter()
            .find(|node| node.id == activity.node_id)
            .and_then(|node| node.window_id);
        match chain_window {
            Some(current) if current > activity.window_id => format!(
                "Node {:02} • {action} for older window #{}; chain now at #{}",
                activity.node_id, activity.window_id, current
            ),
            Some(current) if current != activity.window_id => format!(
                "Node {:02} • {action} for window #{}; chain reports #{}",
                activity.node_id, activity.window_id, current
            ),
            _ => format!(
                "Node {:02} window #{} • {action}...",
                activity.node_id, activity.window_id
            ),
        }
    });
    if transaction_action.is_some() {
        model.current_action = transaction_action;
    } else if model.current_action.as_deref().is_some_and(|action| {
        action.contains("Confirming transaction")
            || action.contains("Signed; awaiting RPC broadcast")
            || action.contains("Finalizing window")
            || action.contains("Recovering transaction")
    }) {
        model.current_action = None;
    }
}

fn initial_transaction_dashboard_state(
    manager: Option<&TransactionManager>,
    diagnostics: &DiagnosticBuffer,
) -> TransactionDashboardState {
    let Some(manager) = manager else {
        return TransactionDashboardState::default();
    };
    let authorization_used = match manager.authorization_used() {
        Ok(exposure) => exposure,
        Err(error) => {
            diagnostics.push(format!(
                "dashboard could not read session authorization total: {error:#}"
            ));
            None
        }
    };
    let actual_rpc_cost = match manager.actual_rpc_cost() {
        Ok(cost) => cost,
        Err(error) => {
            diagnostics.push(format!(
                "dashboard could not read RPC-reported transaction costs: {error:#}"
            ));
            None
        }
    };
    TransactionDashboardState {
        authorization_used,
        actual_rpc_cost,
        mined_rewards: manager.mined_rewards_total(),
        activities: manager.dashboard_activities(),
    }
}

fn report_mining_info(dashboard: &Option<Dashboard>, message: impl Into<String>) {
    let message = message.into();
    if let Some(dashboard) = dashboard {
        dashboard.diagnostics().push(message);
    } else {
        println!("{}", crate::diagnostics::terminal_text(&message));
    }
}

fn history_profile_enabled(value: Option<&str>) -> bool {
    value == Some("1")
}

pub(crate) fn optional_history_profile(
    enabled: bool,
    profile: impl FnOnce() -> String,
) -> Option<String> {
    enabled.then(profile)
}

fn report_mining_warning(dashboard: &Option<Dashboard>, message: impl Into<String>) {
    let message = message.into();
    if let Some(dashboard) = dashboard {
        dashboard.diagnostics().push(message);
    } else {
        eprintln!("{}", crate::diagnostics::terminal_text(&message));
    }
}

fn report_terminal_dashboard_failure(dashboard: &Option<Dashboard>, message: String) {
    report_terminal_dashboard_failure_to(dashboard.as_ref().map(Dashboard::diagnostics), message);
}

fn report_terminal_dashboard_failure_to(diagnostics: Option<DiagnosticBuffer>, message: String) {
    // A failed dashboard cannot be relied on to render its diagnostic buffer.
    // Keep the immediate fallback visible without bypassing terminal sanitization.
    eprintln!("astatine: {}", crate::diagnostics::terminal_text(&message));
    if let Some(diagnostics) = diagnostics {
        diagnostics.push(message);
    }
}

fn report_terminal_monitoring_degraded(
    dashboard: &Option<Dashboard>,
    updater: Option<&DashboardUpdater>,
    observer_monitoring_degraded: &AtomicBool,
    last_reported: &mut Option<String>,
    message: String,
) {
    observer_monitoring_degraded.store(true, Ordering::Release);
    if let Some(updater) = updater {
        let message_for_model = message.clone();
        updater.update(|model| {
            if model.session_limit_reached {
                model.monitoring_error = Some(message_for_model);
                model.connection_error = None;
                model.critical_error = None;
            }
        });
    }
    if last_reported.as_deref() != Some(message.as_str()) {
        report_mining_warning(dashboard, message.clone());
        *last_reported = Some(message);
    }
}

fn clear_terminal_monitoring_degraded(
    updater: Option<&DashboardUpdater>,
    observer_monitoring_degraded: &AtomicBool,
    last_reported: &mut Option<String>,
) {
    observer_monitoring_degraded.store(false, Ordering::Release);
    if last_reported.take().is_some()
        && let Some(updater) = updater
    {
        updater.update(|model| model.monitoring_error = None);
    }
}

fn flush_dashboard_diagnostics(dashboard: &Dashboard) {
    for message in dashboard.drain_diagnostics() {
        eprintln!("astatine: {message}");
    }
}

async fn wait_for_dashboard_event(signal: Option<DashboardSignal>) -> DashboardEventKind {
    match signal {
        Some(signal) => signal.wait().await,
        None => std::future::pending().await,
    }
}

fn print_startup(
    client: &NetworkClient,
    address: Address,
    active_backend: &Arc<RwLock<ActiveBackend>>,
    snapshot: &ReadSnapshot,
    slots: &[NodeSlot],
    selected: &HashSet<u8>,
    selected_work_changed: bool,
) {
    let backend = active_backend
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let ast_decimals = client
        .manifest
        .ast_token
        .as_ref()
        .map(|token| token.decimals)
        .unwrap_or(9);
    println!(
        "Astatine {} | {} (chain {}) | wallet {:#x} | INJ {} | AST {} | DEVICE {} · {} | block {}",
        env!("CARGO_PKG_VERSION"),
        network_label(client.manifest.network),
        client.manifest.chain_id,
        address,
        format_inj(snapshot.native_balance),
        format_token_units(snapshot.ast_balance, ast_decimals),
        backend.label(),
        backend.detail(),
        snapshot.block.number
    );
    let eligible = slots
        .iter()
        .filter(|slot| slot.current_work().is_some())
        .count();
    let finalizable = snapshot
        .nodes
        .iter()
        .filter(|node| selected.contains(&node.id))
        .filter(|node| {
            node.state
                .as_ref()
                .is_some_and(|state| state.finalizable && !state.mining_paused)
        })
        .count();
    if eligible == 0 {
        if finalizable > 0 {
            println!(
                "{} selected window(s) require permissionless finalization; read-only observation and automatic finalization are active.",
                finalizable
            );
        } else if snapshot.nodes.iter().any(|node| {
            selected.contains(&node.id) && node.state.as_ref().is_some_and(|state| state.eligible)
        }) {
            println!(
                "Verified work is eligible but the local slot is waiting for a fresh canonical head; stale work is stopped."
            );
        } else {
            println!("No eligible work in selected nodes; waiting for fresh verified windows.");
        }
    } else {
        println!(
            "Hashing {} eligible node(s); Ctrl+C stops safely.",
            eligible
        );
    }
    if !selected_work_changed {
        println!("No work state changed during startup verification.");
    }
}

fn print_progress(snapshot: &ReadSnapshot, slots: &[NodeSlot], hashes: u64, elapsed: Duration) {
    let eligible = slots
        .iter()
        .filter(|slot| slot.current_work().is_some())
        .count();
    let hashrate = hashes as f64 / elapsed.as_secs_f64().max(0.001);
    println!(
        "block {} | eligible {}/9 | {:.0} H/s",
        snapshot.block.number, eligible, hashrate
    );
    for node in &snapshot.nodes {
        if let Some(state) = &node.state {
            if !state.eligible {
                println!(
                    "  node {}: {} (window {})",
                    node.id, state.eligibility_reason, state.work.window_id
                );
            }
        } else if let Some(error) = &node.error {
            println!(
                "  node {}: unavailable ({})",
                node.id,
                crate::diagnostics::terminal_text(error)
            );
        }
    }
}

fn start_cpu_worker_threads(
    threads: usize,
    context: MiningWorkerContext,
) -> Result<Vec<thread::JoinHandle<()>>> {
    let mut workers = Vec::with_capacity(threads);
    for worker_id in 0..threads {
        let worker_context = context.clone();
        match thread::Builder::new()
            .name(format!("astatine-pow-{worker_id}"))
            .spawn(move || {
                worker_loop(
                    worker_context.slots,
                    worker_context.schedule,
                    worker_context.stop,
                    worker_context.cursor,
                    worker_context.total_hashes,
                    worker_context.proofs,
                    worker_context.telemetry,
                )
            }) {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                context.stop.store(true, Ordering::Release);
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(error).context("start CPU mining worker");
            }
        }
    }
    Ok(workers)
}

async fn receive_backend_event(
    receiver: &mut Option<mpsc::UnboundedReceiver<BackendEvent>>,
) -> Option<BackendEvent> {
    match receiver.as_mut() {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

fn gpu_worker_controller(
    selection: DeviceChoice,
    cpu_threads: usize,
    context: MiningWorkerContext,
    events: mpsc::UnboundedSender<BackendEvent>,
) {
    if context.stop.load(Ordering::Acquire) {
        return;
    }
    let gpu_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
        let mut engine = GpuBackendEngine::initialize()?;
        if context.stop.load(Ordering::Acquire) {
            return Ok(());
        }
        if selection == DeviceChoice::Auto {
            let cpu_rate = benchmark_cpu_reference(cpu_threads)?;
            if context.stop.load(Ordering::Acquire) {
                return Ok(());
            }
            let gpu_rate = engine.info().tuned_hashes_per_second;
            engine.record_cpu_comparison(cpu_rate, cpu_threads);
            if !gpu_is_meaningfully_faster(gpu_rate, cpu_rate) {
                let reason = format!(
                    "auto selected CPU: measured CPU {:.3} MH/s ({cpu_threads} threads) versus GPU {:.3} MH/s; GPU was not at least 10% faster",
                    cpu_rate as f64 / 1_000_000.0,
                    gpu_rate as f64 / 1_000_000.0,
                );
                activate_cpu_fallback(cpu_threads, context.clone(), events.clone(), reason);
                return Ok(());
            }
        }
        if context.stop.load(Ordering::Acquire) {
            return Ok(());
        }
        events
            .send(BackendEvent::Activated(ActiveBackend::Gpu(
                engine.info().clone(),
            )))
            .map_err(|_| anyhow!("GPU backend status channel closed during startup"))?;
        let result = gpu_worker_loop(&mut engine, &context);
        if context.stop.load(Ordering::Acquire) {
            return Ok(());
        }
        result?;
        bail!("GPU compute worker stopped unexpectedly")
    }));

    if context.stop.load(Ordering::Acquire) {
        return;
    }
    let failure = match gpu_result {
        Ok(Ok(())) => return,
        Ok(Err(error)) => format!("GPU failed: {error:#}"),
        Err(payload) => format!("GPU backend panicked: {}", panic_payload_message(payload)),
    };
    if selection == DeviceChoice::Auto {
        activate_cpu_fallback(cpu_threads, context, events, failure);
    } else {
        let _ = events.send(BackendEvent::Failed(format!(
            "{failure}; explicit GPU mode does not substitute CPU hashing"
        )));
    }
}

fn panic_payload_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(message) = payload.downcast_ref::<String>() {
        message.clone()
    } else if let Some(message) = payload.downcast_ref::<&'static str>() {
        (*message).to_owned()
    } else {
        "unknown panic payload".to_owned()
    }
}

fn activate_cpu_fallback(
    cpu_threads: usize,
    context: MiningWorkerContext,
    events: mpsc::UnboundedSender<BackendEvent>,
    reason: String,
) {
    if context.stop.load(Ordering::Acquire) {
        return;
    }
    let workers = match start_cpu_worker_threads(cpu_threads, context.clone()) {
        Ok(workers) => workers,
        Err(error) => {
            let _ = events.send(BackendEvent::Failed(format!(
                "{reason}; CPU backend could not start: {error:#}"
            )));
            return;
        }
    };
    let _ = events.send(BackendEvent::Activated(ActiveBackend::Cpu {
        threads: cpu_threads,
    }));
    let _ = events.send(BackendEvent::FallbackNotice(reason));
    for worker in workers {
        if worker.join().is_err() && !context.stop.load(Ordering::Acquire) {
            let _ = events.send(BackendEvent::Failed(
                "a CPU fallback worker panicked".to_owned(),
            ));
            context.stop.store(true, Ordering::Release);
            return;
        }
    }
}

fn gpu_worker_loop(engine: &mut GpuBackendEngine, context: &MiningWorkerContext) -> Result<()> {
    let mut nonce_exhaustion_reported = false;
    let mut pending: Option<PendingGpuWorkBatch> = None;
    while !context.stop.load(Ordering::Acquire) {
        let mut active = context
            .schedule
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        active.retain(|index| context.slots[*index].current_work().is_some());
        let Some(slot_index) = next_scheduled_slot(&active, &context.cursor) else {
            if let Some(previous) = pending.take() {
                complete_gpu_work_batch(engine, context, previous)?;
            } else {
                thread::sleep(IDLE_INTERVAL);
            }
            continue;
        };
        let slot = &context.slots[slot_index];
        let Some(work) = slot.current_work() else {
            if let Some(previous) = pending.take() {
                complete_gpu_work_batch(engine, context, previous)?;
            } else {
                thread::sleep(IDLE_INTERVAL);
            }
            continue;
        };
        if !slot.is_generation_current(work.generation) {
            context
                .telemetry
                .record(slot.id, ProofMetric::WorkerStoppedGeneration);
            if let Some(previous) = pending.take() {
                complete_gpu_work_batch(engine, context, previous)?;
            }
            continue;
        }
        let Some((first_nonce, count)) = slot.reserve_nonces(engine.batch_size()) else {
            if !nonce_exhaustion_reported {
                context
                    .telemetry
                    .record(slot.id, ProofMetric::WorkerNonceRangeExhausted);
                nonce_exhaustion_reported = true;
            }
            if let Some(previous) = pending.take() {
                complete_gpu_work_batch(engine, context, previous)?;
            } else {
                thread::sleep(IDLE_INTERVAL);
            }
            continue;
        };
        nonce_exhaustion_reported = false;
        let batch = GpuBatchIdentity {
            node_id: slot.id,
            generation: work.generation,
            window_id: work.fingerprint.hashing_context.window_id,
            first_nonce,
            nonce_count: count,
        };
        let submitted = match engine.dispatch_batch(
            &work.hasher,
            first_nonce,
            count,
            work.target,
            work.incumbent,
            &context.stop,
        ) {
            Ok(pending) => pending,
            Err(_error) if context.stop.load(Ordering::Acquire) => return Ok(()),
            Err(error) => return Err(error).context("dispatch GPU SHA-256d nonce batch"),
        };
        let next = PendingGpuWorkBatch {
            slot_index,
            work,
            identity: batch,
            pending: submitted,
        };
        if let Some(previous) = pending.replace(next) {
            complete_gpu_work_batch(engine, context, previous)?;
        }
    }
    if !context.stop.load(Ordering::Acquire)
        && let Some(previous) = pending.take()
    {
        complete_gpu_work_batch(engine, context, previous)?;
    }
    Ok(())
}

fn complete_gpu_work_batch(
    engine: &mut GpuBackendEngine,
    context: &MiningWorkerContext,
    pending: PendingGpuWorkBatch,
) -> Result<()> {
    let PendingGpuWorkBatch {
        slot_index,
        work,
        identity,
        pending,
    } = pending;
    let result = match engine.collect_batch(pending, Some(&context.stop)) {
        Ok(result) => result,
        Err(_error) if context.stop.load(Ordering::Acquire) => return Ok(()),
        Err(error) => return Err(error).context("collect GPU SHA-256d batch readback"),
    };
    if result.completed_hashes != identity.nonce_count
        || result.workgroup_count != identity.nonce_count.div_ceil(result.workgroup_size)
    {
        bail!(
            "GPU completed {} of {} reserved nonce hashes or returned an invalid workgroup count",
            result.completed_hashes,
            identity.nonce_count
        );
    }
    if let Some(batch_size) = engine.observe_batch_latency(result.timings.submission_to_readback) {
        eprintln!(
            "astatine: GPU batch latency exceeded 100 ms; reduced the next dispatch to {batch_size} nonces"
        );
    }
    let slot = &context.slots[slot_index];
    if slot.id != identity.node_id {
        bail!("GPU pending batch crossed into another node's state");
    }
    context
        .total_hashes
        .fetch_add(u64::try_from(result.completed_hashes)?, Ordering::Relaxed);
    slot.completed_hashes
        .fetch_add(u64::try_from(result.completed_hashes)?, Ordering::Relaxed);
    context
        .telemetry
        .record(slot.id, ProofMetric::GpuCompletedBatches);

    let mut seen_nonces = HashSet::with_capacity(result.candidates.len());
    let mut seen_groups = HashSet::with_capacity(result.candidates.len());
    for candidate in &result.candidates {
        let offset = candidate
            .nonce
            .checked_sub(identity.first_nonce)
            .ok_or_else(|| anyhow!("GPU returned a nonce before its reserved batch"))?;
        if offset >= identity.nonce_count as u128
            || usize::try_from(offset)? / result.workgroup_size != candidate.workgroup_index
            || !seen_nonces.insert(candidate.nonce)
            || !seen_groups.insert(candidate.workgroup_index)
        {
            bail!("GPU returned a duplicate, misattributed, or out-of-batch group winner");
        }
    }
    if let Some(candidate) = result.candidates.into_iter().min_by(|left, right| {
        left.hash
            .cmp(&right.hash)
            .then(left.nonce.cmp(&right.nonce))
    }) {
        process_hashed_candidate(
            slot,
            &work,
            HashedCandidate {
                nonce: candidate.nonce,
                hash: candidate.hash,
                reported_gpu_hash: Some(candidate.hash),
                batch_identity: Some(identity),
            },
            &context.proofs,
            &context.telemetry,
        )
        .map_err(|failure| anyhow!("GPU candidate failed CPU verification: {failure}"))?;
    }
    Ok(())
}

fn process_hashed_candidate(
    slot: &NodeSlot,
    work: &Arc<WorkJob>,
    candidate: HashedCandidate,
    proofs: &ProofInboxSender,
    telemetry: &ProofPipelineTelemetry,
) -> std::result::Result<(), GpuCandidateFailure> {
    let HashedCandidate {
        nonce,
        hash,
        reported_gpu_hash,
        batch_identity,
    } = candidate;
    if let Some(batch) = batch_identity {
        if batch.node_id != slot.id
            || batch.generation != work.generation
            || batch.window_id != work.fingerprint.hashing_context.window_id
            || batch.nonce_count == 0
            || !batch.contains(nonce)
        {
            telemetry.record(slot.id, ProofMetric::GpuBatchIdentityRejected);
            return Err(GpuCandidateFailure::InvalidBatchIdentity);
        }
        let Some(reported) = reported_gpu_hash else {
            telemetry.record(slot.id, ProofMetric::GpuBatchIdentityRejected);
            return Err(GpuCandidateFailure::MissingGpuHash);
        };
        let canonical = work.hasher.hash(nonce);
        if canonical != reported || canonical != hash {
            telemetry.record(slot.id, ProofMetric::GpuHashMismatch);
            return Err(GpuCandidateFailure::HashMismatch {
                gpu: reported,
                cpu: canonical,
            });
        }
        telemetry.record(slot.id, ProofMetric::GpuCandidatesCpuVerified);
    } else if reported_gpu_hash.is_some() {
        telemetry.record(slot.id, ProofMetric::GpuBatchIdentityRejected);
        return Err(GpuCandidateFailure::UnexpectedGpuHash);
    }

    if !meets_target(hash, work.target) {
        return Ok(());
    }
    telemetry.record(slot.id, ProofMetric::TargetValidHashes);
    if !slot.is_generation_current(work.generation) {
        telemetry.record(slot.id, ProofMetric::WorkerStaleGenerationHash);
        return Ok(());
    }
    if Instant::now() >= work.valid_until {
        telemetry.record(slot.id, ProofMetric::WorkerDeadlineHashDropped);
        return Ok(());
    }
    if work
        .incumbent
        .is_some_and(|incumbent| !beats_incumbent(hash, incumbent))
    {
        telemetry.record(slot.id, ProofMetric::IncumbentRejectedHashes);
        return Ok(());
    }
    telemetry.record(slot.id, ProofMetric::IncumbentPassedHashes);
    match slot.update_local_best(work.generation, work.valid_until, hash) {
        LocalBestUpdate::NewBest => {}
        LocalBestUpdate::NotBetter => {
            telemetry.record(slot.id, ProofMetric::TargetValidNotNewLocalBest);
            return Ok(());
        }
        LocalBestUpdate::StaleGeneration => {
            telemetry.record(slot.id, ProofMetric::WorkerStaleGenerationHash);
            return Ok(());
        }
        LocalBestUpdate::ExpiredDeadline => {
            telemetry.record(slot.id, ProofMetric::WorkerDeadlineHashDropped);
            return Ok(());
        }
    }
    telemetry.record(slot.id, ProofMetric::NewLocalBestHashes);
    let _ = proofs.deliver(
        ProofFound {
            node_id: slot.id,
            generation: work.generation,
            context: work.fingerprint.hashing_context.clone(),
            nonce,
            hash,
            target: work.target,
            incumbent: work.incumbent,
            batch_identity,
            queued_at: Instant::now(),
            preflight_retries: 0,
        },
        telemetry,
    );
    Ok(())
}

#[derive(Debug)]
enum GpuCandidateFailure {
    InvalidBatchIdentity,
    MissingGpuHash,
    UnexpectedGpuHash,
    HashMismatch { gpu: B256, cpu: B256 },
}

impl std::fmt::Display for GpuCandidateFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidBatchIdentity => {
                formatter.write_str("nonce is outside its assigned batch")
            }
            Self::MissingGpuHash => formatter.write_str("GPU candidate has no reported digest"),
            Self::UnexpectedGpuHash => formatter.write_str("CPU candidate carries a GPU digest"),
            Self::HashMismatch { gpu, cpu } => {
                write!(
                    formatter,
                    "GPU digest {gpu:#x} differs from CPU digest {cpu:#x}"
                )
            }
        }
    }
}

fn worker_loop(
    slots: Arc<Vec<NodeSlot>>,
    schedule: Arc<RwLock<Vec<usize>>>,
    stop: Arc<AtomicBool>,
    cursor: Arc<AtomicUsize>,
    total_hashes: Arc<AtomicU64>,
    proofs: ProofInboxSender,
    telemetry: Arc<ProofPipelineTelemetry>,
) {
    let mut nonce_exhaustion_reported = false;
    while !stop.load(Ordering::Acquire) {
        let mut active = schedule
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        active.retain(|index| slots[*index].current_work().is_some());
        let Some(slot_index) = next_scheduled_slot(&active, &cursor) else {
            thread::sleep(IDLE_INTERVAL);
            continue;
        };
        let slot = &slots[slot_index];
        let Some(work) = slot.current_work() else {
            thread::sleep(IDLE_INTERVAL);
            continue;
        };
        if !slot.is_generation_current(work.generation) {
            telemetry.record(slot.id, ProofMetric::WorkerStoppedGeneration);
            continue;
        }
        let Some((first_nonce, count)) = slot.reserve_nonces(NONCE_BATCH_SIZE) else {
            if !nonce_exhaustion_reported {
                telemetry.record(slot.id, ProofMetric::WorkerNonceRangeExhausted);
                nonce_exhaustion_reported = true;
            }
            thread::sleep(IDLE_INTERVAL);
            continue;
        };
        nonce_exhaustion_reported = false;
        let mut scratch = vec![0_u8; work.hasher.scratch_len()];
        let mut completed = 0_u64;
        for offset in 0..count {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if !slot.is_generation_current(work.generation) {
                telemetry.record(slot.id, ProofMetric::WorkerStoppedGeneration);
                break;
            }
            if Instant::now() >= work.valid_until {
                telemetry.record(slot.id, ProofMetric::WorkerStoppedDeadline);
                break;
            }
            let Some(nonce) = first_nonce.checked_add(offset as u128) else {
                break;
            };
            let Ok(hash) = work.hasher.hash_into(nonce, &mut scratch) else {
                telemetry.record(slot.id, ProofMetric::WorkerHashFailure);
                break;
            };
            completed += 1;
            if process_hashed_candidate(
                slot,
                &work,
                HashedCandidate {
                    nonce,
                    hash,
                    reported_gpu_hash: None,
                    batch_identity: None,
                },
                &proofs,
                &telemetry,
            )
            .is_err()
            {
                telemetry.record(slot.id, ProofMetric::WorkerHashFailure);
                break;
            }
        }
        total_hashes.fetch_add(completed, Ordering::Relaxed);
        slot.completed_hashes
            .fetch_add(completed, Ordering::Relaxed);
    }
}

fn next_scheduled_slot(active: &[usize], cursor: &AtomicUsize) -> Option<usize> {
    if active.is_empty() {
        return None;
    }
    Some(active[cursor.fetch_add(1, Ordering::Relaxed) % active.len()])
}

fn next_poll_delay(current: Duration) -> Duration {
    current
        .checked_mul(2)
        .unwrap_or(MAX_POLL_INTERVAL)
        .min(MAX_POLL_INTERVAL)
}

pub(crate) fn unresolved_session_blocks_mining(
    compute_only: bool,
    has_unresolved_transaction: bool,
    per_run_sessions_enabled: bool,
) -> bool {
    !compute_only && has_unresolved_transaction && !per_run_sessions_enabled
}

#[cfg(test)]
fn per_run_authorization_cap(
    configured_ceiling: U256,
    minimum_reserve: U256,
    pending_exposure: U256,
    confirmed_balance: U256,
) -> U256 {
    let available = confirmed_balance
        .checked_sub(minimum_reserve)
        .and_then(|remaining| remaining.checked_sub(pending_exposure))
        .unwrap_or(U256::ZERO);
    configured_ceiling.min(available)
}

fn floor_inj_to_cents(value: U256) -> U256 {
    let wei_per_cent = U256::from(10_000_000_000_000_000_u128);
    (value / wei_per_cent) * wei_per_cent
}

fn suggested_session_limit(configured_ceiling: U256, available: U256) -> Option<U256> {
    if configured_ceiling.is_zero() {
        return None;
    }
    let suggested = if available >= configured_ceiling {
        configured_ceiling
    } else {
        floor_inj_to_cents(available.min(configured_ceiling))
    };
    (!suggested.is_zero()).then_some(suggested)
}

fn approved_session_limit(
    configured_ceiling: U256,
    available: U256,
    accepted_reduction: bool,
) -> Option<U256> {
    let suggested = suggested_session_limit(configured_ceiling, available)?;
    if available < configured_ceiling && !accepted_reduction {
        return None;
    }
    Some(suggested)
}

#[allow(clippy::too_many_arguments)]
fn prompt_reduced_run_limit(
    wallet: Address,
    configured_ceiling: U256,
    confirmed_balance: U256,
    minimum_reserve: U256,
    pending_exposure: U256,
    available: U256,
    suggested: U256,
    startup: Option<&StartupProgress>,
) -> Result<bool> {
    crate::commands::require_paid_consent_terminal("a reduced session limit")?;
    if let Some(startup) = startup {
        startup.pause_for_prompt("Approve reduced session limit");
    }
    println!("\nASTATINE — INSUFFICIENT SESSION BALANCE");
    println!("Wallet: {wallet:#x}");
    println!(
        "Wallet balance: {} INJ",
        format_inj_min_decimals(confirmed_balance, 2)
    );
    println!(
        "Minimum reserve: {} INJ",
        format_inj_min_decimals(minimum_reserve, 2)
    );
    println!(
        "Outstanding maximum liabilities: {} INJ",
        format_inj_min_decimals(pending_exposure, 2)
    );
    println!(
        "Available for mining: {} INJ",
        format_inj_min_decimals(available, 2)
    );
    println!(
        "\nYour configured session limit is {} INJ.",
        format_inj_min_decimals(configured_ceiling, 2)
    );
    println!(
        "Would you like to use {} INJ\nfor this session instead? [y/N]",
        format_inj_two_decimals(suggested)
    );
    print!("> ");
    io::stdout()
        .flush()
        .context("flush reduced session limit prompt")?;
    let read_result = crate::commands::read_terminal_line();
    if let Some(startup) = startup {
        startup.resume_after_prompt("Rechecking balance and pending liabilities");
    }
    match read_result {
        Ok(answer) => Ok(consent_approved(&answer)),
        // A shutdown signal interrupts the blocking consent read. Treat it as
        // a refusal so the runtime can take its normal graceful-stop path.
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(error) => Err(error).context("read reduced session limit confirmation"),
    }
}

#[cfg(test)]
fn reduced_limit_consent_result(read_result: io::Result<usize>, answer: &str) -> Result<bool> {
    match read_result {
        Ok(_) => Ok(consent_approved(answer)),
        // A shutdown signal interrupts the blocking consent read. Treat it as
        // a refusal so the runtime can take its normal graceful-stop path.
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        Err(error) => Err(error).context("read reduced session limit confirmation"),
    }
}

/// EOF and unrecognized input are treated as refusal. Only an explicit
/// affirmative answer approves a reduced spending limit.
fn consent_approved(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn format_inj_two_decimals(value: U256) -> String {
    let cents = value / U256::from(10_000_000_000_000_000_u128);
    let whole = cents / U256::from(100_u8);
    let fractional = (cents % U256::from(100_u8)).to_string();
    format!("{whole}.{:0>2}", fractional)
}

fn print_wallet_needs_funding(
    wallet: Address,
    confirmed_balance: U256,
    minimum_reserve: U256,
    pending_exposure: U256,
) {
    println!("\nASTATINE — WALLET NEEDS FUNDING");
    println!("Wallet: {wallet:#x}");
    println!(
        "Balance: {} INJ",
        format_inj_min_decimals(confirmed_balance, 4)
    );
    println!(
        "Minimum reserve: {} INJ",
        format_inj_min_decimals(minimum_reserve, 4)
    );
    println!(
        "Outstanding maximum liabilities: {} INJ",
        format_inj_min_decimals(pending_exposure, 4)
    );
    let available = confirmed_balance
        .checked_sub(minimum_reserve)
        .and_then(|remaining| remaining.checked_sub(pending_exposure))
        .unwrap_or(U256::ZERO);
    println!(
        "Available for mining: {} INJ",
        format_inj_min_decimals(available, 4)
    );
    println!("\nYour wallet does not have enough INJ to start a paid mining session.");
    println!(
        "Fund your wallet or allow unresolved transaction liabilities to settle, then try again."
    );
}

fn should_open_transaction_manager(
    compute_only: bool,
    transaction_mode: bool,
    readonly_recovery: bool,
) -> bool {
    !compute_only && (transaction_mode || readonly_recovery)
}

enum UnlockOutcome {
    Unlocked(bip32::secp256k1::ecdsa::SigningKey),
    Cancelled,
}

fn unlock_result<F>(unlock: F) -> Result<UnlockOutcome>
where
    F: FnOnce() -> Result<bip32::secp256k1::ecdsa::SigningKey>,
{
    match unlock() {
        Ok(signer) => Ok(UnlockOutcome::Unlocked(signer)),
        Err(error) if crate::wallet::is_password_prompt_interrupted(&error) => {
            Ok(UnlockOutcome::Cancelled)
        }
        Err(error) => Err(error).context("unlock selected wallet for mining"),
    }
}

fn format_inj(value: Option<U256>) -> String {
    let Some(value) = value else {
        return "unavailable".to_owned();
    };
    let scale = U256::from(1_000_000_000_000_000_000_u128);
    let whole = value / scale;
    let fractional = (value % scale).to_string();
    format!("{whole}.{fractional:0>18}")
}

fn format_token_units(value: Option<U256>, decimals: u8) -> String {
    let Some(value) = value else {
        return "unavailable".to_owned();
    };
    let scale = U256::from(10_u8).pow(U256::from(decimals));
    let whole = value / scale;
    let fractional = (value % scale).to_string();
    let fractional = format!("{fractional:0>width$}", width = usize::from(decimals))
        .trim_end_matches('0')
        .to_owned();
    if fractional.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fractional}")
    }
}

fn format_inj_min_decimals(value: U256, minimum_fractional_digits: usize) -> String {
    let exact = format_token_units(Some(value), 18);
    let Some((whole, fractional)) = exact.split_once('.') else {
        return format!("{exact}.{}", "0".repeat(minimum_fractional_digits));
    };
    if fractional.len() >= minimum_fractional_digits {
        exact
    } else {
        format!(
            "{whole}.{fractional}{}",
            "0".repeat(minimum_fractional_digits - fractional.len())
        )
    }
}

fn network_label(network: crate::cli::Network) -> &'static str {
    match network {
        crate::cli::Network::Testnet => "Testnet",
        crate::cli::Network::Mainnet => "Mainnet",
    }
}

#[cfg(test)]
mod tests {
    fn assert_sanitized_terminal_failure_output(text: &str) {
        assert!(text.contains("terminal dashboard failed"), "{text:?}");
        assert!(
            text.contains("renderer stopped") && text.contains("unexpectedly"),
            "{text:?}"
        );
        assert!(text.contains("\\u{1b}]52;c;cGF5bG9hZA==\\u{7}"), "{text:?}");
        assert!(
            text.contains("\\u{d}") && text.contains("\\u{9b}") && text.contains("\\u{202e}"),
            "{text:?}"
        );
        assert!(
            !text.contains('\x1b')
                && !text.contains('\x07')
                && !text.contains('\r')
                && !text.contains('\u{009b}')
                && !text.contains('\u{202e}')
        );
        assert!(
            text.chars().all(|ch| ch == '\n' || !ch.is_control()),
            "{text:?}"
        );
    }

    #[test]
    fn terminal_mining_info_without_dashboard_escapes_controls() {
        const CHILD: &str = "ASTATINE_TEST_MINING_INFO_CHILD";
        if std::env::var_os(CHILD).is_some() {
            super::report_mining_info(&None, "provider\x1b]52;c;payload\x07\r\nwarning");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mining::tests::terminal_mining_info_without_dashboard_escapes_controls",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("provider\\u{1b}"), "{text:?}");
        assert!(!text.contains('\x1b') && !text.contains('\x07') && !text.contains('\r'));
    }

    #[test]
    fn terminal_dashboard_failure_without_dashboard_output_is_sanitized_and_readable() {
        const CHILD: &str = "ASTATINE_TEST_TERMINAL_DASHBOARD_FAILURE_CHILD";
        const FAILURE: &str =
            "renderer stopped \x1b]52;c;cGF5bG9hZA==\x07\r\n\u{009b}\u{202e}unexpectedly";
        if std::env::var_os(CHILD).is_some() {
            super::report_terminal_dashboard_failure(
                &None,
                format!(
                    "terminal dashboard failed; paid mining remains stopped until Ctrl+C: {FAILURE}"
                ),
            );
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mining::tests::terminal_dashboard_failure_without_dashboard_output_is_sanitized_and_readable",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child failure-output test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(
            text.contains("paid mining remains stopped until Ctrl+C"),
            "{text:?}"
        );
        assert_sanitized_terminal_failure_output(&text);
        assert_eq!(
            text.matches("terminal dashboard failed").count(),
            1,
            "the raw duplicate sink must not survive: {text:?}"
        );
    }

    #[test]
    fn terminal_dashboard_failure_dashboard_sink_output_is_sanitized_and_readable() {
        const CHILD: &str = "ASTATINE_TEST_DASHBOARD_FAILURE_BUFFER_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mining::tests::terminal_dashboard_failure_dashboard_sink_output_is_sanitized_and_readable",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child dashboard-sink test failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stderr).unwrap();
            assert_sanitized_terminal_failure_output(&text);
            assert_eq!(text.matches("terminal dashboard failed").count(), 1);
            return;
        }
        let diagnostics = crate::diagnostics::DiagnosticBuffer::default();
        let message = "terminal dashboard failed; the already-authorized transaction remains in recovery and mining stays stopped: renderer stopped \x1b]52;c;cGF5bG9hZA==\x07\r\n\u{009b}\u{202e}unexpectedly".to_owned();
        super::report_terminal_dashboard_failure_to(Some(diagnostics.clone()), message);
        let rendered = diagnostics
            .drain()
            .pop()
            .expect("the dashboard sink should retain the terminal failure warning");
        assert!(
            rendered.contains("already-authorized transaction remains in recovery"),
            "{rendered:?}"
        );
        assert_sanitized_terminal_failure_output(&rendered);
        assert!(diagnostics.latest().is_none());
    }

    use super::{
        ActiveBackend, DashboardContext, FinalizationState, HashedCandidate, HashingContext,
        MiningWorkerContext, NodeSlot, NonceAllocator, ObserverUpdate,
        PENDING_PROOF_CANDIDATE_CAPACITY, PaidRunSessionOpenLimits, PendingDashboardSync,
        ProofFound, SnapshotFreshness, activate_cpu_fallback, apply_genesis_poll_error,
        apply_transaction_state_to_model, approved_session_limit, clear_genesis_poll_error,
        compare_snapshot_freshness, dashboard_model, dashboard_node_status,
        finalization_retry_delay, gpu_is_meaningfully_faster, gpu_worker_controller,
        gpu_worker_loop, history_profile_enabled, inactive_genesis_nodes, next_poll_delay,
        next_scheduled_slot, open_paid_per_run_session, paid_run_session_open_limits,
        per_run_authorization_cap, process_hashed_candidate, proof_inbox, reconcile_head_progress,
        revalidate_queued_proof, revalidate_queued_proof_at, selected_nodes,
        should_open_transaction_manager, start_cpu_worker_threads, suggested_session_limit,
        take_observer_update, traced_node_status, unresolved_session_blocks_mining, update_slots,
        worker_loop,
    };
    use crate::{
        cli::{DeviceChoice, MineArgs, Network},
        config::{AppConfig, ConfigStore, parse_inj_wei},
        dashboard::{NodeStatus, hashes_per_second},
        deployment::DeploymentManifest,
        gpu::{GpuBackendEngine, GpuBatchIdentity},
        proof_telemetry::{ProofMetric, ProofPipelineTelemetry},
        protocol::{WorkContext, WorkHasher, meets_target},
        rpc::{
            BlockSnapshot, CandidateInfo, ContractPinStatus, NetworkClient, NodeState, NodeView,
            ReadSnapshot, WorkInfo,
        },
        transaction::{
            AUTOMATIC_REWARD_FORWARDING_DISABLED, TransactionActivity, TransactionActivityState,
            TransactionDashboardState, TransactionJournal,
        },
    };
    use alloy_primitives::{Address, B256, Bytes, U256};
    use std::{
        collections::{HashMap, HashSet},
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        thread,
        time::{Duration, Instant},
    };
    use tempfile::tempdir;
    use tokio::sync::{oneshot, watch};
    use tokio::time::timeout;

    fn eligible_state() -> NodeState {
        NodeState {
            work: WorkInfo {
                started: true,
                ended: false,
                window_id: 7,
                window_start_time: 100,
                window_expiry_time: 200,
                seed: B256::with_last_byte(1),
                prev_hash: B256::with_last_byte(2),
                target: U256::MAX,
                reward_per_window: U256::from(100),
                remaining_allocation: U256::from(1_000),
                max_header_length: 64,
                submission_fee: U256::from(10),
            },
            candidate: None,
            mining_paused: false,
            eligible: true,
            finalizable: false,
            eligibility_reason: "eligible",
        }
    }

    fn proof_lifecycle_fixture() -> (
        DeploymentManifest,
        Address,
        ReadSnapshot,
        ProofFound,
        Instant,
        Instant,
    ) {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let wallet = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let state = eligible_state();
        let block = test_block(1, 100);
        let now = Instant::now();
        let slot = NodeSlot::new(1);
        slot.set_work_at(&manifest, wallet, contract, Some(&state), &block, now)
            .unwrap();
        let work = slot.current_work_at(now).unwrap();
        let nonce = 1;
        let hash = work.hasher.hash(nonce);
        let proof = ProofFound {
            node_id: 1,
            generation: work.generation,
            context: work.fingerprint.hashing_context.clone(),
            nonce,
            hash,
            target: state.work.target,
            incumbent: None,
            batch_identity: None,
            queued_at: now,
            preflight_retries: 0,
        };
        let snapshot = ReadSnapshot {
            block,
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: contract,
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(state),
                error: None,
            }],
        };
        (manifest, wallet, snapshot, proof, now, work.valid_until)
    }

    fn proof_refresh_handle_fixture(
        epoch: u64,
        initial_publication: Option<super::RefreshPublication>,
    ) -> (
        super::ObserverRefreshHandle,
        tokio::sync::mpsc::Receiver<()>,
        watch::Sender<Option<super::RefreshPublication>>,
    ) {
        let (sender, requests) = tokio::sync::mpsc::channel(8);
        let (publications_sender, publications) = watch::channel(initial_publication);
        (
            super::ObserverRefreshHandle {
                sender,
                epoch: Arc::new(AtomicU64::new(epoch)),
                publications,
                gate: Arc::new(std::sync::Mutex::new(())),
            },
            requests,
            publications_sender,
        )
    }

    async fn wait_for_runtime_condition(condition: impl Fn() -> bool, reason: &str) {
        timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {reason}"));
    }

    #[cfg(unix)]
    async fn start_compute_only_test_runtime(
        store: &ConfigStore,
        config: crate::config::AppConfig,
        client: NetworkClient,
    ) -> (
        tokio::task::JoinHandle<anyhow::Result<()>>,
        super::MiningProbe,
    ) {
        let (probe_sender, probe_receiver) = oneshot::channel();
        let run_store = store.clone();
        let runtime = tokio::spawn(async move {
            super::run_with_client_test_options(
                &run_store,
                config,
                MineArgs {
                    device: DeviceChoice::Cpu,
                    compute_only: true,
                    new_session: false,
                    threads: None,
                    nodes: vec![1],
                    send_rewards_to: None,
                },
                client,
                None,
                Some(probe_sender),
                false,
                super::RuntimeTestOptions {
                    skip_workers: true,
                    ..super::RuntimeTestOptions::default()
                },
            )
            .await
        });
        let probe = match timeout(Duration::from_secs(5), probe_receiver).await {
            Ok(Ok(probe)) => probe,
            Ok(Err(error)) => panic!(
                "runtime probe sender closed ({error}); runtime result: {:?}",
                runtime.await
            ),
            Err(error) => panic!("runtime probe was not published: {error}"),
        };
        (runtime, probe)
    }

    fn runtime_test_proof(probe: &super::MiningProbe, preflight_retries: u8) -> ProofFound {
        let work = probe.slots[0]
            .current_work()
            .expect("synthetic runtime work should be active");
        let nonce = 1_u128;
        ProofFound {
            node_id: 1,
            generation: work.generation,
            context: work.fingerprint.hashing_context.clone(),
            nonce,
            hash: work.hasher.hash(nonce),
            target: work.target,
            incumbent: work.incumbent,
            batch_identity: None,
            queued_at: Instant::now(),
            preflight_retries,
        }
    }

    #[tokio::test]
    async fn run_runtime_select_loop_retains_expired_quote_and_gates_finalization_until_same_epoch_change()
     {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let wallet = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let token = Address::with_last_byte(10);
        let node_pins = (1..=9)
            .map(|id| {
                (
                    id,
                    Address::with_last_byte(8 + id),
                    B256::with_last_byte(id),
                )
            })
            .collect::<Vec<_>>();
        let mut client = NetworkClient::local_test_client_with_nodes(
            "http://127.0.0.1:1",
            &node_pins,
            token,
            B256::with_last_byte(2),
            9,
        )
        .unwrap();
        let snapshot = ReadSnapshot {
            block: test_block(1, 100),
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: contract,
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(eligible_state()),
                error: None,
            }],
        };
        client.synthetic_snapshot = Some(snapshot.clone());
        let config = crate::config::AppConfig {
            wallet_address: Some(format!("{wallet:#x}")),
            cpu_threads: 1,
            ..crate::config::AppConfig::default()
        };
        store.save(&config).unwrap();

        let (probe_sender, probe_receiver) = oneshot::channel();
        let run_store = store.clone();
        let run_client = client.clone();
        let runtime = tokio::spawn(async move {
            super::run_with_client_test_options(
                &run_store,
                config,
                MineArgs {
                    device: DeviceChoice::Cpu,
                    compute_only: true,
                    new_session: false,
                    threads: None,
                    nodes: vec![1],
                    send_rewards_to: None,
                },
                run_client,
                None,
                Some(probe_sender),
                false,
                super::RuntimeTestOptions {
                    skip_workers: true,
                    ..super::RuntimeTestOptions::default()
                },
            )
            .await
        });
        let probe = match timeout(Duration::from_secs(5), probe_receiver).await {
            Ok(Ok(probe)) => probe,
            Ok(Err(error)) => panic!(
                "runtime probe sender closed ({error}); runtime result: {:?}",
                runtime.await
            ),
            Err(error) => panic!("runtime probe was not published: {error}"),
        };
        assert!(!probe.workers_started.load(Ordering::Acquire));

        let controls = &probe.observer_test_controls;
        controls.pause_publications();
        probe.observer_refresh.force_refresh();
        wait_for_runtime_condition(|| controls.pause_acknowledged(), "observer pause").await;
        let initial_epoch = controls.current_refresh_epoch();
        let turns = probe
            .runtime_lifecycle
            .snapshot_turns
            .load(Ordering::Acquire);
        assert!(controls.publish_snapshot_at(initial_epoch, snapshot.clone()));
        wait_for_runtime_condition(
            || {
                probe
                    .runtime_lifecycle
                    .snapshot_turns
                    .load(Ordering::Acquire)
                    > turns
            },
            "baseline runtime snapshot turn",
        )
        .await;
        let baseline = probe
            .observer_refresh
            .latest_publication()
            .expect("synthetic baseline publication should be visible");
        assert_eq!(baseline.epoch, initial_epoch);
        assert!(baseline.sequence > 0);

        let mut proof = runtime_test_proof(&probe, 0);
        let preflight_epoch = probe.observer_refresh.epoch.load(Ordering::Acquire);
        assert!(probe.inject_proof_with_preflight_failure(
            proof.clone(),
            crate::transaction::synthetic_provider_reported_proof_expiry(),
        ));
        let observer_failures = probe
            .runtime_lifecycle
            .observer_failures
            .load(Ordering::Acquire);
        probe.proof_processing_gate.send_replace(false);
        controls.publish_update(ObserverUpdate::RpcError {
            message: "wake the runtime proof select".to_owned(),
            report: false,
        });
        wait_for_runtime_condition(
            || {
                probe
                    .runtime_lifecycle
                    .observer_failures
                    .load(Ordering::Acquire)
                    > observer_failures
            },
            "runtime proof-select wakeup",
        )
        .await;
        wait_for_runtime_condition(
            || {
                probe
                    .runtime_lifecycle
                    .injected_preflight_failures
                    .load(Ordering::Acquire)
                    == 1
            },
            "first injected proof expiry",
        )
        .await;
        probe.proof_processing_gate.send_replace(true);
        assert!(
            probe
                .runtime_lifecycle
                .pending_proof
                .load(Ordering::Acquire)
        );
        assert!(
            !probe
                .runtime_lifecycle
                .proof_receive_allowed
                .load(Ordering::Acquire)
        );
        assert!(
            !probe
                .runtime_lifecycle
                .proof_receive_allowed
                .load(Ordering::Acquire)
        );
        assert!(
            !probe
                .runtime_lifecycle
                .finalization_allowed
                .load(Ordering::Acquire)
        );
        let requested_epoch = probe.observer_refresh.epoch.load(Ordering::Acquire);
        assert_eq!(requested_epoch, preflight_epoch + 1);

        let failures = probe
            .runtime_lifecycle
            .observer_failures
            .load(Ordering::Acquire);
        controls.publish_update(ObserverUpdate::RpcError {
            message: "deterministic observer failure".to_owned(),
            report: true,
        });
        wait_for_runtime_condition(
            || {
                probe
                    .runtime_lifecycle
                    .observer_failures
                    .load(Ordering::Acquire)
                    > failures
            },
            "failed observer update through the runtime select",
        )
        .await;
        assert!(
            probe
                .runtime_lifecycle
                .pending_proof
                .load(Ordering::Acquire)
        );
        assert!(
            !probe
                .runtime_lifecycle
                .proof_receive_allowed
                .load(Ordering::Acquire)
        );

        let turns = probe
            .runtime_lifecycle
            .snapshot_turns
            .load(Ordering::Acquire);
        assert!(controls.publish_snapshot_at(requested_epoch - 1, snapshot.clone()));
        wait_for_runtime_condition(
            || {
                probe
                    .runtime_lifecycle
                    .snapshot_turns
                    .load(Ordering::Acquire)
                    > turns
            },
            "delayed snapshot through the runtime select",
        )
        .await;
        assert!(
            probe
                .runtime_lifecycle
                .pending_proof
                .load(Ordering::Acquire)
        );
        assert!(
            !probe
                .runtime_lifecycle
                .proof_receive_allowed
                .load(Ordering::Acquire)
        );
        assert!(
            !probe
                .runtime_lifecycle
                .finalization_allowed
                .load(Ordering::Acquire)
        );

        for retry_number in 0..=super::MAX_PROOF_PREFLIGHT_RETRIES {
            if retry_number > 0 {
                proof = runtime_test_proof(&probe, retry_number);
                probe.schedule_preflight_failure(
                    proof.nonce,
                    crate::transaction::synthetic_provider_reported_proof_expiry(),
                );
                let observer_failures = probe
                    .runtime_lifecycle
                    .observer_failures
                    .load(Ordering::Acquire);
                probe.proof_processing_gate.send_replace(false);
                controls.publish_update(ObserverUpdate::RpcError {
                    message: "wake the runtime retry select".to_owned(),
                    report: false,
                });
                wait_for_runtime_condition(
                    || {
                        probe
                            .runtime_lifecycle
                            .observer_failures
                            .load(Ordering::Acquire)
                            > observer_failures
                    },
                    "runtime retry-select wakeup",
                )
                .await;
                wait_for_runtime_condition(
                    || {
                        probe
                            .runtime_lifecycle
                            .injected_preflight_failures
                            .load(Ordering::Acquire)
                            == usize::from(retry_number) + 1
                    },
                    "requeued proof preflight failure",
                )
                .await;
                probe.proof_processing_gate.send_replace(true);
                assert!(
                    probe
                        .runtime_lifecycle
                        .pending_proof
                        .load(Ordering::Acquire)
                );
            }

            let refresh_epoch = probe.observer_refresh.epoch.load(Ordering::Acquire);
            let turns = probe
                .runtime_lifecycle
                .snapshot_turns
                .load(Ordering::Acquire);
            assert!(controls.publish_snapshot_at(refresh_epoch, snapshot.clone()));
            wait_for_runtime_condition(
                || {
                    probe
                        .runtime_lifecycle
                        .snapshot_turns
                        .load(Ordering::Acquire)
                        > turns
                },
                "correlated unchanged snapshot through the runtime select",
            )
            .await;

            if retry_number < super::MAX_PROOF_PREFLIGHT_RETRIES {
                assert!(
                    !probe
                        .runtime_lifecycle
                        .pending_proof
                        .load(Ordering::Acquire),
                    "a verified unchanged snapshot should queue the bounded retry"
                );
                assert!(
                    probe
                        .runtime_lifecycle
                        .proof_receive_allowed
                        .load(Ordering::Acquire)
                );
                assert!(
                    !probe
                        .runtime_lifecycle
                        .finalization_allowed
                        .load(Ordering::Acquire),
                    "the retry-queue snapshot turn must defer finalization"
                );
            } else {
                assert!(
                    probe
                        .runtime_lifecycle
                        .pending_proof
                        .load(Ordering::Acquire),
                    "after the retry bound, unchanged work remains parked"
                );
                assert!(
                    !probe
                        .runtime_lifecycle
                        .proof_receive_allowed
                        .load(Ordering::Acquire)
                );
                assert!(
                    !probe
                        .runtime_lifecycle
                        .finalization_allowed
                        .load(Ordering::Acquire)
                );
            }
        }

        let parked_publication = probe
            .observer_refresh
            .latest_publication()
            .expect("parked proof publication should be visible");
        let mut advanced = snapshot;
        advanced.nodes[0].state.as_mut().unwrap().work.window_id += 1;
        update_slots(
            &probe.slots,
            &probe.schedule,
            &client.manifest,
            wallet,
            &HashSet::from([1]),
            &advanced,
        )
        .unwrap();
        let turns = probe
            .runtime_lifecycle
            .snapshot_turns
            .load(Ordering::Acquire);
        assert!(controls.publish_snapshot_at(parked_publication.epoch, advanced));
        wait_for_runtime_condition(
            || {
                probe
                    .runtime_lifecycle
                    .snapshot_turns
                    .load(Ordering::Acquire)
                    > turns
            },
            "later same-epoch periodic snapshot through the runtime select",
        )
        .await;
        let advanced_publication = probe
            .observer_refresh
            .latest_publication()
            .expect("advanced periodic publication should be visible");
        assert_eq!(advanced_publication.epoch, parked_publication.epoch);
        assert!(advanced_publication.sequence > parked_publication.sequence);
        assert!(
            !probe
                .runtime_lifecycle
                .pending_proof
                .load(Ordering::Acquire)
        );
        assert!(
            probe
                .runtime_lifecycle
                .proof_receive_allowed
                .load(Ordering::Acquire)
        );
        assert!(
            probe
                .runtime_lifecycle
                .finalization_allowed
                .load(Ordering::Acquire)
        );
        assert_eq!(
            probe
                .proof_telemetry
                .count(1, ProofMetric::MainLoopReceived),
            3
        );
        assert_eq!(
            probe
                .proof_telemetry
                .count(1, ProofMetric::PreflightStarted),
            3
        );
        assert_eq!(
            probe
                .proof_telemetry
                .count(1, ProofMetric::PreflightRpcFailure),
            3
        );
        assert_eq!(
            probe
                .proof_telemetry
                .count(1, ProofMetric::PreflightStaleProof),
            1
        );
        assert_eq!(probe.proof_telemetry.count(1, ProofMetric::Signed), 0);
        assert_eq!(probe.proof_telemetry.count(1, ProofMetric::Broadcast), 0);
        assert!(store.read_transaction_journal().unwrap().is_none());

        probe.stop_signal.request_stop();
        let result = timeout(Duration::from_secs(5), runtime)
            .await
            .expect("actual runtime select loop should stop")
            .expect("runtime task should join");
        result.unwrap();
    }

    #[tokio::test]
    async fn runtime_observes_late_operator_stop_after_terminal_dashboard_failure() {
        const CHILD: &str = "ASTATINE_TEST_RUNTIME_DASHBOARD_FAILURE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mining::tests::runtime_observes_late_operator_stop_after_terminal_dashboard_failure",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child runtime test failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let text = String::from_utf8(output.stderr).unwrap();
            assert!(
                text.contains("paid mining remains stopped until Ctrl+C"),
                "{text:?}"
            );
            assert_sanitized_terminal_failure_output(&text);
            assert_eq!(
                text.matches("terminal dashboard failed").count(),
                1,
                "the runtime failure branch must have exactly one sanitized warning sink: {text:?}"
            );
            return;
        }
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let wallet = Address::with_last_byte(0x28);
        let contract = Address::with_last_byte(0x29);
        let token = Address::with_last_byte(0x2a);
        let node_pins = (1..=9)
            .map(|id| {
                let address = if id == 1 {
                    contract
                } else {
                    Address::with_last_byte(0x30 + id)
                };
                let runtime_hash = if id == 1 {
                    B256::with_last_byte(0x2b)
                } else {
                    B256::with_last_byte(id)
                };
                (id, address, runtime_hash)
            })
            .collect::<Vec<_>>();
        let mut client = NetworkClient::local_test_client_with_nodes(
            "http://127.0.0.1:1",
            &node_pins,
            token,
            B256::with_last_byte(0x2c),
            9,
        )
        .unwrap();
        let snapshot = ReadSnapshot {
            block: test_block(1, 100),
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: contract,
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(eligible_state()),
                error: None,
            }],
        };
        client.synthetic_snapshot = Some(snapshot);
        let config = crate::config::AppConfig {
            wallet_address: Some(format!("{wallet:#x}")),
            cpu_threads: 1,
            ..crate::config::AppConfig::default()
        };
        store.save(&config).unwrap();

        let (probe_sender, probe_receiver) = oneshot::channel();
        let run_store = store.clone();
        let run_client = client.clone();
        let runtime = tokio::spawn(async move {
            super::run_with_client_test_options(
                &run_store,
                config,
                MineArgs {
                    device: DeviceChoice::Cpu,
                    compute_only: true,
                    new_session: false,
                    threads: None,
                    nodes: vec![1],
                    send_rewards_to: None,
                },
                run_client,
                None,
                Some(probe_sender),
                false,
                super::RuntimeTestOptions {
                    skip_workers: true,
                    ..super::RuntimeTestOptions::default()
                },
            )
            .await
        });
        let probe = match timeout(Duration::from_secs(5), probe_receiver).await {
            Ok(Ok(probe)) => probe,
            Ok(Err(error)) => panic!(
                "runtime probe sender closed ({error}); runtime result: {:?}",
                runtime.await
            ),
            Err(error) => panic!("runtime probe was not published: {error}"),
        };

        probe.session_limit_reached.store(true, Ordering::Release);
        probe.worker_stop.store(true, Ordering::Release);
        probe.stop_signal.request_failure(
            "terminal dashboard failure after the spending limit latched: renderer stopped \x1b]52;c;cGF5bG9hZA==\x07\r\n\u{009b}\u{202e}unexpectedly".to_owned(),
        );
        wait_for_runtime_condition(
            || {
                probe
                    .runtime_lifecycle
                    .terminal_dashboard_failures
                    .load(Ordering::Acquire)
                    > 0
            },
            "terminal dashboard failure to be consumed",
        )
        .await;

        assert!(probe.session_limit_reached.load(Ordering::Acquire));
        assert!(probe.worker_stop.load(Ordering::Acquire));

        #[cfg(unix)]
        let stop_with_ctrl_c = std::env::var_os("ASTATINE_TEST_FAILURE_CTRL_C_CHILD").is_some();
        #[cfg(not(unix))]
        let stop_with_ctrl_c = false;
        if stop_with_ctrl_c {
            // This branch is used only in the isolated child test process.
            #[cfg(unix)]
            assert_eq!(unsafe { libc::raise(libc::SIGINT) }, 0);
        } else {
            probe.stop_signal.request_stop();
        }
        let result = timeout(Duration::from_secs(5), runtime)
            .await
            .expect(
                "a late operator stop must remain observable after a terminal dashboard failure",
            )
            .expect("runtime task should join");
        result.unwrap();
        assert_eq!(
            probe
                .runtime_lifecycle
                .terminal_dashboard_failures
                .load(Ordering::Acquire),
            1,
            "the latched failure must be consumed exactly once"
        );
        assert!(
            probe.session_limit_reached.load(Ordering::Acquire),
            "a consumed dashboard failure must not clear the spending-stop latch"
        );
        assert!(
            probe.worker_stop.load(Ordering::Acquire),
            "the later operator stop must still halt the runtime"
        );
    }

    #[cfg(unix)]
    #[test]
    fn runtime_ctrl_c_after_terminal_dashboard_failure_retains_stopped_state() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mining::tests::runtime_observes_late_operator_stop_after_terminal_dashboard_failure",
                "--nocapture",
            ])
            .env("ASTATINE_TEST_RUNTIME_DASHBOARD_FAILURE_CHILD", "1")
            .env("ASTATINE_TEST_FAILURE_CTRL_C_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child Ctrl+C runtime test failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stderr).unwrap();
        assert_sanitized_terminal_failure_output(&text);
        assert_eq!(text.matches("terminal dashboard failed").count(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_unix_shutdown_signals_stop_cleanly_and_restart_without_signing() {
        const CHILD: &str = "ASTATINE_TEST_RUNTIME_SIGNAL_CHILD";
        const SIGNAL: &str = "ASTATINE_TEST_RUNTIME_SIGNAL";

        if std::env::var_os(CHILD).is_none() {
            #[allow(unused_mut)]
            let mut signals = vec!["sigterm"];
            #[cfg(target_os = "linux")]
            signals.push("sighup");
            for signal in signals {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "mining::tests::runtime_unix_shutdown_signals_stop_cleanly_and_restart_without_signing",
                        "--nocapture",
                    ])
                    .env(CHILD, "1")
                    .env(SIGNAL, signal)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "child runtime {signal} test failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let stdout = String::from_utf8(output.stdout).unwrap();
                let stderr = String::from_utf8(output.stderr).unwrap();
                assert!(
                    stdout.contains("Stopped compute-only mining"),
                    "the runtime must take the graceful shutdown path for {signal}: stdout={stdout:?} stderr={stderr:?}"
                );
                assert!(
                    stdout.contains("Shutdown signal received:"),
                    "the runtime must report the delivered shutdown signal for {signal}: stdout={stdout:?} stderr={stderr:?}"
                );
            }
            return;
        }

        let signal = std::env::var(SIGNAL).unwrap();
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let wallet = Address::with_last_byte(0x68);
        let contract = Address::with_last_byte(0x69);
        let token = Address::with_last_byte(0x6a);
        let node_pins = (1..=9)
            .map(|id| {
                (
                    id,
                    Address::with_last_byte(0x70 + id),
                    B256::with_last_byte(id),
                )
            })
            .collect::<Vec<_>>();
        let mut client = NetworkClient::local_test_client_with_nodes(
            "http://127.0.0.1:1",
            &node_pins,
            token,
            B256::with_last_byte(0x6b),
            9,
        )
        .unwrap();
        let snapshot = ReadSnapshot {
            block: test_block(1, 100),
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: contract,
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(eligible_state()),
                error: None,
            }],
        };
        client.synthetic_snapshot = Some(snapshot);
        let config = crate::config::AppConfig {
            wallet_address: Some(format!("{wallet:#x}")),
            cpu_threads: 1,
            ..crate::config::AppConfig::default()
        };
        store.save(&config).unwrap();

        let (runtime, probe) =
            start_compute_only_test_runtime(&store, config.clone(), client.clone()).await;
        assert!(!probe.workers_started.load(Ordering::Acquire));

        let signal_number = match signal.as_str() {
            "sigterm" => libc::SIGTERM,
            #[cfg(target_os = "linux")]
            "sighup" => libc::SIGHUP,
            other => panic!("unsupported child runtime signal {other}"),
        };
        // The runtime has published its probe, so the shutdown handlers are
        // already installed in this isolated child process.
        assert_eq!(unsafe { libc::raise(signal_number) }, 0);
        let result = timeout(Duration::from_secs(5), runtime)
            .await
            .expect("runtime should stop after an OS shutdown signal")
            .expect("runtime task should join");
        result.unwrap();
        assert!(
            store.read_transaction_journal().unwrap().is_none(),
            "compute-only shutdown must not create signing state"
        );

        // Restart from the same state root. A completed shutdown must not leave
        // a stale signal request or prevent a fresh runtime from starting.
        let (runtime, probe) = start_compute_only_test_runtime(&store, config, client).await;
        assert!(!probe.workers_started.load(Ordering::Acquire));
        probe.stop_signal.request_stop();
        let result = timeout(Duration::from_secs(5), runtime)
            .await
            .expect("restarted runtime should stop cleanly")
            .expect("restarted runtime task should join");
        result.unwrap();
        assert!(store.read_transaction_journal().unwrap().is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_sigterm_closes_a_paid_session_without_signing() {
        const CHILD: &str = "ASTATINE_TEST_RUNTIME_PAID_SIGNAL_CHILD";

        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "mining::tests::runtime_sigterm_closes_a_paid_session_without_signing",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "child paid-runtime SIGTERM test failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert!(
                stdout.contains("Stopped autonomous Testnet mining"),
                "the paid runtime must close its session gracefully: {stdout:?}"
            );
            assert!(
                stdout.contains("Shutdown signal received: SIGTERM"),
                "the paid runtime must report the delivered signal: {stdout:?}"
            );
            return;
        }

        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let signer = bip32::secp256k1::ecdsa::SigningKey::from_slice(&[0x22; 32]).unwrap();
        let wallet = crate::wallet::signer_address(&signer);
        let contract = Address::with_last_byte(0x81);
        let token = Address::with_last_byte(0x82);
        let server = BalanceRpcServer::start(vec![U256::from(2_000_000_000_000_000_000_u128)]);
        let node_pins = (1..=9)
            .map(|id| {
                let address = if id == 1 {
                    contract
                } else {
                    Address::with_last_byte(0x90 + id)
                };
                (id, address, B256::with_last_byte(id))
            })
            .collect::<Vec<_>>();
        let mut client = NetworkClient::local_test_client_with_nodes(
            server.url(),
            &node_pins,
            token,
            B256::with_last_byte(0x84),
            18,
        )
        .unwrap();
        client.synthetic_snapshot = Some(ReadSnapshot {
            block: test_block(1, 100),
            native_balance: Some(U256::from(2_000_000_000_000_000_000_u128)),
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: contract,
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(eligible_state()),
                error: None,
            }],
        });
        let config = crate::config::AppConfig {
            wallet_address: Some(format!("{wallet:#x}")),
            minimum_reserve_inj: "0.1".to_owned(),
            per_session_spending_limit_inj: "1".to_owned(),
            cpu_threads: 1,
            ..crate::config::AppConfig::default()
        };
        store.save(&config).unwrap();

        let (probe_sender, probe_receiver) = oneshot::channel();
        let run_store = store.clone();
        let run_config = config.clone();
        let run_client = client.clone();
        let runtime = tokio::spawn(async move {
            super::run_with_client_test_options(
                &run_store,
                run_config,
                MineArgs {
                    device: DeviceChoice::Cpu,
                    compute_only: false,
                    new_session: true,
                    threads: None,
                    nodes: vec![1],
                    send_rewards_to: None,
                },
                run_client,
                Some(signer),
                Some(probe_sender),
                true,
                super::RuntimeTestOptions {
                    skip_workers: true,
                    ..super::RuntimeTestOptions::default()
                },
            )
            .await
        });
        let probe = match timeout(Duration::from_secs(5), probe_receiver).await {
            Ok(Ok(probe)) => probe,
            Ok(Err(error)) => panic!(
                "paid runtime probe sender closed ({error}); runtime result: {:?}",
                runtime.await
            ),
            Err(error) => panic!("paid runtime probe was not published: {error}"),
        };
        assert!(!probe.workers_started.load(Ordering::Acquire));

        assert!(
            server.requests() >= 1,
            "the paid session must have revalidated confirmed balance"
        );

        assert_eq!(unsafe { libc::raise(libc::SIGTERM) }, 0);
        let result = timeout(Duration::from_secs(5), runtime)
            .await
            .expect("paid runtime should stop after SIGTERM")
            .expect("paid runtime task should join");
        result.unwrap();

        let after = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(after.closed);
        assert!(after.session_id.is_some());
        assert!(after.unresolved.is_empty());
        assert_eq!(after.authorized_exposure_wei.as_deref(), Some("0"));
    }

    #[tokio::test]
    async fn shutdown_before_startup_reconcile_closes_new_legacy_session_and_requires_restart_authorization()
     {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let wallet = Address::with_last_byte(0x91);
        let contract = Address::with_last_byte(0x92);
        let token = Address::with_last_byte(0x93);
        let node_pins = (1..=9)
            .map(|id| {
                let address = if id == 1 {
                    contract
                } else {
                    Address::with_last_byte(0x90 + id)
                };
                (id, address, B256::with_last_byte(id))
            })
            .collect::<Vec<_>>();
        let client = NetworkClient::local_test_client_with_nodes(
            "http://127.0.0.1:1",
            &node_pins,
            token,
            B256::with_last_byte(0x94),
            18,
        )
        .unwrap();
        let config = crate::config::AppConfig {
            schema_version: 1,
            wallet_address: Some(format!("{wallet:#x}")),
            per_session_spending_limit_inj: "1".to_owned(),
            cpu_threads: 1,
            ..crate::config::AppConfig::default()
        };
        store.save(&config).unwrap();

        super::run_with_client_test_options(
            &store,
            config.clone(),
            MineArgs {
                device: DeviceChoice::Cpu,
                compute_only: false,
                new_session: true,
                threads: None,
                nodes: vec![1],
                send_rewards_to: None,
            },
            client,
            None,
            None,
            true,
            super::RuntimeTestOptions {
                skip_workers: true,
                pre_trigger_shutdown: true,
                ..super::RuntimeTestOptions::default()
            },
        )
        .await
        .unwrap();

        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(
            snapshot.closed,
            "the newly opened session must be closed on the early shutdown path"
        );
        assert!(snapshot.session_id.is_some());
        assert!(snapshot.unresolved.is_empty());
        assert_eq!(snapshot.authorized_exposure_wei.as_deref(), Some("0"));

        let restarted = crate::transaction::TransactionManager::open_with_session_policy(
            &store,
            &config,
            wallet,
            token,
            Arc::new(crate::history_telemetry::HistoryTelemetry::default()),
            false,
            false,
        );
        assert!(
            restarted.is_err(),
            "restart must require explicit new-session authorization for the closed session"
        );
    }

    #[tokio::test]
    async fn interrupted_wallet_unlock_closes_new_legacy_session_and_requires_restart_authorization()
     {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let wallet = Address::with_last_byte(0xa1);
        let token = Address::with_last_byte(0xa2);
        let config = crate::config::AppConfig {
            schema_version: 1,
            wallet_address: Some(format!("{wallet:#x}")),
            per_session_spending_limit_inj: "1".to_owned(),
            ..crate::config::AppConfig::default()
        };
        store.save(&config).unwrap();
        let manager =
            crate::transaction::TransactionManager::open(&store, &config, wallet, token).unwrap();
        let mut lifecycle = super::RuntimeLifecycle {
            transactions: Some(manager),
            worker_guard: None,
            observer: None,
            dashboard: None,
            finalized: false,
        };
        let interrupted = || -> anyhow::Result<bip32::secp256k1::ecdsa::SigningKey> {
            Err(anyhow::Error::new(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "interrupted wallet prompt",
            )))
        };
        let outcome = super::unlock_result(interrupted).unwrap();
        assert!(matches!(outcome, super::UnlockOutcome::Cancelled));

        let diagnostics = crate::diagnostics::DiagnosticBuffer::default();
        let message = lifecycle
            .finalize(None, false, false, false, &diagnostics)
            .await
            .unwrap();
        assert!(
            message.is_some_and(|message| message.contains("Stopped autonomous Testnet mining")),
            "the finalizer must report a clean paid-session close"
        );
        let repeated = lifecycle
            .finalize(None, false, false, false, &diagnostics)
            .await
            .unwrap();
        assert!(
            repeated.is_none(),
            "repeated cleanup must be idempotent and must not create a new message or allowance"
        );

        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(
            snapshot.closed,
            "an interrupted unlock must close the newly opened session"
        );
        assert!(snapshot.session_id.is_some());
        assert!(snapshot.unresolved.is_empty());
        assert_eq!(snapshot.authorized_exposure_wei.as_deref(), Some("0"));

        let restarted = crate::transaction::TransactionManager::open_with_session_policy(
            &store,
            &config,
            wallet,
            token,
            Arc::new(crate::history_telemetry::HistoryTelemetry::default()),
            false,
            false,
        );
        assert!(
            restarted.is_err(),
            "restart must require explicit new-session authorization after an interrupted unlock"
        );
    }

    fn legacy_paid_test_manager() -> (
        tempfile::TempDir,
        ConfigStore,
        crate::config::AppConfig,
        bip32::secp256k1::ecdsa::SigningKey,
        Address,
        Address,
        crate::transaction::TransactionManager,
    ) {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let signer = bip32::secp256k1::ecdsa::SigningKey::from_slice(&[0x33; 32]).unwrap();
        let wallet = crate::wallet::signer_address(&signer);
        let token = Address::with_last_byte(0xb2);
        let config = crate::config::AppConfig {
            schema_version: 1,
            wallet_address: Some(format!("{wallet:#x}")),
            per_session_spending_limit_inj: "1".to_owned(),
            ..crate::config::AppConfig::default()
        };
        store.save(&config).unwrap();
        let manager =
            crate::transaction::TransactionManager::open(&store, &config, wallet, token).unwrap();
        (temp, store, config, signer, wallet, token, manager)
    }

    fn legacy_runtime_fixture() -> (
        tempfile::TempDir,
        ConfigStore,
        crate::config::AppConfig,
        NetworkClient,
        bip32::secp256k1::ecdsa::SigningKey,
        Address,
        Address,
    ) {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let signer = bip32::secp256k1::ecdsa::SigningKey::from_slice(&[0x44; 32]).unwrap();
        let wallet = crate::wallet::signer_address(&signer);
        let contract = Address::with_last_byte(0xc2);
        let token = Address::with_last_byte(0xc3);
        let node_pins = (1..=9)
            .map(|id| {
                let address = if id == 1 {
                    contract
                } else {
                    Address::with_last_byte(0xd0 + id)
                };
                (id, address, B256::with_last_byte(id))
            })
            .collect::<Vec<_>>();
        let mut client = NetworkClient::local_test_client_with_nodes(
            "http://127.0.0.1:1",
            &node_pins,
            token,
            B256::with_last_byte(0xc4),
            18,
        )
        .unwrap();
        client.synthetic_snapshot = Some(ReadSnapshot {
            block: test_block(1, 100),
            native_balance: Some(U256::from(1_000_000_000_000_000_000_u128)),
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: contract,
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(eligible_state()),
                error: None,
            }],
        });
        let config = crate::config::AppConfig {
            schema_version: 1,
            wallet_address: Some(format!("{wallet:#x}")),
            per_session_spending_limit_inj: "1".to_owned(),
            cpu_threads: 1,
            ..crate::config::AppConfig::default()
        };
        store.save(&config).unwrap();
        (temp, store, config, client, signer, wallet, token)
    }

    #[tokio::test]
    async fn finalizer_stops_gpu_worker_and_closes_session_on_cancel() {
        let (_temp, store, config, _signer, wallet, token, manager) = legacy_paid_test_manager();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
        });
        let mut lifecycle = super::RuntimeLifecycle {
            transactions: Some(manager),
            worker_guard: Some(super::MiningWorkers {
                stop: Arc::clone(&stop),
                workers: vec![worker],
                has_gpu_controller: true,
            }),
            observer: None,
            dashboard: None,
            finalized: false,
        };
        let diagnostics = crate::diagnostics::DiagnosticBuffer::default();
        let message = lifecycle
            .finalize(None, false, false, false, &diagnostics)
            .await
            .unwrap();
        assert!(
            message.is_some_and(|message| message.contains("Stopped autonomous Testnet mining"))
        );
        assert!(
            stop.load(Ordering::Acquire),
            "the GPU worker stop flag must be set"
        );
        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(snapshot.closed);
        assert!(snapshot.unresolved.is_empty());
        assert_eq!(snapshot.authorized_exposure_wei.as_deref(), Some("0"));

        let repeated = lifecycle
            .finalize(None, false, false, false, &diagnostics)
            .await
            .unwrap();
        assert!(repeated.is_none(), "repeated cleanup must be idempotent");
        let restarted = crate::transaction::TransactionManager::open_with_session_policy(
            &store,
            &config,
            wallet,
            token,
            Arc::new(crate::history_telemetry::HistoryTelemetry::default()),
            false,
            false,
        );
        assert!(restarted.is_err());
    }

    #[tokio::test]
    async fn finalizer_stops_gpu_worker_and_preserves_original_error_on_failure() {
        let (_temp, store, config, _signer, _wallet, _token, manager) = legacy_paid_test_manager();
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
        });
        let mut lifecycle = super::RuntimeLifecycle {
            transactions: Some(manager),
            worker_guard: Some(super::MiningWorkers {
                stop: Arc::clone(&stop),
                workers: vec![worker],
                has_gpu_controller: true,
            }),
            observer: None,
            dashboard: None,
            finalized: false,
        };
        let diagnostics = crate::diagnostics::DiagnosticBuffer::default();
        let finalize_result = lifecycle
            .finalize(
                Some("gpu startup failed"),
                false,
                false,
                false,
                &diagnostics,
            )
            .await;
        let error = super::combine_runtime_results(
            Err(anyhow::anyhow!("gpu startup failed")),
            finalize_result,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("gpu startup failed"));
        assert!(stop.load(Ordering::Acquire));
        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(snapshot.closed);
        assert!(snapshot.unresolved.is_empty());
    }

    #[tokio::test]
    async fn finalizer_preserves_unresolved_legacy_liability_and_repeated_cleanup_is_idempotent() {
        let (_temp, store, config, signer, _wallet, _token, mut manager) =
            legacy_paid_test_manager();
        let contract = Address::with_last_byte(0xb3);
        let (hash, exposure) = manager
            .inject_unresolved_liability_for_test(&signer, contract)
            .unwrap();
        let mut lifecycle = super::RuntimeLifecycle {
            transactions: Some(manager),
            worker_guard: None,
            observer: None,
            dashboard: None,
            finalized: false,
        };
        let diagnostics = crate::diagnostics::DiagnosticBuffer::default();
        let message = lifecycle
            .finalize(None, false, false, false, &diagnostics)
            .await
            .unwrap();
        assert!(
            message.is_some_and(|message| message.contains("transaction exposure reserved")),
            "unresolved legacy exposure must keep the session open"
        );
        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(!snapshot.closed);
        assert_eq!(snapshot.unresolved.len(), 1);
        assert_eq!(snapshot.unresolved[0].hash, format!("{hash:#x}"));
        assert_eq!(
            snapshot.pending_exposure_wei.as_deref(),
            Some(exposure.to_string().as_str())
        );
        assert_eq!(
            snapshot.authorized_exposure_wei.as_deref(),
            Some(exposure.to_string().as_str())
        );

        let bytes_after_first = store.read_transaction_journal().unwrap().unwrap();
        let repeated = lifecycle
            .finalize(None, false, false, false, &diagnostics)
            .await
            .unwrap();
        assert!(repeated.is_none());
        let bytes_after_second = store.read_transaction_journal().unwrap().unwrap();
        assert_eq!(
            bytes_after_first, bytes_after_second,
            "repeated cleanup must not rewrite, reset, refund, or create an allowance"
        );
    }

    #[tokio::test]
    async fn finalizer_close_failure_before_rename_requires_restart_confirmation() {
        let (_temp, store, config, _signer, _wallet, _token, manager) = legacy_paid_test_manager();
        let session_id = manager.session_id_for_test().unwrap();
        store
            .fail_atomic_write_for_test(
                store.transaction_journal_path_for_test().unwrap(),
                crate::config::AtomicWriteFailPoint::BeforeRename,
            )
            .unwrap();
        let mut lifecycle = super::RuntimeLifecycle {
            transactions: Some(manager),
            worker_guard: None,
            observer: None,
            dashboard: None,
            finalized: false,
        };
        let diagnostics = crate::diagnostics::DiagnosticBuffer::default();
        let error = lifecycle
            .finalize(None, false, false, false, &diagnostics)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("close transaction spending session"),
            "unexpected close-failure error: {error:#}"
        );

        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(
            !snapshot.closed,
            "a BeforeRename close failure must leave the durable journal open"
        );
        assert_eq!(snapshot.session_id.as_deref(), Some(session_id.as_str()));
        assert!(snapshot.unresolved.is_empty());
        assert_eq!(snapshot.authorized_exposure_wei.as_deref(), Some("0"));
        assert!(
            crate::commands::requires_open_legacy_session_confirmation(
                false,
                false,
                crate::config::parse_inj_wei(&config.per_session_spending_limit_inj).unwrap(),
                &snapshot,
                false,
            ),
            "the next ordinary mine must require explicit confirmation before resuming the open session"
        );

        let bytes_after_failure = store.read_transaction_journal().unwrap().unwrap();
        let repeated = lifecycle
            .finalize(None, false, false, false, &diagnostics)
            .await
            .unwrap();
        assert!(
            repeated.is_none(),
            "repeated cleanup must be idempotent after a failed close"
        );
        let bytes_after_repeat = store.read_transaction_journal().unwrap().unwrap();
        assert_eq!(
            bytes_after_failure, bytes_after_repeat,
            "repeated cleanup must not reset, refund, or rewrite the open journal"
        );
    }

    #[tokio::test]
    async fn runtime_dashboard_start_failure_closes_new_legacy_session() {
        let (_temp, store, config, client, signer, wallet, token) = legacy_runtime_fixture();
        let error = super::run_with_client_test_options(
            &store,
            config.clone(),
            MineArgs {
                device: DeviceChoice::Cpu,
                compute_only: false,
                new_session: true,
                threads: None,
                nodes: vec![1],
                send_rewards_to: None,
            },
            client,
            Some(signer),
            None,
            true,
            super::RuntimeTestOptions {
                skip_workers: true,
                fail_dashboard_start: true,
                ..super::RuntimeTestOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("dashboard"),
            "unexpected dashboard-failure error: {error:#}"
        );
        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(snapshot.closed);
        assert!(snapshot.session_id.is_some());
        assert!(snapshot.unresolved.is_empty());
        assert_eq!(snapshot.authorized_exposure_wei.as_deref(), Some("0"));
        let restarted = crate::transaction::TransactionManager::open_with_session_policy(
            &store,
            &config,
            wallet,
            token,
            Arc::new(crate::history_telemetry::HistoryTelemetry::default()),
            false,
            false,
        );
        assert!(restarted.is_err());
    }

    #[tokio::test]
    async fn runtime_reconcile_failure_closes_new_legacy_session() {
        let (_temp, store, config, client, signer, wallet, token) = legacy_runtime_fixture();
        let error = super::run_with_client_test_options(
            &store,
            config.clone(),
            MineArgs {
                device: DeviceChoice::Cpu,
                compute_only: false,
                new_session: true,
                threads: None,
                nodes: vec![1],
                send_rewards_to: None,
            },
            client,
            Some(signer),
            None,
            true,
            super::RuntimeTestOptions {
                skip_workers: true,
                fail_reconcile: true,
                ..super::RuntimeTestOptions::default()
            },
        )
        .await
        .unwrap_err();
        assert!(format!("{error:#}").contains("reconcile"));
        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(snapshot.closed);
        assert!(snapshot.session_id.is_some());
        assert!(snapshot.unresolved.is_empty());
        assert_eq!(snapshot.authorized_exposure_wei.as_deref(), Some("0"));
        let restarted = crate::transaction::TransactionManager::open_with_session_policy(
            &store,
            &config,
            wallet,
            token,
            Arc::new(crate::history_telemetry::HistoryTelemetry::default()),
            false,
            false,
        );
        assert!(restarted.is_err());
    }

    #[tokio::test]
    async fn observer_publishes_identity_before_waking_snapshot_consumers() {
        let wallet = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let token = Address::with_last_byte(10);
        let mut network = NetworkClient::local_test_client(
            "http://127.0.0.1:1",
            contract,
            B256::with_last_byte(1),
            token,
            B256::with_last_byte(2),
            9,
        )
        .unwrap();
        let state = eligible_state();
        let snapshot = ReadSnapshot {
            block: test_block(1, 100),
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: contract,
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(state),
                error: None,
            }],
        };
        network.synthetic_snapshot = Some(snapshot.clone());
        let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let context = DashboardContext {
            network: Network::Testnet,
            chain_id: network.manifest.chain_id,
            address: wallet,
            active_backend: Arc::new(RwLock::new(ActiveBackend::Cpu { threads: 1 })),
            spending_limit: U256::ZERO,
            transaction_mode: false,
            compute_only: true,
            workers_started: Arc::new(AtomicBool::new(false)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            selected: HashSet::from([1]),
            slots: Arc::clone(&slots),
            schedule,
            transaction_state: Arc::new(RwLock::new(TransactionDashboardState::default())),
            pending_sync: Arc::new(RwLock::new(HashMap::new())),
            finalization_state: Arc::new(RwLock::new(HashMap::new())),
        };
        let mut observer = super::start_read_only_observer(
            network,
            context,
            snapshot.clone(),
            None,
            crate::diagnostics::DiagnosticBuffer::default(),
        );
        let requested_epoch = observer.force_refresh();
        let mut updates = observer.updates.clone();
        let publication = timeout(Duration::from_secs(5), async {
            loop {
                updates.changed().await.unwrap();
                if matches!(&*updates.borrow_and_update(), ObserverUpdate::Snapshot(_))
                    && let Some(publication) = observer.latest_publication()
                    && publication.epoch >= requested_epoch
                {
                    break publication;
                }
            }
        })
        .await
        .expect("snapshot consumer should observe its publication identity");
        assert_eq!(publication.epoch, requested_epoch);
        assert_eq!(publication.sequence, 1);
        assert_eq!(publication.snapshot.block.number, snapshot.block.number);
        assert_eq!(
            publication.snapshot.block.timestamp,
            snapshot.block.timestamp
        );
        assert_eq!(publication.snapshot.block.hash, snapshot.block.hash);
        observer.stop().await.unwrap();
    }

    #[tokio::test]
    async fn proof_expiry_event_loop_retains_until_correlated_publication_then_queues_retry() {
        let (manifest, wallet, snapshot, proof, now, valid_until) = proof_lifecycle_fixture();
        let expiry_error = crate::transaction::synthetic_provider_reported_proof_expiry();
        assert!(crate::transaction::is_provider_reported_proof_expiry(
            &expiry_error
        ));
        assert!(crate::transaction::is_proof_quote_unavailable(
            &expiry_error
        ));
        let safe_retry_conditions = super::ProofPreflightRetryConditions {
            session_limit_reached: false,
            authorization_unchanged: true,
            has_new_unresolved: false,
            signing_blocked_by_unresolved: false,
            has_unverified_receipt: false,
        };
        assert!(super::should_retain_proof_after_preflight_failure(
            &expiry_error,
            safe_retry_conditions,
        ));
        for unsafe_conditions in [
            super::ProofPreflightRetryConditions {
                session_limit_reached: true,
                ..safe_retry_conditions
            },
            super::ProofPreflightRetryConditions {
                authorization_unchanged: false,
                ..safe_retry_conditions
            },
            super::ProofPreflightRetryConditions {
                has_new_unresolved: true,
                ..safe_retry_conditions
            },
            super::ProofPreflightRetryConditions {
                signing_blocked_by_unresolved: true,
                ..safe_retry_conditions
            },
            super::ProofPreflightRetryConditions {
                has_unverified_receipt: true,
                ..safe_retry_conditions
            },
        ] {
            assert!(!super::should_retain_proof_after_preflight_failure(
                &expiry_error,
                unsafe_conditions,
            ));
        }
        let baseline = super::RefreshPublication {
            epoch: 0,
            sequence: 10,
            snapshot: snapshot.clone(),
        };
        let (refresh, mut refresh_requests, publications) =
            proof_refresh_handle_fixture(0, Some(baseline));
        let telemetry = ProofPipelineTelemetry::default();
        let mut event_loop = super::ProofRefreshEventLoop::default();
        let (_sender, mut receiver) = proof_inbox(false);

        let identity =
            event_loop.retain_after_preflight_failure(proof.clone(), valid_until, &refresh);
        assert_eq!(identity.epoch, 1);
        assert_eq!(identity.after_sequence, 10);
        refresh_requests.try_recv().unwrap();
        assert!(event_loop.has_pending());
        assert!(!event_loop.can_receive_proof());
        assert!(!event_loop.can_finalize(false));

        let failed = event_loop.handle_observer_update(
            super::ProofObserverUpdate::Failed,
            &manifest,
            wallet,
            &refresh,
            &receiver,
            &telemetry,
        );
        assert!(matches!(
            failed.action,
            super::ProofRefreshEventAction::Waiting
        ));
        assert!(event_loop.has_pending());
        assert!(!event_loop.can_receive_proof());
        assert!(!event_loop.can_finalize(false));

        let delayed = super::RefreshPublication {
            epoch: 0,
            sequence: 11,
            snapshot: snapshot.clone(),
        };
        publications.send_replace(Some(delayed.clone()));
        let delayed_turn = event_loop.handle_observer_update(
            super::ProofObserverUpdate::Snapshot {
                publication: Some(&delayed),
                latest_snapshot_available: true,
                now,
            },
            &manifest,
            wallet,
            &refresh,
            &receiver,
            &telemetry,
        );
        assert!(matches!(
            delayed_turn.action,
            super::ProofRefreshEventAction::Waiting
        ));
        assert!(event_loop.has_pending());

        let unchanged = super::RefreshPublication {
            epoch: 1,
            sequence: 12,
            snapshot,
        };
        publications.send_replace(Some(unchanged.clone()));
        let retry_turn = event_loop.handle_observer_update(
            super::ProofObserverUpdate::Snapshot {
                publication: Some(&unchanged),
                latest_snapshot_available: true,
                now,
            },
            &manifest,
            wallet,
            &refresh,
            &receiver,
            &telemetry,
        );
        assert!(matches!(
            retry_turn.action,
            super::ProofRefreshEventAction::RetryQueued
        ));
        assert!(retry_turn.retry_queued_this_snapshot);
        assert!(!event_loop.has_pending());
        assert!(event_loop.can_receive_proof());
        assert!(
            !event_loop.can_finalize(retry_turn.retry_queued_this_snapshot),
            "same-snapshot retry yields the finalization turn"
        );
        let queued = receiver.recv().await.unwrap();
        assert_eq!(queued.nonce, proof.nonce);
        assert_eq!(queued.preflight_retries, 1);
        // This controller has no transaction manager or signer: the retry is only queued.
    }

    #[tokio::test]
    async fn proof_refresh_event_loop_bounds_retries_and_reopens_finalization_after_same_epoch_change()
     {
        let (manifest, wallet, snapshot, proof, now, valid_until) = proof_lifecycle_fixture();
        let baseline = super::RefreshPublication {
            epoch: 5,
            sequence: 20,
            snapshot: snapshot.clone(),
        };
        let (refresh, mut refresh_requests, publications) =
            proof_refresh_handle_fixture(5, Some(baseline));
        let telemetry = ProofPipelineTelemetry::default();
        let mut event_loop = super::ProofRefreshEventLoop::default();
        let (_sender, mut receiver) = proof_inbox(false);

        let mut candidate = proof;
        for retry_number in 0..super::MAX_PROOF_PREFLIGHT_RETRIES {
            let identity =
                event_loop.retain_after_preflight_failure(candidate, valid_until, &refresh);
            assert_eq!(identity.epoch, 6 + u64::from(retry_number));
            assert_eq!(identity.after_sequence, 20 + u64::from(retry_number));
            refresh_requests.try_recv().unwrap();
            let unchanged = super::RefreshPublication {
                epoch: identity.epoch,
                sequence: identity.after_sequence + 1,
                snapshot: snapshot.clone(),
            };
            publications.send_replace(Some(unchanged.clone()));
            let turn = event_loop.handle_observer_update(
                super::ProofObserverUpdate::Snapshot {
                    publication: Some(&unchanged),
                    latest_snapshot_available: true,
                    now,
                },
                &manifest,
                wallet,
                &refresh,
                &receiver,
                &telemetry,
            );
            assert!(matches!(
                turn.action,
                super::ProofRefreshEventAction::RetryQueued
            ));
            assert!(turn.retry_queued_this_snapshot);
            assert!(!event_loop.can_finalize(turn.retry_queued_this_snapshot));
            candidate = receiver.recv().await.unwrap();
            assert_eq!(candidate.preflight_retries, retry_number + 1);
        }

        let park_identity =
            event_loop.retain_after_preflight_failure(candidate, valid_until, &refresh);
        assert_eq!(park_identity.epoch, 8);
        assert_eq!(park_identity.after_sequence, 22);
        refresh_requests.try_recv().unwrap();
        let parked = super::RefreshPublication {
            epoch: park_identity.epoch,
            sequence: park_identity.after_sequence + 1,
            snapshot: snapshot.clone(),
        };
        publications.send_replace(Some(parked.clone()));
        let parked_turn = event_loop.handle_observer_update(
            super::ProofObserverUpdate::Snapshot {
                publication: Some(&parked),
                latest_snapshot_available: true,
                now,
            },
            &manifest,
            wallet,
            &refresh,
            &receiver,
            &telemetry,
        );
        assert!(matches!(
            parked_turn.action,
            super::ProofRefreshEventAction::Waiting
        ));
        assert!(event_loop.has_pending());
        assert!(!event_loop.can_receive_proof());
        assert!(!event_loop.can_finalize(parked_turn.retry_queued_this_snapshot));
        assert!(!receiver.has_pending());

        let mut advanced_snapshot = snapshot;
        advanced_snapshot.nodes[0]
            .state
            .as_mut()
            .unwrap()
            .work
            .window_id += 1;
        let periodic_same_epoch = super::RefreshPublication {
            epoch: parked.epoch,
            sequence: parked.sequence + 1,
            snapshot: advanced_snapshot,
        };
        publications.send_replace(Some(periodic_same_epoch.clone()));
        let advanced_turn = event_loop.handle_observer_update(
            super::ProofObserverUpdate::Snapshot {
                publication: Some(&periodic_same_epoch),
                latest_snapshot_available: true,
                now,
            },
            &manifest,
            wallet,
            &refresh,
            &receiver,
            &telemetry,
        );
        assert!(matches!(
            advanced_turn.action,
            super::ProofRefreshEventAction::VerifiedStale {
                reason: super::ProofRevalidationFailure::WindowMismatch,
                ..
            }
        ));
        assert!(!event_loop.has_pending());
        assert!(event_loop.can_receive_proof());
        assert!(
            event_loop.can_finalize(advanced_turn.retry_queued_this_snapshot),
            "verified work change releases the finalization gate"
        );
        assert!(!receiver.has_pending());
        // No transaction manager or signer is involved in either gate transition.
    }

    #[tokio::test]
    async fn proof_refresh_event_loop_caps_forced_refreshes_but_tracks_periodic_publications() {
        let (manifest, wallet, snapshot, proof, now, valid_until) = proof_lifecycle_fixture();
        let baseline = super::RefreshPublication {
            epoch: 4,
            sequence: 30,
            snapshot: snapshot.clone(),
        };
        let (refresh, mut refresh_requests, publications) =
            proof_refresh_handle_fixture(4, Some(baseline));
        let telemetry = ProofPipelineTelemetry::default();
        let mut event_loop = super::ProofRefreshEventLoop::default();
        let (_sender, receiver) = proof_inbox(false);

        let mut identity =
            event_loop.retain_after_preflight_failure(proof.clone(), valid_until, &refresh);
        refresh_requests.try_recv().unwrap();
        assert_eq!(identity.epoch, 5);

        let mut unverifiable = snapshot.clone();
        unverifiable.nodes[0].pin.runtime_verified = false;
        for expected_epoch in [6, 7] {
            let publication = super::RefreshPublication {
                epoch: identity.epoch,
                sequence: identity.after_sequence + 1,
                snapshot: unverifiable.clone(),
            };
            publications.send_replace(Some(publication.clone()));
            let turn = event_loop.handle_observer_update(
                super::ProofObserverUpdate::Snapshot {
                    publication: Some(&publication),
                    latest_snapshot_available: true,
                    now,
                },
                &manifest,
                wallet,
                &refresh,
                &receiver,
                &telemetry,
            );
            assert!(matches!(
                turn.action,
                super::ProofRefreshEventAction::SnapshotUnavailable
            ));
            assert!(event_loop.has_pending());
            assert!(!event_loop.can_finalize(false));
            refresh_requests.try_recv().unwrap();
            assert_eq!(refresh.epoch.load(Ordering::Acquire), expected_epoch);
            identity = super::RefreshRequestIdentity {
                epoch: refresh.epoch.load(Ordering::Acquire),
                after_sequence: publication.sequence,
            };
        }

        let capped_publication = super::RefreshPublication {
            epoch: identity.epoch,
            sequence: identity.after_sequence + 1,
            snapshot: unverifiable,
        };
        publications.send_replace(Some(capped_publication.clone()));
        let capped_turn = event_loop.handle_observer_update(
            super::ProofObserverUpdate::Snapshot {
                publication: Some(&capped_publication),
                latest_snapshot_available: true,
                now,
            },
            &manifest,
            wallet,
            &refresh,
            &receiver,
            &telemetry,
        );
        assert!(matches!(
            capped_turn.action,
            super::ProofRefreshEventAction::SnapshotUnavailable
        ));
        assert_eq!(
            refresh.epoch.load(Ordering::Acquire),
            u64::from(super::MAX_PROOF_REFRESH_REQUESTS) + 4
        );
        assert!(refresh_requests.try_recv().is_err());
        assert!(event_loop.has_pending());

        let periodic_valid = super::RefreshPublication {
            epoch: capped_publication.epoch,
            sequence: capped_publication.sequence + 1,
            snapshot,
        };
        publications.send_replace(Some(periodic_valid.clone()));
        let retry_turn = event_loop.handle_observer_update(
            super::ProofObserverUpdate::Snapshot {
                publication: Some(&periodic_valid),
                latest_snapshot_available: true,
                now,
            },
            &manifest,
            wallet,
            &refresh,
            &receiver,
            &telemetry,
        );
        assert!(matches!(
            retry_turn.action,
            super::ProofRefreshEventAction::RetryQueued
        ));
        assert!(retry_turn.retry_queued_this_snapshot);
        assert_eq!(receiver.take_next().unwrap().nonce, proof.nonce);
    }

    #[tokio::test]
    async fn proof_refresh_event_loop_yields_to_competing_work_without_finalizing_same_turn() {
        let (manifest, wallet, snapshot, proof, now, valid_until) = proof_lifecycle_fixture();
        let (refresh, mut refresh_requests, _) = proof_refresh_handle_fixture(0, None);
        let telemetry = ProofPipelineTelemetry::default();
        let mut event_loop = super::ProofRefreshEventLoop::default();
        let (sender, receiver) = proof_inbox(false);
        let identity =
            event_loop.retain_after_preflight_failure(proof.clone(), valid_until, &refresh);
        refresh_requests.try_recv().unwrap();

        let hasher = WorkHasher::new(&proof.context.work_context()).unwrap();
        let (nonce, hash) = (0..u128::MAX)
            .map(|nonce| (nonce, hasher.hash(nonce)))
            .find(|(_, hash)| *hash < proof.hash)
            .expect("a strictly better same-context candidate exists");
        let mut competitor = proof.clone();
        competitor.nonce = nonce;
        competitor.hash = hash;
        assert!(sender.deliver(competitor.clone(), &telemetry));

        let publication = super::RefreshPublication {
            epoch: identity.epoch,
            sequence: identity.after_sequence + 1,
            snapshot,
        };
        let turn = event_loop.handle_observer_update(
            super::ProofObserverUpdate::Snapshot {
                publication: Some(&publication),
                latest_snapshot_available: true,
                now,
            },
            &manifest,
            wallet,
            &refresh,
            &receiver,
            &telemetry,
        );
        assert!(matches!(
            turn.action,
            super::ProofRefreshEventAction::RetryQueued
        ));
        assert!(turn.retry_queued_this_snapshot);
        assert!(!event_loop.can_finalize(turn.retry_queued_this_snapshot));
        let queued = receiver.take_next().unwrap();
        assert_eq!(queued.nonce, competitor.nonce);
        assert_eq!(queued.hash, competitor.hash);
        assert_eq!(telemetry.count(1, ProofMetric::QueueCandidateSuperseded), 1);
    }

    #[test]
    fn proof_refresh_event_loop_releases_only_on_deadline_or_shutdown() {
        let (_manifest, _wallet, _snapshot, proof, _now, valid_until) = proof_lifecycle_fixture();
        let (refresh, mut refresh_requests, _) = proof_refresh_handle_fixture(0, None);
        let mut event_loop = super::ProofRefreshEventLoop::default();
        let (_sender, receiver) = proof_inbox(false);
        event_loop.retain_after_preflight_failure(proof.clone(), valid_until, &refresh);
        refresh_requests.try_recv().unwrap();
        assert!(
            event_loop
                .on_timeout(valid_until - Duration::from_millis(1))
                .is_none()
        );
        assert!(event_loop.has_pending());
        assert!(!event_loop.can_receive_proof());
        assert!(!event_loop.can_finalize(false));
        let expired = event_loop.on_timeout(valid_until).unwrap();
        assert_eq!(expired.nonce, proof.nonce);
        assert!(!event_loop.has_pending());
        assert!(event_loop.can_receive_proof());
        assert!(event_loop.can_finalize(false));
        assert!(!receiver.has_pending());

        let shutdown_proof = proof.clone();
        event_loop.retain_after_preflight_failure(shutdown_proof.clone(), valid_until, &refresh);
        refresh_requests.try_recv().unwrap();
        assert!(event_loop.has_pending());
        let discarded_on_shutdown = event_loop.take_for_shutdown().unwrap();
        assert_eq!(discarded_on_shutdown.nonce, shutdown_proof.nonce);
        assert!(!event_loop.has_pending());
        assert!(event_loop.can_receive_proof());
        assert!(event_loop.can_finalize(false));
        assert!(!receiver.has_pending());
    }

    #[tokio::test]
    async fn synthetic_quote_expiry_does_not_establish_stale_proof() {
        use crate::config::AppConfig;
        use crate::transaction::{ProofSubmission, TransactionManager};
        use crate::wallet::signer_address;
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (arrived_tx, arrived_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let n = stream.read(&mut buffer).unwrap();
                assert!(n > 0);
                request.extend_from_slice(&buffer[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..end]);
                    let len: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    if request.len() >= end + 4 + len {
                        break;
                    }
                }
            }
            assert!(String::from_utf8_lossy(&request).contains("eth_estimateGas"));
            arrived_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            let body = r#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"reverted","data":"0x7bbfb6fe"}}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut extra_requests = 0;
            loop {
                match listener.accept() {
                    Ok(_) => extra_requests += 1,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("loopback listener: {error}"),
                }
                match done_rx.try_recv() {
                    Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
                thread::yield_now();
            }
            extra_requests
        });
        let signer = bip32::secp256k1::ecdsa::SigningKey::from_bytes((&[1u8; 32]).into()).unwrap();
        let wallet = signer_address(&signer);
        let contract = Address::with_last_byte(9);
        let token = Address::with_last_byte(10);
        let mut network = NetworkClient::local_test_client(
            &format!("http://{address}"),
            contract,
            B256::with_last_byte(1),
            token,
            B256::with_last_byte(2),
            9,
        )
        .unwrap();
        let state = eligible_state();
        let block = test_block(1, 100);
        let snapshot = ReadSnapshot {
            block: block.clone(),
            native_balance: Some(U256::MAX),
            native_balance_error: None,
            ast_balance: Some(U256::ZERO),
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: contract,
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(state.clone()),
                error: None,
            }],
        };
        network.synthetic_snapshot = Some(snapshot.clone());
        let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let selected = HashSet::from([1]);
        update_slots(
            &slots,
            &schedule,
            &network.manifest,
            wallet,
            &selected,
            &snapshot,
        )
        .unwrap();
        let context = DashboardContext {
            network: Network::Testnet,
            chain_id: network.manifest.chain_id,
            address: wallet,
            active_backend: Arc::new(RwLock::new(ActiveBackend::Cpu { threads: 1 })),
            spending_limit: U256::from(1),
            transaction_mode: true,
            compute_only: false,
            workers_started: Arc::new(AtomicBool::new(false)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            selected,
            slots: Arc::clone(&slots),
            schedule,
            transaction_state: Arc::new(RwLock::new(TransactionDashboardState::default())),
            pending_sync: Arc::new(RwLock::new(HashMap::new())),
            finalization_state: Arc::new(RwLock::new(HashMap::new())),
        };
        let mut observer = super::start_read_only_observer(
            network.clone(),
            context,
            snapshot.clone(),
            None,
            crate::diagnostics::DiagnosticBuffer::default(),
        );
        let first_requested_epoch = observer.force_refresh();
        let mut publications = observer.publications.clone();
        let first_publication = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(publication) = publications.borrow_and_update().clone()
                    && publication.epoch >= first_requested_epoch
                {
                    break publication;
                }
                publications.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let slot = &slots[0];
        let work = slot.current_work().unwrap();
        let context = WorkContext {
            chain_id: network.manifest.chain_id,
            contract,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner: wallet,
            header: Vec::new(),
        };
        let hash = WorkHasher::new(&context).unwrap().hash(1);
        let proof = ProofFound {
            node_id: 1,
            generation: work.generation,
            context: work.fingerprint.hashing_context.clone(),
            nonce: 1,
            hash,
            target: state.work.target,
            incumbent: None,
            batch_identity: None,
            queued_at: Instant::now(),
            preflight_retries: 0,
        };
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (sender, mut receiver) = proof_inbox(false);
        assert!(sender.deliver(proof, &telemetry));
        let proof = receiver.recv().await.unwrap();
        revalidate_queued_proof(slot, &proof, &telemetry).unwrap();
        let root = tempdir().unwrap();
        let store = ConfigStore::at_root(root.path().to_path_buf());
        let config = AppConfig {
            per_session_spending_limit_inj: "1".to_owned(),
            minimum_reserve_inj: "0".to_owned(),
            ..AppConfig::default()
        };
        let mut manager = TransactionManager::open(&store, &config, wallet, token).unwrap();
        manager.set_proof_telemetry(Arc::clone(&telemetry));
        let before = manager.authorization_used().unwrap();
        let journal_before = store.read_transaction_journal().unwrap();
        let error = {
            let submission = manager.submit_proof(
                &network,
                &signer,
                ProofSubmission {
                    contract,
                    node_id: 1,
                    window_id: 7,
                    nonce: proof.nonce,
                    header: Vec::new(),
                    work_hash: proof.hash,
                },
            );
            tokio::pin!(submission);
            tokio::select! {
                result = &mut submission => panic!("submission returned before gated quote: {result:?}"),
                result = timeout(Duration::from_secs(5), arrived_rx) => result.unwrap().unwrap(),
            }
            release_tx.send(()).unwrap();
            submission.await.unwrap_err()
        };
        assert_eq!(manager.authorization_used().unwrap(), before);
        assert_eq!(telemetry.count(1, ProofMetric::Signed), 0);
        assert_eq!(telemetry.count(1, ProofMetric::Broadcast), 0);
        assert_eq!(store.read_transaction_journal().unwrap(), journal_before);
        done_tx.send(()).unwrap();
        assert_eq!(
            server.join().unwrap(),
            0,
            "no nonce or broadcast request should follow the failed quote"
        );
        assert!(crate::transaction::is_provider_reported_proof_expiry(
            &error
        ));
        assert!(!crate::transaction::is_stale_transaction_preflight(&error));
        assert!(
            !receiver.has_pending(),
            "a provider selector must not put the candidate back in the submission queue"
        );
        assert!(
            !super::is_stale_proof(&error),
            "provider selector alone must not discard proof: {error:#}"
        );
        let refresh_identity = observer.refresh_handle().request_refresh();
        let mut pending = super::PendingProofRefresh {
            proof,
            requested_epoch: refresh_identity.epoch,
            requested_after_sequence: refresh_identity.after_sequence,
            valid_until: work.valid_until,
            refresh_requests: 1,
        };
        assert_eq!(
            pending.on_publication(
                Some(&first_publication),
                observer.latest_snapshot().is_some(),
                &network.manifest,
                wallet,
                Instant::now(),
                &telemetry,
            ),
            super::PendingProofDecision::Waiting,
            "a pre-request publication cannot satisfy the refresh identity"
        );
        let publication = timeout(Duration::from_secs(5), async {
            loop {
                if let Some(publication) = publications.borrow_and_update().clone()
                    && publication.epoch >= refresh_identity.epoch
                    && publication.sequence > refresh_identity.after_sequence
                {
                    break publication;
                }
                publications.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(
            pending.on_publication(
                Some(&publication),
                observer.latest_snapshot().is_some(),
                &network.manifest,
                wallet,
                Instant::now(),
                &telemetry,
            ),
            super::PendingProofDecision::RetryQueued,
            "the actual unchanged published snapshot revalidates, rather than discards, the proof"
        );
        assert_eq!(pending.proof.preflight_retries, 1);
        assert!(receiver.requeue(pending.proof.clone(), &telemetry));
        let queued = receiver.recv().await.unwrap();
        assert_eq!(queued.preflight_retries, 1);
        revalidate_queued_proof(slot, &queued, &telemetry).unwrap();
        observer.stop().await.unwrap();
    }

    #[test]
    fn pending_proof_refresh_requires_matching_publication_and_bounds_retries() {
        let (manifest, wallet, snapshot, proof, now, valid_until) = proof_lifecycle_fixture();
        let telemetry = ProofPipelineTelemetry::default();
        let mut pending = super::PendingProofRefresh {
            proof,
            requested_epoch: 5,
            requested_after_sequence: 0,
            valid_until,
            refresh_requests: 1,
        };
        let old = super::RefreshPublication {
            epoch: 4,
            sequence: 1,
            snapshot: snapshot.clone(),
        };
        assert_eq!(
            pending.on_publication(Some(&old), true, &manifest, wallet, now, &telemetry,),
            super::PendingProofDecision::Waiting
        );
        let matching = super::RefreshPublication {
            epoch: 5,
            sequence: 2,
            snapshot: snapshot.clone(),
        };
        assert_eq!(
            pending.on_publication(Some(&matching), false, &manifest, wallet, now, &telemetry,),
            super::PendingProofDecision::Waiting,
            "an observer error cannot be replaced by an older cached snapshot"
        );

        let mut unverifiable = snapshot.clone();
        unverifiable.nodes[0].pin.runtime_verified = false;
        let unverified_publication = super::RefreshPublication {
            epoch: 5,
            sequence: 3,
            snapshot: unverifiable,
        };
        assert_eq!(
            pending.on_publication(
                Some(&unverified_publication),
                true,
                &manifest,
                wallet,
                now,
                &telemetry,
            ),
            super::PendingProofDecision::SnapshotUnavailable,
            "unverified node state retains the proof instead of classifying it stale"
        );
        pending.requested_epoch = 6;
        pending.requested_after_sequence = 3;
        assert_eq!(
            pending.on_publication(
                Some(&unverified_publication),
                true,
                &manifest,
                wallet,
                now,
                &telemetry,
            ),
            super::PendingProofDecision::Waiting
        );

        for (epoch, sequence, expected) in [
            (6, 4, super::PendingProofDecision::RetryQueued),
            (7, 5, super::PendingProofDecision::RetryQueued),
            (8, 6, super::PendingProofDecision::Parked),
        ] {
            pending.requested_epoch = epoch;
            let publication = super::RefreshPublication {
                epoch,
                sequence,
                snapshot: snapshot.clone(),
            };
            assert_eq!(
                pending.on_publication(
                    Some(&publication),
                    true,
                    &manifest,
                    wallet,
                    now,
                    &telemetry,
                ),
                expected
            );
        }
        assert_eq!(
            pending.proof.preflight_retries,
            super::MAX_PROOF_PREFLIGHT_RETRIES
        );
        assert_eq!(pending.requested_epoch, 8);
        assert_eq!(pending.requested_after_sequence, 6);
        let same_publication = super::RefreshPublication {
            epoch: 8,
            sequence: 6,
            snapshot: snapshot.clone(),
        };
        assert_eq!(
            pending.on_publication(
                Some(&same_publication),
                true,
                &manifest,
                wallet,
                now,
                &telemetry,
            ),
            super::PendingProofDecision::Waiting,
            "an already consumed publication cannot trigger another quote retry"
        );
        assert_eq!(
            pending.on_publication(None, true, &manifest, wallet, valid_until, &telemetry),
            super::PendingProofDecision::LocallyExpired,
            "a stalled refresh releases the in-memory candidate only at the local safe deadline"
        );
    }

    #[test]
    fn parked_proof_observes_later_periodic_publication_at_the_same_refresh_epoch() {
        let (manifest, wallet, snapshot, mut proof, now, valid_until) = proof_lifecycle_fixture();
        let telemetry = ProofPipelineTelemetry::default();
        proof.preflight_retries = super::MAX_PROOF_PREFLIGHT_RETRIES;
        let mut pending = super::PendingProofRefresh {
            proof,
            requested_epoch: 5,
            requested_after_sequence: 0,
            valid_until,
            refresh_requests: super::MAX_PROOF_REFRESH_REQUESTS,
        };
        let first_periodic_publication = super::RefreshPublication {
            epoch: 5,
            sequence: 1,
            snapshot: snapshot.clone(),
        };
        assert_eq!(
            pending.on_publication(
                Some(&first_periodic_publication),
                true,
                &manifest,
                wallet,
                now,
                &telemetry,
            ),
            super::PendingProofDecision::Parked
        );

        let mut advanced = snapshot;
        advanced.nodes[0].state.as_mut().unwrap().work.window_id += 1;
        let later_periodic_publication = super::RefreshPublication {
            epoch: 5,
            sequence: 2,
            snapshot: advanced,
        };
        assert_eq!(
            pending.on_publication(
                Some(&later_periodic_publication),
                true,
                &manifest,
                wallet,
                now,
                &telemetry,
            ),
            super::PendingProofDecision::VerifiedStale(
                super::ProofRevalidationFailure::WindowMismatch
            ),
            "a periodic full snapshot reuses the refresh epoch but must still revalidate parked work"
        );
    }

    #[test]
    fn pending_unverifiable_snapshots_cap_forced_refresh_requests() {
        let (_manifest, _wallet, snapshot, proof, _now, valid_until) = proof_lifecycle_fixture();
        let mut pending = super::PendingProofRefresh {
            proof,
            requested_epoch: 8,
            requested_after_sequence: 7,
            valid_until,
            refresh_requests: super::MAX_PROOF_REFRESH_REQUESTS,
        };
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let latest_publication = super::RefreshPublication {
            epoch: 8,
            sequence: 8,
            snapshot,
        };
        let (publications_tx, publications_rx) = watch::channel(Some(latest_publication.clone()));
        let refresh = super::ObserverRefreshHandle {
            sender,
            epoch: Arc::new(AtomicU64::new(8)),
            publications: publications_rx,
            gate: Arc::new(std::sync::Mutex::new(())),
        };
        assert!(!pending.request_followup_refresh(&refresh, Some(&latest_publication)));
        assert_eq!(pending.refresh_requests, super::MAX_PROOF_REFRESH_REQUESTS);
        assert_eq!(pending.requested_epoch, 8);
        assert_eq!(pending.requested_after_sequence, 8);
        assert!(receiver.try_recv().is_err());

        pending.refresh_requests = 1;
        assert!(pending.request_followup_refresh(&refresh, Some(&latest_publication)));
        assert_eq!(pending.refresh_requests, 2);
        assert_eq!(pending.requested_epoch, 9);
        assert_eq!(pending.requested_after_sequence, 8);
        assert!(receiver.try_recv().is_ok());
        drop(publications_tx);
    }

    #[test]
    fn pending_proof_refresh_only_discards_on_correlated_verified_state_change() {
        let (manifest, wallet, snapshot, proof, now, valid_until) = proof_lifecycle_fixture();
        let telemetry = ProofPipelineTelemetry::default();
        let mut pending = super::PendingProofRefresh {
            proof,
            requested_epoch: 12,
            requested_after_sequence: 0,
            valid_until,
            refresh_requests: 1,
        };
        let delayed = super::RefreshPublication {
            epoch: 11,
            sequence: 11,
            snapshot: snapshot.clone(),
        };
        assert_eq!(
            pending.on_publication(Some(&delayed), true, &manifest, wallet, now, &telemetry,),
            super::PendingProofDecision::Waiting
        );

        let mut advanced = snapshot;
        advanced.nodes[0].state.as_mut().unwrap().work.window_id += 1;
        let advanced_publication = super::RefreshPublication {
            epoch: 12,
            sequence: 12,
            snapshot: advanced,
        };
        assert_eq!(
            pending.on_publication(
                Some(&advanced_publication),
                true,
                &manifest,
                wallet,
                now,
                &telemetry,
            ),
            super::PendingProofDecision::VerifiedStale(
                super::ProofRevalidationFailure::WindowMismatch
            )
        );
    }

    #[test]
    fn pending_proof_retry_yields_to_a_competing_better_candidate_in_the_bounded_inbox() {
        let (manifest, wallet, snapshot, proof, now, valid_until) = proof_lifecycle_fixture();
        let telemetry = ProofPipelineTelemetry::default();
        let mut pending = super::PendingProofRefresh {
            proof: proof.clone(),
            requested_epoch: 1,
            requested_after_sequence: 0,
            valid_until,
            refresh_requests: 1,
        };
        let hasher = WorkHasher::new(&proof.context.work_context()).unwrap();
        let (nonce, hash) = (0..u128::MAX)
            .map(|nonce| (nonce, hasher.hash(nonce)))
            .find(|(_, hash)| *hash < proof.hash)
            .expect("a nonce with a better hash exists in the finite search space");
        let mut competitor = proof.clone();
        competitor.nonce = nonce;
        competitor.hash = hash;
        let (sender, receiver) = proof_inbox(false);
        assert!(sender.deliver(competitor.clone(), &telemetry));

        let publication = super::RefreshPublication {
            epoch: 1,
            sequence: 1,
            snapshot,
        };
        assert_eq!(
            pending.on_publication(Some(&publication), true, &manifest, wallet, now, &telemetry,),
            super::PendingProofDecision::RetryQueued
        );
        assert!(
            !receiver.requeue(pending.proof, &telemetry),
            "the better same-context candidate should supersede the retained proof"
        );
        let queued = receiver.take_next().unwrap();
        assert_eq!(queued.nonce, competitor.nonce);
        assert_eq!(queued.hash, competitor.hash);
        assert_eq!(telemetry.count(1, ProofMetric::QueueCandidateSuperseded), 1);
    }

    #[test]
    fn auto_uses_gpu_only_when_measured_rate_clearly_beats_cpu() {
        assert!(!gpu_is_meaningfully_faster(0, 1));
        assert!(!gpu_is_meaningfully_faster(100, 100));
        assert!(!gpu_is_meaningfully_faster(105, 100));
        assert!(!gpu_is_meaningfully_faster(110, 100));
        assert!(gpu_is_meaningfully_faster(111, 100));
        assert!(!gpu_is_meaningfully_faster(100, 111));
        assert!(gpu_is_meaningfully_faster(200, 100));
    }

    fn test_block(number: u64, timestamp: u64) -> BlockSnapshot {
        BlockSnapshot {
            number,
            timestamp,
            hash: B256::with_last_byte(number as u8),
        }
    }

    #[test]
    fn aggregate_history_profile_requires_explicit_developer_opt_in() {
        assert!(!history_profile_enabled(None));
        assert!(!history_profile_enabled(Some("0")));
        assert!(!history_profile_enabled(Some("true")));
        assert!(history_profile_enabled(Some("1")));
    }

    #[test]
    fn compute_only_can_continue_with_unresolved_transactions_without_opening_a_manager() {
        assert!(!unresolved_session_blocks_mining(true, true, false));
        assert!(unresolved_session_blocks_mining(false, true, false));
        assert!(!unresolved_session_blocks_mining(false, true, true));
        assert!(!should_open_transaction_manager(true, false, true));
        assert!(!should_open_transaction_manager(true, false, false));
    }

    #[test]
    fn per_run_cap_is_bounded_by_balance_after_reserve_and_unresolved_liabilities() {
        let inj = U256::from(1_000_000_000_000_000_000_u128);
        assert_eq!(
            per_run_authorization_cap(
                inj,
                inj / U256::from(10),
                inj / U256::from(5),
                inj * U256::from(2),
            ),
            inj
        );
        assert_eq!(
            per_run_authorization_cap(
                inj * U256::from(3),
                inj / U256::from(10),
                inj / U256::from(5),
                inj * U256::from(2),
            ),
            inj * U256::from(17) / U256::from(10)
        );
        assert_eq!(
            per_run_authorization_cap(inj, inj, U256::ZERO, inj / U256::from(2)),
            U256::ZERO
        );
        assert_eq!(
            per_run_authorization_cap(inj, U256::ZERO, inj, inj / U256::from(2)),
            U256::ZERO
        );
    }

    #[test]
    fn reduced_per_run_limit_rounds_down_and_requires_one_explicit_yes() {
        let inj = U256::from(1_000_000_000_000_000_000_u128);
        let available = U256::from(873_727_000_000_000_000_u128);
        let suggested = U256::from(870_000_000_000_000_000_u128);
        assert_eq!(suggested_session_limit(inj, available), Some(suggested));
        assert_eq!(approved_session_limit(inj, available, false), None);
        assert_eq!(
            approved_session_limit(inj, available, true),
            Some(suggested)
        );
        assert_eq!(suggested_session_limit(inj, U256::ZERO), None);
        assert_eq!(
            approved_session_limit(inj, inj + U256::from(400_000_000_000_000_000_u128), false),
            Some(inj),
            "sufficient balance uses the configured cap without another confirmation"
        );
    }

    struct BalanceRpcServer {
        url: String,
        stop: Arc<AtomicBool>,
        requests: Arc<AtomicUsize>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl BalanceRpcServer {
        fn start(balances: Vec<U256>) -> Self {
            use std::collections::VecDeque;
            use std::io::Write;
            use std::net::TcpListener;

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let stop = Arc::new(AtomicBool::new(false));
            let requests = Arc::new(AtomicUsize::new(0));
            let server_stop = Arc::clone(&stop);
            let server_requests = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                let mut pending = VecDeque::from(balances);
                let mut latest = pending.back().copied().unwrap_or(U256::ZERO);
                while !server_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            let Some(request) = read_balance_request(&mut stream) else {
                                continue;
                            };
                            if request.contains("eth_getBalance") {
                                latest = pending.pop_front().unwrap_or(latest);
                                server_requests.fetch_add(1, Ordering::AcqRel);
                            }
                            let body =
                                format!(r#"{{"jsonrpc":"2.0","id":1,"result":"0x{latest:x}"}}"#);
                            let _ = write!(
                                stream,
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.flush();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                url,
                stop,
                requests,
                handle: Some(handle),
            }
        }

        fn url(&self) -> &str {
            &self.url
        }

        fn requests(&self) -> usize {
            self.requests.load(Ordering::Acquire)
        }
    }

    impl Drop for BalanceRpcServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn read_balance_request(stream: &mut std::net::TcpStream) -> Option<String> {
        use std::io::Read;

        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).ok()?;
            if read == 0 {
                return None;
            }
            request.extend_from_slice(&buffer[..read]);
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if request.len() >= end + 4 + content_length {
                    return Some(String::from_utf8_lossy(&request).into_owned());
                }
            }
        }
    }

    fn paid_run_config(wallet: Address, limit: &str, reserve: &str) -> AppConfig {
        AppConfig {
            network: Network::Testnet,
            wallet_address: Some(format!("{wallet:#x}")),
            minimum_reserve_inj: reserve.to_owned(),
            per_session_spending_limit_inj: limit.to_owned(),
            ..AppConfig::default()
        }
    }

    fn paid_run_client(url: &str) -> NetworkClient {
        NetworkClient::local_test_client(
            url,
            Address::with_last_byte(0x31),
            B256::with_last_byte(0x41),
            Address::with_last_byte(0x51),
            B256::with_last_byte(0x61),
            9,
        )
        .unwrap()
    }

    async fn open_paid_test_session(
        store: &ConfigStore,
        config: &AppConfig,
        client: &NetworkClient,
        wallet: Address,
        configured_limit: U256,
        approved_limit: U256,
        approvals: Vec<bool>,
    ) -> anyhow::Result<Option<(crate::transaction::TransactionManager, U256)>> {
        let open_limits = paid_run_session_open_limits(configured_limit, approved_limit);
        let mut reduced_limit_prompt = super::ReducedLimitPrompt::scripted(approvals);
        open_paid_per_run_session(
            store,
            config,
            wallet,
            Address::with_last_byte(0x51),
            client,
            open_limits.configured_ceiling,
            open_limits.approved_limit,
            &mut reduced_limit_prompt,
            Arc::new(crate::history_telemetry::HistoryTelemetry::default()),
            None,
        )
        .await
    }

    #[test]
    fn paid_run_production_boundary_preserves_configured_ceiling_and_reduced_approval() {
        let configured = parse_inj_wei("1").unwrap();
        let full = paid_run_session_open_limits(configured, configured);
        assert_eq!(
            full,
            PaidRunSessionOpenLimits {
                configured_ceiling: configured,
                approved_limit: configured,
            },
            "a full-cap production startup keeps the configured ceiling and approved limit"
        );

        let reduced = parse_inj_wei("0.87").unwrap();
        let limited = paid_run_session_open_limits(configured, reduced);
        assert_eq!(limited.configured_ceiling, configured);
        assert_eq!(limited.approved_limit, reduced);
        assert_eq!(
            limited,
            PaidRunSessionOpenLimits {
                configured_ceiling: configured,
                approved_limit: reduced,
            },
            "a reduced approval must not replace the saved configured ceiling"
        );
    }

    #[tokio::test]
    async fn paid_run_full_configured_cap_opens_the_session() {
        let wallet = Address::with_last_byte(0x21);
        let config = paid_run_config(wallet, "1", "0.1");
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        TransactionJournal::set_per_run_policy_approval(&store, &config, Some(wallet)).unwrap();
        let configured = parse_inj_wei("1").unwrap();
        let server = BalanceRpcServer::start(vec![U256::from(2_000_000_000_000_000_000_u128)]);
        let client = paid_run_client(server.url());

        let (manager, limit) = open_paid_test_session(
            &store,
            &config,
            &client,
            wallet,
            configured,
            configured,
            Vec::new(),
        )
        .await
        .unwrap()
        .expect("a funded full-cap session should open");
        assert_eq!(limit, configured);
        drop(manager);
        assert_eq!(
            TransactionJournal::inspect_session(&store, &config)
                .unwrap()
                .limit_wei
                .as_deref(),
            Some("1000000000000000000")
        );
    }

    #[tokio::test]
    async fn paid_run_reduced_approval_opens_the_session_with_the_reduced_limit() {
        let wallet = Address::with_last_byte(0x22);
        let config = paid_run_config(wallet, "1", "0.1");
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        TransactionJournal::set_per_run_policy_approval(&store, &config, Some(wallet)).unwrap();
        let configured = parse_inj_wei("1").unwrap();
        let approved = parse_inj_wei("0.87").unwrap();
        // 0.973727 INJ leaves 0.873727 INJ spendable after the 0.1 INJ reserve,
        // the real balance that rounds down to the already-approved 0.87 INJ cap.
        let server = BalanceRpcServer::start(vec![U256::from(973_727_000_000_000_000_u128)]);
        let client = paid_run_client(server.url());

        let (manager, limit) = open_paid_test_session(
            &store,
            &config,
            &client,
            wallet,
            configured,
            approved,
            Vec::new(),
        )
        .await
        .unwrap()
        .expect("an already-approved reduced cap should open with sufficient balance");
        assert_eq!(
            limit, approved,
            "the production boundary must keep the saved ceiling while approving the reduced limit"
        );
        assert_eq!(
            server.requests(),
            1,
            "the already-approved cap must open without prompting or a second balance read"
        );
        drop(manager);
        assert_eq!(
            TransactionJournal::inspect_session(&store, &config)
                .unwrap()
                .limit_wei
                .as_deref(),
            Some("870000000000000000")
        );
    }

    #[tokio::test]
    async fn paid_run_positive_recheck_approval_opens_the_session() {
        let wallet = Address::with_last_byte(0x26);
        let config = paid_run_config(wallet, "1", "0.1");
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        TransactionJournal::set_per_run_policy_approval(&store, &config, Some(wallet)).unwrap();
        let configured = parse_inj_wei("1").unwrap();
        let balance = U256::from(973_727_000_000_000_000_u128);
        let server = BalanceRpcServer::start(vec![balance, balance]);
        let client = paid_run_client(server.url());

        let (manager, limit) = open_paid_test_session(
            &store,
            &config,
            &client,
            wallet,
            configured,
            configured,
            vec![true],
        )
        .await
        .unwrap()
        .expect("the approved reduced limit should open the session after the recheck");
        assert_eq!(
            limit,
            parse_inj_wei("0.87").unwrap(),
            "the accepted recheck must use the reduced 0.87 INJ limit"
        );
        assert_eq!(
            server.requests(),
            2,
            "the accepted reduction must be rechecked against the balance under the journal lock"
        );
        drop(manager);
        assert_eq!(
            TransactionJournal::inspect_session(&store, &config)
                .unwrap()
                .limit_wei
                .as_deref(),
            Some("870000000000000000")
        );
    }

    #[tokio::test]
    async fn paid_run_second_balance_recheck_declines_without_signing_authority() {
        let wallet = Address::with_last_byte(0x23);
        let config = paid_run_config(wallet, "1", "0.1");
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        TransactionJournal::set_per_run_policy_approval(&store, &config, Some(wallet)).unwrap();
        let configured = parse_inj_wei("1").unwrap();
        let server = BalanceRpcServer::start(vec![U256::from(500_000_000_000_000_000_u128)]);
        let client = paid_run_client(server.url());

        let opened = open_paid_test_session(
            &store,
            &config,
            &client,
            wallet,
            configured,
            configured,
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(
            opened.is_none(),
            "a lower balance recheck requires an explicit approval before any session is opened"
        );
        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(snapshot.session_id.is_none());
        assert!(snapshot.limit_wei.is_none());
    }

    #[tokio::test]
    async fn paid_run_insufficient_balance_creates_no_signing_authority() {
        let wallet = Address::with_last_byte(0x24);
        let config = paid_run_config(wallet, "1", "0.1");
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        TransactionJournal::set_per_run_policy_approval(&store, &config, Some(wallet)).unwrap();
        let configured = parse_inj_wei("1").unwrap();
        let server = BalanceRpcServer::start(vec![U256::from(50_000_000_000_000_000_u128)]);
        let client = paid_run_client(server.url());

        let opened = open_paid_test_session(
            &store,
            &config,
            &client,
            wallet,
            configured,
            configured,
            Vec::new(),
        )
        .await
        .unwrap();
        assert!(
            opened.is_none(),
            "a balance below the reserve cannot create a paid session"
        );
        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(snapshot.session_id.is_none());
        assert!(snapshot.limit_wei.is_none());
    }

    #[tokio::test]
    async fn paid_run_mismatched_ceiling_is_refused_without_signing_authority() {
        let wallet = Address::with_last_byte(0x25);
        let config = paid_run_config(wallet, "1", "0.1");
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        TransactionJournal::set_per_run_policy_approval(&store, &config, Some(wallet)).unwrap();
        let reduced = parse_inj_wei("0.87").unwrap();
        let server = BalanceRpcServer::start(vec![U256::from(2_000_000_000_000_000_000_u128)]);
        let client = paid_run_client(server.url());

        let error = open_paid_test_session(
            &store,
            &config,
            &client,
            wallet,
            reduced,
            reduced,
            Vec::new(),
        )
        .await
        .err()
        .expect("a ceiling that differs from the saved configuration must fail closed");
        assert!(
            format!("{error:#}").contains("per-run authorization budget does not match"),
            "{error:#}"
        );
        let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
        assert!(snapshot.session_id.is_none());
        assert!(snapshot.limit_wei.is_none());
    }

    #[test]
    fn dashboard_node_status_requires_verified_live_work_and_respects_transactions() {
        let mut state = eligible_state();
        assert_eq!(
            dashboard_node_status(Some(&state), true, true, true, None),
            NodeStatus::Mining
        );
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, false, None),
            NodeStatus::Waiting
        );
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, true, None),
            NodeStatus::WaitingForChain
        );
        assert_eq!(
            dashboard_node_status(Some(&state), false, true, true, None),
            NodeStatus::RpcError
        );
        assert_eq!(
            dashboard_node_status(None, true, false, false, None),
            NodeStatus::RpcError
        );

        state.work.started = false;
        state.work.ended = false;
        state.work.remaining_allocation = U256::from(10_u8);
        state.eligible = false;
        state.finalizable = false;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, false, None),
            NodeStatus::WaitingForGenesis
        );
        assert_eq!(traced_node_status(Some(&state), true), "WAIT GENESIS");
        state.work.remaining_allocation = U256::ZERO;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, false, None),
            NodeStatus::WaitingForGenesis,
            "a verified unstarted node is waiting for genesis even before allocation is visible"
        );
        assert_eq!(traced_node_status(Some(&state), true), "WAIT GENESIS");
        assert_eq!(
            dashboard_node_status(Some(&state), false, false, false, None),
            NodeStatus::RpcError,
            "an inactive but unverified runtime must not be shown as waiting for genesis"
        );
        assert_eq!(traced_node_status(Some(&state), false), "RPC ERROR");
        state.work.ended = true;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, false, None),
            NodeStatus::Ended,
            "a permanently ended node must not wait for genesis"
        );

        state.work.started = true;
        state.work.ended = false;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, false, None),
            NodeStatus::Ended,
            "an active node with exhausted allocation is ended"
        );
        assert_eq!(traced_node_status(Some(&state), true), "ENDED");
        state.work.remaining_allocation = U256::from(10_u8);
        state.mining_paused = true;
        assert_eq!(
            dashboard_node_status(Some(&state), true, true, true, None),
            NodeStatus::Paused
        );
        state.mining_paused = false;
        state.work.ended = true;
        assert_eq!(
            dashboard_node_status(Some(&state), true, true, true, None),
            NodeStatus::Ended
        );
        state.work.ended = false;
        state.finalizable = true;
        state.eligible = false;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, true, None),
            NodeStatus::FinalizationRequired
        );

        assert_eq!(
            dashboard_node_status(
                Some(&state),
                true,
                false,
                false,
                Some(TransactionActivityState::Finalizing)
            ),
            NodeStatus::Finalizing
        );
        assert_eq!(
            dashboard_node_status(
                Some(&state),
                true,
                false,
                false,
                Some(TransactionActivityState::Confirming)
            ),
            NodeStatus::Confirming
        );
        assert_eq!(
            dashboard_node_status(
                Some(&state),
                true,
                false,
                false,
                Some(TransactionActivityState::Signed)
            ),
            NodeStatus::Signed
        );
        assert_eq!(
            dashboard_node_status(
                Some(&state),
                true,
                false,
                false,
                Some(TransactionActivityState::Recovering)
            ),
            NodeStatus::Recovering
        );
    }

    #[test]
    fn genesis_poll_selection_is_limited_to_selected_verified_unstarted_nodes() {
        let mut inactive = eligible_state();
        inactive.work.started = false;
        inactive.eligible = false;
        inactive.finalizable = false;

        let mut ended = inactive.clone();
        ended.work.ended = true;

        let mut unallocated = inactive.clone();
        unallocated.work.remaining_allocation = U256::ZERO;

        let mut exhausted = eligible_state();
        exhausted.work.remaining_allocation = U256::ZERO;

        let mut nodes = vec![
            NodeView {
                id: 1,
                address: Address::with_last_byte(1),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(inactive.clone()),
                error: None,
            },
            NodeView {
                id: 2,
                address: Address::with_last_byte(2),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(eligible_state()),
                error: None,
            },
            NodeView {
                id: 3,
                address: Address::with_last_byte(3),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(ended),
                error: None,
            },
            NodeView {
                id: 4,
                address: Address::with_last_byte(4),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(unallocated),
                error: None,
            },
            NodeView {
                id: 5,
                address: Address::with_last_byte(5),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: None,
                error: Some("state unavailable".to_owned()),
            },
            NodeView {
                id: 6,
                address: Address::with_last_byte(6),
                pin: ContractPinStatus {
                    runtime_verified: false,
                    abi_verified: false,
                    error: Some("runtime pin not trusted".to_owned()),
                },
                state: Some(inactive),
                error: None,
            },
            NodeView {
                id: 7,
                address: Address::with_last_byte(7),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some({
                    let mut state = eligible_state();
                    state.work.started = false;
                    state.eligible = false;
                    state.finalizable = false;
                    state
                }),
                error: None,
            },
            NodeView {
                id: 8,
                address: Address::with_last_byte(8),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(exhausted),
                error: None,
            },
        ];
        nodes.reverse();
        let snapshot = ReadSnapshot {
            block: test_block(100, 500),
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes,
        };
        let selected = HashSet::from([1, 2, 3, 4, 5, 6, 8]);

        assert_eq!(inactive_genesis_nodes(&snapshot, &selected), [1, 4]);
        assert!(inactive_genesis_nodes(&snapshot, &HashSet::new()).is_empty());
    }

    #[test]
    fn dashboard_model_sorts_and_only_copies_selected_nodes() {
        let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
        let selected = HashSet::from([7, 1, 3]);
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let nodes = [7, 2, 3, 1]
            .into_iter()
            .map(|id| NodeView {
                id,
                address: Address::with_last_byte(id),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(eligible_state()),
                error: None,
            })
            .collect();
        let snapshot = ReadSnapshot {
            block: BlockSnapshot {
                number: 123,
                timestamp: 100,
                hash: B256::with_last_byte(1),
            },
            native_balance: Some(U256::from(1_000)),
            native_balance_error: None,
            ast_balance: Some(U256::from(39_000_000_000_000_u128)),
            ast_balance_error: None,
            nodes,
        };
        let context = DashboardContext {
            network: Network::Testnet,
            chain_id: 1439,
            address: Address::with_last_byte(9),
            active_backend: Arc::new(RwLock::new(ActiveBackend::Cpu { threads: 2 })),
            spending_limit: U256::ZERO,
            transaction_mode: false,
            compute_only: true,
            workers_started: Arc::new(AtomicBool::new(true)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            selected: selected.clone(),
            slots: Arc::clone(&slots),
            schedule: Arc::clone(&schedule),
            transaction_state: Arc::new(RwLock::new(TransactionDashboardState {
                authorization_used: None,
                actual_rpc_cost: None,
                mined_rewards: U256::from(26_000_000_000_000_u128),
                activities: Vec::new(),
            })),
            pending_sync: Arc::new(RwLock::new(HashMap::new())),
            finalization_state: Arc::new(RwLock::new(HashMap::new())),
        };
        update_slots(
            &slots,
            &schedule,
            &DeploymentManifest::load(Network::Testnet).unwrap(),
            context.address,
            &selected,
            &snapshot,
        )
        .unwrap();
        assert_eq!(
            *schedule
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [0, 2, 6]
        );

        let model = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(model.ast_balance, Some(U256::from(39_000_000_000_000_u128)));
        assert_eq!(model.mined_rewards, U256::from(26_000_000_000_000_u128));
        assert_eq!(
            model
                .selected_nodes
                .iter()
                .map(|node| node.id)
                .collect::<Vec<_>>(),
            [1, 3, 7]
        );
        let advanced_at = model.last_block_advanced_at;
        let repeated_read_at = Instant::now() + Duration::from_secs(5);
        let mut repeated = model.clone();
        repeated.snapshot_observed_at = repeated_read_at;
        assert!(!reconcile_head_progress(
            &model,
            &mut repeated,
            repeated_read_at
        ));
        assert_eq!(repeated.last_block_advanced_at, advanced_at);

        repeated.block_number += 1;
        repeated.block_hash = B256::with_last_byte(2);
        assert!(reconcile_head_progress(
            &model,
            &mut repeated,
            repeated_read_at
        ));
        assert_eq!(repeated.last_block_advanced_at, repeated_read_at);

        let mut probe_error_model = model.clone();
        probe_error_model
            .selected_nodes
            .iter_mut()
            .find(|node| node.id == 3)
            .unwrap()
            .status = NodeStatus::WaitingForGenesis;
        let probe_error = "genesis status poll failed for selected node(s) [3]: timeout";
        assert!(apply_genesis_poll_error(
            &mut probe_error_model,
            &[3],
            probe_error
        ));
        assert_eq!(probe_error_model.mode(Instant::now()), "RPC ERROR");
        assert_eq!(
            probe_error_model
                .selected_nodes
                .iter()
                .find(|node| node.id == 3)
                .unwrap()
                .status,
            NodeStatus::RpcError
        );
        assert_eq!(
            probe_error_model
                .selected_nodes
                .iter()
                .find(|node| node.id == 1)
                .unwrap()
                .status,
            NodeStatus::Mining,
            "an inactive-node poll error must not mark other selected mining nodes failed"
        );
        assert!(!clear_genesis_poll_error(
            &mut probe_error_model,
            &[3],
            "a different RPC error"
        ));
        assert!(clear_genesis_poll_error(
            &mut probe_error_model,
            &[3],
            probe_error
        ));
        assert_eq!(probe_error_model.connection_error, None);
        assert_eq!(
            probe_error_model
                .selected_nodes
                .iter()
                .find(|node| node.id == 3)
                .unwrap()
                .status,
            NodeStatus::WaitingForGenesis
        );
    }

    #[test]
    fn dashboard_distinguishes_required_retrying_and_blocked_finalization_from_chain_wait() {
        let wallet = Address::with_last_byte(9);
        let selected = (1_u8..=9).collect::<HashSet<_>>();
        let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let mut state = eligible_state();
        state.eligible = false;
        state.finalizable = true;
        let snapshot = ReadSnapshot {
            block: test_block(101, state.work.window_expiry_time + 1),
            native_balance: Some(U256::from(100)),
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: (1_u8..=9)
                .map(|id| NodeView {
                    id,
                    address: Address::with_last_byte(id),
                    pin: ContractPinStatus {
                        runtime_verified: true,
                        abi_verified: true,
                        error: None,
                    },
                    state: Some(state.clone()),
                    error: None,
                })
                .collect(),
        };
        let finalization_state = Arc::new(RwLock::new(HashMap::new()));
        let context = DashboardContext {
            network: Network::Testnet,
            chain_id: 1439,
            address: wallet,
            active_backend: Arc::new(RwLock::new(ActiveBackend::Cpu { threads: 1 })),
            spending_limit: U256::from(1),
            transaction_mode: true,
            compute_only: false,
            workers_started: Arc::new(AtomicBool::new(true)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            selected: selected.clone(),
            slots: Arc::clone(&slots),
            schedule: Arc::clone(&schedule),
            transaction_state: Arc::new(RwLock::new(TransactionDashboardState::default())),
            pending_sync: Arc::new(RwLock::new(HashMap::new())),
            finalization_state: Arc::clone(&finalization_state),
        };
        let required = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(
            required.selected_nodes[0].status,
            NodeStatus::FinalizationRequired
        );
        assert_eq!(required.mode(Instant::now()), "FINALIZATION REQUIRED");
        assert!(
            required
                .current_action
                .as_deref()
                .is_some_and(|action| action.contains("0 H/s expected")),
            "all nine expired windows should explain the zero hashrate immediately"
        );

        finalization_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                1,
                FinalizationState::Retrying {
                    window_id: state.work.window_id,
                    attempts: 1,
                    retry_at: Instant::now() + Duration::from_secs(1),
                    reason: "temporary RPC failure".to_owned(),
                },
            );
        let retrying = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(
            retrying.selected_nodes[0].status,
            NodeStatus::FinalizationRetrying
        );
        assert!(
            retrying
                .current_action
                .as_deref()
                .unwrap()
                .contains("temporary RPC")
        );

        finalization_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                1,
                FinalizationState::Blocked {
                    window_id: state.work.window_id,
                    reason: "session cap exhausted".to_owned(),
                },
            );
        let blocked = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(
            blocked.selected_nodes[0].status,
            NodeStatus::FinalizationBlocked
        );
        assert_eq!(blocked.mode(Instant::now()), "FINALIZATION BLOCKED");
        assert!(
            blocked
                .current_action
                .as_deref()
                .unwrap()
                .contains("session cap")
        );

        finalization_state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        state.eligible = true;
        state.finalizable = false;
        let mut waiting_snapshot = snapshot.clone();
        for node in &mut waiting_snapshot.nodes {
            node.state = Some(state.clone());
        }
        let waiting = dashboard_model(&context, &waiting_snapshot, Instant::now());
        assert_eq!(
            waiting.selected_nodes[0].status,
            NodeStatus::WaitingForChain
        );
        assert_eq!(waiting.mode(Instant::now()), "WAITING FOR CHAIN");
    }

    #[test]
    fn dashboard_labels_an_in_flight_transaction_for_an_older_window() {
        let wallet = Address::with_last_byte(9);
        let selected = HashSet::from([1_u8]);
        let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let transaction_state = Arc::new(RwLock::new(TransactionDashboardState {
            activities: vec![TransactionActivity {
                node_id: 1,
                window_id: 7,
                state: TransactionActivityState::Recovering,
            }],
            ..TransactionDashboardState::default()
        }));
        let context = DashboardContext {
            network: Network::Testnet,
            chain_id: 1439,
            address: wallet,
            active_backend: Arc::new(RwLock::new(ActiveBackend::Cpu { threads: 1 })),
            spending_limit: U256::from(1),
            transaction_mode: true,
            compute_only: false,
            workers_started: Arc::new(AtomicBool::new(true)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            selected,
            slots,
            schedule,
            transaction_state: Arc::clone(&transaction_state),
            pending_sync: Arc::new(RwLock::new(HashMap::new())),
            finalization_state: Arc::new(RwLock::new(HashMap::new())),
        };
        let mut current_work = eligible_state();
        current_work.work.window_id = 8;
        let snapshot = ReadSnapshot {
            block: test_block(108, 150),
            native_balance: Some(U256::from(100)),
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: Address::with_last_byte(1),
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(current_work),
                error: None,
            }],
        };
        let mut model = dashboard_model(&context, &snapshot, Instant::now());
        apply_transaction_state_to_model(
            &mut model,
            &transaction_state
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        let action = model.current_action.as_deref().unwrap();
        assert!(action.contains("older window #7"), "{action}");
        assert!(action.contains("chain now at #8"), "{action}");
        apply_transaction_state_to_model(&mut model, &TransactionDashboardState::default());
        assert_eq!(
            model.current_action, None,
            "resolved activity must clear its footer action"
        );
    }

    #[test]
    fn snapshot_freshness_rejects_stale_heads_and_accepts_selected_rpc_reorgs() {
        let previous = BlockSnapshot {
            number: 100,
            timestamp: 1_000,
            hash: B256::with_last_byte(1),
        };
        let same = previous.clone();
        assert_eq!(
            compare_snapshot_freshness(&previous, &same, None, None).unwrap(),
            SnapshotFreshness::Current
        );

        let higher = BlockSnapshot {
            number: 101,
            timestamp: 1_001,
            hash: B256::with_last_byte(2),
        };
        assert_eq!(
            compare_snapshot_freshness(&previous, &higher, None, None).unwrap(),
            SnapshotFreshness::Current
        );

        let stale = BlockSnapshot {
            number: 99,
            timestamp: 999,
            hash: B256::with_last_byte(3),
        };
        assert!(compare_snapshot_freshness(&previous, &stale, Some(previous.hash), None).is_err());
        assert_eq!(
            compare_snapshot_freshness(&previous, &stale, Some(B256::with_last_byte(4)), None,)
                .unwrap(),
            SnapshotFreshness::Reorg
        );

        let same_height_reorg = BlockSnapshot {
            number: previous.number,
            timestamp: 1_000,
            hash: B256::with_last_byte(5),
        };
        assert!(compare_snapshot_freshness(&previous, &same_height_reorg, None, None).is_err());
        assert_eq!(
            compare_snapshot_freshness(
                &previous,
                &same_height_reorg,
                None,
                Some(same_height_reorg.hash),
            )
            .unwrap(),
            SnapshotFreshness::Reorg
        );
    }

    #[tokio::test]
    async fn watch_ref_from_match_scrutinee_blocks_publisher_across_async_arm() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (sender, receiver) = watch::channel(ObserverUpdate::RpcError {
                    message: "initial".to_owned(),
                    report: false,
                });
                let (entered_tx, entered_rx) = oneshot::channel();
                let (finish_tx, finish_rx) = oneshot::channel();
                let mut consumer_receiver = receiver.clone();
                let consumer = tokio::task::spawn_local(async move {
                    match consumer_receiver.borrow_and_update().clone() {
                        ObserverUpdate::RpcError { .. } => {
                            entered_tx.send(()).unwrap();
                            finish_rx.await.unwrap();
                        }
                        _ => panic!("unexpected observer update"),
                    }
                });
                entered_rx.await.unwrap();

                let publisher = sender.clone();
                let (published_tx, published_rx) = std::sync::mpsc::channel();
                let thread = thread::spawn(move || {
                    publisher.send_replace(ObserverUpdate::RpcError {
                        message: "next".to_owned(),
                        report: false,
                    });
                    published_tx.send(()).unwrap();
                });
                assert_eq!(
                    published_rx.recv_timeout(Duration::from_millis(50)),
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout),
                    "the match scrutinee read guard should remain held through the async arm"
                );
                finish_tx.send(()).unwrap();
                consumer.await.unwrap();
                published_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("publisher should continue after the match expression ends");
                thread.join().unwrap();
                assert!(matches!(
                    &*receiver.borrow(),
                    ObserverUpdate::RpcError { message, .. } if message == "next"
                ));
            })
            .await;
    }

    #[tokio::test]
    async fn owned_observer_update_does_not_block_publication_during_await() {
        let initial = ObserverUpdate::RpcError {
            message: "initial".to_owned(),
            report: false,
        };
        let (sender, mut receiver) = watch::channel(initial);
        let update = take_observer_update(&mut receiver);
        let (finish_transaction_tx, finish_transaction_rx) = oneshot::channel();
        let consumer = tokio::spawn(async move {
            let _owned_update = update;
            finish_transaction_rx.await.unwrap();
        });

        tokio::task::yield_now().await;
        assert!(
            !consumer.is_finished(),
            "simulated transaction wait is pending"
        );

        let refresh_gate = Arc::new(std::sync::Mutex::new(()));
        let publisher_gate = Arc::clone(&refresh_gate);
        let publisher = tokio::task::spawn_blocking(move || {
            let _commit = publisher_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sender.send_replace(ObserverUpdate::RpcError {
                message: "published while transaction awaits".to_owned(),
                report: false,
            });
        });
        tokio::time::timeout(Duration::from_secs(1), publisher)
            .await
            .expect("watch publisher must not wait for transaction completion")
            .unwrap();

        let force_refresh_gate = Arc::clone(&refresh_gate);
        tokio::time::timeout(
            Duration::from_secs(1),
            tokio::task::spawn_blocking(move || {
                let _commit = force_refresh_gate
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }),
        )
        .await
        .expect("forced refresh must not deadlock behind publication")
        .unwrap();
        finish_transaction_tx.send(()).unwrap();
        consumer.await.unwrap();
        assert!(matches!(
            &*receiver.borrow(),
            ObserverUpdate::RpcError { message, .. }
                if message == "published while transaction awaits"
        ));
    }

    #[test]
    fn accepted_proof_waits_for_receipt_block_then_uses_only_verified_best_candidate() {
        let wallet = Address::with_last_byte(9);
        let selected = HashSet::from([1_u8]);
        let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let mut state = eligible_state();
        let initial_view = NodeView {
            id: 1,
            address: Address::with_last_byte(1),
            pin: ContractPinStatus {
                runtime_verified: true,
                abi_verified: true,
                error: None,
            },
            state: Some(state.clone()),
            error: None,
        };
        let mut snapshot = ReadSnapshot {
            block: BlockSnapshot {
                number: 9,
                timestamp: 100,
                hash: B256::with_last_byte(9),
            },
            native_balance: Some(U256::from(1_000)),
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![initial_view],
        };
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        update_slots(&slots, &schedule, &manifest, wallet, &selected, &snapshot).unwrap();
        let context = DashboardContext {
            network: Network::Testnet,
            chain_id: 1439,
            address: wallet,
            active_backend: Arc::new(RwLock::new(ActiveBackend::Cpu { threads: 2 })),
            spending_limit: U256::ZERO,
            transaction_mode: false,
            compute_only: false,
            workers_started: Arc::new(AtomicBool::new(true)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            selected: selected.clone(),
            slots: Arc::clone(&slots),
            schedule: Arc::clone(&schedule),
            transaction_state: Arc::new(RwLock::new(TransactionDashboardState::default())),
            pending_sync: Arc::new(RwLock::new(HashMap::from([(
                1,
                PendingDashboardSync {
                    window_id: state.work.window_id,
                    receipt_block: 10,
                },
            )]))),
            finalization_state: Arc::new(RwLock::new(HashMap::new())),
        };

        let syncing = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(syncing.selected_nodes[0].status, NodeStatus::Syncing);
        assert_eq!(syncing.selected_nodes[0].candidate, None);
        assert_eq!(
            syncing.selected_nodes[0].window_id,
            Some(state.work.window_id)
        );

        state.candidate = Some(CandidateInfo {
            miner: wallet,
            nonce: 17,
            work_hash: B256::with_last_byte(3),
            submitted_at: 101,
            header: Bytes::new(),
            first_valid_solve_secs: 1,
        });
        snapshot.block.number = 10;
        snapshot.nodes[0].state = Some(state.clone());
        let verified = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(verified.selected_nodes[0].status, NodeStatus::Mining);
        assert_eq!(verified.selected_nodes[0].candidate, Some(wallet));

        state.candidate.as_mut().unwrap().miner = Address::with_last_byte(8);
        snapshot.block.number = 11;
        snapshot.nodes[0].state = Some(state.clone());
        let replaced = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(
            replaced.selected_nodes[0].candidate,
            Some(Address::with_last_byte(8))
        );

        state.work.window_id = 8;
        state.work.window_expiry_time = 260;
        state.candidate = None;
        snapshot.block.number = 11;
        snapshot.block.timestamp = 200;
        snapshot.nodes[0].state = Some(state);
        update_slots(&slots, &schedule, &manifest, wallet, &selected, &snapshot).unwrap();
        let next_window = dashboard_model(&context, &snapshot, Instant::now());
        assert_eq!(next_window.selected_nodes[0].window_id, Some(8));
        assert_eq!(next_window.selected_nodes[0].candidate, None);
        let next_window_time_left = next_window.selected_nodes[0]
            .time_left(Instant::now())
            .unwrap();
        assert!((58..=60).contains(&next_window_time_left));
    }

    #[test]
    fn nonce_ranges_are_non_overlapping_and_stop_at_u128_maximum() {
        let mut allocator = NonceAllocator::default();
        assert_eq!(allocator.reserve(4), Some((0, 4)));
        assert_eq!(allocator.reserve(4), Some((4, 4)));

        let mut final_range = NonceAllocator {
            next: Some(u128::MAX - 1),
        };
        assert_eq!(final_range.reserve(4), Some((u128::MAX - 1, 2)));
        assert_eq!(final_range.reserve(4), None);

        let slot = NodeSlot::new(1);
        let gpu_reserved = slot.reserve_nonces(crate::gpu::MAX_GPU_BATCH_SIZE).unwrap();
        let cpu_fallback = slot.reserve_nonces(super::NONCE_BATCH_SIZE).unwrap();
        assert_eq!(gpu_reserved, (0, crate::gpu::MAX_GPU_BATCH_SIZE));
        assert_eq!(
            cpu_fallback,
            (
                crate::gpu::MAX_GPU_BATCH_SIZE as u128,
                super::NONCE_BATCH_SIZE
            )
        );
    }

    #[test]
    fn gpu_candidate_is_batch_bound_and_cpu_revalidated_before_proof_queueing() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let mut state = eligible_state();
        state.work.target = U256::MAX;
        let now = Instant::now();
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&state),
            &test_block(1, 100),
            now,
        )
        .unwrap();
        let work = slot.current_work_at(now).unwrap();
        let nonce = u128::from(u64::MAX) + 1;
        let hash = work.hasher.hash(nonce);
        let batch = GpuBatchIdentity {
            node_id: 1,
            generation: work.generation,
            window_id: state.work.window_id,
            first_nonce: nonce - 1,
            nonce_count: 3,
        };
        let telemetry = ProofPipelineTelemetry::default();
        let (proofs, receiver) = proof_inbox(false);

        let mismatch = process_hashed_candidate(
            &slot,
            &work,
            HashedCandidate {
                nonce,
                hash: B256::ZERO,
                reported_gpu_hash: Some(B256::ZERO),
                batch_identity: Some(batch),
            },
            &proofs,
            &telemetry,
        );
        assert!(matches!(
            mismatch,
            Err(super::GpuCandidateFailure::HashMismatch { .. })
        ));
        assert!(!receiver.has_pending());
        assert_eq!(telemetry.count(1, ProofMetric::GpuHashMismatch), 1);

        let outside_batch = GpuBatchIdentity {
            first_nonce: nonce + 1,
            nonce_count: 1,
            ..batch
        };
        let rejected = process_hashed_candidate(
            &slot,
            &work,
            HashedCandidate {
                nonce,
                hash,
                reported_gpu_hash: Some(hash),
                batch_identity: Some(outside_batch),
            },
            &proofs,
            &telemetry,
        );
        assert!(matches!(
            rejected,
            Err(super::GpuCandidateFailure::InvalidBatchIdentity)
        ));
        assert!(!receiver.has_pending());

        process_hashed_candidate(
            &slot,
            &work,
            HashedCandidate {
                nonce,
                hash,
                reported_gpu_hash: Some(hash),
                batch_identity: Some(batch),
            },
            &proofs,
            &telemetry,
        )
        .unwrap();
        let queued = receiver.take_next().unwrap();
        assert_eq!(queued.batch_identity, Some(batch));
        revalidate_queued_proof(&slot, &queued, &telemetry)
            .expect("GPU proof must pass the existing final CPU preflight");
        let improved = (nonce + 1..nonce + 50_000)
            .find_map(|next_nonce| {
                let next_hash = work.hasher.hash(next_nonce);
                (next_hash < queued.hash).then_some((next_nonce, next_hash))
            })
            .expect("GPU work should find a better same-window candidate");
        let improved_batch = GpuBatchIdentity {
            first_nonce: improved.0,
            nonce_count: 1,
            ..batch
        };
        process_hashed_candidate(
            &slot,
            &work,
            HashedCandidate {
                nonce: improved.0,
                hash: improved.1,
                reported_gpu_hash: Some(improved.1),
                batch_identity: Some(improved_batch),
            },
            &proofs,
            &telemetry,
        )
        .unwrap();
        let improved_queued = receiver.take_next().unwrap();
        assert_eq!(improved_queued.context.window_id, queued.context.window_id);
        assert_eq!(improved_queued.hash, improved.1);
        assert!(improved_queued.hash < queued.hash);
        revalidate_queued_proof(&slot, &improved_queued, &telemetry)
            .expect("the later GPU candidate still passes canonical CPU validation");
        assert_eq!(telemetry.count(1, ProofMetric::GpuCandidatesCpuVerified), 2);
        assert_eq!(telemetry.count(1, ProofMetric::GpuBatchIdentityRejected), 1);
    }

    #[test]
    fn gpu_candidate_from_invalidated_work_generation_is_never_queued() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let state = eligible_state();
        let start = Instant::now();
        let first_block = test_block(1, 100);
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&state),
            &first_block,
            start,
        )
        .unwrap();
        let old_work = slot.current_work_at(start).unwrap();
        let nonce = u128::from(u64::MAX) + 5;
        let hash = old_work.hasher.hash(nonce);
        let batch = GpuBatchIdentity {
            node_id: 1,
            generation: old_work.generation,
            window_id: old_work.fingerprint.hashing_context.window_id,
            first_nonce: nonce,
            nonce_count: 1,
        };

        let mut new_state = state;
        new_state.work.seed = B256::with_last_byte(0xa7);
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&new_state),
            &test_block(2, 101),
            start + Duration::from_secs(1),
        )
        .unwrap();
        assert_ne!(slot.generation(), old_work.generation);

        let telemetry = ProofPipelineTelemetry::default();
        let (proofs, receiver) = proof_inbox(false);
        process_hashed_candidate(
            &slot,
            &old_work,
            HashedCandidate {
                nonce,
                hash,
                reported_gpu_hash: Some(hash),
                batch_identity: Some(batch),
            },
            &proofs,
            &telemetry,
        )
        .unwrap();
        assert!(!receiver.has_pending());
        assert_eq!(
            telemetry.count(1, ProofMetric::WorkerStaleGenerationHash),
            1
        );
    }

    #[test]
    fn automatic_backend_fallback_starts_shared_allocator_cpu_workers() {
        let stop = Arc::new(AtomicBool::new(false));
        let (proof_sender, _proof_receiver) = proof_inbox(false);
        let (events, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let context = MiningWorkerContext {
            slots: Arc::new((1..=9).map(NodeSlot::new).collect()),
            schedule: Arc::new(RwLock::new(Vec::new())),
            stop: Arc::clone(&stop),
            cursor: Arc::new(AtomicUsize::new(0)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            proofs: proof_sender,
            telemetry: Arc::new(ProofPipelineTelemetry::default()),
        };
        let controller = thread::spawn(move || {
            activate_cpu_fallback(2, context, events, "test-injected GPU failure".to_owned());
        });
        let event = receiver.blocking_recv().unwrap();
        assert!(matches!(
            event,
            super::BackendEvent::Activated(ActiveBackend::Cpu { threads: 2 })
        ));
        let fallback_notice = receiver.blocking_recv().unwrap();
        assert!(matches!(
            fallback_notice,
            super::BackendEvent::FallbackNotice(reason)
                if reason.contains("test-injected GPU failure")
        ));
        stop.store(true, Ordering::Release);
        controller.join().unwrap();
    }

    #[test]
    fn target_and_incumbent_changes_preserve_nonces_but_context_changes_reset_them() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let state = eligible_state();
        let block = test_block(1, 100);

        assert!(
            slot.set_work(&manifest, miner, contract, Some(&state), &block)
                .unwrap()
        );
        let initial_generation = slot.current_work().unwrap().generation;
        assert_eq!(
            slot.reserve_nonces(super::NONCE_BATCH_SIZE),
            Some((0, super::NONCE_BATCH_SIZE))
        );
        assert!(
            !slot
                .set_work(&manifest, miner, contract, Some(&state), &block)
                .unwrap()
        );
        assert_eq!(
            slot.reserve_nonces(super::NONCE_BATCH_SIZE),
            Some((2048, super::NONCE_BATCH_SIZE))
        );

        let mut changed_state = eligible_state();
        changed_state.work.target = U256::MAX - U256::from(1);
        assert!(
            slot.set_work(&manifest, miner, contract, Some(&changed_state), &block)
                .unwrap()
        );
        let target_generation = slot.current_work().unwrap().generation;
        assert!(target_generation > initial_generation);
        assert_eq!(
            slot.reserve_nonces(super::NONCE_BATCH_SIZE),
            Some((4096, super::NONCE_BATCH_SIZE))
        );

        changed_state.candidate = Some(CandidateInfo {
            miner: Address::with_last_byte(7),
            nonce: 9,
            work_hash: B256::with_last_byte(3),
            submitted_at: 150,
            header: Bytes::new(),
            first_valid_solve_secs: 2,
        });
        assert!(
            slot.set_work(&manifest, miner, contract, Some(&changed_state), &block)
                .unwrap()
        );
        let incumbent_generation = slot.current_work().unwrap().generation;
        assert!(incumbent_generation > target_generation);
        assert_eq!(
            slot.reserve_nonces(super::NONCE_BATCH_SIZE),
            Some((6144, super::NONCE_BATCH_SIZE))
        );

        changed_state.work.seed = B256::with_last_byte(4);
        assert!(
            slot.set_work(&manifest, miner, contract, Some(&changed_state), &block)
                .unwrap()
        );
        let context_generation = slot.current_work().unwrap().generation;
        assert!(context_generation > incumbent_generation);
        assert_eq!(
            slot.reserve_nonces(super::NONCE_BATCH_SIZE),
            Some((0, super::NONCE_BATCH_SIZE))
        );

        assert!(
            slot.set_work(&manifest, miner, contract, None, &block)
                .unwrap()
        );
        assert!(!slot.is_generation_current(context_generation));
        assert!(slot.current_work().is_none());
    }

    #[test]
    fn old_worker_hash_cannot_poison_local_best_after_context_invalidation() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let initial = eligible_state();
        let block = test_block(1, 100);
        slot.set_work(&manifest, miner, contract, Some(&initial), &block)
            .unwrap();
        let old_work = slot.current_work().unwrap();
        let old_hash = old_work.hasher.hash(17);

        let mut changed = initial;
        changed.work.seed = B256::with_last_byte(4);
        slot.set_work(&manifest, miner, contract, Some(&changed), &block)
            .unwrap();
        assert_eq!(
            slot.update_local_best(old_work.generation, old_work.valid_until, old_hash),
            super::LocalBestUpdate::StaleGeneration
        );
        assert_eq!(
            *slot
                .local_best
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            None
        );
        assert_eq!(
            slot.update_local_best(
                slot.current_work().unwrap().generation,
                Instant::now() + Duration::from_secs(1),
                B256::with_last_byte(1),
            ),
            super::LocalBestUpdate::NewBest
        );
        assert_eq!(
            slot.update_local_best(
                slot.current_work().unwrap().generation,
                Instant::now() - Duration::from_secs(1),
                B256::with_last_byte(0),
            ),
            super::LocalBestUpdate::ExpiredDeadline
        );
    }

    #[test]
    fn scheduler_round_robins_across_only_the_active_nodes() {
        let active = [0, 8];
        let cursor = AtomicUsize::new(0);
        let mut counts = [0_usize; 9];
        for _ in 0..900 {
            counts[next_scheduled_slot(&active, &cursor).unwrap()] += 1;
        }
        assert_eq!(counts[0], 450);
        assert_eq!(counts[8], 450);
        assert!(counts[1..8].iter().all(|count| *count == 0));
        assert_eq!(next_scheduled_slot(&[], &cursor), None);
    }

    #[test]
    fn deadline_stops_work_before_the_cached_window_expires() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let mut state = eligible_state();
        state.work.window_expiry_time = 102;
        let block = test_block(1, 100);
        slot.set_work(
            &manifest,
            Address::with_last_byte(8),
            Address::with_last_byte(9),
            Some(&state),
            &block,
        )
        .unwrap();
        assert!(slot.current_work().is_none());
    }

    #[tokio::test]
    async fn eligible_slot_rearms_only_after_a_new_verified_head_and_hashes_again() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let slot = NodeSlot::new(1);
        let slots = Arc::new(vec![slot]);
        let schedule = Arc::new(RwLock::new(Vec::new()));
        let selected = HashSet::from([1_u8]);
        let mut state = eligible_state();
        state.work.window_expiry_time = 110;
        state.work.target = U256::MAX;

        let start = Instant::now();
        let first_head = test_block(100, 100);
        assert!(
            slots[0]
                .set_work_at(&manifest, miner, contract, Some(&state), &first_head, start)
                .unwrap()
        );
        let initial_generation = slots[0].current_work_at(start).unwrap().generation;
        let initial_job = slots[0].current_work_at(start).unwrap();
        assert_eq!(
            slots[0].update_local_best(
                initial_generation,
                initial_job.valid_until,
                B256::with_last_byte(8),
            ),
            super::LocalBestUpdate::NewBest
        );
        let local_deadline = start + Duration::from_secs(8);
        let after_local_deadline = local_deadline + Duration::from_secs(1);
        assert!(slots[0].current_work_at(after_local_deadline).is_none());

        assert!(
            !slots[0]
                .set_work_at(
                    &manifest,
                    miner,
                    contract,
                    Some(&state),
                    &first_head,
                    after_local_deadline,
                )
                .unwrap()
        );
        assert!(slots[0].current_work_at(after_local_deadline).is_none());

        let next_head = test_block(101, 100);
        assert!(
            slots[0]
                .set_work_at(
                    &manifest,
                    miner,
                    contract,
                    Some(&state),
                    &next_head,
                    after_local_deadline,
                )
                .unwrap()
        );
        let restarted = slots[0].current_work_at(after_local_deadline).unwrap();
        assert!(restarted.generation > initial_generation);
        assert_eq!(
            *slots[0]
                .local_best
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            None,
            "rearmed work must allow a fresh candidate after the prior local deadline"
        );
        assert_eq!(
            restarted.fingerprint.hashing_context.window_id,
            state.work.window_id
        );

        let snapshot = ReadSnapshot {
            block: next_head,
            native_balance: None,
            native_balance_error: None,
            ast_balance: None,
            ast_balance_error: None,
            nodes: vec![NodeView {
                id: 1,
                address: contract,
                pin: ContractPinStatus {
                    runtime_verified: true,
                    abi_verified: true,
                    error: None,
                },
                state: Some(state),
                error: None,
            }],
        };
        update_slots(&slots, &schedule, &manifest, miner, &selected, &snapshot).unwrap();
        assert_eq!(
            *schedule
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            [0]
        );

        let stop = Arc::new(AtomicBool::new(false));
        let cursor = Arc::new(AtomicUsize::new(0));
        let hashes = Arc::new(AtomicU64::new(0));
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (sender, mut receiver) = proof_inbox(false);
        let worker_slots = Arc::clone(&slots);
        let worker_schedule = Arc::clone(&schedule);
        let worker_stop = Arc::clone(&stop);
        let worker_cursor = Arc::clone(&cursor);
        let worker_hashes = Arc::clone(&hashes);
        let worker_telemetry = Arc::clone(&telemetry);
        let worker = thread::spawn(move || {
            worker_loop(
                worker_slots,
                worker_schedule,
                worker_stop,
                worker_cursor,
                worker_hashes,
                sender,
                worker_telemetry,
            );
        });
        let proof = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("worker should resume hashing on a new eligible head")
            .expect("worker should find a proof under the maximum target");
        stop.store(true, Ordering::Release);
        worker.join().expect("worker should stop cleanly");
        assert_eq!(proof.node_id, 1);
        assert!(hashes.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn verified_chain_time_can_shorten_but_never_extend_a_work_deadline() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let mut state = eligible_state();
        state.work.window_expiry_time = 110;
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let start = Instant::now();
        let first_head = test_block(1, 100);
        slot.set_work_at(&manifest, miner, contract, Some(&state), &first_head, start)
            .unwrap();
        let original_deadline = slot.current_work_at(start).unwrap().valid_until;

        let advanced_head = test_block(2, 106);
        let observed_at = start + Duration::from_secs(1);
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&state),
            &advanced_head,
            observed_at,
        )
        .unwrap();
        let shortened_deadline = slot.current_work_at(observed_at).unwrap().valid_until;
        assert!(shortened_deadline < original_deadline);
        assert_eq!(shortened_deadline, start + Duration::from_secs(3));

        let repeated_observation = observed_at + Duration::from_secs(1);
        assert!(
            !slot
                .set_work_at(
                    &manifest,
                    miner,
                    contract,
                    Some(&state),
                    &advanced_head,
                    repeated_observation,
                )
                .unwrap()
        );
        assert!(slot.current_work_at(shortened_deadline).is_none());

        let next_head = test_block(3, 107);
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&state),
            &next_head,
            shortened_deadline + Duration::from_secs(1),
        )
        .unwrap();
        assert!(
            slot.current_work_at(shortened_deadline + Duration::from_secs(1))
                .is_some()
        );
    }

    #[test]
    fn deadline_only_generation_change_revalidates_a_valid_queued_proof() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let mut state = eligible_state();
        state.work.window_expiry_time = 110;
        let context = WorkContext {
            chain_id: manifest.chain_id,
            contract,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner,
            header: Vec::new(),
        };
        let proof_hash = WorkHasher::new(&context).unwrap().hash(0);
        let target = U256::from_be_bytes(proof_hash.0);
        state.work.target = target;
        assert!(meets_target(proof_hash, target));

        let start = Instant::now();
        let first_head = test_block(100, 100);
        slot.set_work_at(&manifest, miner, contract, Some(&state), &first_head, start)
            .unwrap();
        let original = slot.current_work_at(start).unwrap();
        let queued_proof = ProofFound {
            node_id: 1,
            generation: original.generation,
            context: original.fingerprint.hashing_context.clone(),
            nonce: 0,
            hash: proof_hash,
            target: state.work.target,
            incumbent: None,
            batch_identity: None,
            queued_at: start,
            preflight_retries: 0,
        };

        let updated_at = start + Duration::from_secs(1);
        let deadline_shortening_head = test_block(101, 103);
        slot.set_work_at(
            &manifest,
            miner,
            contract,
            Some(&state),
            &deadline_shortening_head,
            updated_at,
        )
        .unwrap();
        let current = slot.current_work_at(updated_at).unwrap();

        assert_eq!(current.fingerprint, original.fingerprint);
        assert!(current.valid_until < original.valid_until);
        assert!(meets_target(queued_proof.hash, current.target));
        assert_eq!(current.incumbent, queued_proof.incumbent);
        assert_ne!(queued_proof.generation, current.generation);
        let telemetry = ProofPipelineTelemetry::default();
        let revalidated = revalidate_queued_proof(&slot, &queued_proof, &telemetry)
            .expect("same-window proof remains valid after deadline-only generation change");
        assert_eq!(revalidated.generation, current.generation);
        assert_eq!(
            telemetry.count(1, ProofMetric::GenerationMismatchRevalidated),
            1
        );
    }

    #[test]
    fn queued_proof_revalidation_rejects_expiry_window_seed_target_and_incumbent_changes() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let start = Instant::now();
        let initial_block = test_block(1, 100);
        let mut state = eligible_state();
        state.work.window_expiry_time = 200;
        let hashing_context = HashingContext {
            chain_id: manifest.chain_id,
            contract,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner,
            header: Vec::new(),
        };
        let work_hash = WorkHasher::new(&hashing_context.work_context())
            .unwrap()
            .hash(0);
        let target = U256::from_be_bytes(work_hash.0);
        state.work.target = target;
        assert!(meets_target(work_hash, target));

        let create_slot = |node_state: &NodeState, block: &BlockSnapshot| {
            let slot = NodeSlot::new(1);
            slot.set_work_at(&manifest, miner, contract, Some(node_state), block, start)
                .unwrap();
            slot
        };
        let make_proof = |slot: &NodeSlot| ProofFound {
            node_id: 1,
            generation: slot.current_work_at(start).unwrap().generation,
            context: hashing_context.clone(),
            nonce: 0,
            hash: work_hash,
            target,
            incumbent: None,
            batch_identity: None,
            queued_at: start,
            preflight_retries: 0,
        };
        let telemetry = ProofPipelineTelemetry::default();

        let expired_slot = create_slot(&state, &initial_block);
        let expired_proof = make_proof(&expired_slot);
        let expiry = expired_slot.current_work_at(start).unwrap().valid_until;
        assert_eq!(
            revalidate_queued_proof_at(&expired_slot, &expired_proof, &telemetry, expiry)
                .err()
                .unwrap(),
            super::ProofRevalidationFailure::ExpiredDeadline
        );

        let changed_window_slot = create_slot(&state, &initial_block);
        let changed_window_proof = make_proof(&changed_window_slot);
        let mut changed_window = state.clone();
        changed_window.work.window_id += 1;
        changed_window.work.window_expiry_time += 100;
        let next_block = test_block(2, 101);
        changed_window_slot
            .set_work_at(
                &manifest,
                miner,
                contract,
                Some(&changed_window),
                &next_block,
                start + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            revalidate_queued_proof(&changed_window_slot, &changed_window_proof, &telemetry)
                .err()
                .unwrap(),
            super::ProofRevalidationFailure::WindowMismatch
        );

        let changed_seed_slot = create_slot(&state, &initial_block);
        let changed_seed_proof = make_proof(&changed_seed_slot);
        let mut changed_seed = state.clone();
        changed_seed.work.seed = B256::with_last_byte(0x77);
        let seed_block = test_block(2, 101);
        changed_seed_slot
            .set_work_at(
                &manifest,
                miner,
                contract,
                Some(&changed_seed),
                &seed_block,
                start + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            revalidate_queued_proof(&changed_seed_slot, &changed_seed_proof, &telemetry)
                .err()
                .unwrap(),
            super::ProofRevalidationFailure::WorkContextMismatch
        );

        let changed_target_slot = create_slot(&state, &initial_block);
        let changed_target_proof = make_proof(&changed_target_slot);
        let mut changed_target = state.clone();
        changed_target.work.target = target.saturating_sub(U256::from(1));
        let target_block = test_block(2, 101);
        changed_target_slot
            .set_work_at(
                &manifest,
                miner,
                contract,
                Some(&changed_target),
                &target_block,
                start + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            revalidate_queued_proof(&changed_target_slot, &changed_target_proof, &telemetry)
                .err()
                .unwrap(),
            super::ProofRevalidationFailure::CurrentTarget
        );

        let changed_incumbent_slot = create_slot(&state, &initial_block);
        let changed_incumbent_proof = make_proof(&changed_incumbent_slot);
        let mut changed_incumbent = state;
        changed_incumbent.candidate = Some(CandidateInfo {
            miner: Address::with_last_byte(7),
            nonce: 0,
            work_hash,
            submitted_at: 100,
            header: Bytes::new(),
            first_valid_solve_secs: 1,
        });
        let incumbent_block = test_block(2, 101);
        changed_incumbent_slot
            .set_work_at(
                &manifest,
                miner,
                contract,
                Some(&changed_incumbent),
                &incumbent_block,
                start + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(
            revalidate_queued_proof(
                &changed_incumbent_slot,
                &changed_incumbent_proof,
                &telemetry,
            )
            .err()
            .unwrap(),
            super::ProofRevalidationFailure::CurrentIncumbent
        );
    }

    #[test]
    fn proof_inbox_saturation_preserves_the_best_undelivered_candidate() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let mut state = eligible_state();
        let context = WorkContext {
            chain_id: manifest.chain_id,
            contract,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner,
            header: Vec::new(),
        };
        state.work.target = U256::MAX / U256::from(1_000_u64);

        let slot = NodeSlot::new(1);
        slot.set_work(
            &manifest,
            miner,
            contract,
            Some(&state),
            &test_block(1, 100),
        )
        .unwrap();
        let slots = Arc::new(vec![slot]);
        let schedule = Arc::new(RwLock::new(vec![0]));
        let stop = Arc::new(AtomicBool::new(false));
        let cursor = Arc::new(AtomicUsize::new(0));
        let hashes = Arc::new(AtomicU64::new(0));
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (sender, receiver) = proof_inbox(false);
        let work = slots[0].current_work().unwrap();
        for node_id in 1..=PENDING_PROOF_CANDIDATE_CAPACITY as u8 {
            let queued_context = if node_id == 1 {
                work.fingerprint.hashing_context.clone()
            } else {
                HashingContext {
                    chain_id: manifest.chain_id,
                    contract: Address::with_last_byte(node_id),
                    window_id: state.work.window_id,
                    seed: state.work.seed,
                    miner,
                    header: Vec::new(),
                }
            };
            let queued_hash = if node_id == 1 {
                B256::from(U256::MAX.to_be_bytes::<32>())
            } else {
                B256::with_last_byte(2)
            };
            assert!(sender.deliver(
                ProofFound {
                    node_id,
                    generation: work.generation,
                    context: queued_context,
                    nonce: u128::from(node_id),
                    hash: queued_hash,
                    target: state.work.target,
                    incumbent: None,
                    batch_identity: None,
                    queued_at: Instant::now(),
                    preflight_retries: 0,
                },
                &telemetry,
            ));
        }

        let worker_slots = Arc::clone(&slots);
        let worker_schedule = Arc::clone(&schedule);
        let worker_stop = Arc::clone(&stop);
        let worker_cursor = Arc::clone(&cursor);
        let worker_hashes = Arc::clone(&hashes);
        let worker_telemetry = Arc::clone(&telemetry);
        let worker = thread::spawn(move || {
            worker_loop(
                worker_slots,
                worker_schedule,
                worker_stop,
                worker_cursor,
                worker_hashes,
                sender,
                worker_telemetry,
            );
        });

        let deadline = Instant::now() + Duration::from_secs(2);
        while telemetry.count(1, ProofMetric::QueueFullCoalesced) == 0 && Instant::now() < deadline
        {
            thread::yield_now();
        }
        assert!(telemetry.count(1, ProofMetric::QueueFullCoalesced) > 0);
        stop.store(true, Ordering::Release);
        worker.join().unwrap();

        let mut node_one_candidate = None;
        for _ in 0..PENDING_PROOF_CANDIDATE_CAPACITY {
            let delivered = receiver
                .take_next()
                .expect("every bounded inbox slot is populated");
            if delivered.node_id == 1 {
                node_one_candidate = Some(delivered);
            }
        }
        let delivered = node_one_candidate.expect("saturated inbox retains node 1");
        let local_best = *slots[0]
            .local_best
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .unwrap();
        assert_eq!(delivered.hash, local_best);
        assert_eq!(
            WorkHasher::new(&context).unwrap().hash(delivered.nonce),
            delivered.hash
        );
        assert!(meets_target(delivered.hash, delivered.target));
        assert!(telemetry.count(1, ProofMetric::QueuedCandidates) >= 2);
        assert!(
            telemetry.count(1, ProofMetric::QueueWakeCoalesced) > 0,
            "saturation coalesces bounded wakeups without losing inbox candidates"
        );
        assert!(hashes.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn proof_inbox_reports_receiver_closure_without_claiming_delivery() {
        let telemetry = ProofPipelineTelemetry::default();
        let (sender, receiver) = proof_inbox(false);
        drop(receiver);
        let proof = ProofFound {
            node_id: 1,
            generation: 1,
            context: HashingContext {
                chain_id: 1439,
                contract: Address::with_last_byte(9),
                window_id: 3,
                seed: B256::with_last_byte(1),
                miner: Address::with_last_byte(8),
                header: Vec::new(),
            },
            nonce: 7,
            hash: B256::with_last_byte(1),
            target: U256::MAX,
            incumbent: None,
            batch_identity: None,
            queued_at: Instant::now(),
            preflight_retries: 0,
        };

        assert!(!sender.deliver(proof, &telemetry));
        assert_eq!(telemetry.count(1, ProofMetric::QueueReceiverClosed), 1);
        assert_eq!(telemetry.count(1, ProofMetric::QueuedCandidates), 0);
    }

    #[test]
    fn proof_inbox_keeps_same_window_candidates_independent_across_all_nine_nodes() {
        let telemetry = ProofPipelineTelemetry::default();
        let (sender, receiver) = proof_inbox(false);
        for node_id in 1..=9 {
            assert!(sender.deliver(
                ProofFound {
                    node_id,
                    generation: 1,
                    context: HashingContext {
                        chain_id: 1439,
                        contract: Address::with_last_byte(node_id),
                        window_id: 7,
                        seed: B256::with_last_byte(7),
                        miner: Address::with_last_byte(8),
                        header: Vec::new(),
                    },
                    nonce: u128::from(node_id),
                    hash: B256::with_last_byte(node_id),
                    target: U256::MAX,
                    incumbent: None,
                    batch_identity: None,
                    queued_at: Instant::now(),
                    preflight_retries: 0,
                },
                &telemetry,
            ));
        }

        let mut received = (0..9)
            .map(|_| receiver.take_next().expect("one proof per selected node"))
            .map(|proof| proof.node_id)
            .collect::<Vec<_>>();
        received.sort_unstable();
        assert_eq!(received, (1..=9).collect::<Vec<_>>());
        for node_id in 1..=9 {
            assert_eq!(telemetry.count(node_id, ProofMetric::QueuedCandidates), 1);
        }
    }

    #[tokio::test]
    async fn proof_inbox_defers_and_releases_best_candidate_across_unresolved_transaction() {
        let telemetry = ProofPipelineTelemetry::default();
        let (sender, mut receiver) = proof_inbox(true);
        let proof = ProofFound {
            node_id: 1,
            generation: 1,
            context: HashingContext {
                chain_id: 1439,
                contract: Address::with_last_byte(9),
                window_id: 3,
                seed: B256::with_last_byte(1),
                miner: Address::with_last_byte(8),
                header: Vec::new(),
            },
            nonce: 7,
            hash: B256::with_last_byte(1),
            target: U256::MAX,
            incumbent: None,
            batch_identity: None,
            queued_at: Instant::now(),
            preflight_retries: 0,
        };
        assert!(sender.deliver(proof.clone(), &telemetry));
        assert!(
            timeout(Duration::from_millis(25), receiver.recv())
                .await
                .is_err()
        );

        receiver.set_paused(false);
        let first_delivery = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first_delivery.nonce, proof.nonce);
        receiver.set_paused(true);
        assert!(receiver.requeue(first_delivery, &telemetry));
        assert!(
            timeout(Duration::from_millis(25), receiver.recv())
                .await
                .is_err()
        );

        receiver.set_paused(false);
        let deferred = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(deferred.hash, proof.hash);
        assert_eq!(telemetry.count(1, ProofMetric::QueuedCandidates), 2);
    }

    #[test]
    fn terminal_pause_latches_and_discards_queued_proofs() {
        let telemetry = ProofPipelineTelemetry::default();
        let (sender, receiver) = proof_inbox(false);
        let proof = ProofFound {
            node_id: 1,
            generation: 1,
            context: HashingContext {
                chain_id: 1439,
                contract: Address::with_last_byte(9),
                window_id: 3,
                seed: B256::with_last_byte(1),
                miner: Address::with_last_byte(8),
                header: Vec::new(),
            },
            nonce: 7,
            hash: B256::with_last_byte(1),
            target: U256::MAX,
            incumbent: None,
            batch_identity: None,
            queued_at: Instant::now(),
            preflight_retries: 0,
        };
        assert!(sender.deliver(proof, &telemetry));
        assert!(receiver.has_pending());

        receiver.latch_paused();
        assert!(receiver.paused.load(Ordering::Acquire));
        receiver.set_paused(false);
        assert!(
            receiver.paused.load(Ordering::Acquire),
            "ordinary pause updates cannot clear the terminal proof-delivery latch"
        );
        receiver.discard_pending(&telemetry, ProofMetric::RefusedSpendingLimit);
        assert!(
            receiver
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .all(Option::is_none)
        );
        assert_eq!(telemetry.count(1, ProofMetric::RefusedSpendingLimit), 1);
    }

    #[test]
    fn cpu_workers_stop_when_the_paid_session_stop_flag_is_set() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let mut state = eligible_state();
        state.work.target = U256::MAX;
        slot.set_work(
            &manifest,
            miner,
            contract,
            Some(&state),
            &test_block(1, 100),
        )
        .unwrap();

        let slots = Arc::new(vec![slot]);
        let schedule = Arc::new(RwLock::new(vec![0]));
        let stop = Arc::new(AtomicBool::new(false));
        let cursor = Arc::new(AtomicUsize::new(0));
        let total_hashes = Arc::new(AtomicU64::new(0));
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (proofs, _receiver) = proof_inbox(false);
        let workers = start_cpu_worker_threads(
            2,
            MiningWorkerContext {
                slots: Arc::clone(&slots),
                schedule,
                stop: Arc::clone(&stop),
                cursor,
                total_hashes: Arc::clone(&total_hashes),
                proofs,
                telemetry,
            },
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        while slots[0].completed_hashes() == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        assert!(slots[0].completed_hashes() > 0, "CPU worker began hashing");
        stop.store(true, Ordering::Release);
        for worker in workers {
            worker.join().expect("CPU worker exits after the stop flag");
        }
        let stopped_hashes = slots[0].completed_hashes();
        thread::sleep(Duration::from_millis(30));
        assert_eq!(slots[0].completed_hashes(), stopped_hashes);
        assert_eq!(total_hashes.load(Ordering::Relaxed), stopped_hashes);
    }

    #[test]
    fn gpu_controller_does_not_initialize_or_fallback_after_terminal_stop() {
        let stop = Arc::new(AtomicBool::new(true));
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (proofs, _receiver) = proof_inbox(true);
        let context = MiningWorkerContext {
            slots: Arc::new(vec![NodeSlot::new(1)]),
            schedule: Arc::new(RwLock::new(Vec::new())),
            stop: Arc::clone(&stop),
            cursor: Arc::new(AtomicUsize::new(0)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            proofs,
            telemetry,
        };
        let (events, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        gpu_worker_controller(DeviceChoice::Gpu, 1, context, events);
        assert!(stop.load(Ordering::Acquire));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    #[ignore = "requires a physical GPU adapter"]
    fn initialized_gpu_worker_loop_observes_terminal_stop_flag() {
        let mut engine = GpuBackendEngine::initialize().expect("physical GPU adapter is available");
        let stop = Arc::new(AtomicBool::new(true));
        let (proofs, _receiver) = proof_inbox(true);
        let context = MiningWorkerContext {
            slots: Arc::new(vec![NodeSlot::new(1)]),
            schedule: Arc::new(RwLock::new(Vec::new())),
            stop: Arc::clone(&stop),
            cursor: Arc::new(AtomicUsize::new(0)),
            total_hashes: Arc::new(AtomicU64::new(0)),
            proofs,
            telemetry: Arc::new(ProofPipelineTelemetry::default()),
        };
        gpu_worker_loop(&mut engine, &context).unwrap();
        assert!(stop.load(Ordering::Acquire));
        assert_eq!(context.total_hashes.load(Ordering::Relaxed), 0);
        assert_eq!(context.slots[0].completed_hashes(), 0);
    }

    #[test]
    fn rpc_retry_backoff_is_exponential_and_bounded() {
        assert_eq!(
            super::GENESIS_POLL_INTERVAL,
            Duration::from_secs(1),
            "healthy inactive-genesis polling starts at one second"
        );
        assert_eq!(
            next_poll_delay(super::GENESIS_POLL_INTERVAL),
            Duration::from_secs(2),
            "a failed genesis poll applies the same bounded exponential backoff"
        );
        assert_eq!(
            next_poll_delay(super::POLL_INTERVAL),
            Duration::from_secs(10)
        );
        assert_eq!(
            next_poll_delay(Duration::from_secs(10)),
            Duration::from_secs(20)
        );
        assert_eq!(
            next_poll_delay(Duration::from_secs(20)),
            super::MAX_POLL_INTERVAL
        );
        assert_eq!(
            next_poll_delay(super::MAX_POLL_INTERVAL),
            super::MAX_POLL_INTERVAL
        );
        assert_eq!(finalization_retry_delay(1), Duration::from_secs(1));
        assert_eq!(finalization_retry_delay(2), Duration::from_secs(2));
        assert_eq!(finalization_retry_delay(3), Duration::from_secs(4));
        assert_eq!(finalization_retry_delay(7), super::MAX_POLL_INTERVAL);
        assert_eq!(finalization_retry_delay(u8::MAX), super::MAX_POLL_INTERVAL);
    }

    #[tokio::test]
    async fn autonomous_mining_requires_a_selected_wallet_before_connecting() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let error = super::run(
            &store,
            MineArgs {
                device: DeviceChoice::Cpu,
                compute_only: false,
                new_session: false,
                threads: None,
                nodes: Vec::new(),
                send_rewards_to: None,
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("no wallet is selected"));
    }

    #[tokio::test]
    async fn autonomous_signing_is_refused_on_mainnet_before_wallet_or_rpc_access() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let config = crate::config::AppConfig {
            network: Network::Mainnet,
            ..crate::config::AppConfig::default()
        };
        store.save(&config).unwrap();
        let error = super::run(
            &store,
            MineArgs {
                device: DeviceChoice::Cpu,
                compute_only: false,
                new_session: false,
                threads: None,
                nodes: Vec::new(),
                send_rewards_to: None,
            },
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("disabled outside Injective Testnet")
        );
    }

    #[tokio::test]
    async fn reward_forwarding_flag_is_rejected_before_wallet_or_chain_access() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let destination = Address::with_last_byte(0x42);
        let network = NetworkClient::local_test_client(
            "http://127.0.0.1:1",
            Address::with_last_byte(0x51),
            B256::with_last_byte(0x11),
            Address::with_last_byte(0x61),
            B256::with_last_byte(0x22),
            9,
        )
        .unwrap();
        for compute_only in [false, true] {
            let error = super::run_with_client(
                &store,
                crate::config::AppConfig::default(),
                MineArgs {
                    device: DeviceChoice::Cpu,
                    compute_only,
                    new_session: false,
                    threads: None,
                    nodes: vec![1],
                    send_rewards_to: Some(destination),
                },
                network.clone(),
                None,
                None,
                false,
            )
            .await
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(AUTOMATIC_REWARD_FORWARDING_DISABLED)
            );
        }
        let cli_error = super::run(
            &store,
            MineArgs {
                device: DeviceChoice::Cpu,
                compute_only: false,
                new_session: false,
                threads: None,
                nodes: vec![1],
                send_rewards_to: Some(destination),
            },
        )
        .await
        .unwrap_err();
        assert!(
            cli_error
                .to_string()
                .contains(AUTOMATIC_REWARD_FORWARDING_DISABLED)
        );
        assert!(store.read_transaction_journal().unwrap().is_none());
    }

    #[test]
    fn reduced_limit_consent_defaults_to_no_on_eof_or_unrecognized_input() {
        assert!(!super::consent_approved(""));
        assert!(!super::consent_approved("\n"));
        assert!(!super::consent_approved("n\n"));
        assert!(!super::consent_approved("yes please"));
        assert!(super::consent_approved("y\n"));
        assert!(super::consent_approved("YES"));

        assert!(!super::reduced_limit_consent_result(Ok(0), "").unwrap());
        assert!(
            !super::reduced_limit_consent_result(
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "interrupted by shutdown signal",
                )),
                "y\n",
            )
            .unwrap(),
            "an interrupted consent read must not approve spending"
        );
        assert!(super::reduced_limit_consent_result(Ok(2), "y\n").unwrap());
    }

    #[test]
    fn reduced_limit_consent_rejects_piped_yes_without_a_terminal() {
        use std::io::Write;

        const CHILD: &str = "ASTATINE_REDUCED_LIMIT_PIPED_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let error = super::prompt_reduced_run_limit(
                Address::with_last_byte(0xa1),
                U256::from(1_000_000_000_000_000_000_u128),
                U256::from(2_000_000_000_000_000_000_u128),
                U256::from(100_000_000_000_000_000_u128),
                U256::ZERO,
                U256::from(1_900_000_000_000_000_000_u128),
                U256::from(1_000_000_000_000_000_000_u128),
                None,
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("interactive terminal"));
            eprintln!("reduced-limit-piped-child-ran");
            return;
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mining::tests::reduced_limit_consent_rejects_piped_yes_without_a_terminal",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(b"yes\n").unwrap();
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "piped reduced-limit consent child failed: {stderr}"
        );
        assert!(
            stderr.contains("reduced-limit-piped-child-ran"),
            "the child branch must have executed: {stderr}"
        );
    }

    #[test]
    fn node_selection_defaults_to_all_and_rejects_duplicates() {
        assert_eq!(
            selected_nodes(&[]).unwrap(),
            (1..=9).collect::<HashSet<_>>()
        );
        assert!(selected_nodes(&[2, 2]).is_err());
    }

    #[tokio::test]
    async fn worker_continues_same_window_search_for_strictly_better_proofs() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let mut state = eligible_state();
        state.work.target = U256::MAX;
        slot.set_work(
            &manifest,
            miner,
            contract,
            Some(&state),
            &test_block(1, 100),
        )
        .unwrap();

        let slots = Arc::new(vec![slot]);
        let schedule = Arc::new(RwLock::new(vec![0]));
        let stop = Arc::new(AtomicBool::new(false));
        let cursor = Arc::new(AtomicUsize::new(0));
        let total_hashes = Arc::new(AtomicU64::new(0));
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (sender, mut receiver) = proof_inbox(false);
        let worker_slots = Arc::clone(&slots);
        let worker_schedule = Arc::clone(&schedule);
        let worker_stop = Arc::clone(&stop);
        let worker_cursor = Arc::clone(&cursor);
        let worker_hashes = Arc::clone(&total_hashes);
        let worker_telemetry = Arc::clone(&telemetry);
        let worker = thread::spawn(move || {
            worker_loop(
                worker_slots,
                worker_schedule,
                worker_stop,
                worker_cursor,
                worker_hashes,
                sender,
                worker_telemetry,
            );
        });

        let first_result = timeout(Duration::from_secs(2), receiver.recv()).await;
        let first = first_result
            .expect("worker should find a proof under the maximum target")
            .expect("worker should report its first proof");
        let second_result = timeout(Duration::from_secs(2), receiver.recv()).await;
        stop.store(true, Ordering::Release);
        worker.join().expect("worker should stop cleanly");
        let second = second_result
            .expect("worker should continue hashing after delivering its first proof")
            .expect("worker should report a later improvement");

        let context = WorkContext {
            chain_id: manifest.chain_id,
            contract,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner,
            header: Vec::new(),
        };
        for proof in [&first, &second] {
            assert_eq!(proof.node_id, 1);
            assert_eq!(proof.context.window_id, state.work.window_id);
            assert!(slots[0].is_generation_current(proof.generation));
            assert_eq!(
                WorkHasher::new(&context).unwrap().hash(proof.nonce),
                proof.hash
            );
            assert!(meets_target(proof.hash, U256::MAX));
        }
        assert_ne!(first.nonce, second.nonce);
        assert!(second.hash < first.hash);
        assert!(total_hashes.load(Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn hashrate_returns_to_zero_after_all_scheduled_work_is_invalidated() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let slot = NodeSlot::new(1);
        let mut state = eligible_state();
        state.work.target = U256::ZERO;
        let block = test_block(1, 100);
        slot.set_work(&manifest, miner, contract, Some(&state), &block)
            .unwrap();

        let slots = Arc::new(vec![slot]);
        let schedule = Arc::new(RwLock::new(vec![0]));
        let stop = Arc::new(AtomicBool::new(false));
        let cursor = Arc::new(AtomicUsize::new(0));
        let hashes = Arc::new(AtomicU64::new(0));
        let telemetry = Arc::new(ProofPipelineTelemetry::default());
        let (sender, _receiver) = proof_inbox(false);
        let worker_slots = Arc::clone(&slots);
        let worker_schedule = Arc::clone(&schedule);
        let worker_stop = Arc::clone(&stop);
        let worker_cursor = Arc::clone(&cursor);
        let worker_hashes = Arc::clone(&hashes);
        let worker_telemetry = Arc::clone(&telemetry);
        let worker = thread::spawn(move || {
            worker_loop(
                worker_slots,
                worker_schedule,
                worker_stop,
                worker_cursor,
                worker_hashes,
                sender,
                worker_telemetry,
            );
        });
        timeout(Duration::from_secs(2), async {
            while hashes.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("active work must produce completed hashes");

        slots[0]
            .set_work(&manifest, miner, contract, None, &block)
            .unwrap();
        *schedule
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Vec::new();
        let stable_hash_count = tokio::time::timeout(Duration::from_secs(2), async {
            let mut previous = hashes.load(Ordering::Relaxed);
            let mut unchanged_samples = 0_u8;
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let current = hashes.load(Ordering::Relaxed);
                if current == previous {
                    unchanged_samples = unchanged_samples.saturating_add(1);
                    if unchanged_samples == 3 {
                        return current;
                    }
                } else {
                    previous = current;
                    unchanged_samples = 0;
                }
            }
        })
        .await
        .expect("hash counter should settle after work invalidation");
        assert!(stable_hash_count > 0);
        assert!(slots[0].current_work().is_none());
        assert_eq!(
            hashes_per_second(stable_hash_count, stable_hash_count, 1.0),
            0.0
        );

        stop.store(true, Ordering::Release);
        worker.join().expect("worker should stop cleanly");
    }
    #[tokio::test]
    async fn prepared_submission_grace_is_conditional_and_bounded() {
        let pending = Arc::new(AtomicBool::new(false));

        let not_prepared = std::future::ready(7_u8);
        tokio::pin!(not_prepared);
        assert_eq!(
            super::await_prepared_submission_with_grace(
                &pending,
                not_prepared.as_mut(),
                Duration::from_millis(50),
            )
            .await,
            None,
            "a submission still in preflight must not delay shutdown"
        );

        pending.store(true, Ordering::SeqCst);
        let ready = std::future::ready(11_u8);
        tokio::pin!(ready);
        assert_eq!(
            super::await_prepared_submission_with_grace(
                &pending,
                ready.as_mut(),
                Duration::from_millis(50),
            )
            .await,
            Some(11),
            "a prepared submission that concludes inside the grace is retained"
        );

        let stuck = std::future::pending::<u8>();
        tokio::pin!(stuck);
        let started = Instant::now();
        assert_eq!(
            super::await_prepared_submission_with_grace(
                &pending,
                stuck.as_mut(),
                Duration::from_millis(20),
            )
            .await,
            None,
            "a prepared submission that cannot conclude is dropped only after the bound"
        );
        assert!(started.elapsed() >= Duration::from_millis(20));

        let durable = Arc::new(AtomicBool::new(true));
        let clear = Arc::clone(&durable);
        let clearer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            clear.store(false, Ordering::SeqCst);
        });
        let still_pending = std::future::pending::<u8>();
        tokio::pin!(still_pending);
        let started = Instant::now();
        assert_eq!(
            super::await_prepared_submission_with_grace(
                &durable,
                still_pending.as_mut(),
                Duration::from_secs(5),
            )
            .await,
            None,
            "a durable broadcast outcome must stop waiting before the full grace"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        clearer.await.unwrap();
    }
}
