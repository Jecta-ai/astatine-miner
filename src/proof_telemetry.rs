use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const NODE_COUNT: usize = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum ProofMetric {
    TargetValidHashes,
    TargetValidNotNewLocalBest,
    IncumbentRejectedHashes,
    IncumbentPassedHashes,
    NewLocalBestHashes,
    WorkerStaleGenerationHash,
    WorkerDeadlineHashDropped,
    WorkerStoppedGeneration,
    WorkerStoppedDeadline,
    WorkerHashFailure,
    WorkerNonceRangeExhausted,
    QueuedCandidates,
    QueueFullCoalesced,
    QueueCandidateSuperseded,
    QueueReplacedByBetter,
    QueueReplacedByNewContext,
    QueueWakeCoalesced,
    QueueReceiverClosed,
    MainLoopReceived,
    GenerationMismatchRevalidated,
    GenerationMismatchDropped,
    DroppedNoEligibleWork,
    DroppedExpiredDeadline,
    DroppedWindowMismatch,
    DroppedWorkContextMismatch,
    DroppedHashMismatch,
    DroppedCurrentTarget,
    DroppedCurrentIncumbent,
    SuppressedPriorAttempt,
    DeferredUnresolvedTransaction,
    RefusedSpendingLimit,
    RefusedSigningDisabled,
    SignerIdentityMismatch,
    PreflightStarted,
    PreflightRpcFailure,
    PreflightStaleProof,
    PreflightPolicyRefusal,
    PreflightOtherFailure,
    DroppedOnShutdown,
    Signed,
    Broadcast,
    BroadcastOutcomeUnknown,
    ReceiptConfirmed,
    CandidateUpdated,
    CandidateRejected,
}

const METRIC_COUNT: usize = ProofMetric::CandidateRejected as usize + 1;

struct NodeCounters {
    values: [AtomicU64; METRIC_COUNT],
}

struct NodeAttemptGuard {
    attempted: AtomicBool,
    through_window: AtomicU64,
}

impl NodeAttemptGuard {
    fn new() -> Self {
        Self {
            attempted: AtomicBool::new(false),
            through_window: AtomicU64::new(0),
        }
    }
}

pub(crate) struct ProofAttemptGuard {
    nodes: [NodeAttemptGuard; NODE_COUNT],
}

impl Default for ProofAttemptGuard {
    fn default() -> Self {
        Self {
            nodes: std::array::from_fn(|_| NodeAttemptGuard::new()),
        }
    }
}

impl ProofAttemptGuard {
    pub(crate) fn record_attempt(&self, node_id: u8, window_id: u64) {
        let Some(node) = node_id
            .checked_sub(1)
            .map(usize::from)
            .filter(|node| *node < NODE_COUNT)
        else {
            return;
        };
        self.nodes[node]
            .through_window
            .fetch_max(window_id, Ordering::Relaxed);
        self.nodes[node].attempted.store(true, Ordering::Release);
    }

    pub(crate) fn suppresses(&self, node_id: u8, window_id: u64) -> bool {
        let Some(node) = node_id
            .checked_sub(1)
            .map(usize::from)
            .filter(|node| *node < NODE_COUNT)
        else {
            return false;
        };
        self.nodes[node].attempted.load(Ordering::Acquire)
            && window_id <= self.nodes[node].through_window.load(Ordering::Relaxed)
    }

    #[cfg(test)]
    pub(crate) fn last_attempted_window(&self, node_id: u8) -> Option<u64> {
        let node = node_id.checked_sub(1).map(usize::from)?;
        let node = self.nodes.get(node)?;
        node.attempted
            .load(Ordering::Acquire)
            .then(|| node.through_window.load(Ordering::Relaxed))
    }
}

impl NodeCounters {
    fn new() -> Self {
        Self {
            values: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    fn any(&self) -> bool {
        self.values
            .iter()
            .any(|counter| counter.load(Ordering::Relaxed) != 0)
    }
}

pub(crate) struct ProofPipelineTelemetry {
    nodes: [NodeCounters; NODE_COUNT],
}

impl Default for ProofPipelineTelemetry {
    fn default() -> Self {
        Self {
            nodes: std::array::from_fn(|_| NodeCounters::new()),
        }
    }
}

impl ProofPipelineTelemetry {
    pub(crate) fn record(&self, node_id: u8, metric: ProofMetric) {
        let Some(node) = node_id
            .checked_sub(1)
            .map(usize::from)
            .filter(|node| *node < NODE_COUNT)
        else {
            return;
        };
        self.nodes[node].values[metric as usize].fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(crate) fn count(&self, node_id: u8, metric: ProofMetric) -> u64 {
        let Some(node) = node_id
            .checked_sub(1)
            .map(usize::from)
            .filter(|node| *node < NODE_COUNT)
        else {
            return 0;
        };
        self.nodes[node].values[metric as usize].load(Ordering::Relaxed)
    }

    pub(crate) fn report_lines(&self) -> Vec<String> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, counters)| counters.any())
            .map(|(index, counters)| {
                let count = |metric: ProofMetric| {
                    counters.values[metric as usize].load(Ordering::Relaxed)
                };
                format!(
                    "proof-pipeline node={:02} target_valid={} target_valid_not_new_local_best={} incumbent_rejected={} incumbent_passed={} new_local_best={} stale_worker_hash={} worker_deadline_hash_dropped={} worker_stopped_generation={} worker_stopped_deadline={} worker_hash_failures={} nonce_space_exhausted={} queued={} queue_full_coalesced={} queue_candidate_superseded={} queue_replaced_better={} queue_replaced_new_context={} queue_wake_coalesced={} receiver_closed={} received={} generation_revalidated={} generation_dropped={} no_eligible_work={} deadline_expired={} window_mismatch={} context_mismatch={} hash_mismatch={} current_target_rejected={} current_incumbent_rejected={} prior_attempt_suppressed={} unresolved_deferred={} spending_refused={} signing_disabled={} signer_identity_mismatch={} preflight_started={} preflight_rpc_failed={} preflight_stale={} preflight_policy_refused={} preflight_other_failed={} signed={} broadcast={} broadcast_unknown={} receipt_confirmed={} candidate_updated={} candidate_rejected={} dropped_on_shutdown={}",
                    index + 1,
                    count(ProofMetric::TargetValidHashes),
                    count(ProofMetric::TargetValidNotNewLocalBest),
                    count(ProofMetric::IncumbentRejectedHashes),
                    count(ProofMetric::IncumbentPassedHashes),
                    count(ProofMetric::NewLocalBestHashes),
                    count(ProofMetric::WorkerStaleGenerationHash),
                    count(ProofMetric::WorkerDeadlineHashDropped),
                    count(ProofMetric::WorkerStoppedGeneration),
                    count(ProofMetric::WorkerStoppedDeadline),
                    count(ProofMetric::WorkerHashFailure),
                    count(ProofMetric::WorkerNonceRangeExhausted),
                    count(ProofMetric::QueuedCandidates),
                    count(ProofMetric::QueueFullCoalesced),
                    count(ProofMetric::QueueCandidateSuperseded),
                    count(ProofMetric::QueueReplacedByBetter),
                    count(ProofMetric::QueueReplacedByNewContext),
                    count(ProofMetric::QueueWakeCoalesced),
                    count(ProofMetric::QueueReceiverClosed),
                    count(ProofMetric::MainLoopReceived),
                    count(ProofMetric::GenerationMismatchRevalidated),
                    count(ProofMetric::GenerationMismatchDropped),
                    count(ProofMetric::DroppedNoEligibleWork),
                    count(ProofMetric::DroppedExpiredDeadline),
                    count(ProofMetric::DroppedWindowMismatch),
                    count(ProofMetric::DroppedWorkContextMismatch),
                    count(ProofMetric::DroppedHashMismatch),
                    count(ProofMetric::DroppedCurrentTarget),
                    count(ProofMetric::DroppedCurrentIncumbent),
                    count(ProofMetric::SuppressedPriorAttempt),
                    count(ProofMetric::DeferredUnresolvedTransaction),
                    count(ProofMetric::RefusedSpendingLimit),
                    count(ProofMetric::RefusedSigningDisabled),
                    count(ProofMetric::SignerIdentityMismatch),
                    count(ProofMetric::PreflightStarted),
                    count(ProofMetric::PreflightRpcFailure),
                    count(ProofMetric::PreflightStaleProof),
                    count(ProofMetric::PreflightPolicyRefusal),
                    count(ProofMetric::PreflightOtherFailure),
                    count(ProofMetric::Signed),
                    count(ProofMetric::Broadcast),
                    count(ProofMetric::BroadcastOutcomeUnknown),
                    count(ProofMetric::ReceiptConfirmed),
                    count(ProofMetric::CandidateUpdated),
                    count(ProofMetric::CandidateRejected),
                    count(ProofMetric::DroppedOnShutdown),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{ProofAttemptGuard, ProofMetric, ProofPipelineTelemetry};

    #[test]
    fn proof_report_is_bounded_per_node_and_names_each_stage() {
        let telemetry = ProofPipelineTelemetry::default();
        telemetry.record(2, ProofMetric::TargetValidHashes);
        telemetry.record(2, ProofMetric::QueuedCandidates);
        telemetry.record(2, ProofMetric::GenerationMismatchRevalidated);
        telemetry.record(9, ProofMetric::Broadcast);

        let report = telemetry.report_lines();
        assert_eq!(report.len(), 2);
        assert!(report[0].contains("node=02"));
        assert!(report[0].contains("target_valid=1"));
        assert!(report[0].contains("queued=1"));
        assert!(report[0].contains("generation_revalidated=1"));
        assert!(report[1].contains("node=09"));
        assert!(report[1].contains("broadcast=1"));
    }

    #[test]
    fn proof_attempt_guard_suppresses_old_windows_but_allows_newer_work() {
        let guard = ProofAttemptGuard::default();
        assert!(!guard.suppresses(1, 4));
        guard.record_attempt(1, 4);
        assert!(guard.suppresses(1, 3));
        assert!(guard.suppresses(1, 4));
        assert!(!guard.suppresses(1, 5));
        assert!(!guard.suppresses(2, 4));
        guard.record_attempt(1, 7);
        assert!(guard.suppresses(1, 7));
        assert!(!guard.suppresses(1, 8));
        assert_eq!(guard.last_attempted_window(1), Some(7));
    }
}
