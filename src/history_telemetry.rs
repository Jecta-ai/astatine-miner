use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Duration, Instant};

const COUNTER_COUNT: usize = 28;
const DURATION_COUNT: usize = 7;

#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum HistoryCounter {
    CanonicalBlockRequests,
    ReceiptRequests,
    TransactionLookupRequests,
    NonceRequests,
    GetLogsRequests,
    BlockRangesScanned,
    RpcErrors,
    RpcRetries,
    JournalWrites,
    JournalWriteBytes,
    ArchiveFilesValidated,
    ArchiveEntriesValidated,
    ArchiveFilesCreated,
    HistoricalHeadRequests,
    SettledCanonicalChecks,
    JournalWriteFailures,
    ArchiveWriteFailures,
    ArchiveValidationFailures,
    DeepSettledEntriesSkipped,
    RewardScanBatches,
    RewardScanJobs,
    RewardCursorHits,
    RewardCursorResets,
    RewardScanErrors,
    RewardEvidenceVerified,
    RewardServiceCalls,
    RewardCandidates,
    RewardCandidatesWaitingForWindow,
}

#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum HistoryDuration {
    JournalOpen,
    ArchiveValidation,
    ReceiptRecovery,
    ReceiptMonitoring,
    RewardReconciliation,
    JournalPersistence,
    HistoricalRpc,
}

#[derive(Debug)]
pub(crate) struct HistoryTelemetry {
    counters: [AtomicU64; COUNTER_COUNT],
    durations_micros: [AtomicU64; DURATION_COUNT],
}

pub(crate) struct HistoryTimer {
    telemetry: Arc<HistoryTelemetry>,
    duration: HistoryDuration,
    started: Instant,
}

impl Default for HistoryTelemetry {
    fn default() -> Self {
        Self {
            counters: std::array::from_fn(|_| AtomicU64::new(0)),
            durations_micros: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
}

impl HistoryTelemetry {
    pub(crate) fn timer(self: &Arc<Self>, duration: HistoryDuration) -> HistoryTimer {
        HistoryTimer {
            telemetry: Arc::clone(self),
            duration,
            started: Instant::now(),
        }
    }

    pub(crate) fn add(&self, counter: HistoryCounter, value: u64) {
        let counter = &self.counters[counter as usize];
        saturating_add(counter, value);
    }

    pub(crate) fn add_elapsed(&self, duration: HistoryDuration, elapsed: Duration) {
        let micros = elapsed.as_micros().min(u128::from(u64::MAX)) as u64;
        let counter = &self.durations_micros[duration as usize];
        saturating_add(counter, micros);
    }

    pub(crate) fn count(&self, counter: HistoryCounter) -> u64 {
        self.counters[counter as usize].load(Ordering::Relaxed)
    }

    fn elapsed_ms(&self, duration: HistoryDuration) -> f64 {
        self.durations_micros[duration as usize].load(Ordering::Relaxed) as f64 / 1_000.0
    }

    pub(crate) fn format_profile(&self) -> String {
        format!(
            "history-profile canonical_block_requests={} receipt_requests={} transaction_lookups={} nonce_lookups={} historical_head_requests={} eth_getLogs={} block_ranges={} settled_canonical_checks={} deep_settled_skipped={} reward_scan_batches={} reward_scan_jobs={} reward_cursor_hits={} reward_cursor_resets={} reward_scan_errors={} reward_evidence_verified={} reward_service_calls={} reward_candidates={} reward_candidates_waiting_for_window={} rpc_errors={} rpc_retries={} journal_writes={} journal_write_bytes={} journal_write_failures={} archive_files_validated={} archive_entries_validated={} archive_files_created={} archive_write_failures={} archive_validation_failures={} journal_open_ms={:.3} archive_validation_ms={:.3} receipt_recovery_ms={:.3} receipt_monitor_ms={:.3} reward_reconciliation_ms={:.3} journal_persist_ms={:.3} historical_rpc_ms={:.3}",
            self.count(HistoryCounter::CanonicalBlockRequests),
            self.count(HistoryCounter::ReceiptRequests),
            self.count(HistoryCounter::TransactionLookupRequests),
            self.count(HistoryCounter::NonceRequests),
            self.count(HistoryCounter::HistoricalHeadRequests),
            self.count(HistoryCounter::GetLogsRequests),
            self.count(HistoryCounter::BlockRangesScanned),
            self.count(HistoryCounter::SettledCanonicalChecks),
            self.count(HistoryCounter::DeepSettledEntriesSkipped),
            self.count(HistoryCounter::RewardScanBatches),
            self.count(HistoryCounter::RewardScanJobs),
            self.count(HistoryCounter::RewardCursorHits),
            self.count(HistoryCounter::RewardCursorResets),
            self.count(HistoryCounter::RewardScanErrors),
            self.count(HistoryCounter::RewardEvidenceVerified),
            self.count(HistoryCounter::RewardServiceCalls),
            self.count(HistoryCounter::RewardCandidates),
            self.count(HistoryCounter::RewardCandidatesWaitingForWindow),
            self.count(HistoryCounter::RpcErrors),
            self.count(HistoryCounter::RpcRetries),
            self.count(HistoryCounter::JournalWrites),
            self.count(HistoryCounter::JournalWriteBytes),
            self.count(HistoryCounter::JournalWriteFailures),
            self.count(HistoryCounter::ArchiveFilesValidated),
            self.count(HistoryCounter::ArchiveEntriesValidated),
            self.count(HistoryCounter::ArchiveFilesCreated),
            self.count(HistoryCounter::ArchiveWriteFailures),
            self.count(HistoryCounter::ArchiveValidationFailures),
            self.elapsed_ms(HistoryDuration::JournalOpen),
            self.elapsed_ms(HistoryDuration::ArchiveValidation),
            self.elapsed_ms(HistoryDuration::ReceiptRecovery),
            self.elapsed_ms(HistoryDuration::ReceiptMonitoring),
            self.elapsed_ms(HistoryDuration::RewardReconciliation),
            self.elapsed_ms(HistoryDuration::JournalPersistence),
            self.elapsed_ms(HistoryDuration::HistoricalRpc),
        )
    }
}

fn saturating_add(counter: &AtomicU64, value: u64) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_add(value);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

impl Drop for HistoryTimer {
    fn drop(&mut self) {
        self.telemetry
            .add_elapsed(self.duration, self.started.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::{HistoryCounter, HistoryDuration, HistoryTelemetry, saturating_add};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    #[test]
    fn history_profile_contains_only_bounded_aggregate_counters_and_timings() {
        let metrics = HistoryTelemetry::default();
        metrics.add(HistoryCounter::ReceiptRequests, 3);
        metrics.add(HistoryCounter::GetLogsRequests, 2);
        metrics.add_elapsed(
            HistoryDuration::RewardReconciliation,
            Duration::from_millis(17),
        );
        let line = metrics.format_profile();
        assert!(line.contains("receipt_requests=3"));
        assert!(line.contains("eth_getLogs=2"));
        assert!(line.contains("reward_reconciliation_ms=17.000"));
        assert!(!line.contains("0x"));
    }

    #[test]
    fn telemetry_counters_saturate_without_wrapping() {
        let counter = AtomicU64::new(u64::MAX - 1);
        saturating_add(&counter, 2);
        saturating_add(&counter, 1);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
}
