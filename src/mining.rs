use crate::{
    cli::MineArgs,
    config::{ConfigStore, parse_inj_wei},
    dashboard::{
        Dashboard, DashboardEventKind, DashboardModel, DashboardNode, DashboardSignal,
        DashboardUpdater, NodeStatus,
    },
    deployment::DeploymentManifest,
    diagnostics::DiagnosticBuffer,
    protocol::{WorkContext, WorkHasher, beats_incumbent, meets_target},
    rpc::{NetworkClient, NodeState, ReadSnapshot},
    transaction::{
        ConfirmedAction, ProofSubmission, TransactionActivityState, TransactionDashboardState,
        TransactionManager,
    },
    wallet::{selected_address, unlock_selected_interactive},
};
use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result, anyhow, bail};
use std::{
    collections::HashSet,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, time};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(30);
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);
const IDLE_INTERVAL: Duration = Duration::from_millis(20);
const NONCE_BATCH_SIZE: usize = 2_048;
const WORK_EXPIRY_SAFETY_SECS: u64 = 2;

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

struct NodeSlot {
    id: u8,
    generation: AtomicU64,
    work: RwLock<Option<Arc<WorkJob>>>,
    nonces: Mutex<NonceAllocator>,
    local_best: Mutex<Option<B256>>,
}

impl NodeSlot {
    fn new(id: u8) -> Self {
        Self {
            id,
            generation: AtomicU64::new(0),
            work: RwLock::new(None),
            nonces: Mutex::new(NonceAllocator::default()),
            local_best: Mutex::new(None),
        }
    }

    fn current_work(&self) -> Option<Arc<WorkJob>> {
        let work = self
            .work
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()?;
        (Instant::now() < work.valid_until).then_some(work)
    }

    fn is_generation_current(&self, generation: u64) -> bool {
        self.generation.load(Ordering::Acquire) == generation
    }

    fn reserve_nonces(&self) -> Option<(u128, usize)> {
        self.nonces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .reserve(NONCE_BATCH_SIZE)
    }

    fn set_work(
        &self,
        network: &DeploymentManifest,
        miner: Address,
        contract: Address,
        state: Option<&NodeState>,
        block_timestamp: u64,
    ) -> Result<bool> {
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
        let unchanged = match (&*current, &next) {
            (None, None) => true,
            (Some(existing), Some((fingerprint, _, _))) => existing.fingerprint == *fingerprint,
            _ => false,
        };
        if unchanged {
            return Ok(false);
        }

        let context_unchanged = match (&*current, &next) {
            (Some(existing), Some((fingerprint, _, _))) => {
                existing.fingerprint.hashing_context == fingerprint.hashing_context
            }
            _ => false,
        };
        let next_work = if let Some((fingerprint, target, incumbent)) = next {
            let preserve_deadline = context_unchanged
                && current.as_ref().is_some_and(|existing| {
                    existing.fingerprint.window_expiry_time == fingerprint.window_expiry_time
                });
            let hasher = if context_unchanged {
                current
                    .as_ref()
                    .expect("unchanged context requires existing work")
                    .hasher
                    .clone()
            } else {
                WorkHasher::new(&fingerprint.hashing_context.work_context())?
            };
            let now = Instant::now();
            let remaining = fingerprint
                .window_expiry_time
                .saturating_sub(block_timestamp)
                .saturating_sub(WORK_EXPIRY_SAFETY_SECS);
            let proposed_deadline = now
                .checked_add(Duration::from_secs(remaining))
                .unwrap_or(now);
            let valid_until = if preserve_deadline {
                current
                    .as_ref()
                    .expect("unchanged context requires existing work")
                    .valid_until
                    .min(proposed_deadline)
            } else {
                proposed_deadline
            };
            Some((fingerprint, hasher, target, incumbent, valid_until))
        } else {
            None
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
        *current = next_work.map(|(fingerprint, hasher, target, incumbent, valid_until)| {
            Arc::new(WorkJob {
                fingerprint,
                generation,
                hasher,
                target,
                incumbent,
                valid_until,
            })
        });
        Ok(true)
    }
}

#[derive(Clone, Debug)]
struct ProofFound {
    node_id: u8,
    generation: u64,
    nonce: u128,
    hash: B256,
    target: U256,
    incumbent: Option<B256>,
}

fn should_unlock_recovered_wallet(
    transaction_mode: bool,
    spending_limit: U256,
    signer_is_unlocked: bool,
    has_unresolved_transaction: bool,
) -> bool {
    transaction_mode
        && !spending_limit.is_zero()
        && !signer_is_unlocked
        && !has_unresolved_transaction
}

struct CpuWorkers {
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl CpuWorkers {
    fn stop_and_join(&mut self) -> bool {
        self.stop.store(true, Ordering::Release);
        let mut panicked = false;
        for worker in self.workers.drain(..) {
            panicked |= worker.join().is_err();
        }
        panicked
    }
}

impl Drop for CpuWorkers {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

struct DashboardContext<'a> {
    network: crate::cli::Network,
    chain_id: u64,
    address: Address,
    threads: usize,
    spending_limit: U256,
    transaction_mode: bool,
    compute_only: bool,
    workers_started: bool,
    selected: &'a HashSet<u8>,
    slots: &'a [NodeSlot],
}

pub async fn run(store: &ConfigStore, args: MineArgs) -> Result<()> {
    let config = store.load()?;
    if !args.compute_only && config.network != crate::cli::Network::Testnet {
        bail!("autonomous transaction signing is disabled outside Injective Testnet");
    }
    let address = selected_address(&config)?;
    let spending_limit = parse_inj_wei(&config.per_session_spending_limit_inj)?;
    let transaction_mode = !args.compute_only && !spending_limit.is_zero();
    let readonly_recovery = !args.compute_only
        && config.network == crate::cli::Network::Testnet
        && spending_limit.is_zero()
        && store.read_transaction_journal()?.is_some();
    let transaction_manager_mode = transaction_mode || readonly_recovery;
    let threads = args
        .threads
        .map(NonZeroUsize::get)
        .unwrap_or(config.cpu_threads);
    if threads == 0 || threads > config.cpu_threads || threads > 256 {
        bail!(
            "requested threads ({threads}) must be within the configured CPU budget ({}; max 256)",
            config.cpu_threads
        );
    }
    let selected = selected_nodes(&args.nodes)?;
    let mut client = NetworkClient::connect(config.network).await?;
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
    let mut transactions = if transaction_manager_mode {
        let token = client
            .manifest
            .ast_token
            .as_ref()
            .context("AST token pin is missing from the Testnet manifest")?;
        let ast_token = crate::deployment::parse_address(&token.address)?;
        let mut manager = TransactionManager::open(store, &config, address, ast_token)?;
        manager.reconcile(&client).await?;
        Some(manager)
    } else {
        None
    };
    let signing_ready = transactions
        .as_ref()
        .is_some_and(|manager| !manager.journal.has_unresolved());
    if transactions
        .as_ref()
        .is_some_and(|manager| manager.journal.has_unresolved())
    {
        eprintln!(
            "An unresolved or underconfirmed transaction is being recovered. No further transactions will be signed until it settles; maximum exposure remains reserved."
        );
    }
    let mut signer = if transaction_mode && signing_ready {
        Some(unlock_selected_interactive(store, &config)?)
    } else {
        None
    };
    if signer
        .as_ref()
        .is_some_and(|signer| crate::wallet::signer_address(signer) != address)
    {
        bail!("unlocked signer does not match the selected wallet");
    }
    let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
    let schedule = Arc::new(RwLock::new(Vec::new()));
    let mut dashboard_context = DashboardContext {
        network: client.manifest.network,
        chain_id: client.manifest.chain_id,
        address,
        threads,
        spending_limit,
        transaction_mode,
        compute_only: args.compute_only,
        workers_started: false,
        selected: &selected,
        slots: slots.as_slice(),
    };
    let mut snapshot = client.snapshot(Some(address)).await?;
    let mut changed = update_slots(
        &slots,
        &schedule,
        &client.manifest,
        address,
        &selected,
        &snapshot,
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    let cursor = Arc::new(AtomicUsize::new(0));
    let total_hashes = Arc::new(AtomicU64::new(0));
    let diagnostics = DiagnosticBuffer::default();
    let model = dashboard_model(
        &dashboard_context,
        &snapshot,
        transactions.as_ref(),
        &diagnostics,
    );
    let mut dashboard = Dashboard::start(model, Arc::clone(&total_hashes), diagnostics.clone())?;
    if dashboard.is_none() {
        for message in diagnostics.drain() {
            eprintln!("astatine: {message}");
        }
    }
    if let Some(dashboard) = &dashboard {
        let diagnostics = dashboard.diagnostics();
        client.set_diagnostics(diagnostics.clone());
        if let Some(manager) = transactions.as_mut() {
            manager.set_diagnostics(diagnostics);
        }
    }
    connect_transaction_dashboard(&mut transactions, &dashboard);

    let mut blocked_finalizations = HashSet::new();
    if let Some(manager) = transactions.as_mut()
        && let Err(error) = manager.reconcile_rewards(&client, &snapshot).await
    {
        report_mining_warning(
            &dashboard,
            format!("reward-event verification will retry after the next snapshot: {error:#}"),
        );
    }
    if let (Some(manager), Some(signer)) = (transactions.as_mut(), signer.as_ref()) {
        if !manager.journal.has_unresolved() && !manager.budget_remaining()?.is_zero() {
            let finalizing = snapshot
                .nodes
                .iter()
                .filter(|node| {
                    selected.contains(&node.id)
                        && node
                            .state
                            .as_ref()
                            .is_some_and(|state| state.finalizable && !state.mining_paused)
                })
                .map(|node| node.id)
                .collect::<Vec<_>>();
            mark_dashboard_nodes(
                &dashboard,
                finalizing,
                NodeStatus::Finalizing,
                Some("Finalizing expired windows...".to_owned()),
            );
        }
        if finalize_initial_expired_windows(
            &client,
            &selected,
            manager,
            signer,
            address,
            &mut snapshot,
            FinalizationOptions {
                blocked: &mut blocked_finalizations,
                dashboard: &dashboard,
            },
        )
        .await?
            && let Err(error) = manager.reconcile_rewards(&client, &snapshot).await
        {
            report_mining_warning(
                &dashboard,
                format!("reward-event verification will retry after the next snapshot: {error:#}"),
            );
        }
    }
    changed |= update_slots(
        &slots,
        &schedule,
        &client.manifest,
        address,
        &selected,
        &snapshot,
    )?;
    refresh_dashboard(
        &dashboard,
        &dashboard_context,
        &snapshot,
        transactions.as_ref(),
    );
    if !client.verification.token_verified {
        report_mining_warning(
            &dashboard,
            "AST token runtime pin is unavailable; mining proofs can still be computed, but AST balance is not trusted.",
        );
    }
    if dashboard.is_none() {
        if !args.compute_only && spending_limit.is_zero() {
            println!(
                "Per-session spending limit is zero; autonomous signing is disabled. Hashing continues without submissions or finalizations."
            );
        }
        print_startup(&client, address, threads, &snapshot, &slots, changed);
    }
    let (proof_sender, mut proof_receiver) = mpsc::unbounded_channel();
    let mut workers = Vec::with_capacity(threads);
    for worker_id in 0..threads {
        let slots = Arc::clone(&slots);
        let schedule = Arc::clone(&schedule);
        let worker_stop = Arc::clone(&stop);
        let cursor = Arc::clone(&cursor);
        let total_hashes = Arc::clone(&total_hashes);
        let proof_sender = proof_sender.clone();
        let worker = thread::Builder::new()
            .name(format!("astatine-pow-{worker_id}"))
            .spawn(move || {
                worker_loop(
                    slots,
                    schedule,
                    worker_stop,
                    cursor,
                    total_hashes,
                    proof_sender,
                )
            })
            .context("start CPU worker");
        match worker {
            Ok(worker) => workers.push(worker),
            Err(error) => {
                stop.store(true, Ordering::Release);
                for worker in workers {
                    let _ = worker.join();
                }
                return Err(error);
            }
        }
    }
    drop(proof_sender);
    let mut worker_guard = CpuWorkers {
        stop: Arc::clone(&stop),
        workers,
    };
    dashboard_context.workers_started = true;

    let mut progress_ticker = time::interval(PROGRESS_INTERVAL);
    progress_ticker.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    progress_ticker.tick().await;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    let mut last_progress = time::Instant::now();
    let mut consecutive_rpc_errors = 0_u8;
    let mut poll_delay = POLL_INTERVAL;
    let mut next_poll = time::Instant::now() + poll_delay;
    let mut last_snapshot = snapshot;
    refresh_dashboard(
        &dashboard,
        &dashboard_context,
        &last_snapshot,
        transactions.as_ref(),
    );
    let mut fatal_error = None;
    let mut budget_exhausted = false;
    let dashboard_signal = dashboard.as_ref().map(Dashboard::signal);

    loop {
        tokio::select! {
            signal = &mut ctrl_c => {
                if let Err(error) = signal {
                    report_mining_warning(
                        &dashboard,
                        format!("Ctrl+C signal handler failed: {error}"),
                    );
                }
                break;
            }
            event = wait_for_dashboard_event(dashboard_signal.clone()) => {
                match event {
                    DashboardEventKind::StopRequested => break,
                    DashboardEventKind::Failure(error) => {
                        fatal_error = Some(anyhow!("dashboard failed: {error}"));
                        break;
                    }
                }
            }
            _ = time::sleep_until(next_poll) => {
                match client.snapshot(Some(address)).await {
                    Ok(snapshot) => {
                        consecutive_rpc_errors = 0;
                        poll_delay = POLL_INTERVAL;
                        let mut snapshot = snapshot;
                        if let Some(manager) = transactions.as_mut()
                            && let Err(error) = manager.monitor(&client, snapshot.block.number).await
                        {
                            fatal_error = Some(error.context("monitor transaction finality and reorg state"));
                            break;
                        }
                        refresh_dashboard(
                            &dashboard,
                            &dashboard_context,
                            &snapshot,
                            transactions.as_ref(),
                        );
                        if let Some(manager) = transactions.as_ref()
                            && should_unlock_recovered_wallet(
                                transaction_mode,
                                spending_limit,
                                signer.is_some(),
                                manager.journal.has_unresolved(),
                            )
                        {
                            if let Some(dashboard) = dashboard.as_mut()
                                && let Err(error) = dashboard.suspend().await
                            {
                                fatal_error = Some(error.context("suspend dashboard for wallet unlock"));
                                break;
                            }
                            let unlock_result = unlock_selected_interactive(store, &config);
                            if let Some(dashboard) = dashboard.as_mut()
                                && let Err(error) = dashboard.resume(Arc::clone(&total_hashes))
                            {
                                fatal_error = Some(error.context("resume dashboard after wallet unlock"));
                                break;
                            }
                            let recovered_signer = match unlock_result {
                                Ok(recovered_signer)
                                    if crate::wallet::signer_address(&recovered_signer) == address =>
                                {
                                    recovered_signer
                                }
                                Ok(_) => {
                                    fatal_error = Some(anyhow!(
                                        "unlocked signer does not match the selected wallet"
                                    ));
                                    break;
                                }
                                Err(error) => {
                                    fatal_error = Some(
                                        error.context("unlock selected wallet after transaction recovery"),
                                    );
                                    break;
                                }
                            };
                            signer = Some(recovered_signer);
                            report_mining_info(
                                &dashboard,
                                "Transaction recovery settled; autonomous Testnet signing is resuming.",
                            );
                        }
                        if let (Some(manager), Some(signer)) =
                            (transactions.as_mut(), signer.as_ref())
                        {
                            let can_finalize = if manager.journal.has_unresolved() {
                                false
                            } else {
                                match manager.budget_remaining() {
                                    Ok(remaining) => !remaining.is_zero(),
                                    Err(error) => {
                                        fatal_error = Some(error.context("read remaining spending limit"));
                                        break;
                                    }
                                }
                            };
                            if can_finalize {
                                let finalizing = snapshot
                                    .nodes
                                    .iter()
                                    .filter(|node| {
                                        selected.contains(&node.id)
                                            && node.state.as_ref().is_some_and(|state| {
                                                state.finalizable && !state.mining_paused
                                            })
                                    })
                                    .map(|node| node.id)
                                    .collect::<Vec<_>>();
                                if !finalizing.is_empty() {
                                    mark_dashboard_nodes(
                                        &dashboard,
                                        finalizing.clone(),
                                        NodeStatus::Finalizing,
                                        Some("Finalizing expired windows...".to_owned()),
                                    );
                                }
                            }
                            match maybe_finalize_expired(
                                &client,
                                &selected,
                                manager,
                                signer,
                                address,
                                FinalizationOptions {
                                    blocked: &mut blocked_finalizations,
                                    dashboard: &dashboard,
                                },
                            )
                            .await
                            {
                                Ok(true) => match client.snapshot(Some(address)).await {
                                    Ok(fresh) => snapshot = fresh,
                                    Err(error) => {
                                        fatal_error = Some(error.context("refresh after finalization"));
                                        break;
                                    }
                                },
                                Ok(false) => {}
                                Err(error) => {
                                    fatal_error = Some(error);
                                    break;
                                }
                            }
                        }
                        if let Some(manager) = transactions.as_mut()
                            && let Err(error) = manager.reconcile_rewards(&client, &snapshot).await
                        {
                            report_mining_warning(
                                &dashboard,
                                format!("reward-event verification will retry after the next snapshot: {error:#}"),
                            );
                        }
                        let changed = update_slots(
                            &slots,
                            &schedule,
                            &client.manifest,
                            address,
                            &selected,
                            &snapshot,
                        )?;
                        last_snapshot = snapshot;
                        refresh_dashboard(
                            &dashboard,
                            &dashboard_context,
                            &last_snapshot,
                            transactions.as_ref(),
                        );
                        if dashboard.is_none()
                            && (changed || last_progress.elapsed() >= PROGRESS_INTERVAL)
                        {
                            let elapsed = last_progress.elapsed();
                            print_progress(
                                &last_snapshot,
                                &slots,
                                total_hashes.swap(0, Ordering::Relaxed),
                                elapsed,
                            );
                            last_progress = time::Instant::now();
                        }
                    }
                    Err(error) => {
                        consecutive_rpc_errors = consecutive_rpc_errors.saturating_add(1);
                        if consecutive_rpc_errors == 1 || consecutive_rpc_errors.is_multiple_of(5) {
                            report_mining_warning(
                                &dashboard,
                                format!("RPC refresh failed; stale work stopped: {error:#}"),
                            );
                        }
                        for slot in slots.iter() {
                            slot.set_work(
                                &client.manifest,
                                address,
                                Address::ZERO,
                                None,
                                last_snapshot.block.timestamp,
                            )?;
                        }
                        *schedule
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Vec::new();
                        if let Some(dashboard) = &dashboard {
                            let active_nodes = transactions
                                .as_ref()
                                .map(TransactionManager::dashboard_activities)
                                .unwrap_or_default()
                                .into_iter()
                                .map(|activity| (activity.node_id, activity.state))
                                .collect::<std::collections::HashMap<_, _>>();
                            dashboard.update(|model| {
                                model.connection_error = Some(format!("{error:#}"));
                                for node in &mut model.selected_nodes {
                                    if let Some(activity) = active_nodes.get(&node.id) {
                                        node.status = match activity {
                                            TransactionActivityState::Finalizing => NodeStatus::Finalizing,
                                            TransactionActivityState::Confirming => NodeStatus::Confirming,
                                            TransactionActivityState::Recovering => NodeStatus::Recovering,
                                        };
                                    } else {
                                        node.status = NodeStatus::RpcError;
                                    }
                                    node.mining_deadline = None;
                                }
                            });
                        } else {
                            total_hashes.store(0, Ordering::Relaxed);
                        }
                        poll_delay = next_poll_delay(poll_delay);
                    }
                }
                next_poll = time::Instant::now() + poll_delay;
            }
            _ = progress_ticker.tick() => {
                let elapsed = last_progress.elapsed();
                if dashboard.is_none() && elapsed >= PROGRESS_INTERVAL {
                    print_progress(
                        &last_snapshot,
                        &slots,
                        total_hashes.swap(0, Ordering::Relaxed),
                        elapsed,
                    );
                    last_progress = time::Instant::now();
                }
            }
            proof = proof_receiver.recv() => {
                        if let Some(proof) = proof {
                    let slot = &slots[usize::from(proof.node_id - 1)];
                    if slot.is_generation_current(proof.generation)
                        && slot
                            .current_work()
                            .is_some_and(|work| work.generation == proof.generation)
                    {
                        let incumbent = proof.incumbent.map(|hash| format!("; beats incumbent {hash:#x}")).unwrap_or_default();
                        if args.compute_only {
                            report_mining_info(
                                &dashboard,
                                format!(
                                    "valid local proof: node={} nonce={} hash={:#x} target={:#x}{}; not submitted",
                                    proof.node_id, proof.nonce, proof.hash, proof.target, incumbent
                                ),
                            );
                        } else if let (Some(manager), Some(signer)) =
                            (transactions.as_mut(), signer.as_ref())
                        {
                            if manager.journal.has_unresolved() {
                                report_mining_info(
                                    &dashboard,
                                    format!("valid local proof for node {} was withheld while a previous transaction is under recovery", proof.node_id),
                                );
                                continue;
                            }
                            if budget_exhausted || manager.budget_remaining()?.is_zero() {
                                budget_exhausted = true;
                                report_mining_info(
                                    &dashboard,
                                    format!("valid local proof for node {} was not submitted: session spending limit is exhausted", proof.node_id),
                                );
                                continue;
                            }
                            let Some(work) = slot.current_work() else {
                                continue;
                            };
                            let contract = work.fingerprint.hashing_context.contract;
                            let window_id = work.fingerprint.hashing_context.window_id;
                            let header = work.fingerprint.hashing_context.header.clone();
                            mark_dashboard_nodes(
                                &dashboard,
                                [proof.node_id],
                                NodeStatus::Confirming,
                                Some(format!("Node {:02} • Confirming proof...", proof.node_id)),
                            );
                            match manager.submit_proof(
                                &client,
                                signer,
                                ProofSubmission {
                                    contract,
                                    node_id: proof.node_id,
                                    window_id,
                                    nonce: proof.nonce,
                                    header,
                                    work_hash: proof.hash,
                                },
                            )
                            .await
                            {
                                Ok(action) => {
                                    report_mining_info(
                                        &dashboard,
                                        confirmed_action_message("proof", &action),
                                    );
                                    mark_dashboard_nodes(
                                        &dashboard,
                                        [proof.node_id],
                                        NodeStatus::Waiting,
                                        None,
                                    );
                                }
                                Err(error) if manager.journal.has_unresolved() => {
                                    fatal_error = Some(error);
                                    break;
                                }
                                Err(error) if manager.journal.has_unverified_receipt() => {
                                    fatal_error = Some(error);
                                    break;
                                }
                                Err(error) if is_policy_refusal(&error) => {
                                    budget_exhausted |= is_session_limit_refusal(&error);
                                    report_mining_warning(
                                        &dashboard,
                                        format!("valid proof was not submitted: {error:#}"),
                                    );
                                    mark_dashboard_nodes(
                                        &dashboard,
                                        [proof.node_id],
                                        NodeStatus::Mining,
                                        None,
                                    );
                                }
                                Err(error) if is_stale_proof(&error) => {
                                    report_mining_warning(
                                        &dashboard,
                                        format!("discarded stale proof for node {}: {error:#}", proof.node_id),
                                    );
                                    mark_dashboard_nodes(
                                        &dashboard,
                                        [proof.node_id],
                                        NodeStatus::Waiting,
                                        None,
                                    );
                                }
                                Err(error) => {
                                    fatal_error = Some(error);
                                    break;
                                }
                            }
                        } else {
                            report_mining_info(
                                &dashboard,
                                format!("valid local proof for node {} was not submitted: transaction signing is disabled", proof.node_id),
                            );
                        }
                    }
                }
            }
        }
    }

    if worker_guard.stop_and_join() {
        report_mining_warning(&dashboard, "CPU worker stopped after an internal panic.");
    }

    let mut stopped_message = None;
    if fatal_error.is_none() {
        if let Some(manager) = transactions.as_mut() {
            if manager.journal.has_unresolved() {
                stopped_message = Some(
                    "Stopped with transaction exposure reserved for read-only recovery. The session remains open in the private journal.",
                );
            } else if let Err(error) = manager.close_session() {
                fatal_error = Some(error.context("close transaction spending session"));
            } else {
                stopped_message = Some(
                    "Stopped autonomous Testnet mining. Transaction journal retained without private key material.",
                );
            }
        } else if args.compute_only {
            stopped_message =
                Some("Stopped compute-only mining. No transactions were signed or sent.");
        } else {
            stopped_message = Some(
                "Stopped mining. No transactions were signed or sent because the session limit is zero.",
            );
        }
    }

    if let Some(error) = fatal_error.as_ref()
        && let Some(dashboard) = &dashboard
    {
        dashboard.update(|model| {
            model.critical_error = Some(format!("{error:#}"));
            model.current_action = None;
        });
    }
    let restore_result = if let Some(dashboard) = dashboard.as_mut() {
        let result = dashboard.stop().await;
        flush_dashboard_diagnostics(dashboard);
        result
    } else {
        Ok(())
    };
    if let Err(error) = restore_result
        && fatal_error.is_none()
    {
        fatal_error = Some(error.context("restore mining dashboard terminal"));
    }
    if let Some(error) = fatal_error {
        return Err(error);
    }
    if let Some(message) = stopped_message {
        println!("{message}");
    }
    Ok(())
}

pub(crate) struct FinalizationOptions<'a> {
    pub blocked: &'a mut HashSet<(u8, u64)>,
    pub dashboard: &'a Option<Dashboard>,
}

async fn maybe_finalize_expired(
    client: &NetworkClient,
    selected: &HashSet<u8>,
    manager: &mut TransactionManager,
    signer: &bip32::secp256k1::ecdsa::SigningKey,
    wallet: Address,
    options: FinalizationOptions<'_>,
) -> Result<bool> {
    if manager.journal.has_unresolved() || manager.budget_remaining()?.is_zero() {
        return Ok(false);
    }
    let snapshot = client.snapshot(Some(wallet)).await?;
    let mut finalized_any = false;
    for node in &snapshot.nodes {
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
        let key = (node.id, state.work.window_id);
        if options.blocked.contains(&key) {
            continue;
        }
        mark_dashboard_nodes(
            options.dashboard,
            [node.id],
            NodeStatus::Finalizing,
            Some(format!("Node {:02} • Finalizing window...", node.id)),
        );
        match manager
            .finalize_window(client, signer, node.address, node.id, state.work.window_id)
            .await
        {
            Ok(action) => {
                report_mining_info(
                    options.dashboard,
                    confirmed_action_message("finalization", &action),
                );
                mark_dashboard_nodes(options.dashboard, [node.id], NodeStatus::Waiting, None);
                finalized_any = true;
            }
            Err(error) if manager.journal.has_unresolved() => return Err(error),
            Err(error) if manager.journal.has_unverified_receipt() => return Err(error),
            Err(error) if is_policy_refusal(&error) => {
                report_mining_warning(
                    options.dashboard,
                    format!(
                        "node {} window {} finalization skipped: {error:#}",
                        node.id, state.work.window_id
                    ),
                );
                mark_dashboard_nodes(options.dashboard, [node.id], NodeStatus::Waiting, None);
                options.blocked.insert(key);
            }
            Err(error) => {
                report_mining_warning(
                    options.dashboard,
                    format!(
                        "node {} window {} finalization deferred: {error:#}",
                        node.id, state.work.window_id
                    ),
                );
                mark_dashboard_nodes(options.dashboard, [node.id], NodeStatus::Waiting, None);
                options.blocked.insert(key);
            }
        }
        if manager.budget_remaining()?.is_zero() {
            break;
        }
    }
    Ok(finalized_any)
}

pub(crate) async fn finalize_initial_expired_windows(
    client: &NetworkClient,
    selected: &HashSet<u8>,
    manager: &mut TransactionManager,
    signer: &bip32::secp256k1::ecdsa::SigningKey,
    wallet: Address,
    snapshot: &mut ReadSnapshot,
    options: FinalizationOptions<'_>,
) -> Result<bool> {
    if !maybe_finalize_expired(client, selected, manager, signer, wallet, options).await? {
        return Ok(false);
    }
    *snapshot = client.snapshot(Some(wallet)).await?;
    Ok(true)
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
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("maximum exposure exceeds")
        || message.contains("configured per-session limit")
        || message.contains("insufficient confirmed inj balance")
        || message.contains("spending limit is zero")
}

fn is_session_limit_refusal(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("maximum exposure exceeds") || message.contains("configured per-session limit")
}

fn is_stale_proof(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("fresh on-chain")
        || message.contains("different window")
        || message.contains("no longer eligible")
        || message.contains("pending nonce changed")
        || message.contains("paid proof attempt already journaled")
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

fn update_slots(
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
        changed |= slot.set_work(manifest, miner, contract, state, snapshot.block.timestamp)?;
        if slot.current_work().is_some() {
            active.push(index);
        }
    }
    *schedule
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = active;
    Ok(changed)
}

fn dashboard_model(
    context: &DashboardContext<'_>,
    snapshot: &ReadSnapshot,
    transactions: Option<&TransactionManager>,
    diagnostics: &DiagnosticBuffer,
) -> DashboardModel {
    let mut selected_ids = context.selected.iter().copied().collect::<Vec<_>>();
    selected_ids.sort_unstable();
    let activities = transactions
        .map(TransactionManager::dashboard_activities)
        .unwrap_or_default();
    let mut nodes = Vec::with_capacity(selected_ids.len());
    let mut first_error = None;
    for id in selected_ids {
        let view = snapshot.nodes.iter().find(|node| node.id == id);
        let trusted = view.is_some_and(|node| node.pin.runtime_verified && node.pin.abi_verified);
        let state = view.and_then(|node| node.state.as_ref());
        let activity = activities.iter().find(|activity| activity.node_id == id);
        let slot_work = context.slots[usize::from(id - 1)].current_work();
        let status = dashboard_node_status(
            state,
            trusted,
            context.workers_started && slot_work.is_some(),
            activity.map(|activity| activity.state),
        );
        if first_error.is_none() {
            first_error = view
                .and_then(|node| node.error.as_deref().or(node.pin.error.as_deref()))
                .map(str::to_owned);
        }
        let candidate = trusted
            .then(|| {
                state.and_then(|state| state.candidate.as_ref().map(|candidate| candidate.miner))
            })
            .flatten();
        let reward = trusted
            .then(|| state.map(|state| state.work.reward_per_window))
            .flatten();
        nodes.push(DashboardNode {
            id,
            status,
            expiry_timestamp: state
                .filter(|state| state.eligible)
                .map(|state| state.work.window_expiry_time),
            mining_deadline: slot_work.map(|work| work.valid_until),
            candidate,
            reward,
        });
    }
    let session_exposure = transactions.and_then(|manager| match manager.session_exposure() {
        Ok(exposure) => exposure,
        Err(error) => {
            diagnostics.push(format!(
                "dashboard could not read transaction session exposure: {error:#}"
            ));
            None
        }
    });
    DashboardModel {
        network: context.network,
        chain_id: context.chain_id,
        wallet: context.address,
        inj_balance: snapshot.native_balance,
        cpu_threads: context.threads,
        session_limit: Some(context.spending_limit),
        session_exposure,
        block_number: snapshot.block.number,
        block_timestamp: snapshot.block.timestamp,
        snapshot_observed_at: Instant::now(),
        selected_nodes: nodes,
        compute_only: context.compute_only,
        signing_enabled: context.transaction_mode,
        recovering: transactions.is_some_and(|manager| manager.journal.has_unresolved()),
        stopping: false,
        hashrate: 0.0,
        current_action: None,
        connection_error: first_error,
        critical_error: None,
    }
}

fn dashboard_node_status(
    state: Option<&NodeState>,
    trusted: bool,
    has_current_work: bool,
    activity: Option<TransactionActivityState>,
) -> NodeStatus {
    if let Some(activity) = activity {
        return match activity {
            TransactionActivityState::Finalizing => NodeStatus::Finalizing,
            TransactionActivityState::Confirming => NodeStatus::Confirming,
            TransactionActivityState::Recovering => NodeStatus::Recovering,
        };
    }
    if !trusted || state.is_none() {
        return NodeStatus::RpcError;
    }
    let state = state.expect("checked above");
    if state.mining_paused {
        NodeStatus::Paused
    } else if !state.work.started || state.work.ended || state.work.remaining_allocation.is_zero() {
        NodeStatus::Ended
    } else if state.eligible && has_current_work {
        NodeStatus::Mining
    } else {
        NodeStatus::Waiting
    }
}

fn refresh_dashboard(
    dashboard: &Option<Dashboard>,
    context: &DashboardContext<'_>,
    snapshot: &ReadSnapshot,
    transactions: Option<&TransactionManager>,
) {
    let Some(dashboard) = dashboard else {
        return;
    };
    let diagnostics = dashboard.diagnostics();
    let updated = dashboard_model(context, snapshot, transactions, &diagnostics);
    dashboard.update(|model| {
        let hashrate = model.hashrate;
        *model = updated;
        model.hashrate = hashrate;
    });
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
                node.mining_deadline = None;
            }
        }
        model.current_action = action;
    });
}

fn connect_transaction_dashboard(
    transactions: &mut Option<TransactionManager>,
    dashboard: &Option<Dashboard>,
) {
    let (Some(manager), Some(dashboard)) = (transactions.as_mut(), dashboard.as_ref()) else {
        return;
    };
    let updater = dashboard.updater();
    manager.set_dashboard_sink(Arc::new(move |state| {
        apply_transaction_dashboard_state(&updater, state);
    }));
}

fn apply_transaction_dashboard_state(updater: &DashboardUpdater, state: TransactionDashboardState) {
    updater.update(|model| {
        model.session_exposure = state.session_exposure;
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
            node.status = match activity.state {
                TransactionActivityState::Finalizing => NodeStatus::Finalizing,
                TransactionActivityState::Confirming => NodeStatus::Confirming,
                TransactionActivityState::Recovering => NodeStatus::Recovering,
            };
            node.mining_deadline = None;
        }
        model.current_action = state.activities.first().map(|activity| {
            let action = match activity.state {
                TransactionActivityState::Finalizing => "Finalizing window...",
                TransactionActivityState::Confirming => "Confirming transaction...",
                TransactionActivityState::Recovering => "Recovering transaction...",
            };
            format!("Node {:02} • {action}", activity.node_id)
        });
    });
}

fn report_mining_info(dashboard: &Option<Dashboard>, message: impl Into<String>) {
    let message = message.into();
    if let Some(dashboard) = dashboard {
        dashboard.diagnostics().push(message);
    } else {
        println!("{message}");
    }
}

fn report_mining_warning(dashboard: &Option<Dashboard>, message: impl Into<String>) {
    let message = message.into();
    if let Some(dashboard) = dashboard {
        dashboard.diagnostics().push(message);
    } else {
        eprintln!("{message}");
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
    threads: usize,
    snapshot: &ReadSnapshot,
    slots: &[NodeSlot],
    selected_work_changed: bool,
) {
    let ast_decimals = client
        .manifest
        .ast_token
        .as_ref()
        .map(|token| token.decimals)
        .unwrap_or(9);
    println!(
        "Astatine {} | {} (chain {}) | wallet {:#x} | INJ {} | AST {} | CPU {} | block {}",
        env!("CARGO_PKG_VERSION"),
        network_label(client.manifest.network),
        client.manifest.chain_id,
        address,
        format_inj(snapshot.native_balance),
        format_token_units(snapshot.ast_balance, ast_decimals),
        threads,
        snapshot.block.number
    );
    let eligible = slots
        .iter()
        .filter(|slot| slot.current_work().is_some())
        .count();
    if eligible == 0 {
        println!("No eligible work in selected nodes; waiting for fresh verified windows.");
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
            println!("  node {}: unavailable ({})", node.id, error);
        }
    }
}

fn worker_loop(
    slots: Arc<Vec<NodeSlot>>,
    schedule: Arc<RwLock<Vec<usize>>>,
    stop: Arc<AtomicBool>,
    cursor: Arc<AtomicUsize>,
    total_hashes: Arc<AtomicU64>,
    proofs: mpsc::UnboundedSender<ProofFound>,
) {
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
            continue;
        }
        let Some((first_nonce, count)) = slot.reserve_nonces() else {
            thread::sleep(IDLE_INTERVAL);
            continue;
        };
        let mut scratch = vec![0_u8; work.hasher.scratch_len()];
        let mut completed = 0_u64;
        for offset in 0..count {
            if stop.load(Ordering::Relaxed)
                || !slot.is_generation_current(work.generation)
                || Instant::now() >= work.valid_until
            {
                break;
            }
            let Some(nonce) = first_nonce.checked_add(offset as u128) else {
                break;
            };
            let Ok(hash) = work.hasher.hash_into(nonce, &mut scratch) else {
                break;
            };
            completed += 1;
            if !meets_target(hash, work.target)
                || work
                    .incumbent
                    .is_some_and(|incumbent| !beats_incumbent(hash, incumbent))
            {
                continue;
            }
            let mut best = slot
                .local_best
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if best.is_some_and(|previous| hash >= previous) {
                continue;
            }
            *best = Some(hash);
            drop(best);
            let _ = proofs.send(ProofFound {
                node_id: slot.id,
                generation: work.generation,
                nonce,
                hash,
                target: work.target,
                incumbent: work.incumbent,
            });
        }
        total_hashes.fetch_add(completed, Ordering::Relaxed);
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

fn network_label(network: crate::cli::Network) -> &'static str {
    match network {
        crate::cli::Network::Testnet => "Testnet",
        crate::cli::Network::Mainnet => "Mainnet",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DashboardContext, NodeSlot, NonceAllocator, dashboard_model, dashboard_node_status,
        next_poll_delay, next_scheduled_slot, selected_nodes, should_unlock_recovered_wallet,
        worker_loop,
    };
    use crate::{
        cli::{MineArgs, Network},
        config::ConfigStore,
        dashboard::NodeStatus,
        deployment::DeploymentManifest,
        diagnostics::DiagnosticBuffer,
        protocol::{WorkContext, WorkHasher, meets_target},
        rpc::{
            BlockSnapshot, CandidateInfo, ContractPinStatus, NodeState, NodeView, ReadSnapshot,
            WorkInfo,
        },
        transaction::TransactionActivityState,
    };
    use alloy_primitives::{Address, B256, Bytes, U256};
    use std::{
        collections::HashSet,
        sync::{
            Arc, RwLock,
            atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };
    use tempfile::tempdir;
    use tokio::sync::mpsc;
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

    #[test]
    fn dashboard_node_status_requires_verified_live_work_and_respects_transactions() {
        let mut state = eligible_state();
        assert_eq!(
            dashboard_node_status(Some(&state), true, true, None),
            NodeStatus::Mining
        );
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, None),
            NodeStatus::Waiting
        );
        assert_eq!(
            dashboard_node_status(Some(&state), false, true, None),
            NodeStatus::RpcError
        );
        assert_eq!(
            dashboard_node_status(None, true, false, None),
            NodeStatus::RpcError
        );

        state.mining_paused = true;
        assert_eq!(
            dashboard_node_status(Some(&state), true, true, None),
            NodeStatus::Paused
        );
        state.mining_paused = false;
        state.work.ended = true;
        assert_eq!(
            dashboard_node_status(Some(&state), true, true, None),
            NodeStatus::Ended
        );
        state.work.ended = false;
        state.finalizable = true;
        state.eligible = false;
        assert_eq!(
            dashboard_node_status(Some(&state), true, false, None),
            NodeStatus::Waiting
        );

        assert_eq!(
            dashboard_node_status(
                Some(&state),
                true,
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
                Some(TransactionActivityState::Confirming)
            ),
            NodeStatus::Confirming
        );
        assert_eq!(
            dashboard_node_status(
                Some(&state),
                true,
                false,
                Some(TransactionActivityState::Recovering)
            ),
            NodeStatus::Recovering
        );
    }

    #[test]
    fn dashboard_model_sorts_and_only_copies_selected_nodes() {
        let slots = (1..=9).map(NodeSlot::new).collect::<Vec<_>>();
        let selected = HashSet::from([7, 1, 3]);
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
            ast_balance: None,
            ast_balance_error: None,
            nodes,
        };
        let context = DashboardContext {
            network: Network::Testnet,
            chain_id: 1439,
            address: Address::with_last_byte(9),
            threads: 2,
            spending_limit: U256::ZERO,
            transaction_mode: false,
            compute_only: true,
            workers_started: false,
            selected: &selected,
            slots: &slots,
        };

        let model = dashboard_model(&context, &snapshot, None, &DiagnosticBuffer::default());
        assert_eq!(
            model
                .selected_nodes
                .iter()
                .map(|node| node.id)
                .collect::<Vec<_>>(),
            [1, 3, 7]
        );
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
    }

    #[test]
    fn target_and_incumbent_changes_preserve_nonces_but_context_changes_reset_them() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let state = eligible_state();

        assert!(
            slot.set_work(&manifest, miner, contract, Some(&state), 100)
                .unwrap()
        );
        let initial_generation = slot.current_work().unwrap().generation;
        assert_eq!(slot.reserve_nonces(), Some((0, super::NONCE_BATCH_SIZE)));
        assert!(
            !slot
                .set_work(&manifest, miner, contract, Some(&state), 100)
                .unwrap()
        );
        assert_eq!(slot.reserve_nonces(), Some((2048, super::NONCE_BATCH_SIZE)));

        let mut changed_state = eligible_state();
        changed_state.work.target = U256::MAX - U256::from(1);
        assert!(
            slot.set_work(&manifest, miner, contract, Some(&changed_state), 100)
                .unwrap()
        );
        let target_generation = slot.current_work().unwrap().generation;
        assert!(target_generation > initial_generation);
        assert_eq!(slot.reserve_nonces(), Some((4096, super::NONCE_BATCH_SIZE)));

        changed_state.candidate = Some(CandidateInfo {
            miner: Address::with_last_byte(7),
            nonce: 9,
            work_hash: B256::with_last_byte(3),
            submitted_at: 150,
            header: Bytes::new(),
            first_valid_solve_secs: 2,
        });
        assert!(
            slot.set_work(&manifest, miner, contract, Some(&changed_state), 100)
                .unwrap()
        );
        let incumbent_generation = slot.current_work().unwrap().generation;
        assert!(incumbent_generation > target_generation);
        assert_eq!(slot.reserve_nonces(), Some((6144, super::NONCE_BATCH_SIZE)));

        changed_state.work.seed = B256::with_last_byte(4);
        assert!(
            slot.set_work(&manifest, miner, contract, Some(&changed_state), 100)
                .unwrap()
        );
        let context_generation = slot.current_work().unwrap().generation;
        assert!(context_generation > incumbent_generation);
        assert_eq!(slot.reserve_nonces(), Some((0, super::NONCE_BATCH_SIZE)));

        assert!(
            slot.set_work(&manifest, miner, contract, None, 100)
                .unwrap()
        );
        assert!(!slot.is_generation_current(context_generation));
        assert!(slot.current_work().is_none());
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
        slot.set_work(
            &manifest,
            Address::with_last_byte(8),
            Address::with_last_byte(9),
            Some(&state),
            100,
        )
        .unwrap();
        assert!(slot.current_work().is_none());
    }

    #[test]
    fn rpc_retry_backoff_is_exponential_and_bounded() {
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
    }

    #[test]
    fn recovered_transaction_enables_autonomous_unlock_only_after_settlement() {
        let positive_limit = U256::from(1);
        assert!(!should_unlock_recovered_wallet(
            true,
            positive_limit,
            false,
            true
        ));
        assert!(should_unlock_recovered_wallet(
            true,
            positive_limit,
            false,
            false
        ));
        assert!(!should_unlock_recovered_wallet(
            true,
            U256::ZERO,
            false,
            false
        ));
        assert!(!should_unlock_recovered_wallet(
            false,
            positive_limit,
            false,
            false
        ));
        assert!(!should_unlock_recovered_wallet(
            true,
            positive_limit,
            true,
            false
        ));
    }

    #[tokio::test]
    async fn autonomous_mining_requires_a_selected_wallet_before_connecting() {
        let temp = tempdir().unwrap();
        let store = ConfigStore::at_root(temp.path().to_path_buf());
        let error = super::run(
            &store,
            MineArgs {
                compute_only: false,
                threads: None,
                nodes: Vec::new(),
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
                compute_only: false,
                threads: None,
                nodes: Vec::new(),
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

    #[test]
    fn node_selection_defaults_to_all_and_rejects_duplicates() {
        assert_eq!(
            selected_nodes(&[]).unwrap(),
            (1..=9).collect::<HashSet<_>>()
        );
        assert!(selected_nodes(&[2, 2]).is_err());
    }

    #[tokio::test]
    async fn worker_emits_a_locally_verified_proof_without_submitting_it() {
        let manifest = DeploymentManifest::load(Network::Testnet).unwrap();
        let slot = NodeSlot::new(1);
        let miner = Address::with_last_byte(8);
        let contract = Address::with_last_byte(9);
        let mut state = eligible_state();
        state.work.target = U256::MAX;
        slot.set_work(&manifest, miner, contract, Some(&state), 100)
            .unwrap();

        let slots = Arc::new(vec![slot]);
        let schedule = Arc::new(RwLock::new(vec![0]));
        let stop = Arc::new(AtomicBool::new(false));
        let cursor = Arc::new(AtomicUsize::new(0));
        let total_hashes = Arc::new(AtomicU64::new(0));
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let worker_slots = Arc::clone(&slots);
        let worker_schedule = Arc::clone(&schedule);
        let worker_stop = Arc::clone(&stop);
        let worker_cursor = Arc::clone(&cursor);
        let worker_hashes = Arc::clone(&total_hashes);
        let worker = thread::spawn(move || {
            worker_loop(
                worker_slots,
                worker_schedule,
                worker_stop,
                worker_cursor,
                worker_hashes,
                sender,
            );
        });

        let proof_result = timeout(Duration::from_secs(2), receiver.recv()).await;
        stop.store(true, Ordering::Release);
        worker.join().expect("worker should stop cleanly");
        let proof = proof_result
            .expect("worker should find a proof under the maximum target")
            .expect("worker should report its proof");

        let context = WorkContext {
            chain_id: manifest.chain_id,
            contract,
            window_id: state.work.window_id,
            seed: state.work.seed,
            miner,
            header: Vec::new(),
        };
        assert_eq!(proof.node_id, 1);
        assert!(slots[0].is_generation_current(proof.generation));
        assert_eq!(
            WorkHasher::new(&context).unwrap().hash(proof.nonce),
            proof.hash
        );
        assert!(meets_target(proof.hash, U256::MAX));
        assert!(total_hashes.load(Ordering::Relaxed) > 0);
    }
}
