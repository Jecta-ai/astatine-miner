use crate::{
    cli::MineArgs,
    config::{ConfigStore, parse_inj_wei},
    deployment::DeploymentManifest,
    protocol::{WorkContext, WorkHasher, beats_incumbent, meets_target},
    rpc::{NetworkClient, NodeState, ReadSnapshot},
    transaction::{ConfirmedAction, ProofSubmission, TransactionManager},
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
    let client = NetworkClient::connect(config.network).await?;
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
    if !client.verification.token_verified {
        eprintln!(
            "AST token runtime pin is unavailable; mining proofs can still be computed, but AST balance is not trusted."
        );
    }

    let slots = Arc::new((1..=9).map(NodeSlot::new).collect::<Vec<_>>());
    let schedule = Arc::new(RwLock::new(Vec::new()));
    let mut snapshot = client.snapshot(Some(address)).await?;
    let mut blocked_finalizations = HashSet::new();
    if let Some(manager) = transactions.as_mut()
        && let Err(error) = manager.reconcile_rewards(&client, &snapshot).await
    {
        eprintln!("reward-event verification will retry after the next snapshot: {error:#}");
    }
    if let (Some(manager), Some(signer)) = (transactions.as_mut(), signer.as_ref()) {
        if finalize_initial_expired_windows(
            &client,
            &selected,
            manager,
            signer,
            address,
            &mut blocked_finalizations,
            &mut snapshot,
        )
        .await?
            && let Err(error) = manager.reconcile_rewards(&client, &snapshot).await
        {
            eprintln!("reward-event verification will retry after the next snapshot: {error:#}");
        }
    } else if !args.compute_only && spending_limit.is_zero() {
        println!(
            "Per-session spending limit is zero; autonomous signing is disabled. Hashing continues without submissions or finalizations."
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
    print_startup(&client, address, threads, &snapshot, &slots, changed);

    let stop = Arc::new(AtomicBool::new(false));
    let cursor = Arc::new(AtomicUsize::new(0));
    let total_hashes = Arc::new(AtomicU64::new(0));
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
    let mut fatal_error = None;
    let mut budget_exhausted = false;

    loop {
        tokio::select! {
            signal = &mut ctrl_c => {
                if let Err(error) = signal {
                    eprintln!("Ctrl+C signal handler failed: {error}");
                }
                break;
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
                        if let Some(manager) = transactions.as_ref()
                            && should_unlock_recovered_wallet(
                                transaction_mode,
                                spending_limit,
                                signer.is_some(),
                                manager.journal.has_unresolved(),
                            )
                        {
                            let recovered_signer = match unlock_selected_interactive(store, &config) {
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
                            println!("Transaction recovery settled; autonomous Testnet signing is resuming.");
                        }
                        if let (Some(manager), Some(signer)) =
                            (transactions.as_mut(), signer.as_ref())
                        {
                            match maybe_finalize_expired(
                                &client,
                                &selected,
                                manager,
                                signer,
                                address,
                                &mut blocked_finalizations,
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
                            eprintln!("reward-event verification will retry after the next snapshot: {error:#}");
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
                        if changed || last_progress.elapsed() >= PROGRESS_INTERVAL {
                            let elapsed = last_progress.elapsed();
                            print_progress(&last_snapshot, &slots, total_hashes.swap(0, Ordering::Relaxed), elapsed);
                            last_progress = time::Instant::now();
                        }
                    }
                    Err(error) => {
                        consecutive_rpc_errors = consecutive_rpc_errors.saturating_add(1);
                        if consecutive_rpc_errors == 1 || consecutive_rpc_errors.is_multiple_of(5) {
                            eprintln!("RPC refresh failed; stale work stopped: {error:#}");
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
                        total_hashes.store(0, Ordering::Relaxed);
                        poll_delay = next_poll_delay(poll_delay);
                    }
                }
                next_poll = time::Instant::now() + poll_delay;
            }
            _ = progress_ticker.tick() => {
                let elapsed = last_progress.elapsed();
                if elapsed >= PROGRESS_INTERVAL {
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
                            println!("valid local proof: node={} nonce={} hash={:#x} target={:#x}{}; not submitted",
                                proof.node_id, proof.nonce, proof.hash, proof.target, incumbent);
                        } else if let (Some(manager), Some(signer)) =
                            (transactions.as_mut(), signer.as_ref())
                        {
                            if manager.journal.has_unresolved() {
                                println!("valid local proof for node {} was withheld while a previous transaction is under recovery", proof.node_id);
                                continue;
                            }
                            if budget_exhausted || manager.budget_remaining()?.is_zero() {
                                budget_exhausted = true;
                                println!("valid local proof for node {} was not submitted: session spending limit is exhausted", proof.node_id);
                                continue;
                            }
                            let Some(work) = slot.current_work() else {
                                continue;
                            };
                            let contract = work.fingerprint.hashing_context.contract;
                            let window_id = work.fingerprint.hashing_context.window_id;
                            let header = work.fingerprint.hashing_context.header.clone();
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
                            ).await {
                                Ok(action) => print_confirmed_action("proof", &action),
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
                                    eprintln!("valid proof was not submitted: {error:#}");
                                }
                                Err(error) if is_stale_proof(&error) => {
                                    eprintln!("discarded stale proof for node {}: {error:#}", proof.node_id);
                                }
                                Err(error) => {
                                    fatal_error = Some(error);
                                    break;
                                }
                            }
                        } else {
                            println!("valid local proof for node {} was not submitted: transaction signing is disabled", proof.node_id);
                        }
                    }
                }
            }
        }
    }

    stop.store(true, Ordering::Release);
    for worker in workers {
        if worker.join().is_err() {
            eprintln!("CPU worker stopped after an internal panic");
        }
    }
    if let Some(error) = fatal_error {
        return Err(error);
    }
    if let Some(manager) = transactions.as_mut() {
        if manager.journal.has_unresolved() {
            println!(
                "Stopped with transaction exposure reserved for read-only recovery. The session remains open in the private journal."
            );
        } else {
            manager.close_session()?;
            println!(
                "Stopped autonomous Testnet mining. Transaction journal retained without private key material."
            );
        }
    } else if args.compute_only {
        println!("Stopped compute-only mining. No transactions were signed or sent.");
    } else {
        println!(
            "Stopped mining. No transactions were signed or sent because the session limit is zero."
        );
    }
    Ok(())
}

async fn maybe_finalize_expired(
    client: &NetworkClient,
    selected: &HashSet<u8>,
    manager: &mut TransactionManager,
    signer: &bip32::secp256k1::ecdsa::SigningKey,
    wallet: Address,
    blocked: &mut HashSet<(u8, u64)>,
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
        if blocked.contains(&key) {
            continue;
        }
        match manager
            .finalize_window(client, signer, node.address, node.id, state.work.window_id)
            .await
        {
            Ok(action) => {
                print_confirmed_action("finalization", &action);
                finalized_any = true;
            }
            Err(error) if manager.journal.has_unresolved() => return Err(error),
            Err(error) if manager.journal.has_unverified_receipt() => return Err(error),
            Err(error) if is_policy_refusal(&error) => {
                eprintln!(
                    "node {} window {} finalization skipped: {error:#}",
                    node.id, state.work.window_id
                );
                blocked.insert(key);
            }
            Err(error) => {
                eprintln!(
                    "node {} window {} finalization deferred: {error:#}",
                    node.id, state.work.window_id
                );
                blocked.insert(key);
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
    blocked: &mut HashSet<(u8, u64)>,
    snapshot: &mut ReadSnapshot,
) -> Result<bool> {
    if !maybe_finalize_expired(client, selected, manager, signer, wallet, blocked).await? {
        return Ok(false);
    }
    *snapshot = client.snapshot(Some(wallet)).await?;
    Ok(true)
}

fn print_confirmed_action(label: &str, action: &ConfirmedAction) {
    let effective_price = action
        .receipt
        .effective_gas_price
        .map(|price| price.to_string())
        .unwrap_or_else(|| "unknown".to_owned());
    println!(
        "{label} confirmed: tx={:#x} | {} | gas={} | effective price={} wei",
        action.transaction_hash, action.outcome, action.receipt.gas_used, effective_price
    );
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
        NodeSlot, NonceAllocator, next_poll_delay, next_scheduled_slot, selected_nodes,
        should_unlock_recovered_wallet, worker_loop,
    };
    use crate::{
        cli::{MineArgs, Network},
        config::ConfigStore,
        deployment::DeploymentManifest,
        protocol::{WorkContext, WorkHasher, meets_target},
        rpc::{CandidateInfo, NodeState, WorkInfo},
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
