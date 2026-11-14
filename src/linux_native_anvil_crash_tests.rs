// Included only by transaction::tests on Linux. This extends the native
// Secret Service + pinned local Anvil crash harness without adding any
// production configuration or RPC behavior.
use subtle::ConstantTimeEq;

const NATIVE_ANVIL_STAGE_ENV: &str = "ASTATINE_NATIVE_ANVIL_STAGE";
const NATIVE_ANVIL_RECOVERY_CHILD_TEST: &str =
    "transaction::tests::linux_native_provider_anvil_recovery_probe";
const NATIVE_ANVIL_PARENT_READY_TIMEOUT: Duration = Duration::from_secs(60);
const NATIVE_ANVIL_PARENT_CHECK_BUDGET: Duration = Duration::from_secs(60);
const NATIVE_ANVIL_PARENT_RPC_TIMEOUT: Duration = Duration::from_secs(10);
const NATIVE_ANVIL_WORKER_RPC_TIMEOUT: Duration = Duration::from_secs(180);
const NATIVE_ANVIL_WORKER_BROADCAST_WAIT: Duration = Duration::from_secs(240);
const NATIVE_ANVIL_ACK_GATE_PROBE_DELAY: Duration = Duration::from_secs(9);

#[derive(Clone, Copy)]
struct NativeAnvilCrashTestSetup<'a> {
    rpc: &'a reqwest::Client,
    direct_endpoint: &'a str,
    deployment_wallet: Address,
    token: Address,
    token_decimals: u8,
    allocation: U256,
    reward: U256,
    miner_bytecode: &'a [u8],
}

struct NativeAnvilCrashTestContext<'a> {
    setup: NativeAnvilCrashTestSetup<'a>,
    rpc_boundary: &'a AnvilRpcBoundary,
}

async fn exercise_native_anvil_prepare_and_unacknowledged_sigkill_cases(
    context: NativeAnvilCrashTestContext<'_>,
) {
    let NativeAnvilCrashTestContext {
        setup,
        rpc_boundary,
    } = context;
    let NativeAnvilCrashTestSetup {
        rpc,
        direct_endpoint,
        token,
        ..
    } = setup;
    let raw_sends_before_cases = rpc_boundary.raw_send_count();
    rpc_request_local(
        rpc,
        direct_endpoint,
        "anvil_setAutomine",
        serde_json::json!([true]),
    )
    .await
    .expect("enable automining while creating isolated crash-test contracts");

    let prepared_miner = deploy_native_crash_test_miner(&setup, B256::with_last_byte(0x7b)).await;
    run_native_anvil_sigkill_case(
        direct_endpoint,
        &rpc_boundary.endpoint,
        rpc_boundary,
        prepared_miner,
        token,
        "after-prepare",
    )
    .await;

    let unacknowledged_miner =
        deploy_native_crash_test_miner(&setup, B256::with_last_byte(0x7c)).await;
    rpc_request_local(
        rpc,
        direct_endpoint,
        "anvil_setAutomine",
        serde_json::json!([false]),
    )
    .await
    .expect("disable automining before the unacknowledged-broadcast crash boundary");
    run_native_anvil_sigkill_case(
        direct_endpoint,
        &rpc_boundary.endpoint,
        rpc_boundary,
        unacknowledged_miner,
        token,
        "await-broadcast-ack",
    )
    .await;

    rpc_boundary.assert_healthy();
    assert_eq!(
        rpc_boundary.raw_send_count(),
        raw_sends_before_cases + 1,
        "prepare-only recovery sends nothing and the gated broadcast crosses the local boundary once"
    );
}

async fn deploy_native_crash_test_miner(
    setup: &NativeAnvilCrashTestSetup<'_>,
    genesis_seed: B256,
) -> Address {
    let NativeAnvilCrashTestSetup {
        rpc,
        direct_endpoint: endpoint,
        deployment_wallet,
        token,
        token_decimals,
        allocation,
        reward,
        miner_bytecode,
    } = *setup;
    send_unlocked(
        rpc,
        endpoint,
        deployment_wallet,
        Some(token),
        &LocalMockAST::mintCall {
            account: deployment_wallet,
            amount: allocation,
        }
        .abi_encode(),
        U256::ZERO,
    )
    .await;
    let miner = deploy_local_miner(LocalMinerDeployment {
        client: rpc,
        endpoint,
        deployment_wallet,
        token,
        token_decimals,
        allocation,
        reward,
        miner_bytecode,
        initial_target: U256::MAX,
        retarget_interval: 3,
        window_secs: 3_600,
    })
    .await;
    send_unlocked(
        rpc,
        endpoint,
        deployment_wallet,
        Some(token),
        &LocalMockAST::approveCall {
            spender: miner,
            amount: allocation,
        }
        .abi_encode(),
        U256::ZERO,
    )
    .await;
    send_unlocked(
        rpc,
        endpoint,
        deployment_wallet,
        Some(miner),
        &LocalAstatineMiner::fundASTCall { amount: allocation }.abi_encode(),
        U256::ZERO,
    )
    .await;
    send_unlocked(
        rpc,
        endpoint,
        deployment_wallet,
        Some(miner),
        &LocalAstatineMiner::activateGenesisCall {
            initialSeed: genesis_seed,
        }
        .abi_encode(),
        U256::ZERO,
    )
    .await;
    miner
}

async fn run_native_anvil_sigkill_case(
    direct_endpoint: &str,
    worker_endpoint: &str,
    rpc_boundary: &AnvilRpcBoundary,
    miner: Address,
    token: Address,
    stage: &str,
) {
    use std::os::unix::process::ExitStatusExt;

    assert!(matches!(stage, "after-prepare" | "await-broadcast-ack"));
    assert!(
        NATIVE_ANVIL_WORKER_RPC_TIMEOUT
            > NATIVE_ANVIL_PARENT_READY_TIMEOUT + NATIVE_ANVIL_PARENT_CHECK_BUDGET,
        "worker HTTP timeout must exceed the complete bounded parent ready/check/kill interval"
    );
    assert!(
        NATIVE_ANVIL_WORKER_BROADCAST_WAIT > NATIVE_ANVIL_WORKER_RPC_TIMEOUT,
        "the worker's transaction-level wait must not expire before its HTTP request timeout"
    );
    let root = tempdir().expect("create a private native-checkpoint crash-test root");
    let store = ConfigStore::at_root_with_native_journal_anchor_for_test(root.path().to_path_buf())
        .expect("open the isolated native checkpoint for the crash-test stage");
    let _anchor_cleanup = NativeJournalAnchorCleanup(store.clone());
    let parent_rpc = local_rpc_client_with_timeout(NATIVE_ANVIL_PARENT_RPC_TIMEOUT);
    let signer = recovery_signer();
    let wallet = signer_address(&signer);
    let config = AppConfig {
        wallet_address: Some(format!("{wallet:#x}")),
        per_session_spending_limit_inj: "1".to_owned(),
        transaction_confirmations: 1,
        ..AppConfig::default()
    };
    store
        .save(&config)
        .expect("save the synthetic local test configuration");
    drop(
        TransactionJournal::open(&store, &config, wallet)
            .expect("create the authenticated native-checkpoint test journal"),
    );
    assert!(
        store
            .read_journal_anchor()
            .expect("read the native checkpoint directly")
            .is_some(),
        "the process scenario must use the actual isolated Secret Service checkpoint"
    );

    let nonce_before = local_pending_nonce(&parent_rpc, direct_endpoint, wallet).await;
    let raw_sends_before = rpc_boundary.raw_send_count();
    if stage == "await-broadcast-ack" {
        rpc_boundary.hold_next_raw_send_acknowledgement();
    }
    let ready = root.path().join(format!("native-anvil-{stage}.ready"));
    let parent_crash_started_at = Instant::now();
    let mut worker =
        spawn_native_anvil_worker(root.path(), worker_endpoint, miner, token, &ready, stage);

    let ready_deadline = parent_crash_started_at + NATIVE_ANVIL_PARENT_READY_TIMEOUT;
    loop {
        let reached = if stage == "after-prepare" {
            ready.exists()
        } else {
            rpc_boundary.raw_send_acknowledgement_is_held()
        };
        if reached {
            break;
        }
        if let Some(status) = worker.0.try_wait().expect("inspect worker process state") {
            let output = worker
                .wait_with_output()
                .expect("collect early worker process output");
            panic!(
                "native Anvil worker exited before {stage} ({status}): stdout={:?} stderr={:?}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if Instant::now() >= ready_deadline {
            let _ = worker.0.kill();
            let output = worker
                .wait_with_output()
                .expect("collect timed-out worker process output");
            panic!(
                "native Anvil worker did not reach {stage}: stdout={:?} stderr={:?}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let post_signal_deadline = Instant::now() + NATIVE_ANVIL_PARENT_CHECK_BUDGET;
    let parent_crash_deadline = parent_crash_started_at
        + NATIVE_ANVIL_PARENT_READY_TIMEOUT
        + NATIVE_ANVIL_PARENT_CHECK_BUDGET;
    assert!(
        worker
            .0
            .try_wait()
            .expect("check worker before SIGKILL")
            .is_none(),
        "the native transaction worker must still be alive at the selected crash point"
    );

    let journal_before_kill = store
        .read_transaction_journal()
        .expect("read the durable prepared journal")
        .expect("prepared transaction journal exists");
    let state_before_kill: super::JournalState =
        serde_json::from_slice(&journal_before_kill).expect("decode durable journal state");
    assert_eq!(state_before_kill.entries.len(), 1);
    let prepared = &state_before_kill.entries[0];
    assert_eq!(prepared.action, TransactionAction::SubmitProof);
    assert_eq!(prepared.status, TransactionStatus::Prepared);
    assert_eq!(prepared.nonce, nonce_before);
    let transaction_hash = entry_hash(prepared).expect("prepared entry has a transaction hash");
    let maximum_exposure = parse_decimal_wei(&prepared.maximum_exposure_wei)
        .expect("prepared transaction has a valid maximum exposure");
    assert!(maximum_exposure > U256::ZERO);
    let active_session = state_before_kill
        .active_session
        .as_ref()
        .expect("prepared transaction retains its authorized session");
    assert_eq!(
        parse_decimal_wei(&active_session.limit_wei).unwrap(),
        parse_inj_wei("1").unwrap(),
        "the transaction retains the original one-INJ consent limit"
    );
    assert!(!active_session.closed);
    let authorized_before_kill = parse_decimal_wei(
        active_session
            .authorized_exposure_wei
            .as_deref()
            .expect("active session records cumulative authorization"),
    )
    .expect("cumulative authorization is a valid wei amount");
    assert_eq!(authorized_before_kill, maximum_exposure);
    assert!(
        authorized_before_kill <= parse_inj_wei(&config.per_session_spending_limit_inj).unwrap(),
        "durable authorization remains within the original one-INJ consent cap"
    );
    let checkpoint_before_kill = store
        .read_journal_anchor()
        .expect("read the native checkpoint before process termination")
        .expect("the process-kill case has an OS credential-store checkpoint");
    let checkpoint_revision = u64::from_be_bytes(
        checkpoint_before_kill[4..12]
            .try_into()
            .expect("native checkpoint revision has its encoded width"),
    );
    assert_eq!(
        state_before_kill.integrity.as_ref().unwrap().revision,
        checkpoint_revision,
        "the journal and native checkpoint must authenticate the same durable revision"
    );

    if stage == "after-prepare" {
        assert_eq!(rpc_boundary.raw_send_count(), raw_sends_before);
        assert_eq!(
            local_pending_nonce(&parent_rpc, direct_endpoint, wallet).await,
            nonce_before,
            "the prepared-only crash point must precede any Anvil transaction submission"
        );
        let unknown = rpc_request_local(
            &parent_rpc,
            direct_endpoint,
            "eth_getTransactionByHash",
            serde_json::json!([format!("{transaction_hash:#x}")]),
        )
        .await
        .expect("query the local Anvil for a never-broadcast prepared transaction");
        assert!(
            unknown.is_null(),
            "prepared-only transaction must not be on Anvil"
        );
    } else {
        assert!(rpc_boundary.raw_send_acknowledgement_is_held());
        assert_eq!(
            rpc_boundary.raw_send_count(),
            raw_sends_before + 1,
            "the initial raw transaction must reach Anvil exactly once before acknowledgement"
        );
        // The proxy sets this gate only after Anvil returned the raw-send
        // response, while withholding that response from the worker. The fresh
        // recovery child verifies transaction visibility, receipt absence, and
        // pending nonce after SIGKILL.

        // Deliberately keep the acknowledgement withheld longer than the
        // default 8-second RPC timeout. The test-specific worker client must
        // remain pending until the parent completes its bounded checks.
        let probe_deadline = Instant::now() + NATIVE_ANVIL_ACK_GATE_PROBE_DELAY;
        while Instant::now() < probe_deadline {
            assert!(
                rpc_boundary.raw_send_acknowledgement_is_held(),
                "the proxy must continue withholding the initial broadcast acknowledgement"
            );
            assert!(
                worker
                    .0
                    .try_wait()
                    .expect("check worker during the extended acknowledgement hold")
                    .is_none(),
                "worker must remain alive beyond the default RPC timeout while its acknowledgement is held"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    assert!(
        Instant::now() < post_signal_deadline && Instant::now() < parent_crash_deadline,
        "parent ready/check/kill work must stay within its explicit bounded interval"
    );
    if stage == "await-broadcast-ack" {
        assert!(
            rpc_boundary.raw_send_acknowledgement_is_held(),
            "the raw-send acknowledgement must still be gated immediately before SIGKILL"
        );
    }
    assert!(
        worker
            .0
            .try_wait()
            .expect("recheck worker liveness immediately before SIGKILL")
            .is_none(),
        "worker must still be alive immediately before SIGKILL"
    );
    assert_eq!(
        unsafe { libc::kill(worker.0.id() as libc::pid_t, libc::SIGKILL) },
        0,
        "SIGKILL the native Anvil transaction worker: {}",
        std::io::Error::last_os_error()
    );
    let worker_output = worker
        .wait_with_output()
        .expect("collect SIGKILLed native transaction worker output");
    assert_eq!(
        worker_output.status.signal(),
        Some(libc::SIGKILL),
        "the native transaction worker must be terminated by SIGKILL"
    );
    if stage == "await-broadcast-ack" {
        rpc_boundary.release_raw_send_acknowledgement();
        let release_deadline = Instant::now() + Duration::from_secs(5);
        while rpc_boundary.raw_send_acknowledgement_is_held() && Instant::now() < release_deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            !rpc_boundary.raw_send_acknowledgement_is_held(),
            "the proxy must release its gated response after worker death"
        );
    }
    assert_eq!(
        store.read_transaction_journal().unwrap().unwrap(),
        journal_before_kill,
        "SIGKILL must leave the exact authenticated Prepared journal bytes intact"
    );
    let checkpoint_after_kill = store.read_journal_anchor().unwrap().unwrap();
    assert!(
        bool::from(
            checkpoint_after_kill
                .as_slice()
                .ct_eq(checkpoint_before_kill.as_slice())
        ),
        "SIGKILL must leave the native Secret Service checkpoint intact"
    );

    // A zero cap is persisted as ordinary test configuration after the crash;
    // it cannot erase the existing journal authorization or liability.
    let zero_cap_config = AppConfig {
        per_session_spending_limit_inj: "0".to_owned(),
        ..config.clone()
    };
    store
        .save(&zero_cap_config)
        .expect("set the synthetic recovery configuration to a zero spending cap");
    let recovery =
        spawn_native_anvil_recovery_probe(root.path(), worker_endpoint, miner, token, stage);
    let recovery_output = wait_bounded_test_child(recovery, Duration::from_secs(60));
    let stdout = String::from_utf8_lossy(&recovery_output.stdout);
    let stderr = String::from_utf8_lossy(&recovery_output.stderr);
    assert!(
        recovery_output.status.success(),
        "fresh-process native recovery failed: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed")
            || stderr.contains("test result: ok. 1 passed"),
        "recovery child did not report exactly one passing test: stdout={stdout:?} stderr={stderr:?}"
    );

    let recovered_bytes = store
        .read_transaction_journal()
        .expect("read journal after fresh-process recovery")
        .expect("journal remains present after recovery");
    assert_eq!(
        recovered_bytes, journal_before_kill,
        "read-only recovery and zero-cap refusal must not rewrite the Prepared liability"
    );
    let recovered_state: super::JournalState =
        serde_json::from_slice(&recovered_bytes).expect("decode recovered journal");
    assert_eq!(recovered_state.entries.len(), 1);
    let recovered = &recovered_state.entries[0];
    assert_eq!(recovered.transaction_hash, format!("{transaction_hash:#x}"));
    assert_eq!(recovered.status, TransactionStatus::Prepared);
    assert_eq!(recovered.nonce, nonce_before);
    assert_eq!(
        parse_decimal_wei(&recovered.maximum_exposure_wei).unwrap(),
        maximum_exposure
    );
    assert_eq!(
        parse_decimal_wei(
            recovered_state
                .active_session
                .as_ref()
                .unwrap()
                .authorized_exposure_wei
                .as_deref()
                .unwrap()
        )
        .unwrap(),
        authorized_before_kill,
        "fresh-process recovery must not refund or reuse the authorization"
    );
    assert_eq!(
        rpc_boundary.raw_send_count(),
        raw_sends_before + if stage == "await-broadcast-ack" { 1 } else { 0 },
        "fresh recovery and zero-cap refusal must issue no raw transaction send"
    );
    assert_eq!(
        local_pending_nonce(&parent_rpc, direct_endpoint, wallet).await,
        nonce_before + if stage == "await-broadcast-ack" { 1 } else { 0 },
        "recovery must not consume an additional Anvil nonce"
    );
}

fn spawn_native_anvil_worker(
    root: &std::path::Path,
    endpoint: &str,
    miner: Address,
    token: Address,
    ready: &std::path::Path,
    stage: &str,
) -> JournalSigkillChild {
    JournalSigkillChild(
        Command::new(std::env::current_exe().expect("resolve native Anvil test executable"))
            .args([
                "--ignored",
                "--exact",
                NATIVE_ANVIL_CHILD_TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(NATIVE_ANVIL_ROOT_ENV, root)
            .env(NATIVE_ANVIL_RPC_ENV, endpoint)
            .env(NATIVE_ANVIL_MINER_ENV, format!("{miner:#x}"))
            .env(NATIVE_ANVIL_TOKEN_ENV, format!("{token:#x}"))
            .env(NATIVE_ANVIL_READY_ENV, ready)
            .env(NATIVE_ANVIL_STAGE_ENV, stage)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn native Anvil transaction worker"),
    )
}

fn spawn_native_anvil_recovery_probe(
    root: &std::path::Path,
    endpoint: &str,
    miner: Address,
    token: Address,
    stage: &str,
) -> JournalSigkillChild {
    JournalSigkillChild(
        Command::new(std::env::current_exe().expect("resolve native Anvil test executable"))
            .args([
                "--ignored",
                "--exact",
                NATIVE_ANVIL_RECOVERY_CHILD_TEST,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(NATIVE_ANVIL_ROOT_ENV, root)
            .env(NATIVE_ANVIL_RPC_ENV, endpoint)
            .env(NATIVE_ANVIL_MINER_ENV, format!("{miner:#x}"))
            .env(NATIVE_ANVIL_TOKEN_ENV, format!("{token:#x}"))
            .env(NATIVE_ANVIL_STAGE_ENV, stage)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn fresh native Anvil recovery process"),
    )
}

fn wait_bounded_test_child(
    mut child: JournalSigkillChild,
    timeout_after: Duration,
) -> std::process::Output {
    let deadline = Instant::now() + timeout_after;
    loop {
        if child
            .0
            .try_wait()
            .expect("inspect bounded fresh-process recovery child")
            .is_some()
        {
            return child
                .wait_with_output()
                .expect("collect bounded recovery child output");
        }
        if Instant::now() >= deadline {
            let _ = child.0.kill();
            let output = child
                .wait_with_output()
                .expect("collect timed-out recovery child output");
            panic!(
                "fresh-process recovery exceeded its {timeout_after:?} bound: stdout={:?} stderr={:?}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn local_native_anvil_proof_submission(
    rpc: &reqwest::Client,
    endpoint: &str,
    miner: Address,
    wallet: Address,
) -> ProofSubmission {
    let work_bytes = local_call(
        rpc,
        endpoint,
        miner,
        &AstatineMinerRead::workCall {}.abi_encode(),
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
    let work = <WorkReturn as SolValue>::abi_decode_validate(&work_bytes)
        .expect("decode the local synthetic miner work snapshot");
    let header = b"native-provider-fresh-process-crash";
    let context = WorkContext {
        chain_id: 1439,
        contract: miner,
        window_id: work.2,
        seed: work.5,
        miner: wallet,
        header: header.to_vec(),
    };
    let hasher = WorkHasher::new(&context).expect("build the synthetic local proof hasher");
    let (nonce, work_hash) = (0..10_000_u128)
        .find_map(|nonce| {
            let hash = hasher.hash(nonce);
            meets_target(hash, work.7).then_some((nonce, hash))
        })
        .expect("the local Anvil work target must have a valid synthetic proof");
    ProofSubmission {
        contract: miner,
        node_id: 1,
        window_id: work.2,
        nonce,
        header: header.to_vec(),
        work_hash,
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "child probe; invoked by the native Anvil SIGKILL recovery harness"]
async fn linux_native_provider_anvil_recovery_probe() {
    let root = PathBuf::from(
        std::env::var_os(NATIVE_ANVIL_ROOT_ENV)
            .expect("native recovery probe requires its parent-provided root"),
    );
    let endpoint = std::env::var(NATIVE_ANVIL_RPC_ENV)
        .expect("native recovery probe requires its parent-provided local RPC");
    let parsed = reqwest::Url::parse(&endpoint).expect("recovery RPC URL must parse");
    assert!(
        parsed.scheme() == "http"
            && parsed.host_str().is_some_and(|host| {
                host == "127.0.0.1" || host == "::1" || host == "localhost"
            })
            && parsed.username().is_empty()
            && parsed.password().is_none(),
        "recovery RPC must be an unauthenticated local-loopback URL"
    );
    let miner = Address::from_str(
        &std::env::var(NATIVE_ANVIL_MINER_ENV)
            .expect("native recovery probe requires its parent-provided miner"),
    )
    .expect("synthetic miner address must parse");
    let token = Address::from_str(
        &std::env::var(NATIVE_ANVIL_TOKEN_ENV)
            .expect("native recovery probe requires its parent-provided token"),
    )
    .expect("synthetic token address must parse");
    let stage = std::env::var(NATIVE_ANVIL_STAGE_ENV)
        .expect("native recovery probe requires its parent-provided crash stage");
    assert!(matches!(
        stage.as_str(),
        "after-prepare" | "await-broadcast-ack"
    ));

    // The fresh process authenticates directly against the isolated native
    // Secret Service. It does not bridge or copy checkpoint bytes through the
    // process-local cfg(test) backend.
    let store = ConfigStore::at_root_with_native_journal_anchor_for_test(root)
        .expect("fresh recovery process must verify the private unlocked provider");
    let config = store
        .load()
        .expect("load the zero-cap recovery configuration saved after SIGKILL");
    assert_eq!(config.per_session_spending_limit_inj, "0");
    let signer = recovery_signer();
    let wallet = signer_address(&signer);
    let expected_wallet = format!("{wallet:#x}");
    assert_eq!(
        config.wallet_address.as_deref(),
        Some(expected_wallet.as_str())
    );
    let rpc = local_rpc_client();
    let network = NetworkClient::local_test_client(
        &endpoint,
        miner,
        local_code_hash(&rpc, &endpoint, miner).await,
        token,
        local_code_hash(&rpc, &endpoint, token).await,
        9,
    )
    .expect("construct read-only local Anvil recovery client");

    let mut recovery = TransactionManager::open_for_read_only_recovery(
        &store,
        &config,
        wallet,
        token,
        Arc::new(HistoryTelemetry::default()),
    )
    .expect("fresh process must authenticate the existing native-backed journal");
    let before = recovery.journal.state.clone();
    assert_eq!(before.entries.len(), 1);
    let active_session = before
        .active_session
        .as_ref()
        .expect("recovered journal retains its original authorized session");
    assert_eq!(
        parse_decimal_wei(&active_session.limit_wei).unwrap(),
        parse_inj_wei("1").unwrap(),
        "zero recovery cap must not rewrite the session's original consent ceiling"
    );
    assert!(!active_session.closed);
    let prepared = before.entries[0].clone();
    assert_eq!(prepared.status, TransactionStatus::Prepared);
    let hash = entry_hash(&prepared).expect("recovered Prepared entry has a transaction hash");
    let authorized_before = recovery.journal.session_authorized_total().unwrap();
    let exposure_before = recovery.journal.pending_exposure().unwrap();
    assert!(exposure_before > U256::ZERO);
    assert_eq!(
        exposure_before,
        parse_decimal_wei(&prepared.maximum_exposure_wei).unwrap()
    );
    assert_eq!(authorized_before, exposure_before);
    assert!(authorized_before <= parse_inj_wei("1").unwrap());

    let known = network
        .transaction_known(hash)
        .await
        .expect("query local Anvil transaction visibility after process restart");
    assert_eq!(
        known,
        stage == "await-broadcast-ack",
        "the pre-ack stage must be visible at Anvil; the after-prepare stage must not"
    );
    assert!(
        network
            .transaction_receipt(hash)
            .await
            .expect("query the synthetic local transaction receipt")
            .is_none(),
        "automine is disabled and neither crash case may have a receipt"
    );
    assert_eq!(
        network.pending_nonce(wallet).await.unwrap(),
        prepared.nonce + if known { 1 } else { 0 },
        "fresh recovery observes the existing nonce state and never consumes another nonce"
    );
    recovery
        .reconcile(&network)
        .await
        .expect("read-only recovery must observe without rebroadcasting");
    assert_eq!(
        recovery.journal.entry(hash).unwrap().status,
        TransactionStatus::Prepared,
        "neither missing nor unacknowledged RPC evidence promotes Prepared to Broadcast"
    );
    assert_eq!(
        recovery.journal.pending_exposure().unwrap(),
        exposure_before
    );
    assert_eq!(
        recovery.journal.session_authorized_total().unwrap(),
        authorized_before
    );
    drop(recovery);

    let journal_after_recovery = store.read_transaction_journal().unwrap().unwrap();
    let checkpoint_after_recovery = store.read_journal_anchor().unwrap().unwrap();
    let mut zero_cap_manager = TransactionManager::open(&store, &config, wallet, token)
        .expect("zero-cap normal manager may observe but cannot create new liability");
    assert_eq!(zero_cap_manager.budget_remaining().unwrap(), U256::ZERO);
    let submission = local_native_anvil_proof_submission(&rpc, &endpoint, miner, wallet).await;
    let refusal = zero_cap_manager
        .submit_proof(&network, &signer, submission)
        .await
        .expect_err("zero-cap recovery must refuse a new signature before authorization");
    assert_eq!(
        transaction_policy_refusal(&refusal),
        Some(TransactionPolicyRefusalKind::SigningDisabled),
        "the explicit zero-cap policy, not a stale-session or RPC failure, must refuse signing"
    );
    assert_eq!(zero_cap_manager.journal.state.entries.len(), 1);
    assert_eq!(
        zero_cap_manager.journal.entry(hash).unwrap().status,
        TransactionStatus::Prepared
    );
    assert_eq!(
        zero_cap_manager.journal.pending_exposure().unwrap(),
        exposure_before
    );
    assert_eq!(
        zero_cap_manager.journal.session_authorized_total().unwrap(),
        authorized_before,
        "zero-cap refusal must not reuse or increase the durable authorization"
    );
    drop(zero_cap_manager);
    assert_eq!(
        store.read_transaction_journal().unwrap().unwrap(),
        journal_after_recovery,
        "a zero-cap refused attempt must not rewrite authenticated journal state"
    );
    let checkpoint_after_zero_cap = store.read_journal_anchor().unwrap().unwrap();
    assert!(
        bool::from(
            checkpoint_after_zero_cap
                .as_slice()
                .ct_eq(checkpoint_after_recovery.as_slice())
        ),
        "a zero-cap refused attempt must not advance the native checkpoint"
    );
}
