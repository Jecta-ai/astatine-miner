use crate::{
    cli::{Command, InitArgs, Network, WalletCommand},
    config::{AppConfig, ConfigStore, parse_inj_wei},
    deployment::{DeploymentManifest, parse_address},
    mining,
    rpc::{NetworkClient, NodeView},
    transaction::{
        PerRunPolicyApproval, SessionJournalSnapshot, TransactionJournal, TransactionManager,
    },
    wallet,
};
use alloy_primitives::{Address, U256};
use anyhow::{Context, Result, bail};
use std::{
    io::{self, IsTerminal, Write},
    num::NonZeroUsize,
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

pub async fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Init(args) => run_init(args).await,
        Command::Mine(args) => run_mine(args).await,
        Command::Recover => run_recover().await,
        Command::Wallet(WalletCommand::Create) => {
            let store = ConfigStore::system_default()?;
            let mut config = store.load()?;
            let _wallet_change_guard = ensure_standalone_wallet_change_allowed(&store, &config)?;
            wallet::create_interactive(&store, &mut config)?;
            Ok(())
        }
        Command::Wallet(WalletCommand::Import(args)) => {
            let store = ConfigStore::system_default()?;
            let mut config = store.load()?;
            let _wallet_change_guard = ensure_standalone_wallet_change_allowed(&store, &config)?;
            wallet::import_interactive(&store, &mut config, args)?;
            Ok(())
        }
        Command::Wallet(WalletCommand::Address) => {
            let store = ConfigStore::system_default()?;
            let config = store.load()?;
            wallet::print_address(&store, &config)
        }
        Command::NetworkUse(network) => {
            let store = ConfigStore::system_default()?;
            let mut config = store.load()?;
            let approval_revoked = config.network != network && config.per_run_sessions_enabled();
            if approval_revoked {
                let session = TransactionJournal::inspect_session(&store, &config)?;
                if !session.unresolved.is_empty() {
                    bail!(
                        "network changes are blocked while transactions are unresolved; recover them on their original network first"
                    );
                }
                if !prompt_yes_no(
                    "Changing networks revokes the saved per-run spending approval. Continue?",
                    false,
                )? {
                    println!("Network unchanged; the per-run policy approval remains active.");
                    return Ok(());
                }
                TransactionJournal::set_per_run_policy_approval(&store, &config, None)?;
            }
            config.network = network;
            store.save(&config)?;
            println!(
                "Selected {} (chain ID {}). Wallet selection was preserved.",
                network_label(network),
                chain_id(network)
            );
            if approval_revoked {
                println!(
                    "Per-run spending approval was revoked; run `astatine init` to explicitly approve a policy for the selected network."
                );
            }
            if network == Network::Mainnet {
                println!(
                    "Mainnet has no configured Astatine mining deployment; transaction signing is unavailable."
                );
            }
            Ok(())
        }
        Command::GetRpc { network } => run_get_rpc(network),
        Command::SetRpc { network, endpoint } => run_set_rpc(network, endpoint).await,
        Command::Nodes => {
            let store = ConfigStore::system_default()?;
            let config = store.load()?;
            let client = NetworkClient::connect_with_rpc(
                config.network,
                config.rpc_override(config.network),
            )
            .await?;
            if !client.has_mining_deployment() {
                println!(
                    "{} has no verified Astatine mining deployment.",
                    network_label(config.network)
                );
                return Ok(());
            }
            let snapshot = client.snapshot(None).await?;
            print_nodes(&snapshot.nodes);
            Ok(())
        }
        Command::Status => run_status().await,
        Command::Rewards => run_rewards().await,
        Command::Devices => crate::gpu::print_devices(),
        Command::Benchmark(args) => crate::gpu::run_benchmark(args),
    }
}

async fn run_init(args: InitArgs) -> Result<()> {
    let store = ConfigStore::system_default()?;
    run_init_with_store(&store, args).await
}

async fn run_init_with_store(store: &ConfigStore, args: InitArgs) -> Result<()> {
    let mut config = store.load()?;
    let initial_snapshot = TransactionJournal::inspect_session(store, &config)?;
    if let Some(pending) = initial_snapshot.pending_transition.as_ref() {
        println!(
            "An earlier init spending-session change was interrupted. Previous limit: {} INJ; proposed limit: {} INJ.",
            pending.previous_config_limit_inj, pending.proposed_config_limit_inj
        );
        if prompt_paid_consent("Complete that approved change now?", false)? {
            TransactionJournal::resolve_pending_session_transition(store, &mut config, true)?;
            println!("Completed the interrupted spending-session transition.");
        } else {
            TransactionJournal::resolve_pending_session_transition(store, &mut config, false)?;
            println!("Restored the previous spending session and limit.");
        }
        config = store.load()?;
    }
    let persisted_config = config.clone();
    if initial_snapshot.per_run_policy_approval.is_some() && !config.per_run_sessions_enabled() {
        config.schema_version = 2;
        println!(
            "Restored the authenticated per-run policy mode recorded in the transaction journal; paid mining cannot silently downgrade its authorization policy."
        );
    }
    if args.per_run_sessions {
        config.schema_version = 2;
    } else if !config.per_run_sessions_enabled() {
        println!(
            "This existing schema-v1 account keeps its legacy spending-session policy unless you explicitly migrate. Per-run mode starts a fresh allowance for each paid `astatine mine` invocation; the effective cap is reduced by confirmed balance, the reserve, and unresolved maximum exposure."
        );
        if prompt_paid_consent("Migrate this account to per-run spending sessions?", false)? {
            config.schema_version = 2;
        }
    }
    let per_run_sessions = config.per_run_sessions_enabled();
    let mut session_snapshot = TransactionJournal::inspect_session(store, &config)?;
    let effective_limit = session_effective_limit(&session_snapshot, &config)?;
    let stored_limit_wei = parse_inj_wei(&config.per_session_spending_limit_inj)?;
    let journal_limit_wei = session_snapshot
        .limit_wei
        .as_deref()
        .map(|value| U256::from_str_radix(value, 10).context("journal session limit is invalid"))
        .transpose()?;
    let safe_config_limit = if per_run_sessions {
        config.per_session_spending_limit_inj.clone()
    } else {
        journal_limit_wei
            .map(|limit| format_token_units(stored_limit_wei.min(limit), 18))
            .unwrap_or_else(|| config.per_session_spending_limit_inj.clone())
    };
    if safe_config_limit != config.per_session_spending_limit_inj {
        println!(
            "Saved cap {} INJ is above the active journal session limit {} INJ. The old session remains the effective authorization until a new session is explicitly approved.",
            config.per_session_spending_limit_inj, effective_limit
        );
    }
    config.per_session_spending_limit_inj = safe_config_limit.clone();
    if !session_snapshot.unresolved.is_empty() {
        let mut repaired = config.clone();
        if repaired.wallet_address.as_deref() != session_snapshot.wallet.as_deref()
            && session_snapshot.wallet.is_some()
        {
            repaired.wallet_address = session_snapshot.wallet.clone();
        }
        if repaired != persisted_config {
            store.save(&repaired)?;
            config = repaired;
            session_snapshot = TransactionJournal::inspect_session(store, &config)?;
            println!(
                "Restored the original session wallet for read-only recovery at {} INJ.",
                session_effective_limit(&session_snapshot, &config)?
            );
        }
    }
    let previous_config = config.clone();
    println!("ASTATINE · INITIAL SETUP");
    if per_run_sessions {
        println!(
            "Approve one per-run spending policy here. Every later paid mine invocation starts one fresh session under that persisted policy without a full-cap prompt. A reduced balance-derived cap requires separate approval for that invocation."
        );
    } else {
        println!(
            "Every signed transaction permanently consumes its maximum possible INJ authorization for this session; RPC receipts do not refund it. Finalization can spend gas on empty windows or windows won by another miner. The default cap of zero authorizes no transaction spending."
        );
    }

    config.network = match args.network {
        Some(network) => network,
        None => prompt_network(config.network)?,
    };
    if !session_snapshot.unresolved.is_empty() && config.network != previous_config.network {
        bail!(
            "network changes are blocked while transactions are unresolved; recover them on their original network first"
        );
    }
    configure_init_rpc(&mut config, args.rpc.as_deref()).await?;
    config.cpu_threads = match args.threads {
        Some(threads) => threads.get(),
        None => prompt_threads(config.cpu_threads)?,
    };
    config.minimum_reserve_inj = match args.minimum_reserve_inj {
        Some(amount) => amount,
        None => prompt_value("Minimum INJ reserve", &config.minimum_reserve_inj)?,
    };
    let proposed_limit = match args.spending_limit_inj {
        Some(amount) => amount,
        None => prompt_spending_limit(&config.per_session_spending_limit_inj, per_run_sessions)?,
    };
    parse_inj_wei(&proposed_limit)
        .context("spending limit must be a decimal INJ amount with at most 18 decimals")?;
    // Wallet creation/import during setup must never commit the proposed ceiling
    // before the final config save below.
    config.per_session_spending_limit_inj = safe_config_limit.clone();
    config.transaction_confirmations = match args.transaction_confirmations {
        Some(confirmations) => confirmations,
        None => prompt_value(
            "Transaction confirmation blocks (1-12)",
            &config.transaction_confirmations.to_string(),
        )?
        .parse()
        .context("transaction confirmation blocks must be a number from 1 to 12")?,
    };
    config.validate()?;

    if !per_run_sessions
        && !session_snapshot.unresolved.is_empty()
        && parse_inj_wei(&proposed_limit)? != parse_inj_wei(&effective_limit)?
    {
        print_unresolved_session_blocker(&session_snapshot, &effective_limit, &proposed_limit);
        bail!(
            "spending-limit change was not applied; recover the old transaction session and rerun `astatine init`"
        );
    }

    let selected = config
        .wallet_address
        .as_deref()
        .and_then(|address| Address::from_str(address).ok());
    let selected_is_usable = if let Some(address) = selected {
        store
            .read_keystore(address)
            .ok()
            .and_then(|bytes| wallet::validate_v3_keystore(&bytes).ok())
            == Some(address)
    } else {
        false
    };

    if !session_snapshot.unresolved.is_empty()
        && (!selected_is_usable
            || session_snapshot
                .wallet
                .as_deref()
                .is_some_and(|wallet| Some(wallet) != config.wallet_address.as_deref()))
    {
        print_unresolved_session_blocker(&session_snapshot, &effective_limit, &proposed_limit);
        bail!(
            "wallet selection cannot change during unresolved transaction recovery; use `astatine recover` first"
        );
    }

    if selected_is_usable && prompt_yes_no("Keep the selected wallet?", true)? {
        // Keep the currently selected wallet; persistence is deferred until
        // the spending-session transition has been authorized and committed.
    } else {
        if !session_snapshot.unresolved.is_empty() {
            print_unresolved_session_blocker(&session_snapshot, &effective_limit, &proposed_limit);
            bail!("wallet changes are blocked until transaction recovery completes");
        }
        println!(
            "Wallet setup: 1) create a new wallet  2) import a mnemonic  3) import an Ethereum V3 keyfile"
        );
        match prompt_choice("Choose 1, 2, or 3", &["1", "2", "3"])? {
            "1" => {
                wallet::create_interactive_staged(store, &mut config)?;
            }
            "2" => {
                wallet::import_interactive_staged(
                    store,
                    &mut config,
                    crate::cli::ImportArgs {
                        keystore: None,
                        derivation_path: "m/44'/60'/0'/0/0".to_owned(),
                    },
                )?;
            }
            "3" => {
                let path = prompt_value("Path to encrypted V3 keyfile", "")?;
                wallet::import_interactive_staged(
                    store,
                    &mut config,
                    crate::cli::ImportArgs {
                        keystore: Some(PathBuf::from(path)),
                        derivation_path: "m/44'/60'/0'/0/0".to_owned(),
                    },
                )?;
            }
            _ => unreachable!("choice parser restricts valid choices"),
        }
    }

    config.validate()?;
    if per_run_sessions {
        if !parse_inj_wei(&proposed_limit)?.is_zero() && config.wallet_address.is_none() {
            bail!("select a wallet before configuring a positive per-run spending ceiling");
        }
        let previous_wallet = session_snapshot
            .wallet
            .as_deref()
            .or(previous_config.wallet_address.as_deref())
            .map(Address::from_str)
            .transpose()
            .context("previous wallet address is invalid")?;
        let selected_wallet = config
            .wallet_address
            .as_deref()
            .map(Address::from_str)
            .transpose()
            .context("selected wallet address is invalid")?;
        if previous_wallet != selected_wallet
            && !prompt_paid_consent(
                "Use the selected wallet for future per-run spending sessions?",
                false,
            )?
        {
            config.wallet_address = previous_wallet.map(|wallet| format!("{wallet:#x}"));
        }
        config.per_session_spending_limit_inj = proposed_limit;
        let approved_wallet = config
            .wallet_address
            .as_deref()
            .map(Address::from_str)
            .transpose()
            .context("selected wallet address is invalid")?;
        let proposed_policy = approved_wallet
            .map(|wallet| PerRunPolicyApproval::for_config(&config, wallet))
            .transpose()?;
        if proposed_policy != session_snapshot.per_run_policy_approval
            && let Some(wallet) = approved_wallet
            && !prompt_per_run_policy_approval(&config, wallet)?
        {
            println!(
                "Per-run policy was not approved. No session or signing authority was created; run `astatine init` again to review and approve the policy."
            );
            return Ok(());
        }
        TransactionJournal::set_per_run_policy_approval(store, &config, approved_wallet)?;
        store.save(&config)?;
        println!(
            "Configured {} | {} CPU worker(s) | reserve {} INJ | per-run authorization ceiling {} INJ | confirmations {} block(s)",
            network_label(config.network),
            config.cpu_threads,
            config.minimum_reserve_inj,
            config.per_session_spending_limit_inj,
            config.transaction_confirmations
        );
        println!(
            "Wallet address: {}",
            config.wallet_address.as_deref().unwrap_or("not selected")
        );
        println!(
            "Each explicit paid `astatine mine` invocation starts one fresh session under the saved approval. No session or transaction is created by `astatine init`."
        );
        return Ok(());
    }

    let new_wallet = config
        .wallet_address
        .as_deref()
        .map(Address::from_str)
        .transpose()
        .context("selected wallet address is invalid")?;
    let previous_wallet = session_snapshot
        .wallet
        .as_deref()
        .or(previous_config.wallet_address.as_deref())
        .map(Address::from_str)
        .transpose()
        .context("previous spending session wallet address is invalid")?;
    let wallet_changed = new_wallet != previous_wallet;
    let wallet_session_change = wallet_changed
        && (session_snapshot.session_id.is_some() || session_snapshot.has_prior_session_history);
    let previous_session_limit = session_snapshot
        .limit_wei
        .as_deref()
        .map(|value| U256::from_str_radix(value, 10).context("journal session limit is invalid"))
        .transpose()?;
    let proposed_limit_wei = parse_inj_wei(&proposed_limit)?;
    let config_limit_changed = proposed_limit_wei != parse_inj_wei(&safe_config_limit)?;
    let new_paid_session = requires_new_paid_session(
        proposed_limit_wei,
        previous_session_limit,
        wallet_changed,
        session_snapshot.closed || session_snapshot.session_id.is_none(),
    );
    let resume_existing_paid_session = !new_paid_session
        && should_confirm_existing_session_resume(
            config_limit_changed,
            proposed_limit_wei,
            session_snapshot.session_id.is_some(),
            session_snapshot.closed,
        );

    if proposed_limit_wei.is_zero() && config_limit_changed {
        let prompt = format!(
            "Disable paid transactions by changing the current {} INJ limit to 0? Existing authorization remains consumed.",
            effective_limit
        );
        if !prompt_yes_no(&prompt, false)? {
            config.per_session_spending_limit_inj = safe_config_limit.clone();
            store.save(&config)?;
            println!(
                "Kept the existing configured limit of {} INJ.",
                safe_config_limit
            );
            return Ok(());
        }
    } else if new_paid_session
        && !prompt_new_session_confirmation(
            &effective_limit,
            &proposed_limit,
            session_snapshot.authorized_exposure_wei.as_deref(),
            session_snapshot.session_id.is_some(),
            wallet_changed,
            session_snapshot
                .wallet
                .as_deref()
                .or(previous_config.wallet_address.as_deref()),
            config.wallet_address.as_deref(),
        )?
    {
        let existing_session_is_resumable =
            session_snapshot.session_id.is_some() && !session_snapshot.closed;
        config.per_session_spending_limit_inj =
            declined_new_session_limit(&safe_config_limit, existing_session_is_resumable);
        if wallet_session_change {
            config.wallet_address = previous_wallet.map(|wallet| format!("{wallet:#x}"));
        }
        store.save(&config)?;
        if existing_session_is_resumable {
            println!(
                "No new spending session was started; the existing session and authorization remain unchanged."
            );
        } else {
            println!(
                "No new spending session was started. Paid transactions remain disabled until you explicitly approve a positive cap."
            );
        }
        return Ok(());
    } else if resume_existing_paid_session
        && !prompt_resume_existing_session_confirmation(
            &effective_limit,
            session_snapshot.authorized_exposure_wei.as_deref(),
        )?
    {
        config.per_session_spending_limit_inj = safe_config_limit.clone();
        store.save(&config)?;
        println!("Kept the existing spending configuration. No new allowance was authorized.");
        return Ok(());
    }

    if new_paid_session {
        let wallet =
            new_wallet.context("select a wallet before starting a paid spending session")?;
        config.per_session_spending_limit_inj = proposed_limit.clone();
        let mut journal =
            match TransactionJournal::open_for_init_session_transition(
                store,
                &config,
                wallet,
                safe_config_limit.clone(),
                previous_config.wallet_address.clone(),
            ) {
                Ok(journal) => journal,
                Err(error) => return Err(error).context(
                    "new spending session was not started; staged wallet selection was not saved",
                ),
            };
        if let Err(save_error) = store.save(&config) {
            let mut rollback_config = config.clone();
            rollback_config.per_session_spending_limit_inj = safe_config_limit.clone();
            if wallet_changed {
                rollback_config.wallet_address =
                    previous_wallet.map(|wallet| format!("{wallet:#x}"));
            }
            return match journal.rollback_init_session_transition(&mut rollback_config) {
                Ok(()) => Err(save_error).context("save new spending-session configuration; the old session was restored"),
                Err(rollback_error) => Err(save_error).context(format!(
                    "save new spending-session configuration failed and rollback remains pending: {rollback_error:#}"
                )),
            };
        }
        journal.finish_init_session_transition(&config)?;
    } else {
        config.per_session_spending_limit_inj = proposed_limit;
        store.save(&config)?;
    }

    println!(
        "Configured {} | {} CPU worker(s) | reserve {} INJ | per-session authorization cap {} INJ | confirmations {} block(s)",
        network_label(config.network),
        config.cpu_threads,
        config.minimum_reserve_inj,
        config.per_session_spending_limit_inj,
        config.transaction_confirmations
    );
    println!(
        "Wallet address: {}",
        config.wallet_address.as_deref().unwrap_or("not selected")
    );
    println!("A zero per-session limit disables transaction signing and spending.");
    Ok(())
}

async fn run_mine(args: crate::cli::MineArgs) -> Result<()> {
    match run_mine_inner(args).await {
        Err(error) if crate::shutdown::is_prompt_shutdown(&error) => {
            println!(
                "Shutdown signal received while waiting for terminal input; no spending session or transaction was created or changed."
            );
            Ok(())
        }
        result => result,
    }
}

async fn run_mine_inner(args: crate::cli::MineArgs) -> Result<()> {
    // Install handlers before configuration, journal inspection, or any
    // interactive session prompt. A signal before this point still retains the
    // OS default disposition; CLI parsing/dispatch precedes this command.
    let mut shutdown = crate::shutdown::ShutdownSignal::new()
        .context("install shutdown signal handlers for mining")?;
    let store = ConfigStore::system_default()?;
    let config = store.load()?;
    let session = if args.compute_only {
        SessionJournalSnapshot::default()
    } else {
        TransactionJournal::inspect_session(&store, &config)?
    };
    if !args.compute_only && session.pending_transition.is_some() {
        bail!(
            "a spending-session change was interrupted; run `astatine init` to resolve it before mining"
        );
    }
    if config.per_run_sessions_enabled() {
        if !args.compute_only {
            let configured_limit = parse_inj_wei(&config.per_session_spending_limit_inj)?;
            if !configured_limit.is_zero() {
                if config.network != Network::Testnet {
                    bail!("autonomous transaction signing is disabled outside Injective Testnet");
                }
                let selected_wallet = config
                    .wallet_address
                    .as_deref()
                    .and_then(|address| Address::from_str(address).ok());
                if selected_wallet.is_none() {
                    bail!("select a wallet with `astatine init` before authorizing paid mining");
                }
                let wallet = selected_wallet.expect("checked above");
                if !per_run_policy_matches(&session, &config, wallet)? {
                    bail!(
                        "per-run spending approval does not match the selected wallet, network, ceiling, or reserve; run `astatine init` to review and explicitly approve the policy"
                    );
                }
                return mining::run_with_session_confirmation(&store, args, true, &mut shutdown)
                    .await;
            }
        }
        return mining::run_with_session_confirmation(&store, args, false, &mut shutdown).await;
    }
    if !args.compute_only
        && !parse_inj_wei(&config.per_session_spending_limit_inj)?.is_zero()
        && session.per_run_policy_approval.is_some()
    {
        bail!(
            "an authenticated per-run policy exists for this wallet; run `astatine init` to explicitly switch authorization policies"
        );
    }
    if args.new_session {
        if args.compute_only || parse_inj_wei(&config.per_session_spending_limit_inj)?.is_zero() {
            bail!(
                "`astatine mine --new-session` requires transaction mode and a positive per-session authorization cap"
            );
        }
        if !session.unresolved.is_empty() {
            print_unresolved_session_blocker(
                &session,
                &session_effective_limit(&session, &config)?,
                &config.per_session_spending_limit_inj,
            );
            bail!(
                "no new spending session was started; run `astatine recover`, then rerun `astatine mine --new-session`"
            );
        }
        let selected_wallet = config
            .wallet_address
            .as_deref()
            .and_then(|address| Address::from_str(address).ok());
        let wallet_changed = mine_session_wallet_changed(&session, selected_wallet);
        let previous_limit = session_effective_limit(&session, &config)?;
        if !prompt_new_session_confirmation(
            &previous_limit,
            &config.per_session_spending_limit_inj,
            session.authorized_exposure_wei.as_deref(),
            session.session_id.is_some(),
            wallet_changed,
            session.wallet.as_deref(),
            config.wallet_address.as_deref(),
        )? {
            println!("Cancelled. No spending session was changed.");
            return Ok(());
        }
        return mining::run_with_session_confirmation(&store, args, true, &mut shutdown).await;
    }
    if mining::unresolved_session_blocks_mining(
        args.compute_only,
        !session.unresolved.is_empty(),
        config.per_run_sessions_enabled(),
    ) {
        println!("RECOVERY REQUIRED • WALLET LOCKED • mining paused");
        print_unresolved_session_blocker(
            &session,
            &session_effective_limit(&session, &config)?,
            &config.per_session_spending_limit_inj,
        );
        bail!(
            "read-only recovery is required; run `astatine recover`, then start a fresh `astatine mine` process to unlock the wallet"
        );
    }
    let configured_limit = parse_inj_wei(&config.per_session_spending_limit_inj)?;
    if !args.compute_only && !configured_limit.is_zero() {
        let selected_wallet = config
            .wallet_address
            .as_deref()
            .and_then(|address| Address::from_str(address).ok());
        let wallet_changed = mine_session_wallet_changed(&session, selected_wallet);
        if let Some(session_limit) = session.limit_wei.as_deref() {
            let session_limit = U256::from_str_radix(session_limit, 10)
                .context("journal session limit is invalid")?;
            if session_limit != configured_limit {
                bail!(
                    "configured cap differs from the existing journaled session; run `astatine init` to explicitly choose and confirm a session limit, or use `astatine mine --new-session`"
                );
            }
        }
        if mine_requires_session_confirmation(&session, configured_limit, selected_wallet) {
            if session.has_prior_session_history {
                bail!(
                    "previous spending-session or transaction authorization history exists; run `astatine mine --new-session` and confirm before starting another allowance"
                );
            }
            let previous_limit = session_effective_limit(&session, &config)?;
            if !prompt_new_session_confirmation(
                &previous_limit,
                &config.per_session_spending_limit_inj,
                session.authorized_exposure_wei.as_deref(),
                session.session_id.is_some(),
                wallet_changed,
                session.wallet.as_deref(),
                config.wallet_address.as_deref(),
            )? {
                println!("Cancelled. No spending session was changed.");
                return Ok(());
            }
            return mining::run_with_session_confirmation(&store, args, true, &mut shutdown).await;
        }
    }
    if requires_open_legacy_session_confirmation(
        args.compute_only,
        config.per_run_sessions_enabled(),
        configured_limit,
        &session,
        args.new_session,
    ) && !prompt_resume_open_legacy_session_confirmation(&session)?
    {
        println!(
            "No session was resumed. Run `astatine init` or `astatine mine --new-session` to explicitly authorize a new spending session."
        );
        return Ok(());
    }
    mining::run_with_session_confirmation(&store, args, false, &mut shutdown).await
}

async fn run_recover() -> Result<()> {
    // Install handlers before configuration, network, or journal access so a
    // shutdown during recovery cannot fall back to the OS default disposition.
    let mut shutdown = crate::shutdown::ShutdownSignal::new()
        .context("install shutdown signal handlers for transaction recovery")?;
    let store = ConfigStore::system_default()?;
    let config = store.load()?;
    if config.network != Network::Testnet {
        bail!("transaction recovery is restricted to Injective Testnet");
    }
    let session = TransactionJournal::inspect_session(&store, &config)?;
    if session.pending_transition.is_some() {
        bail!(
            "a spending-session change is interrupted; run `astatine init` to resolve it before recovery"
        );
    }
    if session.unresolved.is_empty() {
        println!("No unresolved transaction remains. No new spending session was started.");
        return Ok(());
    }
    let wallet = session
        .wallet
        .as_deref()
        .filter(|wallet| !wallet.is_empty())
        .or(config.wallet_address.as_deref())
        .map(Address::from_str)
        .transpose()
        .context("previous transaction session wallet address is invalid")?
        .context("read-only recovery requires the original wallet address")?;
    let effective_limit = session_effective_limit(&session, &config)?;
    println!("RECOVERING • WALLET LOCKED");
    println!(
        "Read-only recovery using previous spending session limit {effective_limit} INJ. No wallet unlock, signature, or new transaction will be requested."
    );
    print_unresolved_transactions(&session);

    let connected = crate::shutdown::race_with_shutdown(
        NetworkClient::connect_with_rpc(config.network, config.rpc_override(config.network)),
        &mut shutdown,
    )
    .await?;
    let Some(connected) = connected else {
        println!(
            "RECOVERY PAUSED • WALLET LOCKED\nNo spending session was changed. Rerun `astatine recover` to continue read-only verification."
        );
        return Ok(());
    };
    let client = connected?;
    if !client.has_mining_deployment() {
        bail!(
            "verified Testnet mining deployment is unavailable; transaction recovery cannot continue"
        );
    }
    let token = client
        .manifest
        .ast_token
        .as_ref()
        .context("Testnet AST token pin is unavailable for transaction recovery")?;
    let token = parse_address(&token.address)?;
    let mut manager = TransactionManager::open_for_read_only_recovery(
        &store,
        &config,
        wallet,
        token,
        client.history_telemetry(),
    )?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    manager.set_shutdown_request(shutdown.request());
    let mut last_status = Vec::new();
    loop {
        if !reconcile_recovery_or_interrupt(&mut manager, &client, &mut shutdown).await? {
            println!(
                "RECOVERY PAUSED • WALLET LOCKED\nNo spending session was changed. Rerun `astatine recover` to continue read-only verification."
            );
            return Ok(());
        }
        let unresolved = manager.journal.unresolved_transactions();
        if unresolved.is_empty() {
            println!("RECOVERY COMPLETE • WALLET LOCKED");
            println!(
                "No new spending session or transaction was created. Start a fresh `astatine mine` process to unlock the wallet."
            );
            return Ok(());
        }
        if unresolved != last_status {
            println!("Transaction recovery is still pending:");
            for entry in &unresolved {
                println!(
                    "  {} • node {:02} window {} • {}",
                    crate::diagnostics::terminal_text(&entry.hash),
                    entry.node_id,
                    entry.window_id,
                    crate::diagnostics::terminal_text(&entry.status)
                );
            }
            last_status = unresolved;
        }
        if tokio::time::Instant::now() >= deadline {
            bail!(
                "transaction recovery timed out; maximum exposure remains reserved. Rerun `astatine recover` to continue read-only verification"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

pub(crate) async fn reconcile_recovery_or_interrupt(
    manager: &mut TransactionManager,
    client: &NetworkClient,
    shutdown: &mut crate::shutdown::ShutdownSignal,
) -> Result<bool> {
    tokio::select! {
        biased;
        signal = shutdown.recv() => {
            signal.context("listen for a shutdown signal during transaction recovery")?;
            Ok(false)
        }
        result = manager.reconcile(client) => {
            result?;
            Ok(true)
        }
    }
}

fn prompt_spending_limit(current: &str, per_run_sessions: bool) -> Result<String> {
    if per_run_sessions {
        println!("\nMaximum INJ authorization ceiling for each paid mining run.");
    } else {
        println!("\nMaximum INJ allowed for mining transactions in one spending session.");
    }
    println!("This covers proof submission fees and maximum gas costs.");
    println!("It is a safety limit, not an amount charged upfront.");
    if per_run_sessions {
        println!(
            "The configured default ceiling is 1 INJ; choose a lower or higher amount if desired."
        );
    } else {
        println!("Choose a session cap; prior authorization is never refunded.");
    }
    println!("Enter 0 to disable paid transactions.");
    if per_run_sessions {
        println!(
            "After you approve the policy, each explicit paid `astatine mine` invocation starts one fresh allowance without a full-cap Y/N prompt."
        );
        println!(
            "The actual cap may be lower after accounting for confirmed balance, reserve, and unresolved transaction liabilities."
        );
        prompt_value("Maximum INJ per run", current)
    } else {
        println!("Your allowance does not reset when you restart the miner.");
        prompt_value("Maximum INJ per session", current)
    }
}

fn prompt_per_run_policy_approval(config: &AppConfig, wallet: Address) -> Result<bool> {
    println!("\nASTATINE PER-RUN SPENDING POLICY");
    println!(
        "Network: {} (chain {})",
        network_label(config.network),
        chain_id(config.network)
    );
    println!("Wallet: {wallet:#x}");
    println!(
        "Each explicit paid `astatine mine` invocation may authorize up to {} INJ.",
        config.per_session_spending_limit_inj
    );
    println!(
        "The cap resets for the next explicit run; aggregate spending across multiple runs can exceed one run's cap."
    );
    println!(
        "Each run automatically uses the full cap when confirmed balance, the {} INJ reserve, and unresolved liabilities allow it. A reduced cap requires a separate one-time approval for that run.",
        config.minimum_reserve_inj
    );
    prompt_paid_consent(
        "Persist and approve this per-run policy for the selected wallet and network?",
        false,
    )
}

fn requires_new_paid_session(
    proposed_limit: U256,
    previous_session_limit: Option<U256>,
    wallet_changed: bool,
    session_closed: bool,
) -> bool {
    !proposed_limit.is_zero()
        && (previous_session_limit.is_some_and(|limit| limit != proposed_limit)
            || wallet_changed
            || session_closed)
}

fn should_confirm_existing_session_resume(
    config_limit_changed: bool,
    proposed_limit: U256,
    has_session: bool,
    session_closed: bool,
) -> bool {
    config_limit_changed && !proposed_limit.is_zero() && has_session && !session_closed
}

fn declined_new_session_limit(current_limit: &str, existing_session_is_resumable: bool) -> String {
    if existing_session_is_resumable {
        current_limit.to_owned()
    } else {
        "0".to_owned()
    }
}

fn mine_requires_session_confirmation(
    session: &SessionJournalSnapshot,
    configured_limit: U256,
    selected_wallet: Option<Address>,
) -> bool {
    !configured_limit.is_zero()
        && (session.session_id.is_none()
            || session.closed
            || mine_session_wallet_changed(session, selected_wallet))
}

/// A legacy session that is still open after a process boundary is not
/// silently resumable. It may be an init-created session or a session whose
/// clean close failed; either way the operator must explicitly confirm before
/// its remaining authorization is reused. Unresolved sessions are handled by
/// the existing recovery path before this check.
pub(crate) fn requires_open_legacy_session_confirmation(
    compute_only: bool,
    per_run_sessions_enabled: bool,
    configured_limit: U256,
    session: &SessionJournalSnapshot,
    new_session: bool,
) -> bool {
    !compute_only
        && !per_run_sessions_enabled
        && !configured_limit.is_zero()
        && !new_session
        && session.session_id.is_some()
        && !session.closed
        && session.unresolved.is_empty()
}

fn prompt_resume_open_legacy_session_confirmation(
    session: &SessionJournalSnapshot,
) -> Result<bool> {
    let cap = session
        .limit_wei
        .as_deref()
        .context("legacy session has no spending cap")?;
    let cap =
        U256::from_str_radix(cap, 10).context("legacy session spending cap is not decimal wei")?;
    let authorized = session
        .authorized_exposure_wei
        .as_deref()
        .map(|value| {
            U256::from_str_radix(value, 10)
                .context("legacy session authorization counter is not decimal wei")
        })
        .transpose()?
        .unwrap_or(U256::ZERO);
    let remaining = cap.checked_sub(authorized).context(
        "legacy session authorization counter exceeds its cap; refusing to resume an inconsistent session",
    )?;
    let unresolved_exposure = session
        .pending_exposure_wei
        .as_deref()
        .map(|value| {
            U256::from_str_radix(value, 10)
                .context("legacy session unresolved exposure is not decimal wei")
        })
        .transpose()?
        .unwrap_or(U256::ZERO);

    println!("An existing legacy spending session is open from a previous command.");
    println!("Session cap: {} INJ", format_token_units(cap, 18));
    println!(
        "Already authorized: {} INJ",
        format_token_units(authorized, 18)
    );
    println!(
        "Remaining authorization: {} INJ",
        format_token_units(remaining, 18)
    );
    println!(
        "Unresolved transactions: {} ({} INJ maximum exposure)",
        session.unresolved.len(),
        format_token_units(unresolved_exposure, 18)
    );
    if !session.unresolved.is_empty() {
        print_unresolved_transactions(session);
    }
    println!(
        "Resuming keeps the same remaining authorization; it does not create a fresh allowance or refund prior authorization."
    );
    prompt_paid_consent("Resume the existing open spending session?", false)
}

fn mine_session_wallet_changed(
    session: &SessionJournalSnapshot,
    selected_wallet: Option<Address>,
) -> bool {
    session.session_id.is_some()
        && session
            .wallet
            .as_deref()
            .and_then(|wallet| Address::from_str(wallet).ok())
            != selected_wallet
}

pub(crate) fn ensure_standalone_wallet_change_allowed(
    store: &ConfigStore,
    config: &AppConfig,
) -> Result<std::fs::File> {
    let (session, journal_lock) = TransactionJournal::inspect_session_and_lock(store, config)?;
    if session.pending_transition.is_some() {
        bail!("wallet changes are blocked while an init spending-session transition is pending");
    }
    if !session.unresolved.is_empty() {
        bail!(
            "wallet changes are blocked during transaction recovery; run `astatine recover` first"
        );
    }
    if config.per_run_sessions_enabled() && session.per_run_policy_approval.is_some() {
        bail!(
            "a wallet bound to an approved per-run spending policy can only be changed with `astatine init` so the new wallet can be explicitly reauthorized"
        );
    }
    if session.session_id.is_some()
        && !session.closed
        && session
            .limit_wei
            .as_deref()
            .map(|limit| U256::from_str_radix(limit, 10))
            .transpose()
            .context("journal session spending limit is invalid")?
            .is_some_and(|limit| !limit.is_zero())
    {
        bail!(
            "wallet create/import cannot replace a wallet bound to an open paid session; run `astatine init` to approve the wallet and spending-session change together"
        );
    }
    Ok(journal_lock)
}

fn session_effective_limit(session: &SessionJournalSnapshot, config: &AppConfig) -> Result<String> {
    session
        .limit_wei
        .as_deref()
        .map(|value| {
            let wei =
                U256::from_str_radix(value, 10).context("journal session limit is invalid")?;
            Ok(format_token_units(wei, 18))
        })
        .transpose()
        .map(|value| value.unwrap_or_else(|| config.per_session_spending_limit_inj.clone()))
}

fn per_run_policy_matches(
    session: &SessionJournalSnapshot,
    config: &AppConfig,
    wallet: Address,
) -> Result<bool> {
    session
        .per_run_policy_approval
        .as_ref()
        .map(|approval| approval.matches_config(config, wallet))
        .transpose()
        .map(|approved| approved.unwrap_or(false))
}

fn prompt_new_session_confirmation(
    previous_limit: &str,
    proposed_limit: &str,
    previous_authorization_wei: Option<&str>,
    has_previous_session: bool,
    wallet_changed: bool,
    previous_wallet: Option<&str>,
    selected_wallet: Option<&str>,
) -> Result<bool> {
    let previous_used = previous_authorization_wei
        .map(|value| {
            U256::from_str_radix(value, 10)
                .context("previous session authorization counter is invalid")
        })
        .transpose()?
        .unwrap_or(U256::ZERO);
    if has_previous_session {
        println!(
            "The previous spending session had a limit of {previous_limit} INJ and permanently authorized up to {} INJ.",
            format_token_units(previous_used, 18)
        );
    } else {
        println!("No active spending session is open. Configured cap: {previous_limit} INJ.");
    }
    println!("You requested a new limit of {proposed_limit} INJ.");
    println!("This change requires a NEW spending session.");
    println!("The new session gets a fresh allowance of {proposed_limit} INJ.");
    println!(
        "Previous transaction history and authorization records remain saved; prior authorization is not refunded."
    );
    if wallet_changed {
        println!(
            "Wallet change: {} → {}.",
            previous_wallet.unwrap_or("not selected"),
            selected_wallet.unwrap_or("not selected")
        );
        println!("The new session will be bound to the selected wallet above.");
    }
    prompt_paid_consent(
        &format!("Start a new spending session with {proposed_limit} INJ?"),
        false,
    )
}

fn prompt_resume_existing_session_confirmation(
    session_limit: &str,
    authorization_wei: Option<&str>,
) -> Result<bool> {
    let authorized = authorization_wei
        .map(|value| {
            U256::from_str_radix(value, 10).context("session authorization counter is invalid")
        })
        .transpose()?
        .unwrap_or(U256::ZERO);
    println!(
        "The configured cap matches the existing {session_limit} INJ session, which has already authorized up to {} INJ.",
        format_token_units(authorized, 18)
    );
    println!("Resuming this session does not reset its allowance or refund prior authorization.");
    prompt_paid_consent(
        "Enable paid transactions using only the existing session's remaining allowance?",
        false,
    )
}

fn print_unresolved_session_blocker(
    session: &SessionJournalSnapshot,
    previous_limit: &str,
    proposed_limit: &str,
) {
    println!("Cannot change or replace the spending session yet.");
    println!("Previous effective session limit: {previous_limit} INJ.");
    println!("Proposed limit: {proposed_limit} INJ.");
    println!("An unresolved transaction must be verified with the original session first.");
    println!(
        "No spending limit, session ID, transaction history, or authorization record will be reset."
    );
    print_unresolved_transactions(session);
    println!(
        "Safe recovery path: run `astatine recover`; then rerun `astatine init` or `astatine mine --new-session`."
    );
}

fn print_unresolved_transactions(session: &SessionJournalSnapshot) {
    if session.unresolved.is_empty() {
        println!("  No unresolved transaction is recorded.");
        return;
    }
    println!("Unresolved transactions:");
    for entry in &session.unresolved {
        println!(
            "  {} • node {:02} window {} • {}",
            crate::diagnostics::terminal_text(&entry.hash),
            entry.node_id,
            entry.window_id,
            crate::diagnostics::terminal_text(&entry.status)
        );
    }
}

async fn run_status() -> Result<()> {
    let store = ConfigStore::system_default()?;
    let config = store.load()?;
    let wallet_address = config
        .wallet_address
        .as_deref()
        .map(Address::from_str)
        .transpose()
        .context("configured wallet address is invalid")?;
    let client =
        NetworkClient::connect_with_rpc(config.network, config.rpc_override(config.network))
            .await?;
    let snapshot = client.snapshot(wallet_address).await?;
    let eligible = snapshot
        .nodes
        .iter()
        .filter(|node| node.state.as_ref().is_some_and(|state| state.eligible))
        .count();
    println!(
        "{} chain {} | block {} | wallet {} | INJ {} | eligible nodes {}/9",
        network_label(config.network),
        client.manifest.chain_id,
        snapshot.block.number,
        wallet_address
            .map(|address| format!("{address:#x}"))
            .unwrap_or_else(|| "not set".to_owned()),
        format_inj(snapshot.native_balance),
        eligible
    );
    if let Some(error) = snapshot.native_balance_error {
        println!(
            "INJ balance unavailable: {}",
            crate::diagnostics::terminal_text(&error)
        );
    }
    if let Some(balance) = snapshot.ast_balance {
        println!(
            "AST wallet balance: {}",
            format_token_units(
                balance,
                client
                    .manifest
                    .ast_token
                    .as_ref()
                    .map(|token| token.decimals)
                    .unwrap_or(9)
            )
        );
    } else if let Some(error) = snapshot.ast_balance_error {
        println!(
            "AST balance unverified: {}",
            crate::diagnostics::terminal_text(&error)
        );
    }
    print_nodes(&snapshot.nodes);
    Ok(())
}

async fn run_rewards() -> Result<()> {
    let store = ConfigStore::system_default()?;
    let config = store.load()?;
    let address = wallet::selected_address(&config)?;
    let client =
        NetworkClient::connect_with_rpc(config.network, config.rpc_override(config.network))
            .await?;
    let snapshot = client.snapshot(Some(address)).await?;
    if !client.verification.token_verified {
        bail!("AST token runtime pin is not verified; refusing to read its token balance");
    }
    let balance = snapshot
        .ast_balance
        .context("AST wallet balance is unavailable")?;
    let decimals = client
        .manifest
        .ast_token
        .as_ref()
        .map(|token| token.decimals)
        .context("AST token is not configured")?;
    println!(
        "AST wallet balance reported by the selected RPC: {} (token balance; this is not per-window reward attribution)",
        format_token_units(balance, decimals)
    );
    Ok(())
}

fn run_get_rpc(requested_network: Option<Network>) -> Result<()> {
    let store = ConfigStore::system_default()?;
    let config = store.load()?;
    let network = requested_network.unwrap_or(config.network);
    let manifest = DeploymentManifest::load(network)?;
    let custom_rpc = config.rpc_override(network);
    let active_rpc = custom_rpc.unwrap_or(&manifest.primary_rpc);
    println!("Network: {}", network_label(network));
    println!("Chain ID: {}", manifest.chain_id);
    println!("Active RPC: {}", redact_rpc_url(active_rpc));
    println!(
        "Source: {}",
        if custom_rpc.is_some() {
            "user override"
        } else {
            "bundled network default"
        }
    );
    if let Some(archival_rpc) = &manifest.archival_rpc {
        println!(
            "Bundled archival RPC: {} ({})",
            redact_rpc_url(archival_rpc),
            if custom_rpc.is_some() {
                "not used as an automatic fallback for a custom primary"
            } else {
                "historical-read fallback only"
            }
        );
    }
    Ok(())
}

async fn run_set_rpc(
    requested_network: Option<Network>,
    requested_endpoint: Option<String>,
) -> Result<()> {
    let store = ConfigStore::system_default()?;
    let mut config = store.load()?;
    let network = requested_network.unwrap_or(config.network);
    let manifest = DeploymentManifest::load(network)?;
    let current_rpc = config
        .rpc_override(network)
        .unwrap_or(&manifest.primary_rpc);
    println!(
        "Network: {} · chain ID {}",
        network_label(network),
        manifest.chain_id
    );
    println!("Current RPC: {}", redact_rpc_url(current_rpc));

    let endpoint = match requested_endpoint {
        Some(endpoint) => endpoint,
        None => prompt_value(
            "New RPC URL (`default` restores bundled RPC; Enter keeps current)",
            "",
        )?,
    };
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        println!("Kept the current RPC configuration.");
        return Ok(());
    }
    persist_rpc_override(&store, &mut config, network, endpoint).await?;
    if endpoint.eq_ignore_ascii_case("default") {
        println!("Restored the bundled {} RPC.", network_label(network));
    } else {
        println!("Saved custom RPC: {}", redact_rpc_url(endpoint));
    }
    Ok(())
}

async fn configure_init_rpc(
    config: &mut AppConfig,
    requested_endpoint: Option<&str>,
) -> Result<()> {
    let network = config.network;
    let manifest = DeploymentManifest::load(network)?;
    println!("\nNetwork: {}", network_label(network));
    println!("Chain ID: {}", manifest.chain_id);
    println!("Default RPC:\n{}", redact_rpc_url(&manifest.primary_rpc));

    if let Some(endpoint) = requested_endpoint {
        apply_init_rpc(config, network, endpoint).await?;
        return Ok(());
    }

    if let Some(current) = config.rpc_override(network) {
        println!("Saved custom RPC: {}", redact_rpc_url(current));
        if prompt_yes_no("Keep the saved custom RPC?", true)? {
            return Ok(());
        }
        let endpoint = prompt_value(
            "New trusted RPC URL (`default` restores bundled RPC; Enter keeps current)",
            "",
        )?;
        if !endpoint.trim().is_empty() {
            apply_init_rpc(config, network, &endpoint).await?;
        }
        return Ok(());
    }

    if prompt_yes_no("Would you like to use a custom RPC?", false)? {
        let endpoint = prompt_value("Custom trusted RPC URL", "")?;
        if endpoint.trim().is_empty() {
            bail!("a custom RPC URL is required after selecting custom RPC setup");
        }
        apply_init_rpc(config, network, &endpoint).await?;
    }
    Ok(())
}

async fn apply_init_rpc(config: &mut AppConfig, network: Network, endpoint: &str) -> Result<()> {
    select_rpc_override(config, network, endpoint).await
}

async fn select_rpc_override(
    config: &mut AppConfig,
    network: Network,
    endpoint: &str,
) -> Result<()> {
    let endpoint = endpoint.trim();
    if endpoint.eq_ignore_ascii_case("default") {
        config.set_rpc_override(network, None);
        return Ok(());
    }
    NetworkClient::validate_rpc_endpoint(network, endpoint).await?;
    config.set_rpc_override(network, Some(endpoint.to_owned()));
    Ok(())
}

async fn persist_rpc_override(
    store: &ConfigStore,
    config: &mut AppConfig,
    network: Network,
    endpoint: &str,
) -> Result<()> {
    let mut updated = config.clone();
    select_rpc_override(&mut updated, network, endpoint).await?;
    store.save(&updated)?;
    *config = updated;
    Ok(())
}

fn redact_rpc_url(endpoint: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(endpoint) else {
        return "<invalid saved RPC URL>".to_owned();
    };
    let mut redacted = false;
    if !url.username().is_empty() || url.password().is_some() {
        let _ = url.set_username("");
        let _ = url.set_password(None);
        redacted = true;
    }
    if url.query().is_some() {
        url.set_query(None);
        redacted = true;
    }
    if url.fragment().is_some() {
        url.set_fragment(None);
        redacted = true;
    }
    if url.path() != "/" {
        url.set_path("/<redacted>");
        redacted = true;
    }
    if redacted {
        format!("{url} (path/query/credentials redacted)")
    } else {
        url.to_string()
    }
}

fn print_nodes(nodes: &[NodeView]) {
    for node in nodes {
        let code_pin = if node.pin.runtime_verified && node.pin.abi_verified {
            "verified"
        } else {
            "unverified"
        };
        match &node.state {
            Some(state) => {
                let incumbent = state
                    .candidate
                    .as_ref()
                    .map(|candidate| {
                        format!(
                            " incumbent={:#x} miner={:#x} nonce={} submitted_at={} first_valid_solve={}s",
                            candidate.work_hash,
                            candidate.miner,
                            candidate.nonce,
                            candidate.submitted_at,
                            candidate.first_valid_solve_secs
                        )
                    })
                    .unwrap_or_default();
                println!(
                    "node {} {} | window {} | target {:#x} | {}{} | code {}",
                    node.id,
                    node.address,
                    state.work.window_id,
                    state.work.target,
                    if state.eligible {
                        "eligible"
                    } else {
                        state.eligibility_reason
                    },
                    incumbent,
                    code_pin
                );
            }
            None => println!(
                "node {} {} | unavailable | code {} | {}",
                node.id,
                node.address,
                code_pin,
                crate::diagnostics::terminal_text(
                    node.error.as_deref().unwrap_or("state unavailable")
                )
            ),
        }
    }
}

fn prompt_network(current: Network) -> Result<Network> {
    let default = match current {
        Network::Testnet => "testnet",
        Network::Mainnet => "mainnet",
    };
    loop {
        let value = prompt_value("Network (testnet/mainnet)", default)?;
        match value.to_ascii_lowercase().as_str() {
            "testnet" => return Ok(Network::Testnet),
            "mainnet" => return Ok(Network::Mainnet),
            _ => println!("Choose testnet or mainnet."),
        }
    }
}

fn prompt_threads(current: usize) -> Result<usize> {
    loop {
        let value = prompt_value("CPU worker budget (1-256)", &current.to_string())?;
        match value.parse::<NonZeroUsize>() {
            Ok(threads) if threads.get() <= 256 => return Ok(threads.get()),
            _ => println!("Enter a positive worker count no greater than 256."),
        }
    }
}

fn prompt_value(prompt: &str, default: &str) -> Result<String> {
    print!("{prompt} [{default}]: ");
    io::stdout().flush().context("flush input prompt")?;
    let value = match read_terminal_line() {
        Ok(value) => value,
        Err(error)
            if error.kind() == io::ErrorKind::Interrupted
                && crate::shutdown::prompt_shutdown_requested() =>
        {
            return Err(crate::shutdown::prompt_shutdown_error());
        }
        Err(error) => return Err(error).context("read input"),
    };
    let value = value.trim();
    Ok(if value.is_empty() {
        default.to_owned()
    } else {
        value.to_owned()
    })
}

/// Read one terminal line without blocking indefinitely on a shutdown signal.
///
/// The read polls the descriptor in short slices and checks the synchronous
/// shutdown delivery flags between slices. This works regardless of which
/// runtime thread receives a process-directed signal; it does not mutate signal
/// dispositions.
pub(crate) fn read_terminal_line() -> io::Result<String> {
    #[cfg(unix)]
    {
        read_unix_terminal_line()
    }
    #[cfg(not(unix))]
    {
        let mut value = String::new();
        io::stdin().read_line(&mut value)?;
        if crate::shutdown::prompt_shutdown_requested() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "terminal prompt cancelled by shutdown signal",
            ));
        }
        Ok(value)
    }
}

#[cfg(unix)]
fn read_unix_terminal_line() -> io::Result<String> {
    const MAX_PROMPT_BYTES: usize = 8_192;
    let mut bytes = Vec::new();
    loop {
        if crate::shutdown::prompt_shutdown_requested() {
            println!();
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "terminal prompt cancelled by shutdown signal",
            ));
        }
        let mut descriptor = libc::pollfd {
            fd: libc::STDIN_FILENO,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `descriptor` points to one valid `pollfd` and the timeout is
        // a non-negative millisecond value.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 100) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal input descriptor is invalid",
            ));
        }
        let mut byte = [0_u8; 1];
        // SAFETY: the destination buffer is one byte and the descriptor is the
        // process standard input.
        let count = unsafe {
            libc::read(
                libc::STDIN_FILENO,
                byte.as_mut_ptr().cast::<libc::c_void>(),
                1,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 || byte[0] == b'\n' {
            break;
        }
        if bytes.len() >= MAX_PROMPT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "terminal input exceeds the supported prompt length",
            ));
        }
        bytes.push(byte[0]);
    }
    if crate::shutdown::prompt_shutdown_requested() {
        println!();
        return Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "terminal prompt cancelled by shutdown signal",
        ));
    }
    String::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "terminal input is not valid UTF-8",
        )
    })
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    let default = if default_yes { "Y/n" } else { "y/N" };
    loop {
        let value = prompt_value(&format!("{prompt} ({default})"), "")?;
        match value.to_ascii_lowercase().as_str() {
            "" => return Ok(default_yes),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("Answer y or n."),
        }
    }
}

/// Paid authorization must come from a real interactive terminal. Redirected
/// stdin/stdout, pipes, and CI runners cannot accidentally approve spending.
pub(crate) fn require_paid_consent_terminal(action: &str) -> Result<()> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!(
            "refusing to read {action} consent from redirected or non-interactive input; run this command directly in an interactive terminal"
        );
    }
    Ok(())
}

fn prompt_paid_consent(prompt: &str, default_yes: bool) -> Result<bool> {
    require_paid_consent_terminal("paid spending authorization")?;
    prompt_yes_no(prompt, default_yes)
}

fn prompt_choice<'a>(prompt: &str, choices: &'a [&'a str]) -> Result<&'a str> {
    loop {
        let value = prompt_value(prompt, "1")?;
        if let Some(choice) = choices.iter().copied().find(|choice| *choice == value) {
            return Ok(choice);
        }
    }
}

fn format_inj(value: Option<U256>) -> String {
    value
        .map(|value| format_token_units(value, 18))
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn format_token_units(value: U256, decimals: u8) -> String {
    let scale = U256::from(10_u8).pow(U256::from(decimals));
    let whole = value / scale;
    let fractional = (value % scale).to_string();
    let width = usize::from(decimals);
    let fractional = format!("{fractional:0>width$}")
        .trim_end_matches('0')
        .to_owned();
    if fractional.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{fractional}")
    }
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Testnet => "Testnet",
        Network::Mainnet => "Mainnet",
    }
}

fn chain_id(network: Network) -> u64 {
    match network {
        Network::Testnet => 1439,
        Network::Mainnet => 1776,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        configure_init_rpc, declined_new_session_limit, ensure_standalone_wallet_change_allowed,
        mine_requires_session_confirmation, persist_rpc_override, redact_rpc_url,
        requires_new_paid_session, requires_open_legacy_session_confirmation, select_rpc_override,
        should_confirm_existing_session_resume,
    };
    use crate::{
        cli::Network,
        config::{AppConfig, ConfigStore},
        transaction::{SessionJournalSnapshot, TransactionJournal, UnresolvedTransactionSummary},
    };
    use alloy_primitives::{Address, U256};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread::{self, JoinHandle},
        time::Duration,
    };

    fn mock_chain_id_rpc(chain_id: &'static str) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 1024];
                let count = stream.read(&mut chunk).unwrap();
                assert_ne!(count, 0, "RPC client closed before sending its request");
                request.extend_from_slice(&chunk[..count]);
                let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .filter_map(|line| line.split_once(':'))
                    .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": chain_id,
            })
            .to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        (format!("http://{address}"), server)
    }

    #[test]
    fn matching_existing_session_cap_does_not_reset_allowance_after_config_repair() {
        let current_limit = U256::from(500_000_000_000_000_000_u128);
        assert!(
            !requires_new_paid_session(current_limit, Some(current_limit), false, false),
            "matching the journal session limit must resume its existing allowance even if the saved config was lower"
        );
        assert!(requires_new_paid_session(
            current_limit + U256::from(1),
            Some(current_limit),
            false,
            false
        ));
        assert!(requires_new_paid_session(
            current_limit,
            Some(current_limit),
            true,
            false
        ));
        assert!(requires_new_paid_session(
            current_limit,
            Some(current_limit),
            false,
            true
        ));
        assert!(requires_new_paid_session(current_limit, None, false, true));
        assert!(!requires_new_paid_session(
            U256::ZERO,
            Some(current_limit),
            false,
            true
        ));
        assert_eq!(declined_new_session_limit("0.5", true), "0.5");
        assert_eq!(declined_new_session_limit("0.5", false), "0");
        assert!(should_confirm_existing_session_resume(
            true,
            current_limit,
            true,
            false
        ));
        assert!(!should_confirm_existing_session_resume(
            false,
            current_limit,
            true,
            false
        ));
        assert!(!should_confirm_existing_session_resume(
            true,
            U256::ZERO,
            true,
            false
        ));
        assert!(!should_confirm_existing_session_resume(
            true,
            current_limit,
            true,
            true
        ));
        let no_session = SessionJournalSnapshot::default();
        assert!(mine_requires_session_confirmation(
            &no_session,
            current_limit,
            Some(Address::with_last_byte(0xa1))
        ));
        assert!(!mine_requires_session_confirmation(
            &no_session,
            U256::ZERO,
            Some(Address::with_last_byte(0xa1))
        ));
        let open_session = SessionJournalSnapshot {
            session_id: Some("existing-session".to_owned()),
            wallet: Some(format!("{:#x}", Address::with_last_byte(0xa1))),
            closed: false,
            ..SessionJournalSnapshot::default()
        };
        assert!(!mine_requires_session_confirmation(
            &open_session,
            current_limit,
            Some(Address::with_last_byte(0xa1))
        ));
        assert!(mine_requires_session_confirmation(
            &open_session,
            current_limit,
            Some(Address::with_last_byte(0xa2))
        ));
    }

    #[test]
    fn legacy_resume_prompt_fails_closed_on_malformed_or_overdrawn_counters() {
        let base = SessionJournalSnapshot {
            session_id: Some("legacy".to_owned()),
            limit_wei: Some("1000000000000000000".to_owned()),
            authorized_exposure_wei: Some("250000000000000000".to_owned()),
            pending_exposure_wei: Some("0".to_owned()),
            ..SessionJournalSnapshot::default()
        };
        let malformed = SessionJournalSnapshot {
            authorized_exposure_wei: Some("not-decimal".to_owned()),
            ..base.clone()
        };
        let error = super::prompt_resume_open_legacy_session_confirmation(&malformed).unwrap_err();
        assert!(format!("{error:#}").contains("not decimal wei"));

        let overdrawn = SessionJournalSnapshot {
            authorized_exposure_wei: Some("2000000000000000000".to_owned()),
            ..base.clone()
        };
        let error = super::prompt_resume_open_legacy_session_confirmation(&overdrawn).unwrap_err();
        assert!(format!("{error:#}").contains("exceeds its cap"));

        let malformed_exposure = SessionJournalSnapshot {
            pending_exposure_wei: Some("not-decimal".to_owned()),
            ..base
        };
        let error =
            super::prompt_resume_open_legacy_session_confirmation(&malformed_exposure).unwrap_err();
        assert!(format!("{error:#}").contains("not decimal wei"));
    }

    #[test]
    fn open_legacy_session_requires_confirmation_on_process_restart() {
        let limit = U256::from(500_000_000_000_000_000_u128);
        let open = SessionJournalSnapshot {
            session_id: Some("open".to_owned()),
            closed: false,
            ..SessionJournalSnapshot::default()
        };
        let closed = SessionJournalSnapshot {
            session_id: Some("closed".to_owned()),
            closed: true,
            ..SessionJournalSnapshot::default()
        };
        let unresolved = SessionJournalSnapshot {
            session_id: Some("unresolved".to_owned()),
            closed: false,
            unresolved: vec![UnresolvedTransactionSummary {
                hash: "0xabc".to_owned(),
                node_id: 1,
                window_id: 7,
                status: "Broadcast".to_owned(),
            }],
            ..SessionJournalSnapshot::default()
        };

        assert!(requires_open_legacy_session_confirmation(
            false, false, limit, &open, false
        ));
        assert!(!requires_open_legacy_session_confirmation(
            true, false, limit, &open, false
        ));
        assert!(!requires_open_legacy_session_confirmation(
            false, true, limit, &open, false
        ));
        assert!(!requires_open_legacy_session_confirmation(
            false,
            false,
            U256::ZERO,
            &open,
            false
        ));
        assert!(!requires_open_legacy_session_confirmation(
            false, false, limit, &open, true
        ));
        assert!(!requires_open_legacy_session_confirmation(
            false, false, limit, &closed, false
        ));
        assert!(!requires_open_legacy_session_confirmation(
            false,
            false,
            limit,
            &unresolved,
            false
        ));
    }

    fn dummy_v3_keystore(address: Address) -> Vec<u8> {
        let address = format!("{address:#x}");
        let address = address.strip_prefix("0x").unwrap();
        serde_json::to_vec(&serde_json::json!({
            "version": 3,
            "id": "f0e1d2c3-b4a5-4678-89ab-cdef01234567",
            "address": address,
            "crypto": {
                "cipher": "aes-128-ctr",
                "cipherparams": { "iv": "00000000000000000000000000000000" },
                "ciphertext": "0000000000000000000000000000000000000000000000000000000000000000",
                "kdf": "scrypt",
                "kdfparams": {
                    "dklen": 32,
                    "n": 4096,
                    "p": 1,
                    "r": 8,
                    "salt": "0000000000000000000000000000000000000000000000000000000000000000"
                },
                "mac": "0000000000000000000000000000000000000000000000000000000000000000"
            }
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn init_wallet_change_requires_paid_terminal_consent() {
        const CHILD: &str = "ASTATINE_INIT_WALLET_CONSENT_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let temp = tempfile::tempdir().unwrap();
            let store = ConfigStore::at_root(temp.path().to_path_buf());
            let wallet_a = Address::with_last_byte(0xa1);
            let wallet_b = Address::with_last_byte(0xb1);
            let token = Address::with_last_byte(0xc1);
            let base = AppConfig {
                schema_version: 2,
                network: Network::Testnet,
                wallet_address: Some(format!("{wallet_a:#x}")),
                per_session_spending_limit_inj: "1".to_owned(),
                minimum_reserve_inj: "0.1".to_owned(),
                transaction_confirmations: 2,
                testnet_rpc: Some("https://rpc.test.example".to_owned()),
                ..AppConfig::default()
            };
            store.save(&base).unwrap();
            let manager = crate::transaction::TransactionManager::open_with_session_policy(
                &store,
                &base,
                wallet_a,
                token,
                std::sync::Arc::new(crate::history_telemetry::HistoryTelemetry::default()),
                true,
                false,
            )
            .unwrap();
            drop(manager);

            let selected = AppConfig {
                wallet_address: Some(format!("{wallet_b:#x}")),
                ..base.clone()
            };
            store.save(&selected).unwrap();
            TransactionJournal::set_per_run_policy_approval(&store, &selected, Some(wallet_b))
                .unwrap();
            store
                .store_keystore(wallet_b, &dummy_v3_keystore(wallet_b))
                .unwrap();

            let config_before = store.load().unwrap();
            let journal_before = store.read_transaction_journal().unwrap().unwrap();
            let error = super::run_init_with_store(
                &store,
                crate::cli::InitArgs {
                    network: Some(Network::Testnet),
                    threads: Some(std::num::NonZeroUsize::new(1).unwrap()),
                    minimum_reserve_inj: Some("0.1".to_owned()),
                    spending_limit_inj: Some("1".to_owned()),
                    transaction_confirmations: Some(2),
                    rpc: None,
                    per_run_sessions: true,
                },
            )
            .await
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("interactive terminal"),
                "unexpected wallet-consent error: {error:#}"
            );
            assert_eq!(store.load().unwrap(), config_before);
            assert_eq!(
                store.read_transaction_journal().unwrap().unwrap(),
                journal_before
            );
            eprintln!("init-wallet-consent-child-ran");
            return;
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::tests::init_wallet_change_requires_paid_terminal_consent",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"yes\nyes\nyes\n")
            .unwrap();
        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "init wallet-consent child failed: {stderr}"
        );
        assert!(
            stderr.contains("init-wallet-consent-child-ran"),
            "the child branch must have executed: {stderr}"
        );
    }

    #[test]
    fn paid_consent_rejects_piped_yes_without_a_terminal() {
        const CHILD: &str = "ASTATINE_PAID_CONSENT_PIPED_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let error =
                super::prompt_new_session_confirmation("1", "1", None, false, false, None, None)
                    .unwrap_err();
            assert!(format!("{error:#}").contains("interactive terminal"));
            let error = super::prompt_resume_existing_session_confirmation("1", None).unwrap_err();
            assert!(format!("{error:#}").contains("interactive terminal"));
            let error = super::prompt_per_run_policy_approval(
                &AppConfig::default(),
                Address::with_last_byte(0xa1),
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("interactive terminal"));
            let session = SessionJournalSnapshot {
                session_id: Some("open".to_owned()),
                limit_wei: Some("1000000000000000000".to_owned()),
                authorized_exposure_wei: Some("0".to_owned()),
                ..SessionJournalSnapshot::default()
            };
            let error =
                super::prompt_resume_open_legacy_session_confirmation(&session).unwrap_err();
            assert!(format!("{error:#}").contains("interactive terminal"));
            eprintln!("paid-consent-piped-child-ran");
            return;
        }

        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "commands::tests::paid_consent_rejects_piped_yes_without_a_terminal",
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
            "piped paid-consent child failed: {stderr}"
        );
        assert!(
            stderr.contains("paid-consent-piped-child-ran"),
            "the child branch must have executed: {stderr}"
        );
    }

    #[test]
    fn standalone_wallet_selection_is_blocked_for_an_open_paid_session() {
        let root = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(root.path().to_path_buf());
        let wallet = Address::with_last_byte(0xa1);
        let config = AppConfig {
            wallet_address: Some(format!("{wallet:#x}")),
            per_session_spending_limit_inj: "0.5".to_owned(),
            ..AppConfig::default()
        };
        store.save(&config).unwrap();
        drop(TransactionJournal::open(&store, &config, wallet).unwrap());

        let error = ensure_standalone_wallet_change_allowed(&store, &config).unwrap_err();
        assert!(format!("{error:#}").contains("astatine init"));
    }

    #[test]
    fn standalone_wallet_selection_requires_per_run_policy_reauthorization() {
        let root = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(root.path().to_path_buf());
        let wallet = Address::with_last_byte(0xa1);
        let config = AppConfig {
            wallet_address: Some(format!("{wallet:#x}")),
            ..AppConfig::default()
        };
        store.save(&config).unwrap();
        TransactionJournal::set_per_run_policy_approval(&store, &config, Some(wallet)).unwrap();

        let error = ensure_standalone_wallet_change_allowed(&store, &config).unwrap_err();
        assert!(format!("{error:#}").contains("per-run spending policy"));
        assert_eq!(
            store.load().unwrap().wallet_address.as_deref(),
            Some(format!("{wallet:#x}").as_str())
        );
    }

    #[test]
    fn standalone_wallet_selection_is_blocked_during_a_pending_transition() {
        let root = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(root.path().to_path_buf());
        let wallet = Address::with_last_byte(0xa2);
        let previous = AppConfig {
            wallet_address: Some(format!("{wallet:#x}")),
            per_session_spending_limit_inj: "1".to_owned(),
            ..AppConfig::default()
        };
        store.save(&previous).unwrap();
        drop(TransactionJournal::open(&store, &previous, wallet).unwrap());
        let proposed = AppConfig {
            per_session_spending_limit_inj: "2".to_owned(),
            ..previous.clone()
        };
        drop(
            TransactionJournal::open_for_init_session_transition(
                &store,
                &proposed,
                wallet,
                previous.per_session_spending_limit_inj.clone(),
                previous.wallet_address.clone(),
            )
            .unwrap(),
        );

        let error = ensure_standalone_wallet_change_allowed(&store, &previous).unwrap_err();
        assert!(format!("{error:#}").contains("transition is pending"));
    }

    #[test]
    fn standalone_wallet_selection_holds_the_journal_lock_until_config_is_saved() {
        let root = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(root.path().to_path_buf());
        let config = AppConfig::default();
        store.save(&config).unwrap();
        let guard = ensure_standalone_wallet_change_allowed(&store, &config).unwrap();

        assert!(
            TransactionJournal::open(&store, &config, Address::with_last_byte(0xa3)).is_err(),
            "a paid session must not begin between the wallet-change check and config persistence"
        );
        drop(guard);
        assert!(TransactionJournal::open(&store, &config, Address::with_last_byte(0xa3)).is_ok());
    }

    #[tokio::test]
    async fn invalid_rpc_selection_preserves_saved_config_and_other_network_override() {
        let root = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(root.path().to_path_buf());
        let mut config = AppConfig {
            testnet_rpc: Some("https://testnet.example.org/path-secret?token=secret".to_owned()),
            ..AppConfig::default()
        };
        store.save(&config).unwrap();
        let before = store.load().unwrap();

        assert!(
            persist_rpc_override(
                &store,
                &mut config,
                Network::Testnet,
                "http://remote.example.org",
            )
            .await
            .is_err()
        );
        assert_eq!(config, before);
        assert_eq!(store.load().unwrap(), before);

        select_rpc_override(&mut config, Network::Mainnet, "default")
            .await
            .unwrap();
        assert_eq!(
            config.rpc_override(Network::Testnet),
            before.rpc_override(Network::Testnet)
        );
        assert_eq!(config.rpc_override(Network::Mainnet), None);
    }

    #[tokio::test]
    async fn init_and_rpc_changes_preserve_wallet_and_transaction_journal() {
        let root = tempfile::tempdir().unwrap();
        let store = ConfigStore::at_root(root.path().to_path_buf());
        let wallet_address = Address::with_last_byte(0xa1);
        let wallet = format!("{wallet_address:#x}");
        let mut config = AppConfig {
            wallet_address: Some(wallet.clone()),
            per_session_spending_limit_inj: "1".to_owned(),
            testnet_rpc: Some("https://old-testnet.example/rpc".to_owned()),
            mainnet_rpc: Some("https://mainnet.example/rpc".to_owned()),
            ..AppConfig::default()
        };
        store.save(&config).unwrap();
        drop(TransactionJournal::open(&store, &config, wallet_address).unwrap());
        let journal = store.read_transaction_journal().unwrap().unwrap();
        let journal_state: serde_json::Value = serde_json::from_slice(&journal).unwrap();
        let session_id = journal_state["active_session"]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (endpoint, server) = mock_chain_id_rpc("0x59f");
        configure_init_rpc(&mut config, Some(&endpoint))
            .await
            .unwrap();
        server.join().unwrap();
        store.save(&config).unwrap();
        assert_eq!(
            store.load().unwrap().wallet_address.as_deref(),
            Some(wallet.as_str())
        );
        assert_eq!(
            config.rpc_override(Network::Testnet),
            Some(endpoint.as_str())
        );
        assert_eq!(
            config.rpc_override(Network::Mainnet),
            Some("https://mainnet.example/rpc")
        );
        assert_eq!(store.read_transaction_journal().unwrap().unwrap(), journal);
        let reopened = TransactionJournal::open(&store, &config, wallet_address).unwrap();
        drop(reopened);

        let (set_endpoint, set_server) = mock_chain_id_rpc("0x59f");
        persist_rpc_override(&store, &mut config, Network::Testnet, &set_endpoint)
            .await
            .unwrap();
        set_server.join().unwrap();
        assert_eq!(
            config.rpc_override(Network::Testnet),
            Some(set_endpoint.as_str())
        );
        assert_eq!(config.wallet_address.as_deref(), Some(wallet.as_str()));
        assert_eq!(store.read_transaction_journal().unwrap().unwrap(), journal);
        let reopened = TransactionJournal::open(&store, &config, wallet_address).unwrap();
        drop(reopened);

        persist_rpc_override(&store, &mut config, Network::Testnet, "default")
            .await
            .unwrap();
        assert_eq!(config.rpc_override(Network::Testnet), None);
        assert_eq!(
            config.rpc_override(Network::Mainnet),
            Some("https://mainnet.example/rpc")
        );
        assert_eq!(config.wallet_address.as_deref(), Some(wallet.as_str()));
        assert_eq!(
            store.load().unwrap().wallet_address.as_deref(),
            Some(wallet.as_str())
        );
        assert_eq!(store.read_transaction_journal().unwrap().unwrap(), journal);
        let reopened = TransactionJournal::open(&store, &config, wallet_address).unwrap();
        drop(reopened);
        let persisted: serde_json::Value =
            serde_json::from_slice(&store.read_transaction_journal().unwrap().unwrap()).unwrap();
        assert_eq!(persisted["active_session"]["id"], session_id);
        assert_eq!(persisted["active_session"]["authorized_exposure_wei"], "0");
        assert_eq!(persisted["active_session"]["reported_actual_wei"], "0");
    }

    #[test]
    fn rpc_display_redacts_credentials_path_query_and_fragment() {
        for url in [
            "https://rpc.example.org/path-secret?token=query-secret#private-fragment",
            "https://user:password@rpc.example.org/",
        ] {
            let display = redact_rpc_url(url);
            for secret in [
                "path-secret",
                "query-secret",
                "private-fragment",
                "password",
            ] {
                assert!(!display.contains(secret));
            }
        }
        assert_eq!(
            redact_rpc_url("https://rpc.example.org/"),
            "https://rpc.example.org/"
        );
    }

    #[cfg(unix)]
    fn spawn_pty_test_child(
        test_name: &str,
        child_env: &str,
        mode: &str,
    ) -> (std::process::Child, std::fs::File) {
        use std::os::unix::io::FromRawFd;

        let mut master_fd = -1;
        let mut slave_fd = -1;
        // SAFETY: `openpty` writes two valid descriptors on success. No name,
        // termios, or window-size overrides are supplied.
        let result = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(result, 0, "openpty failed");
        // SAFETY: the descriptors are uniquely owned by this function.
        let master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        // SAFETY: the descriptors are uniquely owned by this function.
        let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let stdin = slave.try_clone().unwrap();
        let stdout = slave.try_clone().unwrap();
        let stderr = slave.try_clone().unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env(child_env, "1")
            .env("ASTATINE_PTY_MODE", mode)
            .stdin(std::process::Stdio::from(stdin))
            .stdout(std::process::Stdio::from(stdout))
            .stderr(std::process::Stdio::from(stderr))
            .spawn()
            .unwrap();
        drop(slave);
        (child, master)
    }

    #[cfg(unix)]
    fn read_pty_until(master: &mut std::fs::File, needle: &str, timeout: Duration) -> String {
        use std::os::unix::io::AsRawFd;

        let descriptor = master.as_raw_fd();
        let deadline = std::time::Instant::now() + timeout;
        let mut output = String::new();
        while std::time::Instant::now() < deadline {
            let mut poll = libc::pollfd {
                fd: descriptor,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid `pollfd` is supplied.
            let ready = unsafe { libc::poll(&mut poll, 1, 100) };
            if ready <= 0 {
                continue;
            }
            let mut buffer = [0_u8; 4096];
            // SAFETY: the buffer is valid for its full length.
            let count = unsafe {
                libc::read(
                    descriptor,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if count <= 0 {
                break;
            }
            output.push_str(&String::from_utf8_lossy(&buffer[..count as usize]));
            if output.contains(needle) {
                break;
            }
        }
        output
    }

    #[cfg(unix)]
    fn wait_for_pty_child(
        child: &mut std::process::Child,
        timeout: Duration,
    ) -> Option<std::process::ExitStatus> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return Some(status);
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn signal_interrupts_blocking_terminal_prompt_on_a_disposable_pty() {
        const CHILD: &str = "ASTATINE_PTY_PROMPT_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let _shutdown = crate::shutdown::ShutdownSignal::new().unwrap();
            let mode = std::env::var("ASTATINE_PTY_MODE").unwrap();
            match mode.as_str() {
                "legacy" => {
                    let session = SessionJournalSnapshot {
                        session_id: Some("legacy-pty".to_owned()),
                        wallet: Some(format!("{:#x}", Address::with_last_byte(0xa1))),
                        limit_wei: Some("1000000000000000000".to_owned()),
                        authorized_exposure_wei: Some("250000000000000000".to_owned()),
                        pending_exposure_wei: Some("0".to_owned()),
                        unresolved: Vec::new(),
                        closed: false,
                        ..SessionJournalSnapshot::default()
                    };
                    let error = super::prompt_resume_open_legacy_session_confirmation(&session)
                        .unwrap_err();
                    assert!(crate::shutdown::is_prompt_shutdown(&error));
                }
                "value" => {
                    let error = super::prompt_value("PTY prompt", "default").unwrap_err();
                    assert!(crate::shutdown::is_prompt_shutdown(&error));
                }
                other => panic!("unsupported PTY prompt mode {other}"),
            }
            eprintln!("pty-prompt-child-ran");
            return;
        }

        for mode in ["legacy", "value"] {
            let (mut child, mut master) = spawn_pty_test_child(
                "commands::tests::signal_interrupts_blocking_terminal_prompt_on_a_disposable_pty",
                CHILD,
                mode,
            );
            let needle = if mode == "legacy" {
                "Resume the existing open spending session?"
            } else {
                "PTY prompt"
            };
            let output = read_pty_until(&mut master, needle, Duration::from_secs(5));
            assert!(
                output.contains("Session cap") || output.contains("PTY prompt"),
                "child {mode} did not reach its prompt: {output:?}"
            );
            if mode == "legacy" {
                assert!(
                    output.contains("Remaining authorization")
                        && output.contains("Unresolved transactions"),
                    "legacy consent must display cap, authorized, remaining, and unresolved data: {output:?}"
                );
            }
            // SAFETY: `child.id()` is the live child PID.
            let result = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            assert_eq!(result, 0, "failed to signal PTY child");
            let status = wait_for_pty_child(&mut child, Duration::from_secs(5));
            let mut trailing = String::new();
            if let Ok(mut file) = master.try_clone() {
                let _ = file.read_to_string(&mut trailing);
            }
            let status = status.unwrap_or_else(|| {
                panic!("PTY child {mode} did not exit after SIGTERM: {output:?} {trailing:?}")
            });
            assert!(
                status.success(),
                "PTY child {mode} failed: {output:?} {trailing:?}"
            );
        }
    }
}
