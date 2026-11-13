//! Phase B Linux qualification for authenticated journal persistence.
//!
//! `config` deliberately substitutes an in-memory checkpoint backend in unit
//! tests. These tests therefore bridge the exact checkpoint bytes produced by
//! the real `TransactionJournal` test path into the disposable native Secret
//! Service, then have a separate test process read those bytes back from the
//! native backend and inject them into its own in-memory test backend before it
//! opens the journal. This exercises a real authenticated journal across a
//! process restart without changing production code or storing test secrets in
//! the repository.

use crate::{
    config::{AppConfig, ConfigStore},
    transaction::TransactionJournal,
};
use alloy_primitives::Address;
use std::{
    path::Path,
    process::{Command, Output},
    str::FromStr,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const DISPOSABLE_STORE_ENV: &str = "ASTATINE_DISPOSABLE_CREDENTIAL_STORE";
const QUALIFICATION_MODE_ENV: &str = "ASTATINE_QUALIFICATION_MODE";
const CHILD_ROOT_ENV: &str = "ASTATINE_PHASE_B_JOURNAL_CHILD_ROOT";
const CHILD_OPERATION_ENV: &str = "ASTATINE_PHASE_B_JOURNAL_CHILD_OPERATION";
const CHILD_SESSION_ENV: &str = "ASTATINE_PHASE_B_JOURNAL_EXPECTED_SESSION";
const APP_BINARY_ENV: &str = "ASTATINE_PHASE_B_APP_BINARY";
const TEST_WALLET: &str = "0x1111111111111111111111111111111111111111";
const PREVIOUS_LIMIT: &str = "1";
const PROPOSED_LIMIT: &str = "2";
const CHILD_TEST_NAME: &str =
    "linux_secret_service_phase_b_tests::linux_secret_service_phase_b_child_probe";

fn require_disposable_provider() {
    assert_eq!(
        std::env::var(DISPOSABLE_STORE_ENV).as_deref(),
        Ok("1"),
        "refusing native credential-store access without the disposable-store marker"
    );
    assert_eq!(
        std::env::var(QUALIFICATION_MODE_ENV).as_deref(),
        Ok("provider"),
        "this qualification requires the isolated unlocked provider mode"
    );
    assert_eq!(
        std::env::var("ASTATINE_REQUIRE_NATIVE_CREDENTIAL_STORE").as_deref(),
        Ok("1"),
        "the native provider must be an explicit test requirement"
    );
}

fn require_disposable_missing_mode() {
    assert_eq!(
        std::env::var(DISPOSABLE_STORE_ENV).as_deref(),
        Ok("1"),
        "refusing native credential-store access without the disposable-store marker"
    );
    assert_eq!(
        std::env::var(QUALIFICATION_MODE_ENV).as_deref(),
        Ok("missing"),
        "this qualification requires the isolated no-provider mode"
    );
}

fn test_config() -> (AppConfig, Address) {
    let wallet = Address::from_str(TEST_WALLET).expect("test wallet address is valid");
    let config = AppConfig {
        wallet_address: Some(TEST_WALLET.to_owned()),
        ..AppConfig::default()
    };
    (config, wallet)
}

fn seed_authenticated_journal(root: &Path) -> (ConfigStore, AppConfig, String) {
    let store = ConfigStore::at_root(root.to_path_buf());
    let (config, wallet) = test_config();
    store
        .save(&config)
        .expect("save isolated test configuration");
    drop(
        TransactionJournal::open(&store, &config, wallet)
            .expect("create authenticated test journal"),
    );
    let snapshot = TransactionJournal::inspect_session(&store, &config)
        .expect("inspect newly authenticated test journal");
    let session_id = snapshot
        .session_id
        .expect("positive configured limit creates a session");
    (store, config, session_id)
}

fn checkpoint_from_test_backend(store: &ConfigStore) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        store
            .read_journal_anchor()
            .expect("read generated in-memory test checkpoint")
            .expect("authenticated journal has a checkpoint")
            .to_vec(),
    )
}

fn native_anchor_cleanup(root: &Path) -> NativeAnchorCleanup {
    use sha2::{Digest, Sha256};
    use std::os::unix::ffi::OsStrExt;

    let canonical = std::fs::canonicalize(root).expect("canonicalize disposable data root");
    let account = alloy_primitives::hex::encode(Sha256::digest(canonical.as_os_str().as_bytes()));
    let entry = keyring::Entry::new("ai.jecta.astatine.transaction-journal", &account)
        .expect("construct the disposable native credential entry");
    NativeAnchorCleanup(entry)
}

struct NativeAnchorCleanup(keyring::Entry);

impl Drop for NativeAnchorCleanup {
    fn drop(&mut self) {
        // The surrounding private-session harness owns the disposable keyring;
        // delete this root-scoped entry as an additional cleanup boundary.
        let _ = self.0.delete_credential();
    }
}

fn run_child(root: &Path, operation: &str, expected_session: Option<&str>) -> Output {
    let mut command = Command::new("timeout");
    command
        .args(["--signal=TERM", "--kill-after=5s", "45s"])
        .arg(std::env::current_exe().expect("resolve the test executable"))
        .args([
            "--ignored",
            "--exact",
            CHILD_TEST_NAME,
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ROOT_ENV, root)
        .env(CHILD_OPERATION_ENV, operation)
        .env(DISPOSABLE_STORE_ENV, "1")
        .env(QUALIFICATION_MODE_ENV, "provider")
        .env("ASTATINE_REQUIRE_NATIVE_CREDENTIAL_STORE", "1");
    match expected_session {
        Some(session) => {
            command.env(CHILD_SESSION_ENV, session);
        }
        None => {
            command.env_remove(CHILD_SESSION_ENV);
        }
    }
    command.output().expect("run bounded native restart child")
}

fn assert_child_passed(output: &Output, context: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "{context} failed: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed")
            || stderr.contains("test result: ok. 1 passed"),
        "{context} did not execute exactly one passing test: stdout={stdout:?} stderr={stderr:?}"
    );
}

fn assert_private_mode(path: &Path, expected: u32) {
    use std::os::unix::fs::PermissionsExt;

    let metadata = std::fs::metadata(path).expect("inspect private journal path");
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        expected,
        "unexpected permissions for {}",
        path.display()
    );
}

#[test]
#[ignore = "requires the isolated unlocked Secret Service provider; run from Linux qualification"]
fn linux_secret_service_authenticated_journal_restarts_across_processes() {
    require_disposable_provider();
    let root = tempfile::tempdir().expect("create disposable data root");
    let _cleanup = native_anchor_cleanup(root.path());
    let (store, _config, session_id) = seed_authenticated_journal(root.path());

    let journal_path = store
        .transaction_journal_path_for_test()
        .expect("resolve transaction journal path");
    assert_private_mode(root.path(), 0o700);
    assert_private_mode(&root.path().join("transactions"), 0o700);
    assert_private_mode(&journal_path, 0o600);
    assert_private_mode(&journal_path.with_file_name("miner.lock"), 0o600);

    // JournalAuthenticator uses the in-memory test backend under cfg(test).
    // Persist its exact checkpoint bytes in the live isolated Secret Service.
    let checkpoint = checkpoint_from_test_backend(&store);
    store
        .write_journal_anchor_to_os_for_test(checkpoint.as_slice())
        .expect("persist the journal checkpoint in the native Secret Service");
    let stored = store
        .read_journal_anchor_from_os_for_test()
        .expect("read back native checkpoint")
        .expect("native checkpoint exists");
    assert!(
        bool::from(stored.as_slice().ct_eq(checkpoint.as_slice())),
        "the native credential backend must persist the exact generated checkpoint"
    );

    let child = run_child(root.path(), "reopen", Some(&session_id));
    assert_child_passed(&child, "authenticated journal restart child");
}

#[test]
#[ignore = "requires the isolated unlocked Secret Service provider and a built application"]
fn linux_secret_service_production_recover_authenticates_journal_after_restart() {
    use std::os::unix::fs::DirBuilderExt;

    require_disposable_provider();
    let binary = std::env::var_os(APP_BINARY_ENV)
        .map(std::path::PathBuf::from)
        .expect("qualification must supply the built production application");
    assert!(binary.is_absolute() && binary.is_file());
    let config_home = tempfile::tempdir().expect("create disposable XDG config home");
    let root = config_home.path().join("astatine");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .expect("create private application data root");
    let _cleanup = native_anchor_cleanup(&root);
    let (store, config, _) = seed_authenticated_journal(&root);
    let snapshot = TransactionJournal::inspect_session(&store, &config).unwrap();
    assert!(snapshot.unresolved.is_empty() && snapshot.pending_transition.is_none());
    let checkpoint = checkpoint_from_test_backend(&store);
    store
        .write_journal_anchor_to_os_for_test(checkpoint.as_slice())
        .expect("persist synthetic journal checkpoint in the isolated native provider");

    // With no unresolved transactions, `recover` authenticates the journal and
    // exits before constructing an RPC client. It never unlocks or signs.
    let recover = || {
        Command::new("timeout")
            .args(["--signal=TERM", "--kill-after=5s", "45s"])
            .arg(&binary)
            .arg("recover")
            .env("XDG_CONFIG_HOME", config_home.path())
            .output()
            .expect("run the production application against the isolated provider")
    };
    for _ in 0..2 {
        let output = recover();
        assert!(
            output.status.success(),
            "production recovery failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("No unresolved transaction remains."),
            "production recovery did not reach the no-network success path"
        );
    }
    _cleanup
        .0
        .delete_credential()
        .expect("delete the disposable native checkpoint");
    let missing = recover();
    assert!(
        !missing.status.success(),
        "missing checkpoint must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("has no OS credential-store checkpoint"),
        "missing checkpoint failed for an unexpected reason"
    );
    store
        .write_journal_anchor_to_os_for_test(b"corrupt disposable checkpoint")
        .expect("write a malformed disposable native checkpoint");
    let corrupt = recover();
    assert!(
        !corrupt.status.success(),
        "corrupt checkpoint must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&corrupt.stderr).contains("checkpoint has an invalid length"),
        "corrupt checkpoint failed for an unexpected reason"
    );
}

#[test]
#[ignore = "requires the isolated unlocked Secret Service provider; run from Linux qualification"]
fn linux_secret_service_missing_checkpoint_fails_closed_after_restart() {
    require_disposable_provider();
    let root = tempfile::tempdir().expect("create disposable data root");
    let _cleanup = native_anchor_cleanup(root.path());
    let (_store, _config, _session_id) = seed_authenticated_journal(root.path());

    // Intentionally do not bridge the checkpoint into the native credential
    // store. The journal exists, but a fresh process must reject it.
    let child = run_child(root.path(), "missing-checkpoint", None);
    assert_child_passed(&child, "missing-checkpoint child");
}

#[test]
#[ignore = "requires the isolated unlocked Secret Service provider; run from Linux qualification"]
fn linux_secret_service_corrupt_checkpoint_fails_closed_after_restart() {
    require_disposable_provider();
    let root = tempfile::tempdir().expect("create disposable data root");
    let _cleanup = native_anchor_cleanup(root.path());
    let (store, _config, _session_id) = seed_authenticated_journal(root.path());
    store
        .write_journal_anchor_to_os_for_test(b"corrupt disposable checkpoint")
        .expect("write deliberately malformed checkpoint to disposable native store");

    let child = run_child(root.path(), "corrupt-checkpoint", None);
    assert_child_passed(&child, "corrupt-checkpoint child");
}

#[test]
#[ignore = "requires the isolated unlocked Secret Service provider; run from Linux qualification"]
fn linux_secret_service_interrupted_init_transition_recovers_across_processes() {
    require_disposable_provider();
    let root = tempfile::tempdir().expect("create disposable data root");
    let _cleanup = native_anchor_cleanup(root.path());
    let (store, previous_config, previous_session_id) = seed_authenticated_journal(root.path());

    let wallet = Address::from_str(TEST_WALLET).expect("test wallet address is valid");
    let mut proposed_config = previous_config.clone();
    proposed_config.per_session_spending_limit_inj = PROPOSED_LIMIT.to_owned();
    drop(
        TransactionJournal::open_for_init_session_transition(
            &store,
            &proposed_config,
            wallet,
            PREVIOUS_LIMIT.to_owned(),
            previous_config.wallet_address.clone(),
        )
        .expect("stage the journaled init transition without committing it"),
    );
    let pending = TransactionJournal::inspect_session(&store, &previous_config)
        .expect("inspect interrupted init transition");
    let pending = pending
        .pending_transition
        .expect("the journal records the interrupted init transition");
    assert_eq!(pending.previous_config_limit_inj, PREVIOUS_LIMIT);
    assert_eq!(pending.proposed_config_limit_inj, PROPOSED_LIMIT);

    let checkpoint = checkpoint_from_test_backend(&store);
    store
        .write_journal_anchor_to_os_for_test(checkpoint.as_slice())
        .expect("persist interrupted-transition checkpoint in native Secret Service");

    let child = run_child(root.path(), "recover-init", Some(&previous_session_id));
    assert_child_passed(&child, "interrupted init recovery child");

    let restarted = run_child(
        root.path(),
        "verify-init-recovered",
        Some(&previous_session_id),
    );
    assert_child_passed(&restarted, "post-recovery journal restart child");
}

#[test]
#[ignore = "requires a private D-Bus session with no Secret Service provider"]
fn linux_secret_service_absence_has_no_default_collection_and_fails_closed() {
    require_disposable_missing_mode();
    let owner = Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.DBus",
            "--object-path",
            "/org/freedesktop/DBus",
            "--method",
            "org.freedesktop.DBus.NameHasOwner",
            "org.freedesktop.secrets",
        ])
        .output()
        .expect("query private D-Bus service ownership");
    assert!(owner.status.success(), "D-Bus owner query failed");
    assert!(
        String::from_utf8_lossy(&owner.stdout).contains("false"),
        "missing mode must not expose a Secret Service owner"
    );

    let alias = Command::new("gdbus")
        .args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.secrets",
            "--object-path",
            "/org/freedesktop/secrets",
            "--method",
            "org.freedesktop.Secret.Service.ReadAlias",
            "default",
        ])
        .output()
        .expect("query default Secret Service collection alias");
    assert!(
        !alias.status.success(),
        "there must be no resolvable default collection when the provider is absent"
    );

    let root = tempfile::tempdir().expect("create disposable data root");
    let store = ConfigStore::at_root(root.path().to_path_buf());
    assert!(
        store.read_journal_anchor_from_os_for_test().is_err(),
        "native checkpoint reads must fail closed without a default collection/provider"
    );
    assert!(
        store
            .write_journal_anchor_to_os_for_test(b"disposable-test-only")
            .is_err(),
        "native checkpoint writes must fail closed without a default collection/provider"
    );
    assert!(
        store
            .read_transaction_journal()
            .expect("inspect journal path")
            .is_none(),
        "failed native checkpoint access must not create a journal fallback"
    );
}

#[test]
#[ignore = "child probe; invoked by the Linux Secret Service Phase B parent tests"]
fn linux_secret_service_phase_b_child_probe() {
    require_disposable_provider();
    let root = std::env::var_os(CHILD_ROOT_ENV)
        .map(std::path::PathBuf::from)
        .expect("child probe requires its parent-provided data root");
    let private_tmp = std::env::var_os("TMPDIR")
        .map(std::path::PathBuf::from)
        .expect("child probe requires the private-session TMPDIR");
    let canonical_tmp = std::fs::canonicalize(&private_tmp).expect("canonicalize private TMPDIR");
    let canonical_root = std::fs::canonicalize(&root).expect("canonicalize child data root");
    assert!(
        canonical_root != canonical_tmp && canonical_root.starts_with(&canonical_tmp),
        "child data root must be inside the private-session TMPDIR"
    );
    assert_private_mode(&canonical_tmp, 0o700);
    assert_private_mode(&canonical_root, 0o700);
    let operation = std::env::var(CHILD_OPERATION_ENV)
        .expect("child probe requires its parent-provided operation");
    let store = ConfigStore::at_root(root);

    match operation.as_str() {
        "reopen" => {
            bridge_native_checkpoint(&store);
            let config = store.load().expect("load journal configuration");
            let snapshot = TransactionJournal::inspect_session(&store, &config)
                .expect("authenticate journal with checkpoint read from native backend");
            assert_expected_session(&snapshot.session_id);
            assert!(snapshot.pending_transition.is_none());
        }
        "missing-checkpoint" => {
            assert!(
                store
                    .read_journal_anchor_from_os_for_test()
                    .expect("read missing native checkpoint")
                    .is_none(),
                "the isolated native credential store must have no checkpoint for this root"
            );
            let config = store.load().expect("load journal configuration");
            let error = TransactionJournal::inspect_session(&store, &config)
                .expect_err("authenticated journal without its checkpoint must be rejected");
            assert!(
                format!("{error:#}").contains("has no OS credential-store checkpoint"),
                "unexpected missing-checkpoint error: {error:#}"
            );
        }
        "corrupt-checkpoint" => {
            bridge_native_checkpoint(&store);
            let config = store.load().expect("load journal configuration");
            let error = TransactionJournal::inspect_session(&store, &config)
                .expect_err("malformed native checkpoint must be rejected");
            assert!(
                format!("{error:#}").contains("checkpoint has an invalid length"),
                "unexpected corrupt-checkpoint error: {error:#}"
            );
        }
        "recover-init" => {
            bridge_native_checkpoint(&store);
            let mut config = store.load().expect("load pre-transition configuration");
            assert_eq!(config.per_session_spending_limit_inj, PREVIOUS_LIMIT);
            let pending = TransactionJournal::inspect_session(&store, &config)
                .expect("authenticate interrupted init journal")
                .pending_transition
                .expect("interrupted init is present after process restart");
            assert_eq!(pending.previous_config_limit_inj, PREVIOUS_LIMIT);
            assert_eq!(pending.proposed_config_limit_inj, PROPOSED_LIMIT);
            assert!(
                TransactionJournal::resolve_pending_session_transition(&store, &mut config, false,)
                    .expect("roll back the interrupted init transition")
            );
            assert_eq!(config.per_session_spending_limit_inj, PREVIOUS_LIMIT);
            let recovered = TransactionJournal::inspect_session(&store, &config)
                .expect("verify rolled-back authenticated journal");
            assert_expected_session(&recovered.session_id);
            assert!(recovered.pending_transition.is_none());

            // Persist the resulting test-backend checkpoint back into the live
            // disposable Secret Service for the final independent restart.
            let checkpoint = checkpoint_from_test_backend(&store);
            store
                .write_journal_anchor_to_os_for_test(checkpoint.as_slice())
                .expect("persist recovered checkpoint in native Secret Service");
        }
        "verify-init-recovered" => {
            bridge_native_checkpoint(&store);
            let config = store.load().expect("load recovered configuration");
            assert_eq!(config.per_session_spending_limit_inj, PREVIOUS_LIMIT);
            let recovered = TransactionJournal::inspect_session(&store, &config)
                .expect("reopen recovered journal from a second process");
            assert_expected_session(&recovered.session_id);
            assert!(recovered.pending_transition.is_none());
        }
        other => panic!("unsupported child probe operation: {other}"),
    }
}

fn bridge_native_checkpoint(store: &ConfigStore) {
    let checkpoint = store
        .read_journal_anchor_from_os_for_test()
        .expect("read checkpoint from the real native credential backend")
        .expect("native checkpoint exists");
    store
        .write_journal_anchor(checkpoint.as_slice())
        .expect("bridge native checkpoint into this process's test-only backend");
}

fn assert_expected_session(session_id: &Option<String>) {
    let expected = std::env::var(CHILD_SESSION_ENV)
        .expect("parent must provide the expected session identifier");
    assert_eq!(session_id.as_deref(), Some(expected.as_str()));
}

#[test]
fn native_phase_b_provider_guard_rejects_unmarked_environment_before_store_access() {
    let root = tempfile::tempdir().expect("create disposable data root");
    let child = Command::new(std::env::current_exe().expect("resolve test executable"))
        .args(["--ignored", "--exact", CHILD_TEST_NAME, "--nocapture"])
        .env(CHILD_ROOT_ENV, root.path())
        .env(CHILD_OPERATION_ENV, "reopen")
        .env_remove(DISPOSABLE_STORE_ENV)
        .output()
        .expect("run native-store guard child");
    assert!(
        !child.status.success(),
        "the native-store child must refuse to run without the disposable marker"
    );
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(
        output.contains(
            "refusing native credential-store access without the disposable-store marker"
        ),
        "unexpected unmarked child output: {output:?}"
    );
}
