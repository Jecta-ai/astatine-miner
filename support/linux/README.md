# Linux native qualification (Phase B)

This directory contains test-only infrastructure for
`.github/workflows/linux-native-qualification.yml`, which runs on Ubuntu 24.04
x86_64. It is separate from the general CI workflow and does not publish, sign,
attest, create releases, or contact a public RPC endpoint.

## What the workflow exercises

| Job | Evidence |
| --- | --- |
| `workflow-safety` | Full-SHA action pins, release-authority tripwires, shell syntax, release inventory JSON, offline fixture provenance. |
| `secret-service` (`provider`) | Unlocked disposable GNOME Keyring; test-only `ASTATINE_REQUIRE_NATIVE_CREDENTIAL_STORE=1` and `ASTATINE_DISPOSABLE_CREDENTIAL_STORE=1`; native credential-entry write/read in the parent and a second test process; a separate data root must not see the first root's credential. |
| `secret-service` (`locked`) | The keyring is created unlocked, the daemon is stopped, then restarted without the password. The default collection is verified locked. The ambient-bus assertion verifies the service is present and the default collection is locked; the child probe must not obtain a secret, must reject the credential-store write within a bounded wait, and must not create a plaintext journal. |
| `secret-service` (`missing`) | Private D-Bus session with no service activation and no provider. The unavailable-bus test and the ambient-bus child probe must both fail closed. |
| `production-journal` | The production executable's interactive `init` creates a v10 authenticated journal and its native Secret Service checkpoint; two fresh production `recover` processes authenticate them; a copied data root fails closed without its own checkpoint; `SIGKILL` at a real init prompt remains recoverable; an unavailable provider fails closed without changing the journal. |
| `signals-pty` | Linux `SIGHUP`, `SIGINT`, and `SIGTERM` cancellation and terminal restoration on disposable controlling PTYs; init, wallet import, wallet creation/import/unlock prompts; cross-process journal-lock contention; zero-cap read-only behavior; maximum-exposure/reserve, checkpoint-crash, and copied-data-root guards. |
| `anvil-lifecycle` | Pinned Anvil archive and source-commit verification; offline fixture provenance; local-loopback lifecycle and a test-only native-checkpoint SIGKILL/restart after broadcast. Consult the hosted run for results on the exact commit. |
| `ssh-loopback` | Ephemeral loopback-only `sshd` and disposable keys; verifies PTY allocation and runs the production application through a real SSH disconnect, reconnect and native-checkpoint recovery. Resize evidence is limited to local PTY resize and application responsiveness, not remote window-size propagation. |

## Isolation and secret handling

- Every Secret Service mode gets a private `dbus-daemon` instance with a minimal
  configuration that excludes service activation directories, plus isolated
  `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_CACHE_HOME`,
  `XDG_RUNTIME_DIR`, and `TMPDIR`.
- The disposable keyring password is generated in memory, passed to
  `gnome-keyring-daemon` on stdin, and never printed, exported in logs, or
  written to the workspace. The native persistence test refuses to run unless
  `ASTATINE_DISPOSABLE_CREDENTIAL_STORE=1` and
  `ASTATINE_QUALIFICATION_MODE=provider` are set by the qualification script.
- The locked state intentionally restarts the daemon without the password. This
  avoids the daemon transparently unlocking a just-locked collection from its
  cached login secret, which would make the "locked" label misleading.
- On Linux, the keyring client can report a locked collection as no matching
  entry rather than an access error. The probe therefore requires the
  checkpoint **write** to fail and verifies that no transaction journal is
  created. It also rejects any secret returned from a locked or unavailable
  provider.
- The SSH smoke places only the public `authorized_keys` in a separate
  0755 `/tmp` directory because GitHub's `RUNNER_TEMP` can sit beneath a
  non-traversable `/home/runner`; private keys, host keys, logs, and the sshd
  configuration remain in a 0700 work directory.
- The SSH job creates a disposable local user with a random password marker
  (password authentication is disabled), generates host and user keys under
  `RUNNER_TEMP`, uses a custom `sshd` configuration bound to `127.0.0.1` on an
  ephemeral high port, disables password/PAM/agent/TCP/stream-local forwarding,
  and deletes the key directory and user in a trap. The script refuses to run
  outside a disposable CI runner without an explicit override.
- The workflow uses only `actions/checkout` pinned to a full commit SHA and does
  not reference repository credentials.

## Pinned local Anvil

`anvil-release.json` records the test-only upstream release identity:

- Release: `foundry-rs/foundry` `v1.9.0`
- Source commit: `6056c5845d34205a83cf7108042adb137325c9df`
- Linux amd64 asset: `foundry_v1.9.0_linux_amd64.tar.gz`
- Archive bytes: `118268939`
- SHA-256: `8d17599b42e3139f1a9c171be3798c4ed8e743ae17b84cc3435e57bf2a51ae99`

`install-anvil.sh` downloads over HTTPS with bounded transfer time, verifies the
pinned digest and exact archive size before extracting, checks that the result is an x86-64 ELF
executable, and requires the version banner to report the pinned version and
source commit. The upstream `.sha256` URL and Sigstore attestation URL are
recorded but are **not** fetched or verified by the workflow; the enforced
control is the pinned digest plus the version-banner commit.

Anvil is started only by the existing `#[ignore]` integration tests, on
`127.0.0.1` with a loopback fixture and chain ID `1439`. No public RPC URL is
configured.

## Unqualified: production prepare/broadcast interruption (P2)

The test-only native-provider Anvil harness now exercises SIGKILL after a
broadcast and authenticates the same journal in a fresh test process. It counts
raw sends at a loopback boundary and checks authorization and exposure. It is
not the production CLI and does not establish termination between preparation
and broadcast acknowledgement, or zero-cap recovery after an actual process
kill. The remaining production-path blockers are architectural:

- The production CLI always loads the embedded Testnet manifest
  (`src/deployment.rs:115-124`), requires the selected RPC to report the
  manifest chain ID (`src/rpc.rs:475-503`), and verifies the manifest's pinned
  token and node addresses plus runtime code hashes
  (`src/rpc.rs:1793-1847`). An RPC override changes only the endpoint; it cannot
  select alternate contract addresses. The helper that accepts arbitrary local
  Anvil addresses is `#[cfg(test)]` (`src/rpc.rs:1412-1481`).
- Under `cfg(test)`, journal-anchor reads and writes use a process-local map
  (`src/config.rs:332-342` and `src/config.rs:394-428`); the production
  `not(test)` branches use the native OS credential store. Explicit test-only
  helpers can also access that store. A fresh test process therefore
  cannot authenticate a checkpoint written by another test process without the
  explicit bridge used by `src/linux_secret_service_phase_b_tests.rs:196-212`.

What the existing tests do prove, all without a fresh terminated process:

| Test | Boundary |
| --- | --- |
| `transaction::tests::transaction_manager_local_anvil_lifecycle_recovery_reorg_and_spending_cap` | Ignored loopback-Anvil lifecycle with checked-in fixtures; restart is an in-process manager reopen. |
| `transaction::tests::cancellation_during_pending_broadcast_preserves_prepared_liability` | Task abort after preparation, zero raw sends, in-process reopen. |
| `transaction::tests::shutdown_after_prepare_attempts_one_in_flight_broadcast_then_preserves_unknown` | Injected post-prepare shutdown, one delayed send, in-process reconcile. |
| `transaction::tests::broadcast_acknowledgement_survives_cancellation_and_restart_never_rebroadcasts` | One acknowledged send, no resend after task cancellation and in-process reopen. |
| `transaction::tests::restart_without_observation_preserves_all_transaction_stages_without_rebroadcast` | Synthesized journal stages against an unavailable endpoint; same process. |
| `transaction::tests::zero_cap_preserves_unresolved_liability_without_new_authorization` | Preserves `Prepared`/`Broadcast` liability and refuses new authorization at zero cap; no process termination. |
| `transaction::tests::journal_sigkill_releases_lock_and_restart_preserves_unresolved_states` | SIGKILLs a child that only holds the journal lock; the parent seeded and reopens the journal. |

### Narrowest manual qualification procedure

No complete, safe production-CLI procedure is established with the current repository.
Do not fork a public endpoint, run paid mining, change the pinned production
manifest, or manually modify an authenticated journal to simulate this test.
Qualification requires a separately reviewed, isolated local deployment and a
way to observe and interrupt the actual boundary while retaining the native
checkpoint across processes. Until those prerequisites exist, P2 remains
**BLOCKED**, not passed.

The following component checks are reproducible on disposable Linux x86_64;
they do not prove the combined process-kill scenario:

```sh
python3 support/verify-fixture-provenance.py
bash support/linux/install-anvil.sh "$HOME/.local/astatine-foundry"
PATH="$HOME/.local/astatine-foundry/bin:$PATH" \
  RUSTUP_TOOLCHAIN=1.94.1 cargo test --locked --bin astatine -- \
  --ignored --exact \
  transaction::tests::transaction_manager_local_anvil_lifecycle_recovery_reorg_and_spending_cap \
  --nocapture --test-threads=1
for t in \
  transaction::tests::cancellation_during_pending_broadcast_preserves_prepared_liability \
  transaction::tests::shutdown_after_prepare_attempts_one_in_flight_broadcast_then_preserves_unknown \
  transaction::tests::broadcast_acknowledgement_survives_cancellation_and_restart_never_rebroadcasts \
  transaction::tests::restart_without_observation_preserves_all_transaction_stages_without_rebroadcast \
  transaction::tests::zero_cap_preserves_unresolved_liability_without_new_authorization
do
  RUSTUP_TOOLCHAIN=1.94.1 cargo test --locked --bin astatine -- \
    --exact "$t" --nocapture --test-threads=1 || exit 1
done
```

Require each named test to report exactly one passing test. The first exercises
loopback Anvil; the others use synthetic RPC and in-process restarts. Neither
proves production restart with a native checkpoint after actual termination.

## Local reproduction

The scripts require Linux. On macOS, use an amd64 Linux container. The Anvil
asset is Linux-only; do not substitute a Homebrew binary when checking release
provenance.

```sh
# Secret Service state probe (provider, locked, or missing)
bash support/linux/run-private-session.sh provider -- /bin/true
bash support/linux/run-private-session.sh locked -- /bin/true
bash support/linux/run-private-session.sh missing -- /bin/true

# Native persistence test inside the disposable provider
ASTATINE_QUALIFICATION_TIMEOUT_SECONDS=300 \
  bash support/linux/run-private-session.sh provider -- \
  env RUSTUP_TOOLCHAIN=1.94.1 cargo test --locked --bin astatine -- --ignored --exact \
  config::tests::native_journal_anchor_persists_across_processes_and_is_root_scoped --nocapture

# Production-created journal/checkpoint, restart, copied-root, and fail-closed checks
cargo build --locked --bin astatine
bash support/linux/run-private-session.sh provider -- \
  python3 support/linux/qualify-production-journal.py target/debug/astatine

# Pinned Anvil install (Linux x86_64)
bash support/linux/install-anvil.sh "$HOME/.local/astatine-foundry"

# Offline fixture checks
python3 support/verify-fixture-provenance.py
python3 -m unittest discover -s support/tests -p 'test_*.py'
```

## Honest limits

- GitHub-hosted results apply only to the exact commit tested. Local validation
  using Linux containers or macOS is not a substitute for a hosted-runner run.
- The SSH lifecycle harness exercises a real client disconnect and reconnect on
  the hosted runner when its job passes; consult the run for the exact commit.
  It verifies local PTY resize and application responsiveness, not propagation
  of the new dimensions to the remote PTY. Host-side terminal recording and
  external SSH server policy remain **NOT TESTED**.
- The Foundry Sigstore attestation, the upstream `.sha256` asset fetch, and GPG
  signatures are recorded but **NOT VERIFIED** by the workflow; only the pinned
  digest and version-banner commit are enforced.
- The locked probe verifies fail-closed behavior on a headless private bus. It
  does not represent a desktop keyring that can display an interactive unlock
  prompt.
- The `no-default` mode tests a running Secret Service with no default
  collection separately from an absent provider. Consult the hosted workflow
  result for the exact commit before treating that case as qualified.
- The production `recover` restart test in `linux_secret_service_phase_b_tests.rs`
  authenticates a journal created by the test harness with its checkpoint copied
  into the native provider. The separate `production-journal` job covers the
  no-bridge case: production `init` creates the journal and checkpoint, and
  fresh production `recover` processes authenticate them. Neither test
  interrupts the process inside an atomic journal write; the interrupted-init
  check kills at a real user-visible consent prompt before the write.
- The native-provider Anvil crash test is a test-only path, not the production
  CLI. It exercises a post-broadcast kill; the prepare-to-broadcast crash window
  and zero-cap recovery following an actual process kill remain **NOT TESTED**.
  The production CLI cannot target arbitrary local deployments.
- Physical GPU mining, Windows credential storage, macOS Keychain behavior, the
  real bundled Testnet deployment, paid mining, public RPC endpoints, releases,
  signing, and deployment remain outside this qualification.
- A production host still needs an unlocked Secret Service before paid mining.
  The disposable CI keyring proves the code path, not the operator's host state.
