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
| `signals-pty` | Linux `SIGHUP`, `SIGINT`, and `SIGTERM` cancellation and terminal restoration on disposable controlling PTYs; init, wallet import, wallet creation/import/unlock prompts; cross-process journal-lock contention; zero-cap read-only behavior; maximum-exposure/reserve, checkpoint-crash, and copied-data-root guards. |
| `anvil-lifecycle` | Pinned Anvil archive and source-commit verification; offline fixture provenance; local-loopback lifecycle, recovery, reorg, spending-cap, and nine-node startup tests from the checked-in bytecode fixtures. |
| `ssh-loopback` | Ephemeral loopback-only `sshd` with an ephemeral key; verifies PTY allocation, `isatty`, and `/dev/tty` accessibility. |

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

# Pinned Anvil install (Linux x86_64)
bash support/linux/install-anvil.sh "$HOME/.local/astatine-foundry"

# Offline fixture checks
python3 support/verify-fixture-provenance.py
python3 -m unittest discover -s support/tests -p 'test_*.py'
```

## Honest limits

- The GitHub-hosted workflow has not been executed by this source tree until the
  branch is pushed or opened as a pull request. Local validation used Linux
  containers and the native macOS test suite; it is not a substitute for a
  hosted-runner run.
- The SSH loopback job verifies transport and PTY behavior only. Wallet prompts
  over SSH, including host-side terminal recording and SSH server policy, remain
  **NOT TESTED** here.
- The Foundry Sigstore attestation, the upstream `.sha256` asset fetch, and GPG
  signatures are recorded but **NOT VERIFIED** by the workflow; only the pinned
  digest and version-banner commit are enforced.
- The locked probe verifies fail-closed behavior on a headless private bus. It
  does not represent a desktop keyring that can display an interactive unlock
  prompt.
- Physical GPU mining, Windows credential storage, macOS Keychain behavior, the
  real bundled Testnet deployment, paid mining, public RPC endpoints, releases,
  signing, and deployment remain outside this qualification.
- A production host still needs an unlocked Secret Service before paid mining.
  The disposable CI keyring proves the code path, not the operator's host state.
