# Astatine Miner

Astatine is an open-source Proof-of-Work mining project on Injective EVM. Miners search for valid hashes locally on CPUs or compatible GPUs; Injective contracts verify submissions and settle each work window on-chain. GPU acceleration does not change the canonical SHA-256d work algorithm.

The mining table labels an Astatine mining-window ID as `BLOCK`; this is not the separate Injective EVM block height.

## Nine-node mining

The protocol has nine independent mining nodes, each with its own work and window state. A miner can work across all nine nodes or select specific nodes with `--nodes`. Each selected node is observed and scheduled independently. Inactive nodes report `WAIT GENESIS`; the CLI never calls `activateGenesis()`. See [Nine-node activation and genesis](#nine-node-activation-and-genesis) for activation checks and scheduling behavior.

## Scope and safety

This repository contains the operational Rust command-line miner source. It does not publish, sign, or install binaries, and it provides no self-updater, automatic installer, or automatic rollback. No public binary release is currently published. The [manual macOS ARM64 installation and safety guide](MACOS_ARM64.md) describes the intended verified-archive workflow for a future release.

Astatine trusts the selected RPC provider for blockchain state, receipts, and reward evidence; it does not cryptographically authenticate all RPC data. Automatic AST reward forwarding is disabled. Paid proof submission and finalization consume INJ fees and gas and do not guarantee a reward. The bundled deployment targets Injective Testnet; mainnet transaction signing is disabled. Keep wallets, credentials, configuration, and transaction journals separate from executables, and never overwrite or delete state during an upgrade. Windows native distribution is not qualified until sensitive-file permissions in pre-existing directories, including permissive ACLs, have been verified on Windows. Historical build or GPU results do not establish that qualification; this Windows-only gate does not qualify or disqualify a macOS build.

## Build

Build from source with the pinned Rust toolchain:

```sh
cargo build --locked --release
./target/release/astatine --version
```

The crate declares `rust-version = "1.94.1"`, and CI builds with that Rust toolchain. `support/paste-shim` is a local patch of the `paste` crate and must remain in place.

### Repository identity

`support/release-repository.txt` is a compiled build input containing only an owner/name pair; `build.rs` emits `ASTATINE_RELEASE_REPOSITORY=OWNER/REPOSITORY` and does not read or emit a numeric repository ID. The miner does not read this variable at runtime. Numeric repository IDs and release commit identities must be verified from the hosting service and the authenticated release record; do not infer them from this source tree, an older binary, a checksum file, or an installation guide. Changing this file, or any other compiled input, requires a rebuild and requalification rather than a documentation-only edit.

Stop the miner before replacing an executable. Keep the previous executable and preserve configuration, wallets, credentials and transaction journals separately. On Linux the default state is under `${XDG_CONFIG_HOME:-$HOME/.config}/astatine`, on macOS under `~/Library/Application Support/Astatine`, and on Windows under `%APPDATA%\Astatine`. Custom state locations may differ. Never overwrite or delete state during an upgrade; downgrade compatibility is not guaranteed.

## Mining operation

### Paid-session authorization limit

Paid mining checks the durable remaining session authorization against the canonical 0.003 INJ proof fee. When less than one proof fee remains, the run latches `SESSION LIMIT REACHED`: CPU/GPU workers stop, queued proofs are discarded, and no new proof or finalization transaction is signed. The comparison is strict, so exactly 0.003 INJ remaining is not treated as exhausted. The authorization counter is not reduced by a later receipt or observer snapshot.

The dashboard remains open until a shutdown signal, displays the terminal state, and continues read-only chain observation and recovery of transactions that were already in flight. If the observer stalls or fails, the miner reports monitoring degradation and marks its last verified block stale; it does not exit or start a new session automatically. Starting below the proof-fee threshold skips worker initialization and signer unlocking. In per-run policy mode, a later explicit `astatine mine` invocation starts its own fresh session under the existing approved policy; the current run is never automatically refilled.

### Graceful shutdown signals

On Unix, `SIGINT` (Ctrl+C) and `SIGTERM` take the same graceful shutdown path, including on macOS; Linux additionally handles `SIGHUP`. macOS does not install a `SIGHUP` handler, so terminal-hangup semantics remain unchanged there. Windows keeps the Tokio Ctrl+C handler.

On Unix, the delivery flag is set directly from the operating-system signal handler. The transaction manager acquires an exclusive signing permit immediately before producing a signature; successful permit acquisition followed by a delivery re-check is the pre-sign linearization point. A stop visible at that barrier prevents signing, but any authorization already persisted remains charged even when no transaction is signed or broadcast. The pre-authorization check rejects an already-visible shutdown; a shutdown racing with authorization persistence can still leave that authorization charged. A permit acquired before delivery classifies that signing section as already in flight. Mining workers stop and queued proofs are discarded without submission. A transaction whose authorization and local signature already completed before the stop is never silently dropped: its durable `Prepared` journal entry, charged maximum exposure, and unresolved liability are preserved for read-only recovery. It is not rebroadcast. If unresolved exposure keeps the legacy session open, the process reports that recovery is required rather than deleting or rewriting the journal. A restart requires the documented recovery or explicit session confirmation.

A signal delivered during the final synchronous signing step cannot un-sign local memory, but the journal authorization is durable before signing and the raw transaction is not broadcast without the prepared entry. Additional signals are ignored while graceful shutdown completes. If shutdown persistence fails, the error is reported; a subsequent legacy-session resume requires explicit confirmation.

Signal handlers are installed at the start of the mining or recovery command. The operating system installs one signal handler at a time, so a signal delivered before its specific handler is installed retains the OS default disposition. That residual process-start window precedes configuration, journal, and signing activity; it cannot be made atomic with the available OS APIs.

An open legacy spending session is never silently resumed across a process boundary. On restart, `astatine mine` asks for explicit confirmation before reusing the session and its remaining authorization, including when the previous process crashed or could not persist the final session close. The prompt defaults to no; declining leaves the session, authorization counter, and any liabilities unchanged. Use `astatine init` or `astatine mine --new-session` to explicitly authorize a new session. Per-run sessions are unaffected, and unresolved legacy exposure still follows the `astatine recover` path.

### Competitive proof resubmission

Mining continues after a proof is submitted. The CLI can submit another proof for the same node and window only after a fresh verified chain snapshot confirms that it is strictly better than the current incumbent. Each additional on-chain submission costs the current `0.003 INJ` fee plus gas; if another miner takes the lead after preflight but before inclusion, the contract can reject the proof while the fee is still spent. A temporary lead does not guarantee a reward: only the winning wallet at window finalization receives that window's reward.

### GPU mining

CPU remains the default and requires no GPU driver:

```sh
astatine mine --device cpu
```

Use a validated physical GPU explicitly, or request GPU preference with automatic CPU fallback:

```sh
astatine mine --device gpu
astatine mine --device auto
astatine mine --device gpu --nodes 1,3,5
astatine mine --device gpu --compute-only
```

Explicit `gpu` mode validates the selected physical GPU backend by executing its canonical SHA-256d self-test before mining. On supported Linux and Windows systems, native CUDA is preferred; the existing physical Vulkan, DirectX 12, and Metal backends remain available where supported. If no physical GPU backend passes its self-test, explicit GPU mode stops with an actionable error and never substitutes CPU mining. `auto` performs a short canonical-work comparison and chooses GPU only when its measured throughput is more than 10% faster than CPU; otherwise it chooses CPU. Auto mode also falls back to CPU if GPU operation later fails. Any in-flight GPU nonce range is abandoned on failure, not reassigned. `--threads` controls CPU mining workers; GPU mode uses a dedicated controller and does not start the full CPU mining pool.

Every GPU candidate is rehashed with the canonical Rust `WorkHasher` before it enters the existing bounded proof inbox. The existing proof preflight, journal, signing, submission, finalization, and reward-reconciliation paths remain authoritative. The GPU module does not own wallets, RPC connections, or transaction signing.

### Native NVIDIA CUDA mining

On Linux x86_64/aarch64 and Windows x86_64, `--device gpu` prefers the native CUDA Driver API backend when an NVIDIA device passes its runtime SHA-256d self-test. A compatible CUDA 12.0-or-newer driver and compute capability 5.2 or newer are required. The miner dynamically loads the driver (`libcuda.so.1` on Linux or `nvcuda.dll` on Windows); a CUDA Toolkit, `nvcc`, NVRTC, Vulkan graphics libraries, and a display server are not required on the mining host.

The CUDA kernel is precompiled PTX embedded in the executable. Its `.cu` source and pinned-container reproduction instructions are in `src/gpu/cuda/` and `support/cuda/`. Every CUDA candidate is rehashed by the canonical CPU implementation. CUDA is only selected after actual kernel execution and self-test; if it is unavailable, existing physical Vulkan/DirectX backends may be tried. Explicit GPU mode never substitutes CPU hashing.

### Nine-node activation and genesis

Mining can be started before selected contracts activate. Verified, inactive nodes show `WAIT GENESIS`; when all selected nodes are inactive the dashboard shows `WAITING FOR GENESIS`. The observer checks selected inactive nodes approximately once per second with read-only `work()` calls and a bounded three-node concurrency limit. Active nodes keep the normal observer cadence.

An activation candidate triggers the existing canonical full-snapshot path. The miner rechecks the chain ID, pinned runtime code, ABI coherence and canonical Rust/Solidity `computeWorkHash` parity before publishing eligible work to the existing node scheduler. Partial activation is handled independently per node; nine-node atomic Coordinator activation is discovered by the same mechanism. The CLI never calls `activateGenesis()` or the Coordinator, never asks the user to restart, and does not create mining nonce ranges or paid transactions for unstarted nodes. There is no new init configuration.

```sh
astatine mine --device gpu --nodes 1,2,3,4,5,6,7,8,9
```

The existing proof verification, spending cap, minimum reserve, transaction journal, recovery, and reorganization handling remain in force after activation. Automatic AST reward forwarding remains disabled because the selected RPC can fabricate reward evidence.

### Pinned local Anvil fixtures

Lifecycle and nine-node Anvil tests use checked-in bytecode fixtures and do not build adjacent contract worktrees. The miner fixture is pinned to Solidity source commit `80e8f7cbeb21b18bc5f7475d8b751c9d9e8fb9d1`; the Genesis Coordinator fixture is pinned to `c710b4d7add5f10de326487d0ff851eb926499c6`. The local `MockAST` remains a test-only fixture from its separately recorded source. The miner fixture's `work().submissionFee` is validated against the protocol constant `3000000000000000` wei (`0.003 INJ`). Fixture provenance, hashes, consumers, and regeneration limits are recorded in [tests/fixtures/PROVENANCE.json](tests/fixtures/PROVENANCE.json) and summarized in [tests/fixtures/README.md](tests/fixtures/README.md); `support/verify-fixture-provenance.py` rechecks the inventory offline.

Inspect local compute adapters and run their real shader self-test without connecting to RPC or unlocking a wallet:

```sh
astatine devices
```

The wgpu backends target Metal on macOS, Direct3D 12 or Vulkan on Windows, and Vulkan on Linux. Driver and hardware support varies. Native CUDA Driver API support is included for compatible NVIDIA devices.

Physical mining tests have been performed on Linux and macOS, including NVIDIA CUDA mining on Linux and Apple Metal mining on macOS. Physical mining and GPU runtime testing have not yet been performed on Windows. Windows builds and automated CI tests have passed, but Windows GPU functionality remains physically unverified.

Those are historical reports, not platform qualification of a current release. macOS GPU behavior has been reported as satisfactory; raw GPU and paid-transaction acceptance logs are not attached here. The documented archive target is macOS ARM64 only; Linux and Windows require separate native release acceptance.

| Platform / GPU | Preferred backend | Recorded validation |
|---|---|---|
| Linux x86_64 · NVIDIA RTX 3070 | CUDA Driver API | Physical CUDA mining and runtime testing performed |
| macOS · Apple Silicon M4 | Metal | Physical Metal mining and shader/Anvil lifecycle testing performed |
| Windows x86_64 · NVIDIA GPU | CUDA Driver API | Native builds and automated CI passed; no physical mining or GPU runtime testing |
| Other supported adapters | Vulkan / Direct3D 12 / Metal | Runtime selection still requires the backend self-test; physical validation depends on the specific device and driver |

Adapter enumeration or a successful native build is not itself a GPU correctness test.

Run a local, read-only CPU/GPU benchmark on identical canonical work (no wallet or RPC required):

```sh
astatine benchmark
astatine benchmark --seconds 10 --threads 4
```

The report includes three repeated CPU/GPU samples by default, compares results with the supplied Testnet.11 M4/Metal reference and historical Testnet.10 reference, separates initialization/self-test time from timed throughput, and records host-stage timings and JSON output when requested. GPU compute timestamps are reported only where supported; otherwise dispatch-to-readback is identified as wall latency. `--profile` sweeps all supported batch and workgroup sizes; `--compare-full-sha` compares full SHA-256 with the cached-midstate path, and `--serial` disables the bounded two-batch overlap for comparison. Example:

```sh
astatine benchmark --seconds 10 --threads 4 --batch-size 262144 --workgroup-size 32 --compare-full-sha --output-json gpu-ab.json
```

Use measured results for the installed hardware. The GPU shader implements SHA-256d only; it does not alter the PoW protocol.

Measured throughput depends on the installed hardware and driver, so run `astatine benchmark` on the target machine. Metal exposes no wgpu GPU timestamp queries on the tested adapter, so dispatch-to-readback is wall latency, not isolated shader time.

## Usage

```sh
astatine init
astatine init --per-run-sessions
astatine mine
astatine recover
astatine mine --device cpu
astatine mine --new-session
astatine mine --device gpu --nodes 1,2,3,4,5,6,7,8,9
astatine mine --device auto --nodes 1,3,5
astatine mine --device gpu --compute-only
astatine devices
astatine benchmark
astatine wallet address
```

`astatine init` configures the wallet, network, RPC, CPU budget, reserve, authorization ceiling, and confirmation depth. New installs use a 1 INJ per-run ceiling by default; `astatine init --spending-limit-inj AMOUNT` changes the saved ceiling. During init, the owner approves a persistent policy bound to the selected wallet and network. Each later explicit paid `astatine mine` invocation automatically creates one fresh run session under that policy when the confirmed balance can cover the full configured ceiling after the reserve and unresolved liabilities; a full-ceiling run needs no additional prompt. If the safe cap is lower, the miner asks for consent to use a temporary, rounded-down cap. The locked journal and balance are rechecked before session creation, so a second prompt can occur if that recheck lowers the safe cap again. Reduced caps are not written back to configuration and never grow during a run. Multiple runs can spend more than one run's cap in aggregate. Changing the approved ceiling, reserve, wallet, network, or policy requires explicit reauthorization. Existing schema-v1 accounts retain legacy cumulative-session behavior until the owner explicitly migrates with `astatine init --per-run-sessions` or accepts the interactive migration prompt. `astatine mine --compute-only` hashes verified work without unlocking, signing, changing a session, or broadcasting. In per-run mode, unresolved transactions remain journaled and are reconciled read-only while live hashing and fresh-run signing continue; any new send still requires a distinct pending nonce, sufficient balance after all reserved exposure, and remaining run cap. `astatine recover` can reconcile unresolved transactions from a closed per-run session without reopening it, and never unlocks, signs, or broadcasts. Prior maximum authorization is never refunded. Historical reward reconciliation runs in the background so live proof work can continue while older events are checked against the selected RPC. Interactive terminals use a subtle spinner, while redirected output uses plain-text progress. The mining dashboard shows live node state, RPC-reported INJ and AST balances, RPC-reported rewards for the current invocation, hashrate, transaction state, current-run maximum authorization, remaining run allowance, and RPC-reported actual cost. It distinguishes proof checking, signed-but-not-yet-broadcast, broadcast/confirmation, chain waiting, required/retrying finalization, and policy-blocked finalization. When every selected window is expired, it immediately explains that 0 H/s is expected while finalization proceeds. Autonomous mining retains the best queued proof per node in a bounded inbox, revalidates it against current work, and reports bounded per-node proof-pipeline counters on exit. Use `--nodes 1,3,5` to restrict mining to selected nodes.

Legacy schema-v1 accounts retain the existing recovery gate: unresolved transactions block paid mining until `astatine recover` completes. Non-blocking recovery alongside a fresh paid run applies only after explicit migration to schema-v2 per-run mode.

Finalization intents are deduplicated by miner contract, node, and window across the authenticated journal, session history, and transaction archives. An unresolved or successful prior attempt is never signed again. One retry is permitted only after a confirmed revert is revalidated against its canonical receipt and a fresh snapshot still reports that same window finalizable; uncertain, replaced, missing, or reorged attempts stay reserved and are not blindly resent.

`astatine wallet address` prints the validated address and a scannable QR code in interactive terminals; redirected output remains plain text. Standalone `astatine wallet create` and `astatine wallet import` cannot replace the selected wallet while a paid session is open or transaction recovery/session transition is pending. Use `astatine init` to stage a wallet change with its own explicit spending-session approval.

Automatic AST reward forwarding remains disabled. Passing `--send-rewards-to ADDRESS` is rejected with an explanation: a selected RPC can fabricate a mutually consistent proof receipt, payout events, balances, and confirmations, which could otherwise authorize a real AST transfer from the mining wallet. Reward reconciliation and the `MINED` display remain available, but they are based on selected-RPC data and are not independent proof of payout. Verify a reward through an independent trusted source before making any manual transfer.

Set `ASTATINE_HISTORY_PROFILE=1` before `astatine mine` (or `$env:ASTATINE_HISTORY_PROFILE='1'` in PowerShell) to print aggregate history profiling at startup and shutdown for developer diagnostics. The profile contains counters and timings only. Normal startup continues to display actionable transaction/RPC warnings and the background reward-verification status without the aggregate dump.

Wallet creation requires an interactive terminal and refuses redirected or non-interactive creation before generating a recovery phrase. Use a private, trusted terminal without session recording. An SSH PTY can still be recorded by a malicious host; terminal detection, encrypted storage, and memory zeroization do not protect a wallet from its host operator.

Consent prompts fail closed when input is unavailable. EOF or a closed stdin is treated as an empty answer: new-session, per-run-policy, and reduced-limit approvals default to no, and wallet backup confirmation rejects anything other than the exact confirmation text. Paid authorization consent additionally requires both stdin and stdout to be interactive terminals; redirected input or output, pipes, and non-interactive runners fail closed before a session is resumed, created, or signed. This covers legacy-session resume, `--new-session`, per-run policy approval, wallet selection for per-run sessions, init session transitions, and reduced caps. Compute-only mining and read-only recovery do not request paid consent. The reduced-limit prompt still requires an explicit `y` or `yes`; its prompt text and interactive flow are unchanged. Redirected output disables the full-screen dashboard, and startup progress falls back to plain lines.

New encrypted Ethereum V3 keystores require passwords of at least 12 Unicode characters and at most 1024 bytes. Input is hidden and confirmed. A brief, non-blocking warning recommends a longer unique passphrase when fewer than 16 characters are chosen. Importing an external V3 keystore first uses its original password to validate the key and address, then requires a new confirmed password and encrypts the same key with Astatine's local scrypt profile. The external file is left unchanged. Existing local keystores remain unlockable with their existing passwords and are not silently rewritten during unlock.

**Transaction costs and authorization cap:** Each proof submission, including a competitive improvement within the same window, pays a `0.003 INJ` fee. A proof overtaken between preflight and inclusion may still consume that fee and gas without changing the incumbent. Finalizing a window consumes INJ gas, including when the window is empty or another miner wins. For every signed transaction, Astatine durably charges `gas_limit × max_fee_per_gas + transaction_value` against the current run cap before producing the signature. That maximum authorization is never refunded or reduced by RPC receipts, reported gas usage, or a completed transaction. Unresolved exposure remains reserved across runs and reduces the next run's available cap. The dashboard separates maximum authorized exposure from RPC-reported actual costs. A zero cap disables signing. Schema-v1 accounts retain cumulative session behavior until explicitly migrated; `--new-session` remains available for that legacy mode. Mainnet transaction signing is disabled.

Journal schema v10 authenticates the full journal with HMAC-SHA-256 and keeps its key and latest revision checkpoint in the OS credential store: macOS Keychain, Windows Credential Manager, or the Linux Secret Service. The authenticated journal now also carries the approved per-run policy identity (network/chain, wallet, ceiling, and reserve). Schema-v9 journals migrate without changing existing session counters or transaction liabilities. The credential store must be available; Linux headless systems need an unlocked Secret Service session. A missing, unavailable, or mismatched journal/checkpoint fails closed and does not create an empty journal or fresh allowance. Restoring an older journal is rejected while its matching credential-store checkpoint remains intact. The checkpoint is not a hardware monotonic counter: rolling back or compromising both the journal and the OS credential store, or malware running as the same OS user, is outside this protection. Restore a matching trusted journal and credential-store backup if integrity validation fails.

During the first authenticated journal migration, an active positive-cap legacy session is conservatively charged its full cap. A legacy schema-v1 configuration keeps the existing rule that unresolved transactions require read-only recovery before a new paid session. After explicit migration to schema-v2 per-run mode, unresolved transactions remain attached to their original session and maximum liabilities while a separately approved run may proceed only with sufficient balance, reserve, run cap, and a non-conflicting nonce. For an interrupted initialization transition, the previous session is sealed separately while the proposed session's zero authorization counter is preserved. Already-closed historical session-history entries retain their recorded cumulative authorization counters; they cannot be resumed or silently used to grant fresh spending authorization. New legacy-mode paid runs require explicit session approval; schema-v2 runs use the policy approved during init and prompt only when a reduced safe cap is needed. Authorized exposure records the maximum amount reserved before signing, not actual INJ spent; receipt-reported actual costs are tracked separately and never refund or reduce that authorization. v1-v6 active-session accounting is reconstructed from retained transactions, pending reservations, and validated archives where available; historical sessions without counters are initialized conservatively. Missing or inconsistent v7/v8 counters are rejected. Each run has its own cap; this is not a lifetime spending limit.

The v2 credential checkpoint stores the journal revision and authenticated-state digest, and its OS credential entry is scoped to the SHA-256 identity of the canonical configuration data-root path. Keep that path unchanged when upgrading. Copying or moving the configuration tree, changing `XDG_CONFIG_HOME`, or restoring only `journal.json` does not transfer its checkpoint and fails closed; the application does not create a replacement key or allowance. For backup recovery, restore the matching journal and credential-store entry together at the original canonical data root. If that credential entry is unavailable, do not delete the journal or keyring entry; mining and recovery remain blocked until a trusted matching backup is restored. Compute-only mining does not open the transaction manager and remains available. Earlier unpublished v9 candidate checkpoints that did not authenticate the revision are not silently upgraded or reset; Testnet.13 v7/v8 journals follow the conservative migration above.

Compatibility of a legacy v8 interrupted-init transition with no previous session remains unverified against a historically released writer. That migration shape is not qualified for this release; preserve existing configuration, journal and checkpoint state and obtain qualified recovery guidance rather than deleting or reinitializing them to bypass a refusal.

A valid authenticated journal with an older revision is reported as rollback; an authentication failure is reported separately without guessing whether corruption was accidental or intentional. The checkpoint is software anti-rollback protection, not a hardware monotonic counter; restoring or compromising both the journal and its OS credential-store entry is outside the guarantee.

## RPC Configuration & Trust

Astatine uses the selected network’s RPC URL from the bundled deployment manifest by default. The bundled Testnet primary is `https://k8s.testnet.json-rpc.injective.network/`. You do not need to operate an RPC node. `astatine init` displays the active network’s bundled default and lets you enter a custom RPC; pressing Enter keeps the current selection. Re-running setup keeps an existing custom RPC unless you change it.

View or change the current network’s selection:

```sh
astatine get rpc
astatine set rpc
astatine set rpc https://my-trusted-rpc.example.com
astatine set rpc default
```

PowerShell uses the same commands with `astatine.exe`:

```powershell
astatine.exe get rpc
astatine.exe set rpc
astatine.exe set rpc https://my-trusted-rpc.example.com
astatine.exe set rpc default
```

Use `--network testnet` or `--network mainnet` on `get rpc` and `set rpc` to
inspect or change that network’s override without changing the selected network.
`astatine init --rpc https://my-trusted-rpc.example.com` validates and saves an
override for the selected network. `astatine set rpc` without a URL is
interactive; type `default` to restore the bundled endpoint. A remote endpoint
must use HTTPS and return the selected network’s expected chain ID. HTTP is
accepted only for local loopback development endpoints. URL credentials are not
accepted; paths and query parameters are redacted in CLI output because some
providers use them for API tokens.

Astatine trusts the selected RPC provider for blockchain state, receipts and
reward evidence; it does not cryptographically authenticate all RPC data. A
malicious or compromised provider can return false work, transaction, receipt or
reward information. Automatic AST reward forwarding is disabled because such
false reward evidence must not authorize a transfer. The bundled archival
endpoint is only a historical-log fallback with the bundled primary. It is not
silently substituted when a custom primary is selected. The local session
authorization cap does not depend on receipt correctness: receipts never
replenish signing authority. Journal changes and stale snapshots are rejected
when the OS credential-store checkpoint is intact. The credential store itself
is the trust boundary; it does not provide hardware-backed anti-rollback if the
entire user credential store is also restored or compromised.

A dishonest selected RPC can also make still-live transactions appear settled and supply false balances for later runs, undermining unresolved-liability, nonce and reserve calculations across runs. The original run's authorization remains charged, but per-run caps are not a lifetime wallet-loss guarantee or an independent proof of reserves. False work or chain state can cause submissions to consume the approved proof fee and gas without a reward. These are accepted selected-provider trust boundaries, not fixed by local hashing or journal authentication.

## Bundled Testnet deployment

The bundled Testnet manifest pins chain `1439`, the AST token `0x5C730A3110a565bf388120ce64F37bb7dd0c7F83`, nine miner contracts, and their configured Genesis Coordinator. The miners are pinned to source commit `80e8f7cbeb21b18bc5f7475d8b751c9d9e8fb9d1`; the Coordinator is pinned to source commit `c710b4d7add5f10de326487d0ff851eb926499c6`. Startup verifies runtime hashes, token identity, miner constructor parameters, the `0.003 INJ` submission fee, and the Coordinator's configured owner, token, and ordered node list. The deployed miners are initially unstarted; the CLI displays `WAIT GENESIS` and never activates Genesis. Mainnet remains read-only.

## Repository checks

The project does not provide an automated publishing or signing service. Verify any release through the authenticated release record described in the [macOS ARM64 guide](MACOS_ARM64.md).

`.github/workflows/ci.yml` runs formatting, `cargo check`, test compilation with `cargo test --no-run`, clippy with `-D warnings`, release builds on five native targets with safe CLI smoke tests (`--version`, `--help`, `mine --help`), the CUDA PTX reproduction on Linux x86_64 (requires Docker), and the dependency policy: `cargo deny`, `cargo audit` with the documented RUSTSEC-2026-0387 exception, a guard that keeps the vulnerable optional `crypto-bigint 0.5.5` out of the active graph, and a byte comparison of regenerated third-party notices. A separate Linux job runs the non-ignored unit-test suite in an isolated temporary `HOME` with a deliberately unavailable Secret Service bus. It skips the native credential-store test by name and leaves Anvil, physical-GPU, and native-keyring opt-in tests unset. The workflow does not publish, sign, attest, or create releases; it does not use repository secrets.

The isolated Linux Secret Service test proves that an unavailable provider fails closed: checkpoint reads and writes return errors rather than `NoEntry` or a plaintext fallback, and no journal file is created. A real locked or provider-equipped Secret Service session is not exercised in CI; that remains a deployment blocker to verify on the target host before paid mining. The native credential-store persistence test is `#[ignore]`d and must be run explicitly on a provider-equipped machine; it is never pointed at a personal keyring by the default suite. Anvil lifecycle tests and physical-GPU tests remain `#[ignore]`d. Run `python3 support/verify-fixture-provenance.py` and `python3 -m unittest discover -s support/tests -p 'test_*.py'` for the offline fixture checks. Mining, wallet and RPC commands read and write local state and contact configured endpoints, so run them deliberately.

## License

The miner is licensed under [MIT](LICENSE-MIT). Third-party dependency notices are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
