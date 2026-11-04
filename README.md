# Astatine Miner

Astatine is an open-source Proof-of-Work mining project on Injective EVM. Miners search for valid hashes locally on CPUs or compatible GPUs; Injective contracts verify submissions and settle each work window on-chain. GPU acceleration does not change the canonical SHA-256d work algorithm.

The protocol has nine independent mining nodes, each with its own work and window state. A miner can work across all nodes or select specific nodes.

## Install

Testnet.17 installers verify the signed release manifest and the platform archive digest before installation. No root or administrator access is required. The installer replaces only the executable and license notices; configuration, wallets, and transaction journals are left untouched. The manifest is signed with the RSA release key pinned in the client and installer scripts.

### macOS and Linux

Requires `curl`, `openssl`, `tar`, and `install`. Supported targets are Apple Silicon and Intel macOS, plus x86_64 and aarch64 Linux (glibc 2.35 or later).

```sh
curl --fail --show-error --location https://raw.githubusercontent.com/Jecta-ai/astatine-miner/v0.1.0-testnet.17/support/install-unix.sh | sh
```

To download and review the installer before executing it:

```sh
curl --fail --show-error --location https://raw.githubusercontent.com/Jecta-ai/astatine-miner/v0.1.0-testnet.17/support/install-unix.sh -o "$HOME/astatine-install-unix.sh"
less "$HOME/astatine-install-unix.sh"
sh "$HOME/astatine-install-unix.sh"
```

Apple Silicon requires macOS 11 or later; Intel requires macOS 10.12 or later. The executable and license notices are installed under `~/.local/bin`; add that directory to `PATH` if needed. Linux configuration, wallets, and transaction journals use `${XDG_CONFIG_HOME:-$HOME/.config}/astatine`.

### Windows PowerShell

Supported target: Windows 10 or later, x86_64. The executable is installed under your user profile.

```powershell
$Installer = Join-Path $env:TEMP 'astatine-install.ps1'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Jecta-ai/astatine-miner/v0.1.0-testnet.17/support/install-windows.ps1' -OutFile $Installer; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

To download and review the PowerShell installer before executing it:

```powershell
$Installer = Join-Path $env:TEMP 'astatine-install.ps1'
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Jecta-ai/astatine-miner/v0.1.0-testnet.17/support/install-windows.ps1' -OutFile $Installer
Get-Content -LiteralPath $Installer -Raw
# After reviewing the script:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

Add `$HOME\bin` to your user `Path`, then open a new PowerShell window and verify with `astatine.exe --version`. Configuration, wallets, and transaction journals remain in `%APPDATA%\Astatine`.

### Authenticated updates

`astatine update --check` verifies the signed release manifest and reports whether a newer Testnet release is available without downloading an executable. `astatine update` checks the signed manifest, downloads the matching executable and license notices, validates sizes and SHA-256 digests, smoke-tests the new executable, then replaces the installed files with rollback on failure. Windows uses a helper that waits for the updater process to exit before replacing the running executable. Mining checks for newer signed releases in a background task and adds a dashboard notification; it never updates or restarts a running miner automatically. Updates do not modify configuration, wallets, or transaction journals.

### Paid-session authorization limit

Paid mining checks the durable remaining session authorization against the canonical 0.01 INJ proof fee. When less than one proof fee remains, the run latches `SESSION LIMIT REACHED`: CPU/GPU workers stop, queued proofs are discarded, and no new proof or finalization transaction is signed. The comparison is strict, so exactly 0.01 INJ remaining is not treated as exhausted. The authorization counter is not reduced by a later receipt or observer snapshot.

The dashboard remains open until Ctrl+C, displays the terminal state, and continues read-only chain observation and recovery of transactions that were already in flight. If the observer stalls or fails, the miner reports monitoring degradation and marks its last verified block stale; it does not exit or start a new session automatically. Starting below the proof-fee threshold skips worker initialization and signer unlocking. In per-run policy mode, a later explicit `astatine mine` invocation starts its own fresh session under the existing approved policy; the current run is never automatically refilled.

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

Explicit `gpu` mode stops with an actionable error if no physical adapter passes the actual WGSL SHA-256d self-test. It never silently becomes CPU mining. `auto` performs a short canonical-work comparison and chooses GPU only when its measured throughput is more than 10% faster than CPU; otherwise it chooses CPU. Auto mode also falls back to CPU if GPU operation later fails. Any in-flight GPU nonce range is abandoned on failure, not reassigned. `--threads` controls CPU mining workers; GPU mode uses a dedicated controller and does not start the full CPU mining pool.

Every GPU candidate is rehashed with the canonical Rust `WorkHasher` before it enters the existing bounded proof inbox. The existing proof preflight, journal, signing, submission, finalization, and reward-reconciliation paths remain authoritative. The GPU module does not own wallets, RPC connections, or transaction signing.

### Native NVIDIA CUDA mining

On Linux x86_64/aarch64 and Windows x86_64, `--device gpu` prefers the native CUDA Driver API backend when an NVIDIA device passes its runtime SHA-256d self-test. A compatible CUDA 12.0-or-newer driver and compute capability 5.2 or newer are required. The miner dynamically loads the driver (`libcuda.so.1` on Linux or `nvcuda.dll` on Windows); a CUDA Toolkit, `nvcc`, NVRTC, Vulkan graphics libraries, and a display server are not required on the mining host.

The CUDA kernel is precompiled PTX embedded in the executable. Its `.cu` source and pinned-container reproduction instructions are in `src/gpu/cuda/` and `support/cuda/`. Every CUDA candidate is rehashed by the canonical CPU implementation. CUDA is only selected after actual kernel execution and self-test; if it is unavailable, existing physical Vulkan/DirectX backends may be tried. Explicit GPU mode never substitutes CPU hashing.

### Starting before genesis

Mining can be started before selected contracts activate. Verified, inactive nodes show `WAIT GENESIS`; when all selected nodes are inactive the dashboard shows `WAITING FOR GENESIS`. The observer checks selected inactive nodes approximately once per second with read-only `work()` calls and a bounded three-node concurrency limit. Active nodes keep the normal observer cadence.

An activation candidate triggers the existing canonical full-snapshot path. The miner rechecks the chain ID, pinned runtime code, ABI coherence and canonical Rust/Solidity `computeWorkHash` parity before publishing eligible work to the existing node scheduler. Partial activation is handled independently per node; nine-node atomic Coordinator activation is discovered by the same mechanism. The CLI never calls `activateGenesis()` or the Coordinator, never asks the user to restart, and does not create mining nonce ranges or paid transactions for unstarted nodes. There is no new init configuration.

```sh
astatine mine --device gpu --nodes 1,2,3,4,5,6,7,8,9
```

The existing proof verification, spending cap, minimum reserve, transaction journal, recovery, and reorganization handling remain in force after activation. Automatic AST reward forwarding remains disabled because the selected RPC can fabricate reward evidence.

### Pinned local Anvil fixtures

Lifecycle and nine-node Anvil tests use the checked-in Testnet.15 bytecode fixtures and do not build an adjacent `astatineEVM` checkout. The Astatine miner fixture is pinned to Solidity source commit `eb9ea498ed4da10536cd6b4d5d8b55cf38e8aa30`; the Coordinator fixture is pinned to `54588aa7b020cd7e49fa2275a560cde8138dd707`. The miner fixture's `work().submissionFee` is validated against the protocol constant `10000000000000000` wei (`0.01 INJ`).

Inspect local compute adapters and run their real shader self-test without connecting to RPC or unlocking a wallet:

```sh
astatine devices
```

The wgpu backends target Metal on macOS, Direct3D 12 or Vulkan on Windows, and Vulkan on Linux. Driver and hardware support varies:

| Platform / GPU | Preferred backend | Testnet.12 evidence |
|---|---|---|
| Apple Silicon · Apple M4 | Metal | Physical shader parity, three-window mining/reward reconciliation, 1/3/9-node genesis activation, and one-second pre-genesis polling tested |
| Intel macOS GPU | Metal | Native target CI passes; physical GPU runtime not tested |
| NVIDIA / AMD Windows GPU | Direct3D 12 or Vulkan | Native Windows CI passes; physical GPU runtime not tested |
| NVIDIA / AMD Linux GPU | Vulkan | Native Linux CI passes; physical GPU runtime not tested |

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

The Testnet.11 M4/Metal reference supplied for this release is `69.102 MH/s` GPU median and `23.284 MH/s` CPU median (four CPU workers). A fresh comparable Testnet.12 run measured GPU `68.689 MH/s` median (`68.689`, `68.677`, `68.738 MH/s`) and CPU `22.304 MH/s` median (`22.727`, `22.304`, `22.126 MH/s`). Across fifteen local Testnet.12 samples, the combined GPU median is `68.568 MH/s`. The GPU shader and compute pipeline were not changed. Full per-run samples, methodology, genesis activation latencies, and timing limitations are in [the Testnet.12 performance report](support/testnet12-performance.md). Metal exposes no wgpu GPU timestamp queries on this adapter, so dispatch-to-readback is wall latency, not isolated shader time. These are measured results, not a guarantee across devices; run `astatine benchmark` on the target hardware.

Release manifests are authenticated by a pinned RSA-3072 key in addition to
HTTPS. The currently embedded key's SHA-256 SubjectPublicKeyInfo fingerprint is
`7a89234d5b269bb5372eab957e66307e321f4d9de9a550f7a2d7a6783cc50650`. This
owner-supplied key is integrated across the Rust updater, Unix/Windows
installers, and release validators; `support/release-key-fingerprint.txt`
contains the matching active fingerprint. Before signing, the offline signer
requires the selected private key to derive this exact public anchor. Replacing
the pin means existing Testnet.12 clients with the legacy key cannot verify
releases signed only by the new key. This candidate does not include a
backward-compatible bridge; clients that require automatic updates from
Testnet.12 need a migration path before release. macOS binaries are not
Developer ID signed or notarized, and Windows binaries are not Authenticode
signed.

GitHub Actions only builds/tests unsigned artifacts and creates provenance for
the exact source commit. Creating a tag does not publish a release. The owner
downloads and independently verifies the asset attestations, signs the manifest
offline, then explicitly publishes the signed 15-asset inventory with
`support/publish_signed_release.py`. See
[`support/OFFLINE_RELEASE_PROCESS.md`](support/OFFLINE_RELEASE_PROCESS.md) for
the owner commands and recovery behavior. To inspect build provenance for an
unsigned package, use:

```sh
gh attestation verify astatine-linux-x86_64.tar.gz \
  --repo "$(tr -d '\n' < support/release-repository.txt)"
```

## Use

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
astatine update
astatine update --check
astatine wallet address
```

`astatine init` configures the wallet, network, RPC, CPU budget, reserve, authorization ceiling, and confirmation depth. New installs use a 1 INJ per-run ceiling by default; `astatine init --spending-limit-inj AMOUNT` changes the saved ceiling. During init, the owner approves a persistent policy bound to the selected wallet and network. Each later explicit paid `astatine mine` invocation automatically creates one fresh run session under that policy when the confirmed balance can cover the full configured ceiling after the reserve and unresolved liabilities; a full-ceiling run needs no additional prompt. If the safe cap is lower, the miner asks for consent to use a temporary, rounded-down cap. The locked journal and balance are rechecked before session creation, so a second prompt can occur if that recheck lowers the safe cap again. Reduced caps are not written back to configuration and never grow during a run. Multiple runs can spend more than one run's cap in aggregate. Changing the approved ceiling, reserve, wallet, network, or policy requires explicit reauthorization. Existing schema-v1 accounts retain legacy cumulative-session behavior until the owner explicitly migrates with `astatine init --per-run-sessions` or accepts the interactive migration prompt. `astatine mine --compute-only` hashes verified work without unlocking, signing, changing a session, or broadcasting. In per-run mode, unresolved transactions remain journaled and are reconciled read-only while live hashing and fresh-run signing continue; any new send still requires a distinct pending nonce, sufficient balance after all reserved exposure, and remaining run cap. `astatine recover` can reconcile unresolved transactions from a closed per-run session without reopening it, and never unlocks, signs, or broadcasts. Prior maximum authorization is never refunded. Historical reward reconciliation runs in the background so live proof work can continue while older events are checked against the selected RPC. Interactive terminals use a subtle spinner, while redirected output uses plain-text progress. The mining dashboard shows live node state, RPC-reported INJ and AST balances, RPC-reported rewards for the current invocation, hashrate, transaction state, current-run maximum authorization, remaining run allowance, and RPC-reported actual cost. It distinguishes proof checking, signed-but-not-yet-broadcast, broadcast/confirmation, chain waiting, required/retrying finalization, and policy-blocked finalization. When every selected window is expired, it immediately explains that 0 H/s is expected while finalization proceeds. Autonomous mining retains the best queued proof per node in a bounded inbox, revalidates it against current work, and reports bounded per-node proof-pipeline counters on exit. Use `--nodes 1,3,5` to restrict mining to selected nodes.

Legacy schema-v1 accounts retain the existing recovery gate: unresolved transactions block paid mining until `astatine recover` completes. Non-blocking recovery alongside a fresh paid run applies only after explicit migration to schema-v2 per-run mode.

Finalization intents are deduplicated by miner contract, node, and window across the authenticated journal, session history, and transaction archives. An unresolved or successful prior attempt is never signed again. One retry is permitted only after a confirmed revert is revalidated against its canonical receipt and a fresh snapshot still reports that same window finalizable; uncertain, replaced, missing, or reorged attempts stay reserved and are not blindly resent.

`astatine wallet address` prints the validated address and a scannable QR code in interactive terminals; redirected output remains plain text. Standalone `astatine wallet create` and `astatine wallet import` cannot replace the selected wallet while a paid session is open or transaction recovery/session transition is pending. Use `astatine init` to stage a wallet change with its own explicit spending-session approval.

Automatic AST reward forwarding remains disabled. Passing `--send-rewards-to ADDRESS` is rejected with an explanation: a selected RPC can fabricate a mutually consistent proof receipt, payout events, balances, and confirmations, which could otherwise authorize a real AST transfer from the mining wallet. Reward reconciliation and the `MINED` display remain available, but they are based on selected-RPC data and are not independent proof of payout. Verify a reward through an independent trusted source before making any manual transfer.

Set `ASTATINE_HISTORY_PROFILE=1` before `astatine mine` (or `$env:ASTATINE_HISTORY_PROFILE='1'` in PowerShell) to print aggregate history profiling at startup and shutdown for developer diagnostics. The profile contains counters and timings only. Normal startup continues to display actionable transaction/RPC warnings and the background reward-verification status without the aggregate dump.

New encrypted Ethereum V3 keystores require passwords of at least 12 Unicode characters and at most 1024 bytes. Input is hidden and confirmed. A brief, non-blocking warning recommends a longer unique passphrase when fewer than 16 characters are chosen. This applies to new wallets and mnemonic imports; importing an existing V3 keystore continues to use its original password without a new minimum.

**Transaction costs and authorization cap:** Each proof submission pays a `0.01 INJ` fee. Finalizing a window consumes INJ gas, including when the window is empty or another miner wins. For every signed transaction, Astatine durably charges `gas_limit × max_fee_per_gas + transaction_value` against the current run cap before producing the signature. That maximum authorization is never refunded or reduced by RPC receipts, reported gas usage, or a completed transaction. Unresolved exposure remains reserved across runs and reduces the next run's available cap. The dashboard separates maximum authorized exposure from RPC-reported actual costs. A zero cap disables signing. Schema-v1 accounts retain cumulative session behavior until explicitly migrated; `--new-session` remains available for that legacy mode. Mainnet transaction signing is disabled.

Journal schema v10 authenticates the full journal with HMAC-SHA-256 and keeps its key and latest revision checkpoint in the OS credential store: macOS Keychain, Windows Credential Manager, or the Linux Secret Service. The authenticated journal now also carries the approved per-run policy identity (network/chain, wallet, ceiling, and reserve). Schema-v9 journals migrate without changing existing session counters or transaction liabilities. The credential store must be available; Linux headless systems need an unlocked Secret Service session. A missing, unavailable, or mismatched journal/checkpoint fails closed and does not create an empty journal or fresh allowance. Restoring an older journal is rejected while its matching credential-store checkpoint remains intact. The checkpoint is not a hardware monotonic counter: rolling back or compromising both the journal and the OS credential store, or malware running as the same OS user, is outside this protection. Restore a matching trusted journal and credential-store backup if integrity validation fails.

During the first authenticated journal migration, an active positive-cap legacy session is conservatively charged its full cap. A legacy schema-v1 configuration keeps the existing rule that unresolved transactions require read-only recovery before a new paid session. After explicit migration to schema-v2 per-run mode, unresolved transactions remain attached to their original session and maximum liabilities while a separately approved run may proceed only with sufficient balance, reserve, run cap, and a non-conflicting nonce. For an interrupted initialization transition, the previous session is sealed separately while the proposed session's zero authorization counter is preserved. Already-closed historical session-history entries retain their recorded cumulative authorization counters; they cannot be resumed or silently used to grant fresh spending authorization. New legacy-mode paid runs require explicit session approval; schema-v2 runs use the policy approved during init and prompt only when a reduced safe cap is needed. Authorized exposure records the maximum amount reserved before signing, not actual INJ spent; receipt-reported actual costs are tracked separately and never refund or reduce that authorization. v1-v6 active-session accounting is reconstructed from retained transactions, pending reservations, and validated archives where available; historical sessions without counters are initialized conservatively. Missing or inconsistent v7/v8 counters are rejected. Each run has its own cap; this is not a lifetime spending limit.

The v2 credential checkpoint stores the journal revision and authenticated-state digest, and its OS credential entry is scoped to the SHA-256 identity of the canonical configuration data-root path. Keep that path unchanged when upgrading. Copying or moving the configuration tree, changing `XDG_CONFIG_HOME`, or restoring only `journal.json` does not transfer its checkpoint and fails closed; the application does not create a replacement key or allowance. For backup recovery, restore the matching journal and credential-store entry together at the original canonical data root. If that credential entry is unavailable, do not delete the journal or keyring entry; mining and recovery remain blocked until a trusted matching backup is restored. Compute-only mining does not open the transaction manager and remains available. Earlier unpublished v9 candidate checkpoints that did not authenticate the revision are not silently upgraded or reset; Testnet.13 v7/v8 journals follow the conservative migration above.

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

## License

The miner is licensed under [MIT](LICENSE-MIT). Third-party dependency notices are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
