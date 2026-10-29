# Astatine Miner

Astatine is an open-source Proof-of-Work mining project on Injective EVM. Miners search for valid hashes locally on CPUs or compatible GPUs; Injective contracts verify submissions and settle each work window on-chain. GPU acceleration does not change the canonical SHA-256d work algorithm.

The protocol has nine independent mining nodes, each with its own work and window state. A miner can work across all nodes or select specific nodes.

## Install

Testnet.11 installers verify the signed release manifest and the platform archive digest before installation. No root or administrator access is required. The installer replaces only the executable and license notices; configuration, wallets, and transaction journals are left untouched. The manifest is signed with the RSA release key pinned in the client and installer scripts.

### macOS and Linux

Requires `curl`, `openssl`, `tar`, and `install`. Supported targets are Apple Silicon and Intel macOS, plus x86_64 and aarch64 Linux (glibc 2.35 or later).

```sh
curl --fail --show-error --location https://raw.githubusercontent.com/emyrinj/astatine-miner/v0.1.0-testnet.11/support/install-unix.sh | sh
```

To download and review the installer before executing it:

```sh
curl --fail --show-error --location https://raw.githubusercontent.com/emyrinj/astatine-miner/v0.1.0-testnet.11/support/install-unix.sh -o "$HOME/astatine-install-unix.sh"
less "$HOME/astatine-install-unix.sh"
sh "$HOME/astatine-install-unix.sh"
```

Apple Silicon requires macOS 11 or later; Intel requires macOS 10.12 or later. The executable and license notices are installed under `~/.local/bin`; add that directory to `PATH` if needed. Linux configuration, wallets, and transaction journals use `${XDG_CONFIG_HOME:-$HOME/.config}/astatine`.

### Windows PowerShell

Supported target: Windows 10 or later, x86_64. The executable is installed under your user profile.

```powershell
$Installer = Join-Path $env:TEMP 'astatine-install.ps1'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/emyrinj/astatine-miner/v0.1.0-testnet.11/support/install-windows.ps1' -OutFile $Installer; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

To download and review the PowerShell installer before executing it:

```powershell
$Installer = Join-Path $env:TEMP 'astatine-install.ps1'
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/emyrinj/astatine-miner/v0.1.0-testnet.11/support/install-windows.ps1' -OutFile $Installer
Get-Content -LiteralPath $Installer -Raw
# After reviewing the script:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

Add `$HOME\bin` to your user `Path`, then open a new PowerShell window and verify with `astatine.exe --version`. Configuration, wallets, and transaction journals remain in `%APPDATA%\Astatine`.

### Authenticated updates

`astatine update --check` verifies the signed release manifest and reports whether a newer Testnet release is available without downloading an executable. `astatine update` checks the signed manifest, downloads the matching executable and license notices, validates sizes and SHA-256 digests, smoke-tests the new executable, then replaces the installed files with rollback on failure. Windows uses a helper that waits for the updater process to exit before replacing the running executable. Mining checks for newer signed releases in a background task and adds a dashboard notification; it never updates or restarts a running miner automatically. Updates do not modify configuration, wallets, or transaction journals.

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

Every GPU candidate is rehashed with the canonical Rust `WorkHasher` before it enters the existing bounded proof inbox. The existing proof preflight, journal, signing, submission, finalization, reward reconciliation, and forwarding pipelines remain authoritative. The GPU module does not own wallets, RPC connections, or transaction signing.

Inspect local compute adapters and run their real shader self-test without connecting to RPC or unlocking a wallet:

```sh
astatine devices
```

The wgpu backends target Metal on macOS, Direct3D 12 or Vulkan on Windows, and Vulkan on Linux. Driver and hardware support varies:

| Platform / GPU | Preferred backend | Testnet.11 evidence |
|---|---|---|
| Apple Silicon · Apple M4 | Metal | Physical shader parity, three-window mining and reward forwarding, and 1/3/9-node compute-only scheduling tested |
| Intel macOS GPU | Metal | Physical runtime not tested; x86_64 target check passes locally |
| NVIDIA / AMD Windows GPU | Direct3D 12 or Vulkan | Physical runtime not tested; Testnet.11 native CI pending |
| NVIDIA / AMD Linux GPU | Vulkan | Physical runtime not tested; Testnet.11 native CI pending |

Adapter enumeration or a successful native build is not itself a GPU correctness test.

Run a local, read-only CPU/GPU benchmark on identical canonical work (no wallet or RPC required):

```sh
astatine benchmark
astatine benchmark --seconds 10 --threads 4
```

The report includes three repeated CPU/GPU samples by default, separates initialization/self-test time from timed throughput, and records host-stage timings and JSON output when requested. GPU compute timestamps are reported only where supported; otherwise dispatch-to-readback is identified as wall latency. `--profile` sweeps all supported batch and workgroup sizes; `--compare-full-sha` compares full SHA-256 with the cached-midstate path, and `--serial` disables the bounded two-batch overlap for comparison. Example:

```sh
astatine benchmark --seconds 10 --threads 4 --batch-size 262144 --workgroup-size 32 --compare-full-sha --output-json gpu-ab.json
```

Use measured results for the installed hardware. The GPU shader implements SHA-256d only; it does not alter the PoW protocol.

The Testnet.10 reference is retained in [the Testnet.11 performance report](support/testnet11-performance.md). On the same Apple M4 / Metal adapter, the combined Testnet.11 configuration (262,144-nonce batches, 32-lane workgroups, SHA-256 midstate, and two-slot readback pipeline) measured a three-sample median of `59.504 MH/s`, 44.60x the supplied Testnet.10 GPU reference. Metal exposes no wgpu GPU timestamp queries on this adapter; the report separates effective throughput from submit-to-readback latency and records the serial, full-SHA, midstate, and pipeline comparisons. This is one machine's measured result, not a performance guarantee; run `astatine benchmark` on the target hardware.

The archives are authenticated by the pinned RSA-3072 key in addition to HTTPS. Its SHA-256 SubjectPublicKeyInfo fingerprint is `e610269b1a6dffe64eb1b9b4d97e9cca434884f5908a38888e310bdd74322e7c`; the PEM and Windows XML forms are in `support/release-signing-public.*`. macOS binaries are not Developer ID signed or notarized, and Windows binaries are not Authenticode signed; the release manifest signature provides the project-level authenticity check.

GitHub build-provenance attestations are published for the release archives, native executables, and signed manifest. To inspect one, use `gh attestation verify astatine-linux-x86_64.tar.gz --repo emyrinj/astatine-miner` with the GitHub CLI.

## Use

```sh
astatine init
astatine mine
astatine mine --device cpu
astatine mine --device gpu --nodes 1,2,3,4,5,6,7,8,9
astatine mine --device auto --nodes 1,3,5
astatine mine --device gpu --compute-only
astatine mine --device gpu --send-rewards-to 0x0123456789abcdef0123456789abcdef01234567
astatine devices
astatine benchmark
astatine update
astatine update --check
```

`astatine init` configures the wallet, network, CPU budget, reserve, transaction cap, and confirmation depth. Startup shows configuration, RPC/deployment checks, transaction recovery, wallet unlock, initial work, worker preparation and when historical reward verification is scheduled; detailed history counters are hidden during ordinary startup. Historical reward verification runs in the background so live proof work can continue while older events are checked. Interactive terminals use a subtle spinner, while redirected output uses plain-text progress. The mining dashboard shows live node state, INJ and AST balances, canonically verified rewards mined during the current invocation, hashrate, transaction, and session-exposure status; it distinguishes proof checking, signed-but-not-yet-broadcast, broadcast/confirmation, chain waiting, required/retrying finalization, and policy-blocked finalization. Autonomous mining retains the best queued proof per node in a bounded inbox, revalidates it against current verified work, and reports bounded per-node proof-pipeline counters on exit (including rejection reasons, paid-attempt suppression, broadcast, and verified candidate events). `--compute-only` hashes locally without unlocking a wallet or sending transactions. Use `--nodes 1,3,5` to restrict mining to selected nodes.

Reward forwarding is off by default. `--send-rewards-to ADDRESS` explicitly authorizes this invocation to transfer only an AST payout verified from a canonical winning window receipt to that destination. The transfer amount is exact, the destination is persisted in the transaction journal, and the transfer fee counts toward the configured INJ session cap and reserve. It cannot be combined with `--compute-only`; the mining wallet's AST balance may decrease while `MINED` remains the total verified reward earned in this invocation. If a payout is pending or blocked, resume with the same destination before selecting another one.

Set `ASTATINE_HISTORY_PROFILE=1` before `astatine mine` (or `$env:ASTATINE_HISTORY_PROFILE='1'` in PowerShell) to print aggregate history profiling at startup and shutdown for developer diagnostics. The profile contains counters and timings only. Normal startup continues to display actionable transaction/RPC warnings and the background reward-verification status without the aggregate dump.

New encrypted Ethereum V3 keystores accept passwords of at least four Unicode characters and at most 1024 bytes. Input is hidden and confirmed. A brief, non-blocking warning recommends a longer unique password when fewer than 12 characters are chosen. This applies to new wallets and mnemonic imports; importing an existing V3 keystore continues to use its original password.

**Transaction costs:** Each proof submission pays a `0.01 INJ` fee. Finalizing a window consumes INJ gas, including when the window is empty or another miner wins. AST forwarding transfers also consume INJ gas. These costs count toward the configured per-session cap. The default cap is zero, which disables transaction signing; a positive cap explicitly authorizes spending. Mainnet transaction signing is disabled.

## License

The miner is licensed under [MIT](LICENSE-MIT). Third-party dependency notices are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
