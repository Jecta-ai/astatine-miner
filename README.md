# Astatine Miner

Astatine is an open-source Proof-of-Work mining project on Injective EVM. Miners search for valid hashes locally on their CPUs; Injective contracts verify submissions and settle each work window on-chain. This gives CPU miners a way to compete using verifiable work.

The protocol has nine independent mining nodes, each with its own work and window state. A miner can work across all nodes or select specific nodes.

## Install

Testnet.9 installers verify the signed release manifest and the platform archive digest before installation. No root or administrator access is required. The installer replaces only the executable and license notices; configuration, wallets, and transaction journals are left untouched. The manifest is signed with the RSA release key pinned in the client and installer scripts.

### macOS and Linux

Requires `curl`, `openssl`, `tar`, and `install`. Supported targets are Apple Silicon and Intel macOS, plus x86_64 and aarch64 Linux (glibc 2.35 or later).

```sh
curl --fail --show-error --location https://raw.githubusercontent.com/emyrinj/astatine-miner/03a6288cd2589834c6e227074ff46f0b486047c3/support/install-unix.sh | sh
```

To download and review the installer before executing it:

```sh
curl --fail --show-error --location https://raw.githubusercontent.com/emyrinj/astatine-miner/03a6288cd2589834c6e227074ff46f0b486047c3/support/install-unix.sh -o "$HOME/astatine-install-unix.sh"
less "$HOME/astatine-install-unix.sh"
sh "$HOME/astatine-install-unix.sh"
```

Apple Silicon requires macOS 11 or later; Intel requires macOS 10.12 or later. The executable and license notices are installed under `~/.local/bin`; add that directory to `PATH` if needed. Linux configuration, wallets, and transaction journals use `${XDG_CONFIG_HOME:-$HOME/.config}/astatine`.

### Windows PowerShell

Supported target: Windows 10 or later, x86_64. The executable is installed under your user profile.

```powershell
$Installer = Join-Path $env:TEMP 'astatine-install.ps1'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/emyrinj/astatine-miner/03a6288cd2589834c6e227074ff46f0b486047c3/support/install-windows.ps1' -OutFile $Installer; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

To download and review the PowerShell installer before executing it:

```powershell
$Installer = Join-Path $env:TEMP 'astatine-install.ps1'
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/emyrinj/astatine-miner/03a6288cd2589834c6e227074ff46f0b486047c3/support/install-windows.ps1' -OutFile $Installer
Get-Content -LiteralPath $Installer -Raw
# After reviewing the script:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

Add `$HOME\bin` to your user `Path`, then open a new PowerShell window and verify with `astatine.exe --version`. Configuration, wallets, and transaction journals remain in `%APPDATA%\Astatine`.

### Authenticated updates

`astatine update --check` verifies the signed release manifest and reports whether a newer Testnet release is available without downloading an executable. `astatine update` checks the signed manifest, downloads the matching executable and license notices, validates sizes and SHA-256 digests, smoke-tests the new executable, then replaces the installed files with rollback on failure. Windows uses a helper that waits for the updater process to exit before replacing the running executable. Mining checks for newer signed releases in a background task and adds a dashboard notification; it never updates or restarts a running miner automatically. Updates do not modify configuration, wallets, or transaction journals.

The archives are authenticated by the pinned RSA-3072 key in addition to HTTPS. Its SHA-256 SubjectPublicKeyInfo fingerprint is `e610269b1a6dffe64eb1b9b4d97e9cca434884f5908a38888e310bdd74322e7c`; the PEM and Windows XML forms are in `support/release-signing-public.*`. macOS binaries are not Developer ID signed or notarized, and Windows binaries are not Authenticode signed; the release manifest signature provides the project-level authenticity check.

GitHub build-provenance attestations are published for the release archives, native executables, and signed manifest. To inspect one, use `gh attestation verify astatine-linux-x86_64.tar.gz --repo emyrinj/astatine-miner` with the GitHub CLI.

## Use

```sh
astatine init
astatine mine
astatine mine --compute-only
astatine mine --send-rewards-to 0x0123456789abcdef0123456789abcdef01234567
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
