# Astatine Miner

Astatine is an open-source Proof-of-Work mining project on Injective EVM. Miners search for valid hashes locally on their CPUs; Injective contracts verify submissions and settle each work window on-chain. This gives CPU miners a way to compete using verifiable work.

The protocol has nine independent mining nodes, each with its own work and window state. A miner can work across all nodes or select specific nodes.

## Install

The Testnet.8 downloads contain only the executable and license notices. Installers verify the published SHA-256 entry before replacing the executable; they do not modify configuration, wallets or transaction journals. Stop the miner before updating it.

### macOS

```sh
set -euo pipefail
case "$(uname -s)" in Darwin) ;; *) printf '%s\n' 'macOS is required' >&2; exit 1;; esac
case "$(uname -m)" in
  arm64|aarch64) asset=astatine-macos-aarch64.tar.gz;;
  x86_64|amd64) asset=astatine-macos-x86_64.tar.gz;;
  *) printf '%s\n' 'Unsupported macOS architecture' >&2; exit 1;;
esac
version=v0.1.0-testnet.8
base="https://github.com/emyrinj/astatine-miner/releases/download/$version"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl --fail --show-error --location --connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 240 --progress-bar "$base/$asset" -o "$tmp/$asset"
curl --fail --show-error --location --connect-timeout 10 --max-time 60 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
(cd "$tmp" && grep -F "  $asset" SHA256SUMS | shasum -a 256 -c -)
tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$tmp/astatine" "$HOME/.local/bin/astatine"
mkdir -p "$HOME/.local/share/astatine/licenses"
install -m 0644 "$tmp/LICENSE-MIT" "$HOME/.local/share/astatine/licenses/LICENSE-MIT"
install -m 0644 "$tmp/THIRD_PARTY_LICENSES.md" "$HOME/.local/share/astatine/licenses/THIRD_PARTY_LICENSES.md"
"$HOME/.local/bin/astatine" --version
```

Apple Silicon requires macOS 11 or later; Intel requires macOS 10.12 or later. If `~/.local/bin` is not on your `PATH`, add it before running `astatine` from a new terminal.

### Linux

Supported targets are x86_64 and aarch64/ARM64 on glibc-based Linux with glibc 2.35 or later. No root privileges are required.

```sh
set -euo pipefail
case "$(uname -s)" in Linux) ;; *) printf '%s\n' 'Linux is required' >&2; exit 1;; esac
case "$(uname -m)" in
  x86_64|amd64) asset=astatine-linux-x86_64.tar.gz;;
  aarch64|arm64) asset=astatine-linux-aarch64.tar.gz;;
  *) printf '%s\n' 'Unsupported Linux architecture' >&2; exit 1;;
esac
version=v0.1.0-testnet.8
base="https://github.com/emyrinj/astatine-miner/releases/download/$version"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl --fail --show-error --location --connect-timeout 10 --max-time 120 --retry 2 --retry-max-time 240 --progress-bar "$base/$asset" -o "$tmp/$asset"
curl --fail --show-error --location --connect-timeout 10 --max-time 60 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
(cd "$tmp" && grep -F "  $asset" SHA256SUMS | sha256sum -c -)
tar -xzf "$tmp/$asset" -C "$tmp"
mkdir -p "$HOME/.local/bin"
install -m 0755 "$tmp/astatine" "$HOME/.local/bin/astatine"
mkdir -p "$HOME/.local/share/astatine/licenses"
install -m 0644 "$tmp/LICENSE-MIT" "$HOME/.local/share/astatine/licenses/LICENSE-MIT"
install -m 0644 "$tmp/THIRD_PARTY_LICENSES.md" "$HOME/.local/share/astatine/licenses/THIRD_PARTY_LICENSES.md"
"$HOME/.local/bin/astatine" --version
```

If `~/.local/bin` is not on your `PATH`, add it in your shell startup file (for example, `export PATH="$HOME/.local/bin:$PATH"` in `~/.profile` or `~/.zshrc`). Linux configuration, wallets, and transaction journals use `${XDG_CONFIG_HOME:-$HOME/.config}/astatine`.

### Windows PowerShell

Supported target: Windows 10 or later, x86_64. The executable is installed under your user profile and no administrator access is needed.

```powershell
$ErrorActionPreference = 'Stop'
$Version = 'v0.1.0-testnet.8'
$Asset = 'astatine-windows-x86_64.zip'
$Base = "https://github.com/emyrinj/astatine-miner/releases/download/$Version"
$Temp = Join-Path $env:TEMP ("astatine-install-" + [Guid]::NewGuid().ToString('N'))
$Archive = Join-Path $Temp $Asset
$Checksums = Join-Path $Temp 'SHA256SUMS'
New-Item -ItemType Directory -Path $Temp | Out-Null
try {
    Invoke-WebRequest -Uri "$Base/$Asset" -OutFile $Archive -TimeoutSec 180
    Invoke-WebRequest -Uri "$Base/SHA256SUMS" -OutFile $Checksums -TimeoutSec 60
    $Line = Get-Content $Checksums | Where-Object { $_ -match '\s+astatine-windows-x86_64\.zip$' } | Select-Object -First 1
    if (-not $Line) { throw 'Windows archive checksum is missing from SHA256SUMS' }
    $Expected = ($Line -split '\s+')[0].ToLowerInvariant()
    $Actual = (Get-FileHash -Path $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected) { throw 'SHA-256 verification failed; archive was not installed' }
    Expand-Archive -Path $Archive -DestinationPath $Temp
    $InstallDir = Join-Path $HOME 'bin'
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item (Join-Path $Temp 'astatine.exe') (Join-Path $InstallDir 'astatine.exe') -Force
    $LicenseDir = Join-Path $InstallDir 'licenses'
    New-Item -ItemType Directory -Path $LicenseDir -Force | Out-Null
    Copy-Item (Join-Path $Temp 'LICENSE-MIT') (Join-Path $LicenseDir 'LICENSE-MIT') -Force
    Copy-Item (Join-Path $Temp 'THIRD_PARTY_LICENSES.md') (Join-Path $LicenseDir 'THIRD_PARTY_LICENSES.md') -Force
    & (Join-Path $InstallDir 'astatine.exe') --version
} finally {
    Remove-Item $Temp -Recurse -Force -ErrorAction SilentlyContinue
}
```

Add `$HOME\bin` to your user `Path` through **Settings → System → About → Advanced system settings → Environment Variables**, then open a new PowerShell window and verify with `astatine.exe --version`. Configuration, wallets, and transaction journals remain in `%APPDATA%\Astatine`.

SHA-256 checks detect damaged or mismatched downloads. Release binaries are not Developer ID signed or notarized on macOS and are not Authenticode signed on Windows. Apple Silicon has the linker-provided ad-hoc signature; Intel macOS, Linux and Windows binaries are unsigned.

## Use

```sh
astatine init
astatine mine
astatine mine --compute-only
```

`astatine init` configures the wallet, network, CPU budget, reserve, transaction cap, and confirmation depth. Startup shows configuration, RPC/deployment checks, transaction recovery, wallet unlock, initial work, worker preparation and when historical reward verification is scheduled; detailed history counters are hidden during ordinary startup. Historical reward verification runs in the background so live proof work can continue while older events are checked. Interactive terminals use a subtle spinner, while redirected output uses plain-text progress. The mining dashboard shows live node state, INJ and AST balances, canonically verified rewards mined during the current invocation, hashrate, transaction, and session-exposure status; it distinguishes proof checking, signed-but-not-yet-broadcast, broadcast/confirmation, chain waiting, required/retrying finalization, and policy-blocked finalization. Autonomous mining retains the best queued proof per node in a bounded inbox, revalidates it against current verified work, and reports bounded per-node proof-pipeline counters on exit (including rejection reasons, paid-attempt suppression, broadcast, and verified candidate events). `--compute-only` hashes locally without unlocking a wallet or sending transactions. Use `--nodes 1,3,5` to restrict mining to selected nodes.

Set `ASTATINE_HISTORY_PROFILE=1` before `astatine mine` (or `$env:ASTATINE_HISTORY_PROFILE='1'` in PowerShell) to print aggregate history profiling at startup and shutdown for developer diagnostics. The profile contains counters and timings only. Normal startup continues to display actionable transaction/RPC warnings and the background reward-verification status without the aggregate dump.

New encrypted Ethereum V3 keystores accept passwords of at least four Unicode characters and at most 1024 bytes. Input is hidden and confirmed. A brief, non-blocking warning recommends a longer unique password when fewer than 12 characters are chosen. This applies to new wallets and mnemonic imports; importing an existing V3 keystore continues to use its original password.

**Transaction costs:** Each proof submission pays a `0.01 INJ` fee. Finalizing a window consumes INJ gas, including when the window is empty or another miner wins. These costs count toward the configured per-session cap. The default cap is zero, which disables transaction signing; a positive cap explicitly authorizes spending. Mainnet transaction signing is disabled.

## License

The miner is licensed under [MIT](LICENSE-MIT). Third-party dependency notices are in [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
