## Astatine Miner v0.1.0-testnet.9

Testnet.9 adds opt-in AST reward forwarding and authenticated release updates while preserving the Testnet.8 mining defaults.

### Reward forwarding

- Use `astatine mine --send-rewards-to ADDRESS` to authorize forwarding this invocation's verified AST rewards to one EVM address.
- Only canonical, confirmed winning-window payouts are eligible. Transfers use the exact verified payout and are journaled to prevent duplicate sends across restarts and retries.
- `MINED` remains the invocation's earned-reward total; the wallet's AST `BALANCE` reflects completed transfers.
- Transfer gas counts against the configured INJ spending cap and reserve. Forwarding is disabled by default and is incompatible with `--compute-only`.

### Authenticated releases and updates

- Signed RSA release manifest binds the Testnet channel, version, five platform archives, five native executables, license notices, SHA-256 digests, and asset sizes.
- `astatine update --check` verifies the signed manifest without downloading or installing binaries. `astatine update` verifies each downloaded digest before replacing installed files; failed installations roll back. Configuration, wallets, and transaction journals are untouched.
- GitHub build-provenance attestations are published for the release assets. Verify one with `gh attestation verify <asset> --repo emyrinj/astatine-miner`.

### Install

macOS/Linux one-command install:

```sh
curl --fail --show-error --location https://raw.githubusercontent.com/emyrinj/astatine-miner/__RELEASE_COMMIT__/support/install-unix.sh | sh
```

Windows PowerShell one-command install:

```powershell
$Installer = Join-Path $env:TEMP 'astatine-install.ps1'; Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/emyrinj/astatine-miner/__RELEASE_COMMIT__/support/install-windows.ps1' -OutFile $Installer; powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Installer
```

Both scripts can be downloaded and reviewed before execution; the full commands are in the README.

### Downloads

- `astatine-macos-aarch64.tar.gz`
- `astatine-macos-x86_64.tar.gz`
- `astatine-linux-aarch64.tar.gz`
- `astatine-linux-x86_64.tar.gz`
- `astatine-windows-x86_64.zip`
- `update-manifest.txt`, `update-manifest.sig`, and `SHA256SUMS`

Install instructions and platform support details are in the repository README. Mainnet transaction signing remains disabled.
