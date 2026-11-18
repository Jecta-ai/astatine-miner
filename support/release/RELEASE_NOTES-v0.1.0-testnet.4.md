# Astatine Miner v0.1.0-testnet.4 — Testnet prerelease

Testnet prerelease with native binaries for macOS ARM64, Linux x86_64, and Windows x86_64.

## Highlights

- Adds a native Windows x86_64 package (`astatine.exe` in a deterministic ZIP) alongside the macOS ARM64 and Linux x86_64 archives.
- Uses per-target exact archive layouts with deterministic timestamps and file modes.
- Adds a Windows installation and safety guide with PowerShell verification steps.
- Updates install and safety documentation across all three platforms.

## Downloads

| Platform | Archive | Binary |
|---|---|---|
| macOS ARM64 | `astatine-v0.1.0-testnet.4-macos-arm64.tar.gz` | `astatine` |
| Linux x86_64 | `astatine-v0.1.0-testnet.4-linux-x86_64.tar.gz` | `astatine` |
| Windows x86_64 | `astatine-v0.1.0-testnet.4-windows-x86_64.zip` | `astatine.exe` |

Additional files:

- `SHA256SUMS`
- `release-provenance.json`
- `release-notes.md` (this file)

Each binary archive contains exactly five files: the binary, `LICENSE-MIT`, `THIRD_PARTY_LICENSES.md`, `BUILD-INFO.json`, and `INSTALL.md`.

Verify the exact asset inventory and digests against the authenticated release record. Binaries are format-validated per target (Mach-O ARM64, ELF x86_64, PE x86-64).

## Install

See the platform guides before downloading or running anything:

- macOS ARM64: `MACOS_ARM64.md`
- Linux x86_64: `LINUX_X86_64.md`
- Windows x86_64: `WINDOWS_X86_64.md`

Verify `SHA256SUMS`, the GitHub build-provenance attestations for the exact tag, and the release immutable status before installing. Never trust an archive alone.

## Compatibility and safety

- Testnet only. Mainnet transaction signing is disabled.
- Proof submissions and finalization consume INJ fees and gas and do not guarantee rewards.
- macOS: ad-hoc signature only; not Developer ID signed or notarized.
- Linux: Ubuntu 24.04 / glibc baseline. Paid mining requires an available, unlocked Secret Service.
- Windows: install to a user-owned directory without elevation. The packaged executable is validated as an x86-64 PE binary. GPU operation on Windows is unqualified; CPU mining is the qualified path.
- No separate vendor or operating-system code-signing signature is claimed. Stop the miner before replacing the binary and preserve configuration, wallets, credentials, journals, and transaction archives.
