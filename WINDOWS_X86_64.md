# Windows x86_64 manual installation

This guide describes the `v0.1.0-testnet.5` Windows x86_64 Testnet prerelease
candidate. Confirm that the release has actually been published and read back
its authenticated release record before downloading. This guide is not evidence
that a release or its attestations exist.

## Download and verify — before extracting or running

Use the exact tag and asset name below; do not use a debug or source archive.
Obtain the repository name and numeric ID, exact source commit and tree, and
signer-workflow identity from the authenticated release record. Do not infer
these values from this guide, a checksum, an older binary, or the checkout.
Run each verification command and stop on any failure or mismatch.

```powershell
$tag = "v0.1.0-testnet.5"
$asset = "astatine-v0.1.0-testnet.5-windows-x86_64.zip"
# Set these from the authenticated release record after read-back.
# $repo, $repoId, $sourceCommit, $signerWorkflow
$sourceDigest = $sourceCommit
$sourceRef = "refs/tags/$tag"

curl.exe --fail --location --proto "=https" --tlsv1.2 --output $asset `
  "https://github.com/$repo/releases/download/$tag/$asset"
curl.exe --fail --location --proto "=https" --tlsv1.2 --output SHA256SUMS `
  "https://github.com/$repo/releases/download/$tag/SHA256SUMS"
curl.exe --fail --location --proto "=https" --tlsv1.2 --output release-provenance.json `
  "https://github.com/$repo/releases/download/$tag/release-provenance.json"
if ((gh api "repos/$repo" --jq .id) -ne $repoId) { throw "repository id mismatch" }
gh release verify "$tag" --repo "$repo"
gh release verify-asset "$tag" "./$asset" --repo "$repo"
gh release verify-asset "$tag" ./SHA256SUMS --repo "$repo"
gh release verify-asset "$tag" ./release-provenance.json --repo "$repo"
gh attestation verify "./$asset" --repo "$repo" `
  --signer-workflow "$signerWorkflow" `
  --source-digest $sourceDigest --source-ref $sourceRef
Select-String -Path SHA256SUMS -Pattern "  $asset" -SimpleMatch
(Get-FileHash .\$asset -Algorithm SHA256).Hash
```

Check that the checksum row names this exact archive and compare its full
64-hex digest with `Get-FileHash` output. Confirm the tag, source commit/tree,
repository identity, and signer workflow all match the authenticated release
record. The build attestation binds the archive to the recorded workflow and
source reference; it is not independent proof of reproducible compilation or a
substitute for reviewing the release record.

## Inspect and install without elevation

List the ZIP contents before extraction. The expected single root is
`astatine-v0.1.0-testnet.5-windows-x86_64/`, containing exactly five entries:
`astatine.exe`, `LICENSE-MIT`, `THIRD_PARTY_LICENSES.md`,
`BUILD-INFO.json`, and `INSTALL.md`. The archive records Unix-style modes
in its ZIP metadata (`astatine.exe` 0755, the other four files 0644); these
are packaging metadata, not Windows filesystem permissions, and Windows
extracts them with default ACLs. Reject extra, hidden,
absolute, traversal, duplicate, linked, or special-file entries, or any
unexpected archived mode. Extract as your ordinary user into a new empty private
directory; do not use elevation.

```powershell
# List without extracting
tar -tf $asset
# Or PowerShell:
# Expand-Archive -Path $asset -DestinationPath "$env:USERPROFILE\astatine-inspect" -WhatIf

$extractDir = "$env:USERPROFILE\astatine-v0.1.0-testnet.5-windows-x86_64"
New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
Expand-Archive -Path $asset -DestinationPath $extractDir -Force
$verified = "$extractDir\astatine-v0.1.0-testnet.5-windows-x86_64"

$destDir = "$env:USERPROFILE\.local\bin"
New-Item -ItemType Directory -Force -Path $destDir | Out-Null
if (Test-Path "$destDir\astatine.exe") { throw "destination already exists; do not overwrite" }
Copy-Item "$verified\astatine.exe" -Destination "$destDir\astatine.exe"
& "$destDir\astatine.exe" --version
& "$destDir\astatine.exe" --help
```

Require `astatine 0.1.0-testnet.5` and recheck the installed executable's
approved digest. Keep both license notices with the installation records.
These version/help checks do not create or unlock a wallet, start mining, or
contact an RPC endpoint.

## Platform and operation limits

The package baseline is Windows 11 / Server 2025 x86_64. Older Windows
environments are not qualified.

Windows paid mining requires the Windows Credential Manager entry for the
separately stored journal-authentication key and checkpoint. The credential
store must be available; an encrypted keystore alone is insufficient.
Do not delete or reset journals or credential-store entries to bypass an
integrity or availability failure. Private state uses isolated safe paths;
do not place archives, extracts, or executables inside credential or state
directories, and do not run with elevation.

CUDA and GPU operation are not qualified by this package. A GPU backend being
present in the executable does not qualify a device, driver, or mining result;
do not treat CUDA/GPU use as supported on the strength of this archive alone.
Native Windows builds and automated CI smoke tests have passed, but Windows
GPU functionality remains physically unverified.

This is a Testnet-only candidate. Mainnet transaction signing is disabled.
Verification commands above are not mining instructions or permission to spend
Testnet funds. Paid transactions consume INJ fees and gas and do not guarantee a
reward. The miner trusts the selected RPC provider for chain state, receipts,
and reward evidence; it does not cryptographically authenticate all RPC data.

No separate vendor or operating-system code-signing signature is claimed for
the Windows executable. GitHub release/build attestations and checksums must be
verified as described above; do not infer signing or publisher authentication
beyond those documented controls.

## State and upgrades

Windows state is stored under `%APPDATA%\Astatine`, not beside the executable.
Stop the miner before replacement. Retain configuration, wallets, credentials,
journals, and transaction archives; replace only the verified executable and
do not overwrite or delete state. Downgrade compatibility is not guaranteed.
