# Linux x86_64 manual installation

This guide describes the `v0.1.0-testnet.6` Linux x86_64 Testnet prerelease
candidate. Confirm that the release has actually been published and read back
its authenticated release record before downloading. This guide is not evidence
that a release or its attestations exist.

## Download and verify — before extracting or running

Use the exact tag and asset name below; do not use a debug or source archive.
Obtain the repository name and numeric ID, exact source commit and tree, and
signer-workflow identity from the authenticated release record. Do not infer
these values from this guide, a checksum, an older binary, or the checkout.
Run each verification command and stop on any failure or mismatch.

```sh
tag=v0.1.0-testnet.6
asset=astatine-v0.1.0-testnet.6-linux-x86_64.tar.gz
# Set these from the authenticated release record after read-back.
: "${repo:?set the verified OWNER/REPOSITORY}"
: "${repo_id:?set the verified numeric repository ID}"
: "${source_commit:?set the exact source commit from the release record}"
: "${signer_workflow:?set the verified signer workflow from the release record}"
source_digest="$source_commit"
source_ref="refs/tags/$tag"

curl --fail --location --proto '=https' --tlsv1.2 --output "$asset" \
  "https://github.com/$repo/releases/download/$tag/$asset"
curl --fail --location --proto '=https' --tlsv1.2 --output SHA256SUMS \
  "https://github.com/$repo/releases/download/$tag/SHA256SUMS"
curl --fail --location --proto '=https' --tlsv1.2 --output release-provenance.json \
  "https://github.com/$repo/releases/download/$tag/release-provenance.json"
test "$(gh api "repos/$repo" --jq .id)" = "$repo_id"
gh release verify "$tag" --repo "$repo"
gh release verify-asset "$tag" "./$asset" --repo "$repo"
gh release verify-asset "$tag" ./SHA256SUMS --repo "$repo"
gh release verify-asset "$tag" ./release-provenance.json --repo "$repo"
gh attestation verify "./$asset" --repo "$repo" \
  --signer-workflow "$signer_workflow" \
  --source-digest "$source_digest" --source-ref "$source_ref"
grep -F "  $asset" SHA256SUMS
sha256sum "$asset"
```

Check that the checksum row names this exact archive and compare its full
64-hex digest with `sha256sum` output. Confirm the tag, source commit/tree,
repository identity, and signer workflow all match the authenticated release
record. The build attestation binds the archive to the recorded workflow and
source reference; it is not independent proof of reproducible compilation or a
substitute for reviewing the release record.

## Inspect and install without elevated privileges

Inspect `tar -tzvf "$asset"` before extraction. The expected single root is
`astatine-v0.1.0-testnet.6-linux-x86_64/`, containing exactly five regular files:
`astatine` (mode 0755), `LICENSE-MIT`, `THIRD_PARTY_LICENSES.md`,
`BUILD-INFO.json`, and `INSTALL.md` (mode 0644). Reject extra, hidden,
absolute, traversal, duplicate, linked, or special-file entries, or any
unexpected mode. Extract as your ordinary user into a new empty private
directory; do not use `sudo`.

Install only the verified executable into a user-owned, nonsymlink path such as
`$HOME/.local/bin`. Inspect existing path components and ownership first, and do
not overwrite an existing executable or symlink.

```sh
mkdir -m 700 "$HOME/astatine-v0.1.0-testnet.6-linux-x86_64"
tar -xzf "$asset" -C "$HOME/astatine-v0.1.0-testnet.6-linux-x86_64"
verified="$HOME/astatine-v0.1.0-testnet.6-linux-x86_64/astatine-v0.1.0-testnet.6-linux-x86_64"

mkdir -p "$HOME/.local/bin"
test ! -e "$HOME/.local/bin/astatine" && test ! -L "$HOME/.local/bin/astatine"
install -m 755 "$verified/astatine" "$HOME/.local/bin/astatine"
"$HOME/.local/bin/astatine" --version
"$HOME/.local/bin/astatine" --help
```

Require `astatine 0.1.0-testnet.6` and recheck the installed executable's
approved digest. Keep both license notices with the installation records.
Check `command -v astatine` for aliases or older copies; use the full verified
path if resolution is ambiguous. These version/help checks do not create or
unlock a wallet, start mining, or contact an RPC endpoint.

## Platform and operation limits

The package baseline is Ubuntu 24.04 x86_64 / glibc 2.39. Older distributions
and other Linux environments are not qualified; do not assume compatibility
with an older glibc.

Linux paid mining requires an available, unlocked Secret Service for the
separately stored journal-authentication key and checkpoint. Headless systems
and containers may not provide one; an encrypted keystore alone is insufficient.
Do not delete or reset journals or credential-store entries to bypass an
integrity or availability failure.

CUDA and GPU operation are not qualified by this package. A GPU backend being
present in the executable does not qualify a device, driver, or mining result;
do not treat CUDA/GPU use as supported on the strength of this archive alone.

This is a Testnet-only candidate. Mainnet transaction signing is disabled.
Verification commands above are not mining instructions or permission to spend
Testnet funds. Paid transactions consume INJ fees and gas and do not guarantee a
reward. The miner trusts the selected RPC provider for chain state, receipts,
and reward evidence; it does not cryptographically authenticate all RPC data.

No separate vendor or operating-system code-signing signature is claimed for
the Linux executable. GitHub release/build attestations and checksums must be
verified as described above; do not infer signing or publisher authentication
beyond those documented controls.

## State and upgrades

Linux state is stored under `${XDG_CONFIG_HOME:-$HOME/.config}/astatine`, not
beside the executable. Stop the miner before replacement. Retain configuration,
wallets, credentials, journals, and transaction archives; replace only the
verified executable and do not overwrite or delete state. Downgrade compatibility
is not guaranteed.
