# macOS ARM64 manual installation

This guide describes the `v0.1.0-testnet.0` macOS ARM64 Testnet prerelease, Apple
Silicon only. Confirm the release record and publication status before use. Source
is MIT; binary archives include MIT and third-party notices. Linux/Windows
distribution needs separate qualification.

The compiled `support/release-repository.txt` contains only the owner/name pair; it
does not contain a numeric repository ID or release commit. Obtain the
`OWNER/REPOSITORY` pair, numeric repository ID and release commit from the
authenticated release record after read-back; do not infer or reuse them from an
older binary, checksum file, package or guide. A same-name repository does not by
itself change compiled inputs or require a rebuild.

## Download and authenticate — before extracting or running

Choose `astatine-v0.1.0-testnet.0-macos-arm64.tar.gz`, not a debug/source archive.
Use a trusted GitHub CLI with `release verify`/`verify-asset` support. Run each
command individually; **stop on any failure or mismatch**. Never pipe downloads
to a shell. These commands do not authorize installation or paid mining themselves.

```sh
tag=v0.1.0-testnet.0
asset=astatine-v0.1.0-testnet.0-macos-arm64.tar.gz
# Set these from the authenticated release record after read-back.
# Use the verified repository name and numeric ID from that record.
: "${repo:?set the verified OWNER/REPOSITORY}"
: "${repo_id:?set the verified numeric repository ID}"
curl --fail --location --proto '=https' --tlsv1.2 --output "$asset" \
  "https://github.com/$repo/releases/download/$tag/$asset"
curl --fail --location --proto '=https' --tlsv1.2 --output SHA256SUMS \
  "https://github.com/$repo/releases/download/$tag/SHA256SUMS"
test "$(gh api "repos/$repo" --jq .id)" = "$repo_id"
gh release verify "$tag" --repo "$repo"
gh release verify-asset "$tag" "./$asset" --repo "$repo"
gh release verify-asset "$tag" ./SHA256SUMS --repo "$repo"
grep -F "  $asset" SHA256SUMS
```

Check the exact archive filename and 64-hex digest in the authenticated checksum
record, then compare `shasum -a 256 "$asset"` to that value. Also check the intended
release tag/commit against the authenticated release record.
Release attestations bind GitHub release assets; they do not independently prove
honest source-to-binary compilation or remove administrator trust. If attestations
are unavailable, stop pending an explicitly approved alternative authentication
channel. A checksum and archive from the same unauthenticated source alone do not
authenticate a publisher. No Actions/SLSA build attestation is promised.

Inspect `tar -tzvf "$asset"` first. Exactly one root directory
`astatine-v0.1.0-testnet.0-macos-arm64/` must contain four regular files:
`astatine` (0755), `LICENSE-MIT`, `THIRD_PARTY_LICENSES.md`, `INSTALL.md` (0644).
Reject extra/hidden/absolute/traversal paths, duplicates, links and special files.
Extract as your ordinary user into a **new empty private directory**, never with
sudo. Hash the extracted executable against the independently approved binary
digest in the release manifest, and run `codesign --verify --strict --verbose=4`
on that file. Keep both license files with your copy.

## macOS security boundary

The binary deliberately uses a valid linker-generated **ad-hoc** signature, not
Apple Developer ID or notarization. This does not authenticate the publisher.
Nonquarantined local Terminal execution has been reported to work even though
`spctl` rejected the file. **Quarantined browser-download/clean-user behavior is
not fully qualified**; a local launch is not proof that a download will launch.
The Mach-O floor is macOS11.0, not a claim that every older macOS/GPU was tested.

If macOS blocks launch, stop and retain the exact warning/OS/download/quarantine
details. Do not disable Gatekeeper, strip quarantine or alter system policy.
If macOS offers a per-application UI exception, choosing it requires your separate
explicit decision; this guide does not automatically authorize or click it.
No paid Apple signing infrastructure is required by this project's policy.

## Install executable and PATH (no sudo)

Use a user-owned nonsymlink directory such as `$HOME/.local/bin`; inspect its
existing path components and ownership first. Do not overwrite an active miner or
an unexpected existing executable/symlink. If this is a fresh destination, create
it yourself, then copy only the verified executable, mode0755. For example, after
setting `verified` to the verified extracted root:

```sh
mkdir -p "$HOME/.local/bin"
test ! -e "$HOME/.local/bin/astatine" && test ! -L "$HOME/.local/bin/astatine"
install -m 755 "$verified/astatine" "$HOME/.local/bin/astatine"
"$HOME/.local/bin/astatine" --version
"$HOME/.local/bin/astatine" --help
```

Require `astatine 0.1.0-testnet.0`, and recheck the installed binary's approved
hash. Store `LICENSE-MIT` and `THIRD_PARTY_LICENSES.md` with your installation
records. Inspect `type -a astatine`/`command -v astatine` for aliases, functions or
older copies; use the full verified path if resolution is ambiguous.

For macOS zsh, if `$HOME/.local/bin` is not already in PATH, manually add **one**
line to `~/.zshrc` (inspect first; do not append duplicates):

```sh
export PATH="$HOME/.local/bin:$PATH"
```

Open a new Terminal, or reload your reviewed configuration with `source ~/.zshrc`
and `rehash`. Recheck `command -v astatine` and `astatine --version`. No installer
or miner changes shell startup files for you.

## Configure, protect keys, and authorize deliberately

Only after verification and your explicit decision to create/use a wallet, run
`astatine init`. Use disposable **Testnet-only** material initially. It configures
network/RPC/wallet/threads/reserve/confirmation depth and a persistent per-run
authorization policy; review every prompt. It does not broadcast a transaction,
but it changes application state and can access macOS Keychain.

Use a private trusted real terminal with no recording/screen sharing. Never put
a recovery phrase, private key or wallet password in command arguments, shell
history, environment variables, screenshots, support logs or chat. Confirm the
offline recovery backup before accepting `BACKED UP`. Losing/deleting a keystore
without a verified usable recovery backup can permanently destroy asset access.

On macOS the separate application state is under
`~/Library/Application Support/Astatine`: configuration, encrypted Ethereum V3
wallets and transaction journal/archives. Native journal authentication/checkpoints
use macOS Keychain and the canonical data-root identity. Expect possible Keychain
access prompts; verify which program/action requested access and decide yourself.
Prompt frequency depends on the OS/Keychain policy; none is promised. Wallet
commands can read Keychain through journal guards. A different HOME is not a
separate login Keychain. Do not move/reset the root or delete native entries to
bypass integrity errors; use qualified recovery guidance and matching trusted state.

Each explicit paid `astatine mine` in per-run mode can start a fresh allowance
under the saved policy. A full-ceiling run may need no repeat approval; reduced
balance-derived caps require consent. Repeated runs can spend more than one cap.
The cap charges maximum value+gas **before signing**, never refunds authorization
from receipts, and is not lifetime loss protection against a dishonest RPC.
Each proof/improvement costs0.003 INJ plus gas; finalization also costs gas and
neither guarantees a reward. There is no hard transaction-count limiter: a normal
run can submit multiple improved proofs/finalizations. A policy approved for one
test identity does not authorize anyone else's mining or automatic refills; each
later paid `astatine mine` is a separate explicit invocation under the saved policy.
Mainnet signing and automatic AST forwarding are disabled. Independently verify
chain outcomes.

Start compute/paid mining only deliberately, with your own approved risk budget.
Press **Ctrl+C** to request stop; wait for clean process exit. Already signed or
broadcast transactions cannot be recalled. Use `astatine recover` deliberately
for no-new-signature/broadcast reconciliation of pending Testnet transactions;
it may update local journal/Keychain state. Do not clear pending liabilities to
obtain fresh authorization. In the dashboard, `BLOCK` means an **Astatine mining
window ID**, not the separately displayed Injective EVM block height.

## Update or uninstall — executable is not wallet state

Stop every active miner before replacement. Authenticate the new archive, retain
the old executable/hash and replace **only** the executable; retain notices and
leave configuration, keystores, journal/archives and Keychain at the same canonical
root untouched. Recheck binary hash/version/PATH. Binary rollback does not roll
back authenticated state; historical v8 no-prior interrupted-init compatibility
is unqualified, and `.0` is not an automatic safe upgrade from older `.18` builds.

To uninstall, after stopping the process and checking the exact nonsymlink path,
remove only the installed executable (and optionally its installation-only notice
copies). Review PATH manually if needed; do not remove unrelated entries. Keep
application data and Keychain by default. **Deleting a wallet, its encrypted
keystore, journal, checkpoint or test account is a separate destructive decision,
not executable uninstall.** Never delete them to make a failed recovery pass.
