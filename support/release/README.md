# Linux release dry-run (blocked gate, no publication, no attestation)

This directory holds the inputs and evidence for the local Linux
release **dry-run**. The rights lane owns
`support/release/distribution-inventory.json`; the dry-run lane reads it and
must never edit it into an authorized state.

This dry-run does **not** satisfy E-06 on its own: E-06 remains open until an
authorized publisher, an independently verified Linux x86_64 artifact, and
contemporaneous qualification evidence exist. What follows is a rehearsal
from the dispatched commit that stays blocked, not publisher authentication.

## What the dry-run proves

- The workflow builds the locked Linux x86_64 binary from the dispatched
  checkout (`cargo build --locked --release` with pinned Rust `1.94.1`) and
  passes CLI smoke checks (`--version`, `--help`). The builder additionally
  requires the observed compiler to report exactly `rustc 1.94.1`, records
  the observed `cargo` version and the `Cargo.lock` SHA-256, and requires
  the archived binary to be an ELF64 little-endian x86_64 object before it
  is archived. The packaged scope is the `astatine` native binary from the
  `astatine-cli-rust` package (release profile) — not an npm package.
- `support/verify-fixture-provenance.py` and
  `support/verify-distribution-inventory.py` independently confirm the
  recorded gate before anything is archived.
- `support/release/build-dry-run.py` reads **only** the canonical
  `tests/fixtures/PROVENANCE.json` and
  `support/release/distribution-inventory.json` (no path overrides exist),
  matches the gate against the **exact canonical blocked text** (not
  prefixes): the full publication-decision sentence, the checklist status
  `OPEN — publication remains BLOCKED`, `UNRESOLVED` notice applicability,
  and the byte-for-byte RIGHTS-02..RIGHTS-05 action/owner/evidence records.
  Every provenance fixture must declare `release_archive_member: false`.
- The builder requires the **full source tree**, including both gate files,
  to be clean at `HEAD` (staged and unstaged tracked changes rejected, as are
  non-ignored untracked files; every archive document must additionally be
  tracked and clean) and records `source_clean_at_head` plus explicit
  gate-file cleanliness. Git-ignored files are generally not inspected by this
  Git check; `target/` is the expected build output and the only explicitly
  allowed untracked path. A clean tree does **not** prove the archived
  binary was built from `HEAD`; that linkage is workflow-build-only (fresh
  checkout, then build) and is recorded as unverified in
  `binary_build_linkage`.
- The workflow builds a **deterministic** `tar.gz` from exactly five members:
  the explicit source allowlist (`astatine` + `LICENSE-MIT` +
  `THIRD_PARTY_LICENSES.md`) plus two deterministically generated members
  (`BUILD-INFO.json` and `INSTALL.md`, produced in memory by the builder and
  never written to the source tree). The generated members carry the exact
  source identity (repository/commit/tree/commit-timestamp date), the package
  version, the corresponding-source recipe, dependency hashes, install and
  upgrade notes, and the unverified-linkage statement. No fixture, provenance
  file, source file, or forbidden path can enter the archive.
- No attestation is recorded or verified. The workflow performs no
  attestation dispatch, requests no OIDC identity, stores no attestation
  record, and uploads no release asset of any kind (no upload-artifact step,
  no tag, no branch, no push, no GitHub release, no `cargo publish`, and no
  external release binary is signed). This absence is intentional: the
  distribution inventory explicitly records workflow attestation dispatch as
  not authorized.
- `release-provenance.json` records the canonical gate paths, commit/tree,
  `source_clean_at_head`, gate-file cleanliness, `git_verified` status,
  package/binary/profile/target, Cargo command and versions, lock hash,
  binary install info, artifact and member hashes, gate state, and
  `publication_authorized: false`. It records no absolute checkout path and
  no raw invocation, to avoid identifying data in artifacts that operators
  might copy; legitimate provenance (commit, tree, source date, toolchain,
  lock hash, artifact and member hashes, gate state) is preserved.

## What the dry-run does NOT prove

- It does not authorize publication. The rights gate stays **BLOCKED**:
  the exact publication-decision sentence above, NOTICE applicability
  `UNRESOLVED`, and `RIGHTS-02` through `RIGHTS-05` remain OPEN and
  blocking. Any move to an authorized state needs reviewed code changes,
  not data-only edits. No legal approval is inferred from any of these
  checks.
- No attestation exists to authenticate. No attestation is dispatched,
  stored, or verified by this lane; the absence of attestation is required
  by the blocked gate. The dry-run therefore authenticates no publisher and
  no legal approval, and it is not release evidence.
- Bit-for-bit reproducibility across hosts is **not** claimed. The tarball
  is deterministic given identical inputs (sorted members, zeroed
  timestamps/ownership, fixed modes, `gzip -n` equivalent, commit-timestamp
  source date instead of the wall clock), but toolchain,
  host, and dependency differences are out of scope.
- Build-from-HEAD linkage is **not** proven by this script (see
  `binary_build_linkage`): the workflow builds after checkout, but the
  script only verifies the tree is clean and the binary has the expected
  shape — it cannot prove the binary bytes came from that source.
- No installer, updater, deployment credential, paid-mining run, public
  RPC contact, or production wallet operation is involved.

## No publication path

The dry-run creates only local files inside an output directory that must
be **new or empty and lie outside the source tree** (pre-existing files,
symlinks, non-empty directories, and in-tree locations are all refused,
and each output file is created exclusively): the `.dry-run.tar.gz`
archive, `SHA256SUMS`, and `release-provenance.json`. No attestation is
added by the workflow. There is intentionally:

- no artifact or release upload step and no stored attestation record,
- no tag, branch, push, or GitHub release,
- no `cargo publish` and no external release binary signing,
- no stored repository credentials and no OIDC identity request: job
  permissions are `contents: read` only (see assumptions below).

`--mode release` in `build-dry-run.py` always fails closed because no
authorized publisher exists. `--mode dry-run` also fails if the gate text
is not exactly canonical, if the tree is not clean, if the toolchain or
binary shape is wrong, or if a tracked member is dirty, so a changed gate
or source forces re-review instead of silently passing.

## Review/CI branch-push authorization (limited)

- Pushing the `fix/phase-e-e02-e07` remediation branch to the already-public
  repository **solely for review and CI** is authorized by the project owner
  on 2026-11-16 (`review_ci_branch_push_authorization`,
  status `AUTHORIZED \u2014 REVIEW/CI ONLY`, recorded identically in
  `tests/fixtures/PROVENANCE.json` and the distribution inventory; the
  dry-run builder exact-matches it and fails closed on any difference).
- Public repository visibility authorizes nothing beyond that push. It does
  **not** authorize a source archive, a binary archive or release, tag or
  public release publication, workflow attestation dispatch, a broader
  license grant or legal clearance, or resolution of RIGHTS-02 through
  RIGHTS-05. Do not infer authorization from public visibility.
- Unchanged and still blocking: RIGHTS-02 through RIGHTS-05 remain OPEN and
  blocking; `source_distribution` and `binary_distribution` remain BLOCKED;
  the publication decision remains the exact BLOCKED text. No tag, release,
  or attestation dispatch is authorized or performed by this lane.

## Install, upgrade, and corresponding source

`INSTALL.md` (in the archive) is the human-readable operator note;
`BUILD-INFO.json` is the machine-readable equivalent. Both are generated
deterministically from the dispatched commit — the source date is the commit
timestamp, never the wall clock — and both restate that the archive is NOT
FOR PUBLICATION OR DISTRIBUTION.

- Install: verify `SHA256SUMS` externally, extract, install `astatine` 0755
  on `PATH`, confirm `--version`.
- Upgrade: stop the miner, keep configuration/wallets/keystores/credentials/
  journals, replace only the binary, never overwrite or delete state; see the
  top-level README.md for platform state locations. Downgrade compatibility
  is not guaranteed.
- Corresponding source is **not** in the archive. Obtain it with
  `git clone https://github.com/Jecta-ai/astatine-miner.git &&
  git checkout <commit>` using the exact commit recorded in
  `BUILD-INFO.json`; dependency pins are in `Cargo.lock` (hash recorded),
  notices in `THIRD_PARTY_LICENSES.md`, license in `LICENSE-MIT`.

## Runner assumptions (no attestation)

- The workflow is `workflow_dispatch` only and runs on GitHub-hosted
  `ubuntu-24.04` x86_64 with pinned action SHAs and `contents: read`
  at the top and job level. No `id-token: write` or `attestations: write`
  grant exists, and no OIDC identity is requested. No `github.token`
  exposure beyond the default read-only checkout occurs.
- The following are **unsupported or unverified** and must not be treated
  as equivalent evidence: fork PR runs, self-hosted runners, offline or
  third-party mirrors, and any manual copy of the archive.
- Inspect the hosted workflow result for the exact dispatched commit. A
  configured workflow file alone is not evidence of execution.

## Prerequisites: green CI for the exact commit (required)

- Do not dispatch the dry-run unless the exact dispatched commit shows
  green `Rust CI` in the hosted workflow results. Green means the
  `native-checks`, `linux-safe-tests`, and `dependency-policy` jobs all
  passed for that commit, including toolchain pin checks, fixture and
  distribution inventory verifiers, `cargo deny check`, the inactive-graph
  guard, `cargo audit`, and third-party license notice regeneration checks.
- A configured workflow file alone is not evidence of execution. Inspect
  the hosted workflow result for the exact dispatched commit before running
  the dry-run.
- Only the three tracked workflows in `.github/workflows/` are authorized:
  `ci.yml` (push/pull-request only), `linux-native-qualification.yml`, and
  `linux-release-dry-run.yml` (manual dispatch only). No other workflow,
  dispatch source, or publish/release path is authorized while the gate is
  BLOCKED.
- The dry-run does not replace CI and does not satisfy E-06. E-06 remains
  open until an authorized publisher, an independently verified Linux
  x86_64 artifact, and contemporaneous qualification evidence exist.
- The green-CI prerequisite above is inspected separately in the hosted
  workflow results for the exact commit; it is not executed by the dry-run
  steps. The commands under `Local use (offline)` below are the only steps
  executed by this lane.

## Local use (offline)

```sh
python3 -B support/verify-fixture-provenance.py
python3 -B support/verify-distribution-inventory.py
cargo build --locked --release
python3 -B support/release/build-dry-run.py --mode dry-run --output-dir /tmp/astatine-dry-run-out
python3 -B -m unittest discover -s support/tests -p 'test_*.py'
```

The local build must be on Linux x86_64 with the pinned Rust 1.94.1 toolchain.

The output directory must not exist or must be empty, and must be outside
the source tree. The source tree itself must be a clean Git checkout at
HEAD; non-Git roots fail closed, produce no clean-tree record, and cannot
satisfy the workflow's `git_verified` assertion. The Python checks are offline and stdlib-only; the locked Cargo build uses
the recorded dependency set and may fetch it if it is not cached. They write
no `__pycache__` when run with `-B`, never read wallets, and never modify the
source tree.
