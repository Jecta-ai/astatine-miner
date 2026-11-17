# Release lanes: nonpublishing dry-run vs release-intent dual-platform release (draft-only)

This directory holds the offline release gate and packaging lanes.
`support/release/gate.py` is the shared fail-closed loader for
`support/release/distribution-inventory.json` (schema
`astatine-distribution-inventory/v3`) against
`tests/fixtures/PROVENANCE.json` (schema `astatine-fixture-provenance/v3`).
`support/verify-distribution-inventory.py` uses `gate.py` and accepts both
the blocked v1 and the release-intent v3 states.

Regression preservation: the original blocked-state verifier code remains in
`support/verify-distribution-inventory.py` and dispatches v3 to `gate.py`. The
original 49 blocked-state tests remain in
`support/tests/test_distribution_inventory.py` against frozen blocked fixtures;
`support/tests/test_distribution_inventory_authorized.py` adds authorized-v3
coverage. No prior negative test was deleted.

Fixture preservation: the original 66 blocked-state fixture tests remain in
`support/tests/test_fixture_provenance_blocked.py` against the frozen blocked
fixture tree; the live v3 release-intent fixture suite remains in
`support/tests/test_fixture_provenance.py`. No prior fixture negative test was
deleted.

Licensing for candidate `v0.1.0-testnet.2` (macOS ARM64 and Linux x86_64 only)
is owner-authorized first-party source/binary distribution **intent**
(`release_intent_authorization` dated 2026-11-17); repository technical NOTICE
review recorded with citations; no legal conclusion and no separate release
approver appointed/consulted; final release controls outstanding.
Apache-2.0/MIT texts and fixture NOTICE included; all fixtures remain with
`release_archive_member: false`. Release execution
remains externally gated and draft-only: the exact tag, protected `release`
environment with explicit owner self-approval (owner reviewer pinned to
immutable numeric GitHub id 86115037 and login, `prevent_self_review: false`, no
admin bypass, exact-tag deployment policy, verified pagination total count),
separate refs/tags/v* creation and immutability rulesets, exact-commit main CI
(Rust CI + Linux native qualification), and build-provenance attestations are
enforced by
`.github/workflows/release.yml` preflight/build jobs; immutable-release
verification and manual publication are owner/admin steps. Owner self-approval
removes independent review and separation of duties; the security tradeoff and
owner-account residual risk are documented in the release notes and
inventories. Neither offline check nor draft creation establishes publication.
The historical `v0.1.0-testnet.1` tag remains at
`99a8630a7ae7f5c5950031dfba8c3b0c3f132cbc`; its pending workflow was not
cancelled or deleted and no `.1` release was published. The `.1` rights decision, scope and approval roles are preserved
in `HISTORICAL-v0.1.0-testnet.1.md` and in the
`historical_release_intent` inventory records. The `.2` authorization does not
rewrite that history.

`support/release/verify-protected-environment.py` validates the owner
self-approval environment snapshot (owner reviewer id `86115037`, false
self-review prevention, no admin bypass, exact tag policy, verified pagination
`total_count`). `support/release/verify-tag-ruleset.py` validates the two
composable ruleset snapshots:
`astatine-release-tag-creation` (exactly the creation rule, exactly
`refs/tags/v*` with no exclusions, with exactly the owner-user bypass
(User 86115037, always) for owner-only creation; repository-admin bypass is
rejected) and
`astatine-release-tags` (exactly update/deletion/non-fast-forward with zero
bypass actors, covering exactly `refs/tags/v*` with no exclusions). Creation
protection is retained; it is not removed or broadened. Narrowing either
ruleset to the single `.2` tag or to the historical `.0`/`.1`/`.2` list
weakens protection for all other `v*` tags and is rejected. Both are offline
fail-closed inputs to the workflow; a missing, combined, broadened, narrowed,
or bypassable snapshot fails closed. GitHub returns
`bypass_actors` only to a caller with write access to the ruleset; whether the
default workflow token has that access is not established by this revision. A
snapshot without the field fails closed as unverifiable. No token or secret is
added. Until a controlled runtime demonstrates the field is visible, or an
authorized admin-visible verification path exists, dispatch remains blocked
rather than weakening creation protection. Creation and immutability are
each exactly scoped to `refs/tags/v*` with no exclusions, preserving the live
breadth. Future releases require a reviewed scope update.
Offline checks cannot establish environment,
tag, CI, or immutable-setting state. The workflow creates and verifies a
**draft only**; it does not publish.

## GitHub App admin-visible verification (isolated, owner-authorized, NOT activated here)

The default workflow token's read access to tag-ruleset `bypass_actors` is not
established (see above): a snapshot without the field fails closed as
unverifiable. The only authorized path to an admin-visible read is a dedicated,
isolated GitHub App verification job, documented here and NOT activated by this
revision. If the candidate read permission is absent or the field is missing,
STOP: dispatch remains blocked rather than weakening creation protection.

Contract (the three isolated jobs `tag-ruleset-admin-verify`,
`tag-ruleset-admin-verify-package`, and `tag-ruleset-admin-verify-draft` are
defined in `.github/workflows/release.yml` by the workflow lane; this section
is the authorization boundary, not an activation):

- Dual-environment separation (read-first). The three verifier jobs are each
  bound to the dedicated protected `release-admin` environment
  (`environment: release-admin`) — verifiers only, never package/draft.
  `release-package` and `release-draft` stay bound to the protected `release`
  environment (`environment: release`). That is 3 `release-admin` + 2
  `release` = 5 protected environments total, out of 10 jobs total. Both
  environments share the same owner-only gate: owner sole self-approval
  (owner reviewer pinned to immutable numeric GitHub id 86115037 and login,
  `prevent_self_review: false`, no admin bypass `can_admins_bypass: false`,
  exact-tag deployment policy for the exact tag `v0.1.0-testnet.2` with
  verified pagination `total_count`). Credentials are owner-provided
  environment secrets (`RELEASE_ADMIN_APP_ID` /
  `RELEASE_ADMIN_APP_PRIVATE_KEY`) bound ONLY to the `release-admin`
  environment: 2 references x 3 verifier jobs = 6 total secret references,
  zero in `release` (package/draft carry no App secrets). Needs sequencing is
  exact: `tag-ruleset-admin-verify` needs `preflight` (initial verification
  before builds); `tag-ruleset-admin-verify-package` needs `attest-macos`,
  `attest-linux`, and `tag-ruleset-admin-verify` (fresh verification
  immediately before packaging); `tag-ruleset-admin-verify-draft` needs
  `release-package` (fresh verification immediately before draft creation).
  `release-package` needs the fresh `tag-ruleset-admin-verify-package` job
  (not the stale initial verification), plus the four build/attest jobs;
  `release-draft` needs `[release-package, tag-ruleset-admin-verify-draft]`
  (fresh before draft mutation).
- No checkout, no repository code, no candidate executables, and no build/test
  scripts run while any token is live; each job only mints its own token and
  performs bounded read-only `gh api` GET fetches of the live
  ruleset/environment state. Read-only allowlist only: `gh api "repos/$repo"`
  with `--jq .id`, `gh api "repos/$repo/rulesets?includes_parents=true&per_page=100"`,
  `gh api "repos/$repo/rulesets/$creation_id"`,
  `gh api "repos/$repo/rulesets/$immutability_id"`, and the draft tag-ref
  peeling reads (`gh api "repos/$repo/git/ref/tags/$tag"`,
  `gh api "repos/$repo/git/tags/$obj_sha"`). Mutating invocations are
  FORBIDDEN in all three admin jobs: no `-X`/`--method`, no POST/PATCH/PUT/DELETE,
  no `gh api -X POST`, no `gh release create/edit/delete`, no
  `gh attestation`, no `support/` scripts, no `cargo build`, no
  `target/release`. No job checks out code, downloads/uploads artifacts,
  executes candidate binaries, or runs repository scripts while its token is
  live. Negative tests attempting mutating commands must fail.
- The token is minted with the pinned third-party action
  `actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510`
  (`# v3.3.0`), scoped to exactly one repository (`owner: Jecta-ai`,
  `repositories: astatine-miner`, i.e. `Jecta-ai/astatine-miner` id
  `1454137135`) with a CANDIDATE permission under test
  (`permission-administration: read`). Research-librarian confirmation:
  `v3.3.0` SHA `64ab729a6294000f5aa4a4bc0b73d1f32bc45510` resolved via
  `api.github.com/repos/actions/create-github-app-token/git/ref/tags/v3.3.0`
  (type commit); `action.yml`/`README` at that SHA verified: `skip-token-revoke`
  defaults to `false`, the token output is masked and the installation token
  is revoked by the post-step unless `skip-token-revoke: true`, installation
  token expiry is 1 hour, and scoping is `owner` plus `repositories`
  (`owner` alone means all repositories of the owner; `repositories` narrows
  to the single named repository). Docs permission claims for the ruleset
  read were UNVERIFIED (upstream redirects to `llms.txt`); per the official
  researcher, the ruleset GET documents `Metadata: read` as its minimum,
  while `bypass_actors` is returned only to a caller with ruleset-write
  access. Whether Administration `read` grants that visibility is UNPROVEN —
  Administration `read` is plausible but NEITHER proven necessary NOR
  sufficient until the owner tests it live AFTER audit. There is NO write
  fallback: broadening to `permission-administration: write` without a
  reviewed contract update and fresh audit is PROHIBITED. Nothing broader is
  granted in the meantime, and each isolated job MUST fail closed if the
  field is absent. No other repositories, no other permissions. The same
  strict validation, same single-repo scope, same explicit revocation config,
  and same no-reuse rule apply identically to all three jobs; no signed
  snapshot is reused across jobs.
- Credentials are owner-provided `release-admin` environment secrets
  (`RELEASE_ADMIN_APP_ID` / `RELEASE_ADMIN_APP_PRIVATE_KEY`). This
  implementation creates NO GitHub App, stores NO keys, changes NO repository
  or environment settings, and contains NO secret values. The owner creates
  the App and stores the secrets manually, only AFTER independent audit of
  this contract. Do not ask for, print, or transmit secrets here. No
  credentials are activated by this revision.
- The minted tokens are short-lived (1-hour installation-token expiry) and
  scoped to the single repository; each of the three jobs sets explicit
  `skip-token-revoke: false` so the action post-step revokes the token.
  This is a neutral config check only: the `Check admin token handling`
  step (`if: always()`) `echo` does NOT prove revocation — do NOT claim echo
  proves revoke, and no test asserts that echo verifies revocation. The private key and each token
  are never printed, logged, stored, or uploaded: no `echo`/`print` of
  secrets, no artifact uploads from any admin job, and `GH_TOKEN` inside each
  job is sourced only from `steps.app-token.outputs.token` of that same job.
  Token reuse outside the three isolated admin jobs is PROHIBITED, and reuse
  across the three jobs is likewise prohibited: each job mints and consumes
  only its own token.
- Each admin job independently checks the exact tag `v0.1.0-testnet.2`,
  `GITHUB_REF`, canonical repository `Jecta-ai/astatine-miner`, and numeric
  repository id `1454137135` live. The admin jobs do not compare
  `GITHUB_SHA` directly: no checkout occurs while the App token is live.
  `needs` does NOT automatically inherit SHA binding; instead, GITHUB_SHA trust
  is inherited through each same-run needs chain from preflight, which verifies
  `HEAD==GITHUB_SHA` and `tag peel==GITHUB_SHA` via checkout. No stale
  snapshots are accepted and no signed snapshot is reused across jobs. The
  pre-existing exact-tag, exact-commit main CI, and fixture/provenance gates
  are preserved unchanged. Ruleset/repository/ref checks are live; a snapshot
  file carried across jobs (including via artifacts) would be stale by
  definition and is prohibited.
- Tag-protection semantics are unchanged: `astatine-release-tag-creation`
  keeps exactly the `creation` rule on exactly `refs/tags/v*` with no
  exclusions and exactly the owner-user bypass (`User 86115037`, always);
  `astatine-release-tags` keeps exactly `update`/`deletion`/`non_fast_forward`
  on exactly `refs/tags/v*` with no exclusions and zero bypass actors. Both
  fail closed; administrator bypass stays disabled. Each verification result
  feeds only its immediate mutation gate and is re-verified before mutation:
  the initial verification gates the build chain, the fresh package
  verification (which lists attestations plus the initial verification in
  `needs`) gates `release-package` (which lists the fresh package job in
  `needs`, not the stale initial job), and the fresh draft verification
  (which lists `release-package` in `needs`) gates `release-draft` (which
  lists `[release-package, tag-ruleset-admin-verify-draft]` in `needs`); no
  verification weakens or replaces those gates. Temporal disclosure
  (corrected): environment approvals can delay execution, so no
  atomic/immediate claim is made; a check-then-mutate race remains between
  each fresh check and its immediately following mutation (rulesets or
  environment could change after the fresh fetch and before package/draft
  mutation). It is mitigated by `needs` sequencing, `release-admin`
  approval on every verifier plus `release` approval on every mutation job,
  and re-verification immediately before each mutation, but it cannot be
  eliminated; this contract does NOT claim atomicity or immediacy between
  check and mutation. Manual prepublish recheck remains required immediately
  before publication (immutable-releases flag, exact tag, split rulesets with
  an owner/admin-visible token, every draft asset digest, draft body).
- Package and draft delegate bypass validation to the fresh admin jobs and
  run no default-token detail checks there. Each mutation job carries only a
  fresh-delegation comment (authoritative bypass validation is delegated to
  the fresh isolated App job sequenced via needs before this stage); the default
  token cannot see bypass_actors, so no ruleset-detail fetch and no
  verify-tag-ruleset.py run occur in either mutation job, and
  package-rulesets.json / draft-rulesets.json snapshot files are forbidden
  there. Authoritative validation lives only in the three isolated admin
  jobs, each live-fetching immediately before its stage with no stale signed
  snapshot reuse. Stale one-time owner check disclaimer: any one-time
  owner/admin console check is unavoidably stale the moment it is recorded —
  do NOT substitute it for the live per-job checks; live fetches in each of
  the three verifier jobs remain mandatory.
- Validator coverage is three `verify-protected-environment.py` invocations: preflight verifies BOTH live environments (`--expected-environment release` with `$env_out` plus `--expected-environment release-admin` with `$admin_env_out` variables), and `release-package` keeps its `release` re-verify before mutation; each admin job re-verifies `release-admin` live inline before mint; `release-draft` keeps its `release` re-verify. Temporal/SHA language is `same-run needs does NOT inherit SHA`, `not atomic or immediate`, `manual prepublish recheck remains`.
- No mining, wallet, payment, or network-mining behavior is added or changed.

Residual risk (stated honestly, not mitigated away): the minting action is a
third-party action handling the App private key and the installation token; a
compromised or mistaken action version, owner account, or leaked short-lived
token could weaken or dismantle the very protections these jobs verify. A SHA
pin only fixes the mutable-tag risk, not inherent action safety. Stated
mitigations are ONLY pin + isolation + revoke + single-repo: the exact SHA
pin `64ab729a6294000f5aa4a4bc0b73d1f32bc45510` (`# v3.3.0`) against tag
mutability, per-job isolation (no checkout/artifact/candidate/script while
the token is live), explicit `skip-token-revoke: false` per job with 1-hour
token lifetime, and single-repository scoping (`owner: Jecta-ai`,
`repositories: astatine-miner`). None of them constrains the
owner/administrator account itself, and owner self-approval already removes
independent review (see the tradeoff above). Token reuse outside the three
isolated admin jobs is PROHIBITED, and cross-job token reuse is likewise
PROHIBITED. Broadening permissions beyond `administration: read`, or
extending repository scope beyond `Jecta-ai/astatine-miner`, is PROHIBITED
without a reviewed contract update and fresh audit.

Until the owner has manually created the App, stored the `release-admin`
environment secrets, and each isolated job demonstrates the admin-visible
read in a controlled run, dispatch remains blocked rather than weakening
creation protection, and any missing candidate field fails closed with STOP.
This revision creates NO GitHub App, stores NO keys, changes NO repository or
environment settings, and activates NO credentials; all token minting occurs
only in the workflow at dispatch time after audit-gated App/secret setup.

## Nonpublishing Linux x86_64 dry-run (`build-dry-run.py`)

The dry-run is a local rehearsal that never becomes a release path. It accepts
either the blocked or the owner-authorized release-intent licensing gate via
`gate.py` (so it keeps working after release-intent authorization) but always
records `publication_authorized: false` and `mode: dry-run`, claims no final
publication, creates only a local `.dry-run.tar.gz` archive plus `SHA256SUMS`
and `release-provenance.json`, and performs no OIDC, no attestation, no upload,
no tag, and no GitHub release. `--mode release` always fails in this script;
the release-intent dual-platform release is built only by `build-release.py`.

What the dry-run proves:

- The locked Linux x86_64 binary shape (`cargo build --locked --release` with
  pinned Rust `1.94.1`; observed `rustc`/`cargo --version` must be exactly the
  official single-line `1.94.1` lines with at most one trailing LF/CRLF,
  bounded to 513 bytes) and `Cargo.lock` SHA-256 are recorded; the archived
  binary must be an ELF64 little-endian x86_64 object before archiving.
- `support/verify-fixture-provenance.py` and
  `support/verify-distribution-inventory.py` confirm the recorded gate. The
  release workflow runs both verifiers in preflight; the offline packager
  relies on `gate.py` plus the fixture-verifier contract (it does not
  re-execute the fixture verifier itself). `build-dry-run.py` reads only the
  canonical gate paths (no overrides), requires the full source tree clean at
  `HEAD`, and builds a deterministic `tar.gz` from exactly five members
  (`astatine` + `LICENSE-MIT` + `THIRD_PARTY_LICENSES.md` plus generated
  `BUILD-INFO.json` and `INSTALL.md` in memory). No fixture, provenance, or
  forbidden path can enter the archive. A clean tree does NOT prove the binary
  was built from `HEAD` (workflow-build-only linkage, recorded as unverified).
- No attestation is recorded or verified; no OIDC identity is requested
  (`contents: read` only). `release-provenance.json` records gate state,
  commit/tree/source-date, toolchain, lock hash, artifact/member hashes, and
  `publication_authorized: false` with no absolute checkout path and no raw
  invocation.

What the dry-run does NOT prove:

- It does not authorize publication or establish external execution. Even when
  release intent is owner-authorized, the dry-run establishes no environment, tag, CI, or
  attestation; it is not release evidence and authenticates no publisher.
- Bit-for-bit reproducibility across hosts is not claimed (deterministic given
  identical inputs only). Build-from-HEAD linkage is not proven. No installer,
  paid-mining run, wallet, or network operation is involved.

No publication path: the dry-run writes only to a new-or-empty directory
outside the source tree (pre-existing files, symlinks, non-empty dirs, and
in-tree locations refused, files created exclusively). There is intentionally
no upload, tag, push, release, `cargo publish`, signing, credentials, or OIDC
grant.

## Release-intent dual-platform release (`build-release.py`, draft-only)

`support/release/build-release.py` requires the release-intent gate via `gate.py`
(blocked gates fail closed; no final publication is authorized) and packages exactly two deterministic archives:

- `astatine-v0.1.0-testnet.2-macos-arm64.tar.gz` (`aarch64-apple-darwin`)
- `astatine-v0.1.0-testnet.2-linux-x86_64.tar.gz` (`x86_64-unknown-linux-gnu`)

Each archive contains exactly five regular files under a single platform
root directory (`astatine-v0.1.0-testnet.2-macos-arm64/` or
`astatine-v0.1.0-testnet.2-linux-x86_64/`): `<root>/astatine` (0755),
`<root>/LICENSE-MIT`, `<root>/THIRD_PARTY_LICENSES.md`,
`<root>/BUILD-INFO.json`, `<root>/INSTALL.md` (0644), sorted, with zeroed
timestamps/ownership, fixed modes, and `gzip -n` equivalent. (The
nonpublishing dry-run remains flat; only the release-intent release uses the
root prefix.) It verifies the git
tree clean at `HEAD`, the tag exists and resolves to `HEAD`, the tag matches
the Cargo package version (`v` + version), the repository is
`Jecta-ai/astatine-miner`, the repository-id is digits, and the `Cargo.lock`
hash is recorded. It validates the macOS Mach-O 64-bit ARM64 header and the
Linux ELF64 little-endian x86_64 header without executing the binaries, and
refuses fixtures, forbidden globs, symlinks, in-tree or pre-existing output,
wrong tag/version/commit, dirty trees, wrong binary formats, and
duplicate/missing members. It is stdlib-only and offline and never executes
candidate code, wallets, mining, or the network. Low-10 limitation:
`build-release.py` validates binary format only (Mach-O/ELF headers); binary
identity and source linkage are established by the workflow build jobs plus
GitHub build provenance, verified again by the protected draft after safe
archive-member validation, a target-format check, and extraction, not by this
offline packager. Read-only build jobs run the candidate smoke checks; separate
pinned attestation jobs receive OIDC/attestation-write, verify the build-output
hash, and attest the raw binary without executing it.

The release workflow creates and verifies a **draft only** and never publishes
from automation. It gates draft creation, not the manual publish action:
repository writers and write-capable apps with contents-write can publish or
modify the draft outside the protected environment, so release authority must
be restricted to the owner/admin before dispatch. If that cannot be
established, draft dispatch remains blocked — do not weaken. Preflight
verifies the actual protected `release` environment (owner reviewer pinned by
immutable numeric GitHub id 86115037, prevent self-review intentionally false,
no admin bypass, exact-tag deployment policy with verified pagination total
count, separate creation and no-bypass immutability rulesets) and the
canonical repository, and fails closed if the environment is absent or
unprotected; preflight runs both fixture and distribution-inventory verifiers
and the package step uses the already-validated gate via `gate.py` (it does
not rerun both verifier scripts). Admin verification that immutable releases
are enabled is a **pre-dispatch/draft-creation prerequisite**, rechecked
immediately before manual publication. Manual publication remains owner-only
after admin immutable-setting verification:

```sh
# Stop on any failure; run each command individually.
tag=v0.1.0-testnet.2
repo=Jecta-ai/astatine-miner
repo_id='<numeric repository ID from the authenticated release record>'
source_commit='<exact source commit from the authenticated release record>'
test "$(gh api "repos/$repo" --jq .id)" = "$repo_id"
# Pre-dispatch prerequisite (and recheck again immediately before publishing):
gh api "repos/$repo/immutable-releases" --jq .enabled | grep -q true
gh release view "$tag" --repo "$repo" --json isDraft --jq .isDraft | grep -q true
# Only after the draft, attestations, and immutable-setting check pass,
# recheck the tag immediately before manual publication (handles both
# annotated tags via the peeled commit and lightweight tags via the direct
# commit):
tag_refs="$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}")"
resolved_tag_commit="$(
  printf '%s\n' "$tag_refs" |
    awk -v ref="refs/tags/$tag" '
      $2 == ref "^{}" { peeled = $1 }
      $2 == ref { direct = $1 }
      END {
        if (peeled != "") print peeled
        else if (direct != "") print direct
        else exit 1
      }
    '
)"
test "$resolved_tag_commit" = "$source_commit"
# Recheck both split tag rulesets (creation restriction and no-bypass
# immutability) with an owner/admin-visible token and every draft asset
# digest/size and the draft body immediately before publishing. Run
# verify-tag-ruleset.py against fresh creation/immutability snapshots. Draft
# assets and body are mutable by any repository writer; stop on any change
# instead of overwriting assets.
gh release view "$tag" --repo "$repo" --json isDraft,body,assets
tmpdir="$(mktemp -d)"
git fetch origin "refs/tags/$tag:refs/tags/$tag"
git show "refs/tags/$tag:support/release/RELEASE_NOTES-v0.1.0-testnet.2.md" > "$tmpdir/release-notes.md"
gh api "repos/$repo/releases/tags/$tag" > "$tmpdir/draft.json"
python3 - "$tmpdir/draft.json" "$tmpdir/release-notes.md" <<'PY'
import json
import pathlib
import sys
body = json.load(open(sys.argv[1], encoding="utf-8"))["body"].encode("utf-8")
notes = pathlib.Path(sys.argv[2]).read_bytes()
if body != notes:
    raise SystemExit("draft body does not exactly match the tagged release notes")
print("draft body matches the tagged release notes")
PY
rm -rf "$tmpdir"
# Recheck immutable releases immediately before publishing:
gh api "repos/$repo/immutable-releases" --jq .enabled | grep -q true
gh release edit "$tag" --repo "$repo" --draft=false --prerelease
# Post-publication verification (stop on any failure):
gh release view "$tag" --repo "$repo" --json isDraft,isPrerelease --jq '[.isDraft, .isPrerelease]'
```

`BUILD-INFO.json` (schema `astatine-build-info/v1`, deterministic) records
repository, repository id, tag, commit, tree, package version, target,
profile, pinned expected toolchain lines, `Cargo.lock` SHA-256, binary/archive hashes, source
date, `release_intent_authorized: true`, `publication_authorized: false`, and
`final_release_controls_complete: false`, the workflow-from-tag linkage
statement (build-provenance attestation required; independent reproducibility
not claimed), and release-control requirements. `INSTALL.md` is
platform-specific: macOS is ad-hoc signed only (NOT Developer ID/notarized);
if Gatekeeper blocks, stop and retain the warning — do NOT disable Gatekeeper,
strip quarantine, alter system policy, or silently bypass; install only to a
user-owned path such as `$HOME/.local/bin` (never sudo); single-platform
operators verify only their archive's row (an operator holding both archives
verifies each row separately):
`grep -F "  astatine-v0.1.0-testnet.2-macos-arm64.tar.gz" SHA256SUMS | shasum -a 256 -c -`
on macOS and
`grep -F "  astatine-v0.1.0-testnet.2-linux-x86_64.tar.gz" SHA256SUMS | sha256sum -c -`
on Linux, and always verify GitHub attestations. Linux notes glibc/Ubuntu 24.04,
unlocked
Secret Service for paid mining, and CUDA/GPU not qualified. Both state
Testnet only (no mainnet), and require verifying `SHA256SUMS` and GitHub
attestations. No false claims are made. `SHA256SUMS` covers both archives;
`release-provenance.json` (schema `astatine-release-provenance/v1`) is a separate release asset whose digest is checked by the workflow, and records
both archives/binaries, source identity, lock hash, gate state, and
`release_intent_authorized: true` with `publication_authorized: false` and
`final_release_controls_complete: false`, with no absolute paths or raw invocation.

Example:

```sh
python3 -B support/release/build-release.py --tag v0.1.0-testnet.2 \
  --repository-id 123456789 --macos-binary /tmp/macos-astatine \
  --linux-binary /tmp/linux-astatine --output-dir /tmp/astatine-release-out \
  --rustc-version "rustc 1.94.1 (e408947bf 2026-03-25)" \
  --cargo-version "cargo 1.94.1 (29ea6fb6a 2026-03-24)"
```

The `--rustc-version`/`--cargo-version` values are the exact full lines observed
in the read-only CI build jobs and are asserted again by the packager before any
archive is written.

## Review history (superseded)

Pushing the `fix/phase-e-e02-e07` branch solely for review and CI was
authorized 2026-11-16 (`AUTHORIZED — REVIEW/CI ONLY`); it authorized no
archive, release, tag, or attestation. That record is now
`SUPERSEDED — OWNER-AUTHORIZED RELEASE INTENT` (`superseded_by:
release_intent_authorization`, `superseded_on: 2026-11-17`) and retained as
history. Public repository visibility alone authorizes no distribution.

## Install, upgrade, and corresponding source

`INSTALL.md` is the human-readable note; `BUILD-INFO.json` is the
machine-readable equivalent. Both use the commit timestamp as source date
(never the wall clock). Corresponding source is NOT in the archives; obtain it
with `git clone https://github.com/Jecta-ai/astatine-miner.git && git checkout
<tag/commit>` using the exact tag/commit in `BUILD-INFO.json`. Verify
`SHA256SUMS` externally and the GitHub attestations for the exact tag before
installing. Upgrade preserves state: stop the miner, keep
configuration/wallets/keystores/credentials/journals, replace only the binary;
downgrade compatibility is not guaranteed.

## Local use (offline)

```sh
python3 -B support/verify-fixture-provenance.py
python3 -B support/verify-distribution-inventory.py
cargo build --locked --release
python3 -B support/release/build-dry-run.py --mode dry-run --output-dir /tmp/astatine-dry-run-out
python3 -B -m unittest discover -s support/tests -p 'test_*.py'
```

The dry-run build must be on Linux x86_64 with pinned Rust `1.94.1`. The
release packager needs the two prebuilt binaries plus a clean checkout at the
exact tag; it never builds or runs them. All Python checks are offline and
stdlib-only with `-B` (no `__pycache__`), never read wallets, and never modify
the source tree. Output directories must be new-or-empty and outside the
source tree; non-Git roots fail closed.
