# Astatine Miner v0.1.0-testnet.4 — Release audit record (internal)

This file preserves the full technical, security, and legal record for the `v0.1.0-testnet.4` triple-platform draft-only release. The public GitHub release body is the concise product notes in `RELEASE_NOTES-v0.1.0-testnet.4.md`; this audit record retains all authorization, tradeoff, verification, and publication-control facts without shortening them.

# Astatine Miner v0.1.0-testnet.4 — Testnet prerelease

**Prepared triple-platform candidate; this document is not a publication record.**
The expected tag is exactly `v0.1.0-testnet.4`. Do not treat a configured
workflow or these notes as evidence that the release has run or been published.

## Authenticated release identity

The repository ID, source commit, source tree, signer-workflow identity, and all
release record values must be taken from the authenticated release record after
read-back. They are deliberately not inferred or assigned here.

| Field | Required value |
|---|---|
| Tag | `v0.1.0-testnet.4` (verify against the release record) |
| Repository name and numeric ID | Read from the authenticated release record |
| Source commit and tree | Read from the authenticated release record |
| Signer workflow | Read from the authenticated release record |

Expected binary assets:

- `astatine-v0.1.0-testnet.4-macos-arm64.tar.gz`
- `astatine-v0.1.0-testnet.4-linux-x86_64.tar.gz`
- `astatine-v0.1.0-testnet.4-windows-x86_64.zip`
- `SHA256SUMS`
- `release-provenance.json`

The archive names are expected names, not proof that these assets have been
attached. Verify the exact release asset inventory and archive digests against
the authenticated record. Each binary archive contains `BUILD-INFO.json`;
binary archives exclude test fixtures, while corresponding source archives
include the checked-in fixtures and their provenance records.

## Distribution intent and fixture NOTICE review

The project owner authorized first-party source/binary distribution intent for
`v0.1.0-testnet.4` and the first-party license declarations. This records intent,
not completed publication authorization or a legal conclusion.

A repository technical NOTICE review found no NOTICE file in the pinned contract
fixture subtrees; the private EVM root NOTICE was scoped to a separate Rust
subtree. The fixture source tree includes Apache-2.0 license text and a fixture
NOTICE. Evidence:

- [tests/fixtures/PROVENANCE.json](../../tests/fixtures/PROVENANCE.json)
- [tests/fixtures/README.md](../../tests/fixtures/README.md)
- [tests/fixtures/LICENSE-APACHE-2.0.txt](../../tests/fixtures/LICENSE-APACHE-2.0.txt)
- [tests/fixtures/LICENSE-MIT.txt](../../tests/fixtures/LICENSE-MIT.txt)
- [tests/fixtures/OPENZEPPELIN_LICENSE.txt](../../tests/fixtures/OPENZEPPELIN_LICENSE.txt)
- [tests/fixtures/NOTICE](../../tests/fixtures/NOTICE)

This is not a legal conclusion. The project owner did not personally determine
NOTICE applicability. No separate release approver has been appointed or
consulted, and no separate release approval is claimed.

## Owner self-approval policy and security tradeoff

This candidate deliberately replaces independent environment review with an
explicit owner self-approval policy authorized by the project owner. The same
owner account initiates the release workflow, approves the protected `release`
environment, and manually publishes the verified draft. The required
environment reviewer is the owner account `emyrinj`, pinned to GitHub's
immutable numeric user id `86115037`; `prevent_self_review` must be `false` and
administrator bypass must be disabled. The environment deployment policy must
be the exact tag `v0.1.0-testnet.4`, not a wildcard series.

**No independent review, separation of duties, or second-person approval is
claimed.** This is a security tradeoff: a compromised, malicious, or mistaken
owner account can approve and publish without another human check. It reduces
the historical non-self-review control. Compensating controls are the exact
tag and exact-tag policy, no administrator environment bypass, a separate
creation ruleset with one designated admin bypass, a separate no-bypass
immutability ruleset, immutable releases, exact-commit green main CI,
binary and archive provenance attestations, draft-only workflow execution,
owner-only repository write authority, and immediate pre-publication
verification. These controls reduce but do not eliminate owner-account risk.

## Historical v0.1.0-testnet.1 record

The existing `v0.1.0-testnet.1` tag remains at commit
`99a8630a7ae7f5c5950031dfba8c3b0c3f132cbc` and is not moved. Its pending
draft-workflow run is not cancelled or deleted, and no `.1` release was
published. The historical `.1` rights decision, scope, and approval-role fields
are preserved verbatim in
[`HISTORICAL-v0.1.0-testnet.1.md`](HISTORICAL-v0.1.0-testnet.1.md) and in the
release inventories. This `.4` document does not rewrite that history.

## Historical v0.1.0-testnet.2 record

The `v0.1.0-testnet.2` candidate was superseded before publication by this `.3`
correction. The `v0.1.0-testnet.2` tag exists at `206d97b1e157e7f386f37f4f1b3b3a158eb0e3c4` (same as `origin/main`), unchanged; it was not moved or deleted, and no
`.2` release or draft remains as release evidence; the failed live packaging run
(`44283340169`) failed in the `release-package` provenance validator and did not
reach the `release-draft` validator, with no archive attestations or draft created
and no assets attached or replaced. The `.2` owner self-approval
authorization and its explicit tradeoff disclosure are preserved in
[`RELEASE_NOTES-v0.1.0-testnet.2.md`](RELEASE_NOTES-v0.1.0-testnet.2.md) and in
the preserved `.1` historical record. This `.4` document does not rewrite that
history; it records the schema correction (top-level `rights_decision` in
release provenance, matching the workflow package and draft validators) and the
`.3` version pins. This `.4` document preserves that `.3` record unchanged.


## Historical v0.1.0-testnet.3 record

The `v0.1.0-testnet.3` dual-platform candidate remains at its tagged commit, unchanged; it was not moved or deleted. No `.3` publication is claimed here. The `.3` owner self-approval authorization, dual-platform scope (macOS ARM64 and Linux x86_64), and tradeoff disclosure are preserved in [`RELEASE_NOTES-v0.1.0-testnet.3.md`](RELEASE_NOTES-v0.1.0-testnet.3.md) and in the preserved `.1`/`.2` records. This `.4` document does not rewrite that history; it adds native Windows x86_64 distribution (ZIP) for triple-platform coverage and the `.4` version pins.

## Draft verification and manual publication

The protected release workflow creates and verifies a GitHub release draft
only; it does not auto-publish. Read-only build jobs compile the candidate,
observe and assert the exact Rust/Cargo version lines, run the smoke checks, and
upload the raw binary; they do not receive OIDC or attestation-write
permissions. Separate pinned attestation jobs download the build artifact,
verify its SHA-256 against the build job output, and attest the raw binary
without executing it, before the protected `release` environment gate. After
the owner reviewer approves that environment under the explicit owner
self-approval policy, the protected package job verifies those binary
attestations before packaging and generates archive attestations.
The protected draft job then validates each archive's exact member allowlist,
paths, and modes without extracting untrusted paths, extracts only the binary
member, checks its target-specific Mach-O ARM64, ELF x86_64, or PE x86_64 header, and
verifies that extracted binary against its build attestation with the exact
repository, signer workflow, source digest, and tag before creating/verifying
the draft. The environment gates archive packaging/attestation and draft
creation, not the earlier non-release binary build attestations or the manual
publish action. An archive attestation alone is not accepted as proof of
compilation of its binary member.

Any repository writer or write-capable app could publish or modify the verified
draft unless release authority is restricted to the owner/admin. Establish that
restriction before dispatch; if it cannot be established, do not dispatch the
draft workflow.

Before dispatch, these prerequisites must pass:

- The exact release tag identifies the intended commit on `main`, and CI must
  pass for that exact commit (`exact-commit main CI`) before dispatch. This is a
  prerequisite, not a claim that final CI is complete.
- Dispatch the workflow against the exact tag ref (`GITHUB_REF=refs/tags/<tag>`),
  not a branch with the tag supplied only as an input.
- Two active composable repository rulesets must be configured, each exactly
  `refs/tags/v*` with no exclusions:
  - `astatine-release-tag-creation`: exactly the `creation` rule, scoped
    exactly to `refs/tags/v*`, with exactly one designated bypass
    actor: the owner user (`actor_type: User`, `actor_id: 86115037`) with
    `bypass_mode: always` for owner-only creation. Repository-admin bypass
    (`RepositoryRole`, `actor_id: 5`) is rejected and administrator bypass is
    disabled. **Creation protection is retained and
    must not be removed, broadened, or narrowed.**
  - `astatine-release-tags`: exactly `update`, `deletion`, and
    `non_fast_forward` with **zero bypass actors**, scoped to exactly
    `refs/tags/v*` with no exclusions. This preserves protection for all `v*`
    tags; do not narrow it to the single `.4` tag or to the historical
    `.0`/`.1`/`.2`/`.3` list.
  The owner creates the `.4` tag through the owner-only creation bypass; the
  workflow preflight then validates both ruleset snapshots and fails closed if
  either is missing, combined, broadened, or bypassable. A repository admin can
  still reconfigure or delete rulesets, so tag immutability cannot constrain
  that account; repository administrator authority must remain owner-only.
  GitHub only returns `bypass_actors` to a caller with write access to the
  ruleset; the default read-only workflow token lacks that access, so an
  absent field does NOT prove an empty bypass list. Automation does NOT verify
  bypass: preflight checks structural fields only (names, scope, enforcement,
  active state, ids, rules; visible mismatch fails) and tolerates an absent
  `bypass_actors` field ONLY with an explicit manual-verification-required
  disclosure. No App, private key, installation token, or extra secret is used.
  The authoritative bypass check is an owner-authorized manual live check
  OUTSIDE the workflow with the owner `gh` credential, run before dispatch
  AND again immediately before manual publication (TOCTOU: approvals delay,
  `needs` does NOT inherit SHA/tag binding, draft mutable by writers):

  ```sh
  tag=v0.1.0-testnet.4
  repo=Jecta-ai/astatine-miner
  gh api "repos/$repo/rulesets?includes_parents=true&per_page=100" --jq '.[] | {id, name, target, source_type, source, enforcement}'
  gh api "repos/$repo/rulesets/$creation_id" > /tmp/creation.json
  gh api "repos/$repo/rulesets/$immutability_id" > /tmp/immutability.json
  python3 -B support/release/verify-tag-ruleset.py --creation-ruleset-json /tmp/creation.json --immutability-ruleset-json /tmp/immutability.json --repository "$repo" --tag "$tag"
  gh api "repos/$repo/environments/release" > /tmp/release-env.json
  gh api "repos/$repo/environments/release/deployment-branch-policies?per_page=100" > /tmp/release-policies.json
  python3 -B support/release/verify-protected-environment.py --environment-json /tmp/release-env.json --policies-json /tmp/release-policies.json --tag "$tag" --expected-environment release
  gh api "repos/$repo/immutable-releases" --jq .enabled | grep -q true
  ```
- An owner/admin checks `GET /repos/{owner}/{repo}/immutable-releases` before
  draft creation and confirms the response is `enabled: true`. Recheck this
  setting immediately before manual publication. Published assets are
  immutable only if it is confirmed enabled at both points.
- The workflow preflight must observe no existing release for the exact tag.
  If any draft or release already exists for `v0.1.0-testnet.4`, stop: do not
  attach, replace, or clobber assets.

At the time these notes were prepared, the live `release` environment still
reflected the historical `.1` reviewer/tag policy and the live tag ruleset was
still the combined historical configuration with an administrator-role bypass.
Those live settings were **not** changed by this revision. A
coordinator-approved split-ruleset and environment update is required before
dispatch; until then the workflow preflight fails closed. The split update
preserves live breadth: both creation and immutability rulesets are exactly
`refs/tags/v*` with no exclusions. When updating the
environment, set the exact `.4` tag deployment policy first, then adjust the
reviewer/self-review settings; do not approve the pending `.1` run or use it as
`.4` evidence. Creation and immutability are each exactly scoped to
`refs/tags/v*` with no exclusions. A future release requires a reviewed scope
update.

The protected `release` environment requires approval by the owner reviewer
when the workflow reaches that gate, before it creates the draft. Because
`prevent_self_review` is `false`, the initiating owner may approve the same
deployment. No independent approval is claimed; this gate does not control the
earlier binary builds or the later manual publish action. GitHub
release-attestation verification (`gh release verify` and
`gh release verify-asset`) is available only after manual publication; do not
use it as a pre-publication draft check.

Fill every shell variable from the authenticated release record; do not use
guessed values or values copied from an older release. Before dispatching the
draft workflow, an owner/admin should verify the repository identity and
immutable-release setting:

```sh
tag=v0.1.0-testnet.4
repo='<OWNER/REPOSITORY from the authenticated release record>'
repo_id='<numeric repository ID from the authenticated release record>'
source_commit='<full source commit from the authenticated release record>'
signer_workflow='<verified OWNER/REPOSITORY workflow path from the release record>'
source_digest="$source_commit"
source_ref="refs/tags/$tag"

test "$(gh api "repos/$repo" --jq .id)" = "$repo_id"
test "$(gh api "repos/$repo/immutable-releases" --jq .enabled)" = "true"
```

Only dispatch after the release authority restriction and pre-dispatch setting
check are established. After the workflow creates the draft, check its asset
inventory, local checksums, and build attestations before manual publication:

```sh
set -euo pipefail
gh release view "$tag" --repo "$repo" --json assets \
  --jq '.assets[] | {name, size, digest}'
# macOS:
grep -F "  astatine-v0.1.0-testnet.4-macos-arm64.tar.gz" SHA256SUMS | shasum -a 256 -c -
# Linux:
grep -F "  astatine-v0.1.0-testnet.4-linux-x86_64.tar.gz" SHA256SUMS | sha256sum -c -
# Windows (PowerShell):
(Get-FileHash .\astatine-v0.1.0-testnet.4-windows-x86_64.zip -Algorithm SHA256).Hash
gh attestation verify ./astatine-v0.1.0-testnet.4-macos-arm64.tar.gz \
  --repo "$repo" --signer-workflow "$signer_workflow" \
  --source-digest "$source_digest" --source-ref "$source_ref"
gh attestation verify ./astatine-v0.1.0-testnet.4-linux-x86_64.tar.gz \
  --repo "$repo" --signer-workflow "$signer_workflow" \
  --source-digest "$source_digest" --source-ref "$source_ref"
gh attestation verify ./astatine-v0.1.0-testnet.4-windows-x86_64.zip \
  --repo "$repo" --signer-workflow "$signer_workflow" \
  --source-digest "$source_digest" --source-ref "$source_ref"
```

Compare the draft inventory's asset names, sizes, and digests with the
authenticated release record. Also compare each `SHA256SUMS` row with the
locally calculated archive digest.
Run the appropriate `gh attestation verify` command for each archive present;
an operator may verify both archives when both are available. The commands
above verify archive attestations generated after packaging. The protected draft
job separately validates archive members and verifies each extracted binary's
compiled-binary build attestation before draft creation; archive attestations
alone are not accepted as proof of compilation or source-to-binary linkage.
Require the expected signer workflow and source digest/reference in the
provenance verification. Stop before publication on any missing, inconsistent,
or unverifiable record.

## Prepublish draft asset-substitution concern

A draft release is mutable by anyone with repository write or release
permissions. The workflow creates and verifies its own assets, but it cannot
prevent a concurrently authorized writer from modifying or replacing the draft
after creation and before manual publication. Do not treat draft creation as
final. Before publishing:

1. Restrict repository write and release authority to the owner/admin, and do
   not grant write-capable apps or external automations release permission.
2. Record the created draft's release id, body, asset names, sizes, and
   `sha256:` digests from `gh release view --json databaseId,body,assets`.
   Compare the draft body bytes exactly with the reviewed
   `support/release/RELEASE_NOTES-v0.1.0-testnet.4.md`; stop on any difference.
3. Download the draft assets into a new empty directory, verify `SHA256SUMS`,
   verify both archive attestations against the exact tag and source digest,
   and compare the downloaded digests with the recorded draft digests.
4. Immediately before publication, repeat the draft asset digest/size check
   and the remote-tag check. With the owner `gh` credential OUTSIDE the
   workflow (no App), re-fetch both split ruleset details, re-verify the
   `release` environment, recheck immutable releases, and run:
   `gh api "repos/$repo/rulesets?includes_parents=true&per_page=100"`,
   per-id `gh api "repos/$repo/rulesets/$id"` fetches, then
   `python3 -B support/release/verify-tag-ruleset.py --creation-ruleset-json <creation.json> --immutability-ruleset-json <immutability.json> --repository "$repo" --tag "$tag"`,
   plus `gh api "repos/$repo/environments/release"`,
   `gh api "repos/$repo/environments/release/deployment-branch-policies?per_page=100"`,
   `python3 -B support/release/verify-protected-environment.py --environment-json <env.json> --policies-json <policies.json> --tag "$tag" --expected-environment release`,
   and `gh api "repos/$repo/immutable-releases" --jq .enabled`.
   Stop on any difference, missing asset, extra asset, changed release id, or
   ruleset mismatch; do not overwrite, delete, or re-upload the draft to force
   a pass.
5. Publish only after immutable releases is confirmed enabled, then verify the
   published release and every asset. If post-publication verification fails,
   stop and investigate; do not rewrite assets.

Exact draft-body check:

```sh
tmpdir="$(mktemp -d)"
git fetch origin "refs/tags/$tag:refs/tags/$tag"
git show "refs/tags/$tag:support/release/RELEASE_NOTES-v0.1.0-testnet.4.md" > "$tmpdir/release-notes.md"
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
```

The notes bytes come from the exact tag object, not the mutable working tree.

If a failed workflow leaves an unverified, never-published `.4` draft that
blocks retries, record its release id, asset names, sizes, and digests, confirm
it is still a draft and was never published, and delete it only with explicit
owner authorization before retrying. Do not overwrite, replace, or re-upload
assets into the existing draft to force a pass.

After every prerequisite passes, immediately recheck the immutable-release
setting and the remote tag target against the authenticated source commit. The
tag check handles both annotated tags (peeled commit) and lightweight tags.
Only then may the owner manually publish the draft and verify the release and
every asset:

```sh
set -euo pipefail
test "$(gh api "repos/$repo/immutable-releases" --jq .enabled)" = "true"
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
gh release edit "$tag" --draft=false --prerelease --repo "$repo"
# Stop and investigate if the published release is not immutable; do not rewrite assets.
test "$(gh release view "$tag" --repo "$repo" --json isImmutable --jq .isImmutable)" = "true"
# Build-provenance attestations cover the three archives, not SHA256SUMS or
# release-provenance.json. Verify the attested archives:
for asset in \
  astatine-v0.1.0-testnet.4-macos-arm64.tar.gz \
  astatine-v0.1.0-testnet.4-linux-x86_64.tar.gz \
  astatine-v0.1.0-testnet.4-windows-x86_64.zip
do
  gh release verify-asset "$tag" "./$asset" --repo "$repo"
done
# Verify the non-attested metadata files against the authenticated release
# record and local checksums; do not expect archive-style attestations for them.
gh api "repos/$repo/releases/tags/$tag" --jq '.assets[] | {name, size, digest}'
sha256sum -c SHA256SUMS   # macOS: shasum -a 256 -c SHA256SUMS
```

Do not run `gh release verify` as a blanket gate unless the release-level
attestation is known to cover every asset; a missing attestation for
`SHA256SUMS` or `release-provenance.json` is expected and is not evidence of
archive tampering.

Stop on any failure. If the immutable setting is not enabled before draft
creation or at publication, if the tag does not resolve to the authenticated
source commit, or if manual publication or post-publication verification fails,
do not replace or rewrite assets; investigate.

Final release controls remain outstanding: owner self-approval of the
protected environment under the explicitly documented policy, exact tag-ref
dispatch and exact-commit main CI, repository writer/app restriction, active
split tag creation/immutability rulesets, immutable-setting verification,
required binary and archive attestations, manual publication, and
post-publication verification.
No independent review, final release approval, or CI completion is claimed.

These are requirements for a future controlled execution, not claims that the
attestations have been issued or verified. The controls do not claim independent
bit-for-bit reproducibility, nor publisher authentication beyond the
authenticated release record and documented GitHub release/build-attestation
controls.

## Platform notes

- **macOS ARM64:** the executable uses an ad-hoc linker-generated signature
  only. It is **not** Developer ID signed and is **not notarized**. Gatekeeper
  and quarantine behavior remain unqualified; do not disable Gatekeeper or
  remove quarantine to force execution.
- **Linux x86_64:** Ubuntu 24.04 / glibc 2.39 is the package baseline; older
  glibc environments are not qualified. Paid Linux mining requires an
  available, unlocked Secret Service. CUDA/GPU operation is not qualified by
  this package.
- **Windows x86_64:** native Windows 11 / Server 2025 build (`astatine.exe`)
  in a deterministic ZIP. Install to a user-owned directory without elevation;
  paid mining on Windows was not exercised for this release and GPU operation
  remains unqualified. The packaged executable is validated as an x86-64 PE
  binary before the draft is created.
- Neither archive claims a separate vendor or operating-system code-signing
  signature. Verify the recorded release/build attestations and checksums;
  do not infer stronger signing or publisher claims.

## Safety and scope

This prerelease is Testnet only; mainnet transaction signing is disabled. These
release notes make no claim that paid mining was performed and do not authorize
paid mining. Proof submissions and finalization consume INJ fees and gas and do
not guarantee rewards.

The per-run authorization cap is charged by maximum transaction value plus gas
before signing and is not refunded by receipts. A new explicit run can receive
another allowance under the saved policy, so aggregate spending across runs can
exceed one run's cap; it is not a lifetime spending or loss limit. The selected
RPC provider remains trusted for chain state, receipts, and reward evidence.
False RPC data can undermine observed balances and transaction outcomes; local
hashing and journal authentication do not independently authenticate RPC data.

The executable archives omit test fixtures. Source archives retain the
checked-in fixtures and provenance documentation; fixture presence in source
does not make them runtime package content or evidence of independent
reproducibility.
