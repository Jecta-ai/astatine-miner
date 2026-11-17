# Astatine Miner v0.1.0-testnet.1 — Testnet prerelease

**Prepared dual-platform candidate; this document is not a publication record.**
The expected tag is exactly `v0.1.0-testnet.1`. Do not treat a configured
workflow or these notes as evidence that the release has run or been published.

## Authenticated release identity

The repository ID, source commit, source tree, signer-workflow identity, and all
release record values must be taken from the authenticated release record after
read-back. They are deliberately not inferred or assigned here.

| Field | Required value |
|---|---|
| Tag | `v0.1.0-testnet.1` (verify against the release record) |
| Repository name and numeric ID | Read from the authenticated release record |
| Source commit and tree | Read from the authenticated release record |
| Signer workflow | Read from the authenticated release record |

Expected binary assets:

- `astatine-v0.1.0-testnet.1-macos-arm64.tar.gz`
- `astatine-v0.1.0-testnet.1-linux-x86_64.tar.gz`
- `SHA256SUMS`
- `release-provenance.json`

The archive names are expected names, not proof that these assets have been
attached. Verify the exact release asset inventory and archive digests against
the authenticated record. Each binary archive contains `BUILD-INFO.json`;
binary archives exclude test fixtures, while corresponding source archives
include the checked-in fixtures and their provenance records.

## Distribution intent and fixture NOTICE review

The project owner authorized first-party source/binary distribution intent for
`v0.1.0-testnet.1` and the first-party license declarations. This records intent,
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

## Draft verification and manual publication

The protected release workflow creates and verifies a GitHub release draft
only; it does not auto-publish. Read-only build jobs compile the candidate,
observe and assert the exact Rust/Cargo version lines, run the smoke checks, and
upload the raw binary; they do not receive OIDC or attestation-write
permissions. Separate pinned attestation jobs download the build artifact,
verify its SHA-256 against the build job output, and attest the raw binary
without executing it, before the protected `release` environment gate. After a
non-self reviewer approves that environment, the protected package job verifies
those binary attestations before packaging and generates archive attestations.
The protected draft job then validates each archive's exact member allowlist,
paths, and modes without extracting untrusted paths, extracts only the binary
member, checks its target-specific Mach-O ARM64 or ELF x86_64 header, and
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
- An owner/admin checks `GET /repos/{owner}/{repo}/immutable-releases` before
  draft creation and confirms the response is `enabled: true`. Recheck this
  setting immediately before manual publication. Published assets are
  immutable only if it is confirmed enabled at both points.

The protected `release` environment requires approval by a non-self reviewer
when the workflow reaches that gate, before it creates the draft. No such
approval is claimed here; this gate does not control the earlier binary builds
or the later manual publish action.
GitHub release-attestation verification (`gh release verify` and
`gh release verify-asset`) is available only after manual publication; do not
use it as a pre-publication draft check.

Fill every shell variable from the authenticated release record; do not use
guessed values or values copied from an older release. Before dispatching the
draft workflow, an owner/admin should verify the repository identity and
immutable-release setting:

```sh
tag=v0.1.0-testnet.1
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
grep -F "  astatine-v0.1.0-testnet.1-macos-arm64.tar.gz" SHA256SUMS | shasum -a 256 -c -
# Linux:
grep -F "  astatine-v0.1.0-testnet.1-linux-x86_64.tar.gz" SHA256SUMS | sha256sum -c -
gh attestation verify ./astatine-v0.1.0-testnet.1-macos-arm64.tar.gz \
  --repo "$repo" --signer-workflow "$signer_workflow" \
  --source-digest "$source_digest" --source-ref "$source_ref"
gh attestation verify ./astatine-v0.1.0-testnet.1-linux-x86_64.tar.gz \
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
gh release verify "$tag" --repo "$repo"
for asset in \
  astatine-v0.1.0-testnet.1-macos-arm64.tar.gz \
  astatine-v0.1.0-testnet.1-linux-x86_64.tar.gz \
  SHA256SUMS \
  release-provenance.json
do
  gh release verify-asset "$tag" "./$asset" --repo "$repo"
done
```

Stop on any failure. If the immutable setting is not enabled before draft
creation or at publication, if the tag does not resolve to the authenticated
source commit, or if manual publication or post-publication verification fails,
do not replace or rewrite assets; investigate.

Final release controls remain outstanding: protected-environment approval,
exact tag-ref dispatch and exact-commit main CI, repository writer/app
restriction, immutable-setting verification, required binary and archive
attestations, manual publication, and post-publication verification. No final
release approval or CI completion is claimed.

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
