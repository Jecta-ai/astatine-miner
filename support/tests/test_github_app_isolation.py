#!/usr/bin/env python3
"""Isolation regression tests for the owner-authorized GitHub App verification.

Text-only assertions against `.github/workflows/release.yml`; no network, no
secrets, no live App testing. Stdlib only; run with `python3 -B`.

Contract under test (workflow lane owns `release.yml`): three isolated jobs
`tag-ruleset-admin-verify` (initial, needs preflight),
`tag-ruleset-admin-verify-package` (fresh before package, needs attest-macos,
attest-linux, tag-ruleset-admin-verify), and
`tag-ruleset-admin-verify-draft` (fresh before draft, needs release-package);
each `environment: release-admin` (dedicated, verifiers only), minimal `contents: none` permissions, pinned
`actions/create-github-app-token@64ab729a6294000f5aa4a4bc0b73d1f32bc45510`,
single-repo scope (`owner: Jecta-ai`, `repositories: astatine-miner`),
`permission-administration: read` as a CANDIDATE permission under test (read-first; NO write fallback).
`release-package` needs the fresh package job (not the stale initial);
`release-draft` needs `[release-package, fresh-draft job]`.

Correction note: `permission-administration: read` is NOT asserted to be
sufficient. The ruleset GET documents `Metadata: read` as its minimum while
`bypass_actors` is returned only to a caller with ruleset-write access;
whether this App permission grants that access is UNPROVEN until the owner
tests it live AFTER audit. Docs permission claims at the pinned SHA were
UNVERIFIED (upstream redirects to llms.txt). If the field is absent each
workflow job MUST fail closed with STOP (covered by `test_workflow_fails_closed_on_missing_bypass_actors`
and the per-job fail-closed tests). Temporal: approvals can delay, no atomic/immediate claim;
manual prepublish recheck remains. SHA binding: needs does NOT automatically
inherit SHA binding; each admin job inherits GITHUB_SHA trust from same-run
preflight through the needs chain (preflight verifies HEAD==GITHUB_SHA and
tag peel==GITHUB_SHA via checkout). Admin jobs verify GITHUB_REF/tag/repo-id
live but do no direct SHA equality check by design (no checkout while App
token is live).
"""

from __future__ import annotations

import pathlib
import re
import unittest

SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW_PATH = SOURCE_ROOT / ".github" / "workflows" / "release.yml"

ADMIN_JOB = "tag-ruleset-admin-verify"
FRESH_PACKAGE_JOB = "tag-ruleset-admin-verify-package"
FRESH_DRAFT_JOB = "tag-ruleset-admin-verify-draft"
ADMIN_JOBS = (ADMIN_JOB, FRESH_PACKAGE_JOB, FRESH_DRAFT_JOB)
PINNED_APP_TOKEN_ACTION = (
    "actions/create-github-app-token"
    "@64ab729a6294000f5aa4a4bc0b73d1f32bc45510"
)
APP_TOKEN_STEP_ID="app-token"
APP_TOKEN_OUTPUT_REF="steps.app-token.outputs.token"
ALLOWED_SECRETS = frozenset(
    {"RELEASE_ADMIN_APP_ID", "RELEASE_ADMIN_APP_PRIVATE_KEY"}
)


def read_workflow_text() -> str:
    text = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert text.strip(), "real release.yml must not be empty"
    return text


def extract_job_block(text: str, job_name: str) -> str:
    """Return the raw text of one top-level job block (header to next job)."""
    header = re.search(r"(?m)^  %s:\n" % re.escape(job_name), text)
    if header is None:
        raise AssertionError(
            "job %r not found; pending workflow-lane change" % job_name
        )
    rest = text[header.end():]
    follower = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", rest)
    end = header.end() + follower.start() if follower else len(text)
    return text[header.start():end]


class GithubAppIsolationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = read_workflow_text()

    def admin_block(self) -> str:
        self.assertIn(
            "  %s:" % ADMIN_JOB,
            self.text,
            "admin job %r missing; pending workflow-lane change" % ADMIN_JOB,
        )
        return extract_job_block(self.text, ADMIN_JOB)

    def test_admin_job_defined(self) -> None:
        self.assertIn(
            "  %s:" % ADMIN_JOB,
            self.text,
            "admin job %r missing; pending workflow-lane change" % ADMIN_JOB,
        )

    def test_admin_job_environment_release(self) -> None:
        block = self.admin_block()
        self.assertIn(
            "environment: release-admin",
            block,
            "admin job must be bound to the dedicated release-admin environment",
        )
        self.assertNotIn(
            "environment: release\n",
            block,
            "admin job must not use the plain release environment (dedicated release-admin only)",
        )

    def test_admin_job_permissions_minimal(self) -> None:
        block = self.admin_block()
        self.assertIn(
            "contents: none",
            block,
            "admin job permissions must be minimal (contents: none)",
        )
        self.assertNotIn(
            "contents: read",
            block,
            "admin job must not request contents read",
        )
        self.assertNotIn(
            "contents: write",
            block,
            "admin job must not request contents write",
        )

    def test_admin_job_uses_pinned_token_action(self) -> None:
        block = self.admin_block()
        self.assertIn(
            PINNED_APP_TOKEN_ACTION,
            block,
            "admin job must mint the token with the pinned action SHA",
        )

    def test_admin_job_single_repo_scoping(self) -> None:
        block = self.admin_block()
        self.assertRegex(
            block,
            r"owner:\s*['\"]?Jecta-ai['\"]?",
            "admin job must scope the token to owner Jecta-ai",
        )
        self.assertRegex(
            block,
            r"repositories:\s*['\"]?astatine-miner['\"]?",
            "admin job must scope the token to exactly astatine-miner",
        )

    def test_admin_job_candidate_administration_permission(self) -> None:
        # Candidate under test only: presence is asserted, sufficiency is NOT.
        # Whether administration:read grants ruleset-write visibility of
        # bypass_actors is UNPROVEN until the owner tests it live after audit.
        # Docs permission claims at the pinned SHA were UNVERIFIED; STOP if missing.
        block = self.admin_block()
        self.assertRegex(
            block,
            r"permission-administration\s*:\s*read",
            "admin job must carry the candidate permission-administration: read (read-first)",
        )
        self.assertNotRegex(
            block,
            r"permission-administration\s*:\s*write",
            "admin job must not fall back to permission-administration: write",
        )
        self.assertNotRegex(
            block,
            r"permission-\S+\s*:\s*admin",
            "admin job must not grant any admin-level permission",
        )

    def test_admin_job_no_checkout_or_code_actions(self) -> None:
        block = self.admin_block()
        for action in (
            "actions/checkout@",
            "actions/download-artifact@",
            "actions/upload-artifact@",
            "actions/attest",
        ):
            self.assertNotIn(
                action,
                block,
                "admin job must not run %s while the token is live" % action,
            )

    def test_admin_job_no_secret_logging_or_upload(self) -> None:
        block = self.admin_block()
        for lineno, line in enumerate(block.splitlines(), start=1):
            if re.search(r"\b(echo|print)\b", line, re.IGNORECASE) and re.search(
                r"outputs\.token|secrets\.|private-key",
                line,
                re.IGNORECASE,
            ):
                self.fail(
                    "admin job must never log secrets (line %d: %s)"
                    % (lineno, line.strip())
                )
        for secret in re.findall(r"secrets\.([A-Za-z0-9_]+)", block):
            self.assertIn(
                secret,
                ALLOWED_SECRETS,
                "admin job must reference only owner-provided App secrets",
            )
        self.assertIn(
            "RELEASE_ADMIN_APP_ID",
            block,
            "admin job must source the App id from the owner-provided secret",
        )
        self.assertNotIn(
            "actions/upload-artifact@",
            block,
            "admin job must not upload artifacts while the token is live",
        )

    def test_admin_job_token_binding(self) -> None:
        block = self.admin_block()
        self.assertIn(
            "id: %s" % APP_TOKEN_STEP_ID,
            block,
            "token-minting step must carry id %r" % APP_TOKEN_STEP_ID,
        )
        # Two GH_TOKEN bindings: default github.token for pre-mint env re-verify
        # plus minted app-token for post-mint ruleset reads. The ruleset binding
        # must be the minted token; env re-verify may use the default token.
        self.assertIn(
            APP_TOKEN_OUTPUT_REF,
            block,
            "admin job must bind GH_TOKEN from the minted token output for ruleset reads",
        )
        self.assertIn(
            "GH_TOKEN: ${{ github.token }}",
            block,
            "admin job env re-verify uses default token before mint",
        )

    def test_admin_token_not_reused_elsewhere(self) -> None:
        # Each of the three isolated jobs mints and consumes only its own
        # token; no token output may appear outside the three admin blocks.
        # The legacy single-job wording ("the isolated admin job") is preserved
        # here as the three-job containment check.
        in_blocks = 0
        for job in ADMIN_JOBS:
            block = extract_job_block(self.text, job)
            in_blocks += block.count(APP_TOKEN_OUTPUT_REF)
        total = self.text.count(APP_TOKEN_OUTPUT_REF)
        self.assertGreater(
            in_blocks,
            0,
            "minted token outputs must be consumed inside the admin jobs",
        )
        self.assertEqual(
            total,
            in_blocks,
            "token reuse outside the isolated admin jobs is PROHIBITED",
        )

    def test_release_package_needs_admin_job(self) -> None:
        package = extract_job_block(self.text, "release-package")
        self.assertIn(
            "- %s" % ADMIN_JOB,
            package,
            "release-package needs must include the admin verification job",
        )

    def test_no_skip_token_revoke_true(self) -> None:
        self.assertNotRegex(
            self.text,
            r"skip-token-revoke\s*:\s*true",
            "automatic token revocation must apply (never skip-token-revoke: true)",
        )
        # Explicit opt-in to revocation is required in each admin job; omission
        # defaults to false per the action README but is NOT asserted as proof.
        # Neutral config check only — no echo-proves-revoke claim. Count only
        # non-comment config lines (comments also mention the key).
        import re as _re
        config_lines = [
            line for line in self.text.splitlines()
            if _re.search(r"skip-token-revoke\s*:\s*false", line)
            and not line.strip().startswith("#")
        ]
        self.assertEqual(
            len(config_lines),
            3,
            "each of the three admin jobs must set explicit skip-token-revoke: false",
        )

    def test_workflow_fails_closed_on_missing_bypass_actors(self) -> None:
        # Any admin-visible fetch, including the future isolated job's, must
        # fail closed when bypass_actors is absent: the inline validator must
        # require the field as a list and exit nonzero.
        self.assertIn(
            "bypass_actors must be a list",
            self.text,
            "workflow must fail closed when bypass_actors is absent",
        )
        match = re.search(
            r"bypass_actors must be a list.*\n.*sys\.exit\(1\)",
            self.text,
        )
        self.assertIsNotNone(
            match,
            "missing bypass_actors must exit nonzero (fail closed)",
        )


    def test_admin_job_marks_permission_candidate_unproven(self) -> None:
        # The workflow itself must carry the candidate-under-test wording:
        # administration:read is plausible but NEITHER proven necessary NOR
        # sufficient until the owner tests it live after audit. Docs claims
        # UNVERIFIED; missing field is STOP.
        block = self.admin_block()
        for marker in (
            "# v3.3.0",
            "candidate under test",
            "UNPROVEN",
            "permission-administration: read",
        ):
            self.assertIn(
                marker,
                block,
                "admin job must document the candidate permission as UNPROVEN with fail-closed wording",
            )
        self.assertRegex(
            block,
            re.compile(r"fails closed if bypass_actors is\s*\n?\s*#?\s*absent", re.IGNORECASE),
            "admin job must document fail-closed when bypass_actors is absent",
        )
        self.assertNotRegex(
            block,
            __import__("re").compile(r"permission-administration\s*:\s*write"),
            "admin job must not document a write fallback",
        )

    # ---- Three-job extension (additive; the 14 tests above are preserved) ----

    def admin_blocks(self) -> dict:
        blocks = {}
        for job in ADMIN_JOBS:
            self.assertIn(
                "  %s:" % job,
                self.text,
                "admin job %r missing; pending workflow-lane change" % job,
            )
            blocks[job] = extract_job_block(self.text, job)
        return blocks

    def test_three_admin_jobs_defined(self) -> None:
        for job in ADMIN_JOBS:
            self.assertIn(
                "  %s:" % job,
                self.text,
                "admin job %r missing; pending workflow-lane change" % job,
            )

    def test_total_admin_count_three(self) -> None:
        found = [
            job
            for job in ADMIN_JOBS
            if ("  %s:" % job) in self.text
        ]
        self.assertEqual(
            len(found),
            3,
            "exactly three isolated admin verification jobs required: %r" % (ADMIN_JOBS,),
        )
        # No fourth admin job may appear.
        extra = re.findall(r"(?m)^  (tag-ruleset-admin-verify\S*):\n", self.text)
        self.assertEqual(
            sorted(set(extra)),
            sorted(ADMIN_JOBS),
            "no extra tag-ruleset-admin-* jobs allowed (got %r)" % extra,
        )

    def test_total_jobs_ten(self) -> None:
        expected = {
            "preflight",
            "build-macos",
            "build-linux",
            "attest-macos",
            "attest-linux",
            "tag-ruleset-admin-verify",
            "tag-ruleset-admin-verify-package",
            "tag-ruleset-admin-verify-draft",
            "release-package",
            "release-draft",
        }
        for job in expected:
            self.assertIn(
                "  %s:" % job,
                self.text,
                "job %r missing; expected 10-job set" % job,
            )
        found_top = set(re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\n", self.text))
        # Filter to known job namespace (exclude env/runner-temp style keys is
        # unnecessary: top-level two-space keys in this workflow are only jobs
        # plus `workflow_dispatch`-adjacent config; assert the 10 jobs present
        # and no extra tag-ruleset/release/package jobs).
        for job in found_top:
            if job.startswith("tag-ruleset-admin-") or job.startswith("release-"):
                self.assertIn(
                    job,
                    expected,
                    "unexpected release/admin job %r; expected exactly %r" % (job, sorted(expected)),
                )

    def test_each_admin_job_environment_release(self) -> None:
        for job, block in self.admin_blocks().items():
            self.assertIn(
                "environment: release-admin",
                block,
                "%s must be bound to the dedicated release-admin environment" % job,
            )
            self.assertNotIn(
                "environment: release\n",
                block,
                "%s must not use the plain release environment" % job,
            )

    def test_each_admin_job_permissions_minimal(self) -> None:
        for job, block in self.admin_blocks().items():
            self.assertIn(
                "contents: none",
                block,
                "%s permissions must be minimal (contents: none)" % job,
            )
            self.assertNotIn(
                "contents: read",
                block,
                "%s must not request contents read" % job,
            )
            self.assertNotIn(
                "contents: write",
                block,
                "%s must not request contents write" % job,
            )

    def test_each_admin_job_uses_pinned_token_action(self) -> None:
        for job, block in self.admin_blocks().items():
            self.assertIn(
                PINNED_APP_TOKEN_ACTION,
                block,
                "%s must mint the token with the pinned action SHA" % job,
            )
            self.assertIn(
                "# v3.3.0",
                block,
                "%s must carry the v3.3.0 version comment" % job,
            )

    def test_each_admin_job_single_repo_scoping(self) -> None:
        for job, block in self.admin_blocks().items():
            self.assertRegex(
                block,
                r"owner:\s*['\"]?Jecta-ai['\"]?",
                "%s must scope the token to owner Jecta-ai" % job,
            )
            self.assertRegex(
                block,
                r"repositories:\s*['\"]?astatine-miner['\"]?",
                "%s must scope the token to exactly astatine-miner" % job,
            )

    def test_each_admin_job_candidate_administration_permission(self) -> None:
        for job, block in self.admin_blocks().items():
            self.assertRegex(
                block,
                r"permission-administration\s*:\s*read",
                "%s must carry the candidate permission-administration: read (read-first)" % job,
            )
            self.assertNotRegex(
                block,
                r"permission-administration\s*:\s*write",
                "%s must not fall back to permission-administration: write" % job,
            )
            self.assertNotRegex(
                block,
                r"permission-\S+\s*:\s*admin",
                "%s must not grant any admin-level permission" % job,
            )

    def test_each_admin_job_marks_candidate_unproven(self) -> None:
        for job, block in self.admin_blocks().items():
            for marker in (
                "candidate under test",
                "UNPROVEN",
                "Metadata",
                "ruleset-write",
                "permission-administration: read",
            ):
                self.assertIn(
                    marker,
                    block,
                    "%s must document the candidate as UNPROVEN with fail-closed wording" % job,
                )
            self.assertRegex(
                block,
                re.compile(r"fails closed if bypass_actors is\s*\n?\s*#?\s*absent", re.IGNORECASE),
                "%s must document fail-closed when bypass_actors is absent" % job,
            )
            self.assertNotRegex(
                block,
                __import__("re").compile(r"permission-administration\s*:\s*write"),
                "%s must not document a write fallback" % job,
            )

    def test_each_admin_job_no_checkout_or_code_actions(self) -> None:
        for job, block in self.admin_blocks().items():
            for action in (
                "actions/checkout@",
                "actions/download-artifact@",
                "actions/upload-artifact@",
                "actions/attest",
            ):
                self.assertNotIn(
                    action,
                    block,
                    "%s must not run %s while the token is live" % (job, action),
                )

    def test_each_admin_job_no_secret_logging_or_upload(self) -> None:
        for job, block in self.admin_blocks().items():
            for lineno, line in enumerate(block.splitlines(), start=1):
                if re.search(r"\b(echo|print)\b", line, re.IGNORECASE) and re.search(
                    r"outputs\.token|secrets\.|private-key",
                    line,
                    re.IGNORECASE,
                ):
                    self.fail(
                        "%s must never log secrets (line %d: %s)"
                        % (job, lineno, line.strip())
                    )
            for secret in re.findall(r"secrets\.([A-Za-z0-9_]+)", block):
                self.assertIn(
                    secret,
                    ALLOWED_SECRETS,
                    "%s must reference only owner-provided App secrets" % job,
                )
            self.assertNotIn(
                "actions/upload-artifact@",
                block,
                "%s must not upload artifacts while the token is live" % job,
            )

    def test_each_admin_job_token_binding(self) -> None:
        for job, block in self.admin_blocks().items():
            self.assertIn(
                "id: %s" % APP_TOKEN_STEP_ID,
                block,
                "%s token-minting step must carry id %r" % (job, APP_TOKEN_STEP_ID),
            )
            self.assertIn(
                APP_TOKEN_OUTPUT_REF,
                block,
                "%s must bind GH_TOKEN from the minted token output for ruleset reads" % job,
            )
            self.assertIn(
                "GH_TOKEN: ${{ github.token }}",
                block,
                "%s env re-verify uses default token before mint" % job,
            )

    def test_each_admin_job_fail_closed_on_missing_bypass_actors(self) -> None:
        for job, block in self.admin_blocks().items():
            self.assertIn(
                "bypass_actors must be present as a list",
                block,
                "%s must fail closed when bypass_actors is absent" % job,
            )
            self.assertIn(
                "absent snapshots fail closed",
                block,
                "%s must document absent snapshots fail closed" % job,
            )
            match = re.search(
                r"bypass_actors must be present as a list.*\n.*sys\.exit\(1\)",
                block,
            )
            self.assertIsNotNone(
                match,
                "%s missing bypass_actors must exit nonzero (fail closed)" % job,
            )

    def test_each_admin_job_no_revoke_bypass(self) -> None:
        import re as _re
        for job, block in self.admin_blocks().items():
            self.assertNotRegex(
                block,
                _re.compile(r"skip-token-revoke\s*:\s*true"),
                "%s must not bypass automatic token revocation" % job,
            )
            config_lines = [
                line for line in block.splitlines()
                if _re.search(r"skip-token-revoke\s*:\s*false", line)
                and not line.strip().startswith("#")
            ]
            self.assertEqual(
                len(config_lines),
                1,
                "%s must set explicit skip-token-revoke: false exactly once (neutral config check only)" % job,
            )
            self.assertIn(
                "auto-revok",
                block,
                "%s must document automatic token revocation" % job,
            )

    def test_admin_needs_chain_correct(self) -> None:
        try:
            import yaml as _yaml
        except ImportError:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.text)
        jobs = parsed["jobs"]
        # Initial verification runs after preflight, before builds.
        self.assertEqual(
            jobs["tag-ruleset-admin-verify"].get("needs"),
            "preflight",
            "initial admin verification must need preflight",
        )
        # Fresh-before-package runs after attestations and the initial check.
        self.assertEqual(
            set(jobs["tag-ruleset-admin-verify-package"].get("needs")),
            {"attest-macos", "attest-linux", "tag-ruleset-admin-verify"},
            "fresh package verification must need attest-macos, attest-linux, tag-ruleset-admin-verify",
        )
        # Fresh-before-draft runs after the package job, immediately before draft.
        self.assertEqual(
            jobs["tag-ruleset-admin-verify-draft"].get("needs"),
            "release-package",
            "fresh draft verification must need release-package",
        )

    def test_release_package_needs_fresh_not_stale(self) -> None:
        try:
            import yaml as _yaml
        except ImportError:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.text)
        needs = parsed["jobs"]["release-package"].get("needs")
        self.assertIsInstance(needs, list, "release-package needs must be a list")
        self.assertIn(
            FRESH_PACKAGE_JOB,
            needs,
            "release-package must need the fresh package verification job",
        )
        # The stale initial verification must not be a direct dependency of
        # packaging: the fresh job already sequences after it via attest+initial.
        self.assertNotIn(
            ADMIN_JOB,
            needs,
            "release-package must not directly need the stale initial verification (needs fresh %r, got %r)"
            % (FRESH_PACKAGE_JOB, needs),
        )

    def test_release_draft_needs_package_and_fresh(self) -> None:
        try:
            import yaml as _yaml
        except ImportError:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.text)
        needs = parsed["jobs"]["release-draft"].get("needs")
        self.assertIsInstance(needs, list, "release-draft needs must be a list")
        self.assertEqual(
            set(needs),
            {"release-package", FRESH_DRAFT_JOB},
            "release-draft must need exactly [release-package, fresh-draft job]",
        )

    def test_no_stale_snapshot_file_reference(self) -> None:
        # Each admin job must perform live `gh api` fetches; no committed
        # snapshot file and no artifact-carried snapshot may substitute.
        for job, block in self.admin_blocks().items():
            self.assertIn(
                'gh api "repos/$repo/rulesets',
                block,
                "%s must perform live ruleset fetches (no stale snapshot)" % job,
            )
            self.assertNotIn(
                "download-artifact",
                block,
                "%s must not consume a snapshot via artifacts" % job,
            )
        self.assertNotIn(
            "snapshot.json",
            self.text,
            "workflow must not reference a stale snapshot file",
        )
        # Live binding markers must appear in each admin job.
        for job, block in self.admin_blocks().items():
            for marker in (
                'test "$GITHUB_REF" = "refs/tags/$tag"',
                'test "$tag" = "v0.1.0-testnet.2"',
                '"1454137135"',
            ):
                self.assertIn(
                    marker,
                    block,
                    "%s live fetch must be bound to run/commit/tag/repo-id" % job,
                )

    def test_four_checkouts_total_three_admin_zero_checkout(self) -> None:
        self.assertEqual(
            self.text.count("actions/checkout@"),
            4,
            "exactly 4 checkouts total (preflight/builds/package; none in draft/attest/admin)",
        )
        for job, block in self.admin_blocks().items():
            self.assertNotIn(
                "actions/checkout@",
                block,
                "%s must have zero checkouts" % job,
            )
        draft = extract_job_block(self.text, "release-draft")
        self.assertNotIn(
            "actions/checkout@",
            draft,
            "release-draft must have zero checkouts",
        )

    def test_pinned_app_token_count_three(self) -> None:
        self.assertEqual(
            self.text.count(PINNED_APP_TOKEN_ACTION),
            3,
            "pinned create-github-app-token action must appear exactly 3 times",
        )

    def test_admin_secrets_six_total_in_three_jobs(self) -> None:
        app_id = "${{ secrets.RELEASE_ADMIN_APP_ID }}"
        priv = "${{ secrets.RELEASE_ADMIN_APP_PRIVATE_KEY }}"
        self.assertEqual(self.text.count(app_id), 3)
        self.assertEqual(self.text.count(priv), 3)
        self.assertEqual(self.text.count(app_id) + self.text.count(priv), 6)
        for job, block in self.admin_blocks().items():
            for secret in (app_id, priv):
                self.assertIn(
                    secret,
                    block,
                    "%s must reference %s once" % (job, secret),
                )

    def test_package_draft_fresh_delegation_markers(self) -> None:
        package = extract_job_block(self.text, "release-package")
        draft = extract_job_block(self.text, "release-draft")
        for section, fresh in (
            (package, "tag-ruleset-admin-verify-package"),
            (draft, "tag-ruleset-admin-verify-draft"),
        ):
            self.assertIn(
                "Fresh isolated App verification sequenced via needs: %s" % fresh,
                section,
                "mutation job must carry fresh-delegation comment for %s" % fresh,
            )
            self.assertIn(
                "authoritative bypass validation is delegated",
                section,
                "mutation job must delegate authoritative bypass validation",
            )
        # No default-token bypass detail blocks in mutation jobs.
        for section, name in ((package, "release-package"), (draft, "release-draft")):
            for forbidden in (
                "package-rulesets.json",
                "draft-rulesets.json",
                "verify-tag-ruleset.py",
            ):
                self.assertNotIn(
                    forbidden,
                    section,
                    "%s must not contain %s" % (name, forbidden),
                )



    # ---- NO-GO remediation additive coverage (read-first, dual-env) ----
    # New tests are additive only; the 36 prior tests above are preserved.

    def test_dual_env_separation_three_admin_two_release(self) -> None:
        try:
            import yaml as _yaml
        except ImportError:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.text)
        jobs = parsed["jobs"]
        for job in ADMIN_JOBS:
            self.assertEqual(
                jobs[job].get("environment"),
                "release-admin",
                "%s must use dedicated release-admin (verifiers only)" % job,
            )
        for job in ("release-package", "release-draft"):
            self.assertEqual(
                jobs[job].get("environment"),
                "release",
                "%s must stay in release (mutation jobs)" % job,
            )
        env_values = sorted(
            {jobs[j].get("environment") for j in list(ADMIN_JOBS) + ["release-package", "release-draft"]}
        )
        self.assertEqual(env_values, ["release", "release-admin"])
        # Exactly 5 protected envs total: 3 release-admin + 2 release.
        count_admin = self.text.count("environment: release-admin")
        self.assertEqual(count_admin, 3, "exactly 3 release-admin bindings required")
        count_release_exact = len(
            __import__("re").findall(r"environment:\s*release\s*(?:#.*)?$", self.text, __import__("re").MULTILINE)
        )
        self.assertEqual(count_release_exact, 2, "exactly 2 plain release bindings required")

    def test_admin_secrets_zero_in_release_env_jobs(self) -> None:
        for job in ("release-package", "release-draft"):
            block = extract_job_block(self.text, job)
            self.assertNotIn(
                "RELEASE_ADMIN_APP_ID",
                block,
                "%s (release env) must carry zero App secrets" % job,
            )
            self.assertNotIn(
                "RELEASE_ADMIN_APP_PRIVATE_KEY",
                block,
                "%s (release env) must carry zero App secrets" % job,
            )
            self.assertNotIn(
                "secrets.",
                block,
                "%s must contain no secrets context" % job,
            )

    def test_each_admin_job_explicit_skip_token_revoke_false(self) -> None:
        import re as _re
        for job, block in self.admin_blocks().items():
            config_lines = [
                line for line in block.splitlines()
                if _re.search(r"skip-token-revoke\s*:\s*false", line)
                and not line.strip().startswith("#")
            ]
            self.assertEqual(
                len(config_lines),
                1,
                "%s must set explicit skip-token-revoke: false exactly once (got %r)" % (job, config_lines),
            )

    def test_each_admin_job_readonly_gh_allowlist(self) -> None:
        allowed = (
            'gh api "repos/$repo" --jq .id',
            'gh api "repos/$repo/rulesets?includes_parents=true&per_page=100"',
            'gh api "repos/$repo/rulesets/$creation_id"',
            'gh api "repos/$repo/rulesets/$immutability_id"',
        )
        for job, block in self.admin_blocks().items():
            for pattern in allowed:
                self.assertIn(
                    pattern,
                    block,
                    "%s must use read-only GET pattern %r" % (job, pattern),
                )

    def test_each_admin_job_forbid_mutating_gh_verbs(self) -> None:
        # Read-only GET only: forbid actual mutating invocations
        # (gh api -X/--method, mutating gh release/attestation). Disclosure
        # comments mentioning "(no -X/--method)" are allowed and required.
        import re as _re
        forbidden_patterns = (
            r"gh\s+api\s+-X\b",
            r"gh\s+api\s+--method\b",
            r"gh\s+api\s+[^\n]*\bPOST\b",
            r"gh\s+api\s+[^\n]*\bPATCH\b",
            r"gh\s+api\s+[^\n]*\bPUT\b",
            r"gh\s+api\s+[^\n]*\bDELETE\b",
            r"gh\s+release\s+(create|edit|delete)\b",
            r"gh\s+attestation\b",
        )
        for job, block in self.admin_blocks().items():
            for pat in forbidden_patterns:
                self.assertNotRegex(
                    block,
                    _re.compile(pat),
                    "%s must not contain mutating invocation %r" % (job, pat),
                )

    def test_mutating_gh_command_rejected(self) -> None:
        # Negative test: attempting a mutating gh command in an admin job
        # must fail the read-only rule. Disclosure comments mentioning
        # "(no -X/--method)" are allowed; only actual invocations are rejected.
        import re as _re

        def _code_lines(block: str) -> str:
            return "\n".join(
                line for line in block.splitlines()
                if not line.strip().startswith("#")
            )

        def _assert_readonly(block: str) -> None:
            code = _code_lines(block)
            for pat in (
                r"gh\s+api\s+-X\b",
                r"gh\s+api\s+--method\b",
                r"gh\s+release\s+(create|edit|delete)\b",
                r"gh\s+attestation\b",
            ):
                if _re.search(pat, code):
                    raise AssertionError("mutating gh invocation forbidden: %r" % pat)

        for job in ADMIN_JOBS:
            block = extract_job_block(self.text, job)
            # Baseline must pass.
            _assert_readonly(block)
            # Mutated variants must fail.
            for injection in (
                'gh api -X POST "repos/$repo/rulesets"',
                'gh api --method PATCH "repos/$repo/rulesets/$creation_id"',
                'gh release delete "$tag"',
            ):
                mutated = block + "\n          " + injection + "\n"
                try:
                    _assert_readonly(mutated)
                except AssertionError:
                    continue
                self.fail(
                    "%s must reject mutating injection %r" % (job, injection)
                )

    def test_no_echo_proves_revoke_claim(self) -> None:
        # Neutral config check only: no admin job may claim echo proves revoke.
        for job, block in self.admin_blocks().items():
            self.assertNotRegex(
                block,
                __import__("re").compile(r"echo.*proves.*revok", __import__("re").IGNORECASE),
                "%s must not claim echo proves revoke" % job,
            )
            self.assertNotRegex(
                block,
                __import__("re").compile(r"revoke.*verified.*echo", __import__("re").IGNORECASE),
                "%s must not claim echo verifies revocation" % job,
            )
        # The neutral handling step must be present with if:always().
        # Old `Confirm admin token auto-revoke` and `intentionally omitted`
        # wording is removed. The echo must not assert proof of revocation.
        for job, block in self.admin_blocks().items():
            self.assertIn(
                "Check admin token handling",
                block,
                "%s must carry neutral Check admin token handling step" % job,
            )
            self.assertIn(
                "if: always()",
                block,
                "%s handling step must run if: always()" % job,
            )
            self.assertNotIn(
                "Confirm admin token auto-revoke",
                block,
                "%s must not use old Confirm wording" % job,
            )
            self.assertNotIn(
                "intentionally omitted",
                block,
                "%s must not use old intentionally-omitted wording" % job,
            )

    def test_corrected_temporal_language_markers(self) -> None:
        # Approvals can delay; no atomic/immediate claim; manual prepublish
        # recheck remains. Each admin block carries the corrected disclosure
        # ("not atomic", "can delay", "manual prepublish recheck remains").
        # Neutral wording only — no claim of atomicity or immediacy.
        for job, block in self.admin_blocks().items():
            self.assertIn(
                "can delay",
                block,
                "%s must disclose approvals can delay" % job,
            )
            self.assertRegex(
                block,
                __import__("re").compile(r"not atomic", __import__("re").IGNORECASE),
                "%s must state it is not atomic (no atomic claim)" % job,
            )
            self.assertRegex(
                block,
                __import__("re").compile(r"manual prepublish recheck", __import__("re").IGNORECASE),
                "%s must state manual prepublish recheck remains" % job,
            )
        self.assertIn(
            "manual prepublish recheck",
            self.text.lower(),
            "workflow must state manual prepublish recheck remains",
        )
        self.assertRegex(
            self.text,
            __import__("re").compile(r"does NOT inherit", __import__("re").IGNORECASE),
            "workflow must state needs does NOT inherit SHA binding",
        )

    def test_sha_binding_inherited_from_preflight_per_job(self) -> None:
        # Each verifier checks ref/tag/repo-id live and inherits SHA trust from
        # the same-run preflight through the needs chain; no direct SHA
        # equality check is performed while the App token is live.
        for job, block in self.admin_blocks().items():
            for marker in (
                'test "$GITHUB_REF" = "refs/tags/$tag"',
                'test "$tag" = "v0.1.0-testnet.2"',
                'test "$repo_id" = "1454137135"',
                "GITHUB_REF/tag/repository id live itself",
                "GITHUB_SHA trust is inherited from same-run preflight",
                "through the needs chain",
                "Preflight verifies HEAD==GITHUB_SHA",
                "tag peel==GITHUB_SHA via checkout",
                "No direct SHA equality check here by design",
                "no checkout while App token is live",
            ):
                self.assertIn(
                    marker,
                    block,
                    "%s must preserve the truthful SHA-binding boundary %r" % (job, marker),
                )
            self.assertIn(
                "does NOT inherit",
                block,
                "%s must document needs does NOT inherit SHA binding" % job,
            )
            self.assertNotIn(
                "verifies GITHUB_SHA, tag, repository id, and ref live itself",
                block,
                "%s must not claim it verifies GITHUB_SHA live itself" % job,
            )
            self.assertNotRegex(
                block,
                re.compile(r"\bverifies(?:\s|#)*GITHUB_SHA\b[\s\S]{0,160}?\blive itself\b", re.IGNORECASE),
                "%s must not claim direct GITHUB_SHA verification" % job,
            )

    def test_ten_job_five_env_split_counts(self) -> None:
        self.assertEqual(
            self.text.count("environment: release-admin"),
            3,
            "exactly 3 release-admin envs",
        )
        exact_release = len(
            __import__("re").findall(r"environment:\s*release\s*(?:#.*)?$", self.text, __import__("re").MULTILINE)
        )
        self.assertEqual(exact_release, 2, "exactly 2 plain release envs")
        self.assertEqual(
            self.text.count("actions/checkout@"),
            4,
            "exactly 4 checkouts total",
        )
        for job in ADMIN_JOBS:
            self.assertNotIn(
                "actions/checkout@",
                extract_job_block(self.text, job),
                "%s must have zero checkouts" % job,
            )

    def test_pinned_action_with_risk_markers(self) -> None:
        self.assertEqual(
            self.text.count(PINNED_APP_TOKEN_ACTION),
            3,
            "pinned action must appear exactly 3 times",
        )
        for job, block in self.admin_blocks().items():
            for marker in ("# v3.3.0", "third-party", "SHA pin"):
                self.assertIn(
                    marker,
                    block,
                    "%s must carry pin+risk disclosure marker %r" % (job, marker),
                )

    def test_read_first_no_write_fallback_anywhere_admin(self) -> None:
        for job, block in self.admin_blocks().items():
            self.assertRegex(
                block,
                __import__("re").compile(r"permission-administration\s*:\s*read"),
                "%s must be read-first" % job,
            )
            self.assertNotRegex(
                block,
                __import__("re").compile(r"permission-administration\s*:\s*write"),
                "%s must have no write fallback" % job,
            )
            self.assertIn(
                "STOP",
                block,
                "%s must document STOP on missing field" % job,
            )



    def test_final_neutral_handling_step(self) -> None:
        for job, block in self.admin_blocks().items():
            self.assertIn("Check admin token handling", block)
            self.assertIn("if: always()", block)
            self.assertNotIn("Confirm admin token auto-revoke", block)
            self.assertNotIn("intentionally omitted", block)

    def test_final_temporal_sha_exact_phrases(self) -> None:
        import re as _re
        for job, block in self.admin_blocks().items():
            self.assertIn("same-run needs does NOT inherit SHA", block)
            self.assertIn("not atomic or immediate", block)
            self.assertIn("manual prepublish recheck remains", block)
        # Delegation sequencing phrase lives in package/draft, not admin verifiers.
        for job in ("release-package", "release-draft"):
            section = extract_job_block(self.text, job)
            self.assertIn("sequenced via needs", section)

    def test_final_secrets_singular_no_plural_tripwire(self) -> None:
        import re as _re
        # 6 code refs only; comments use singular secret so no plural tripwire.
        self.assertEqual(self.text.count("${{ secrets.RELEASE_ADMIN_APP_ID }}"), 3)
        self.assertEqual(self.text.count("${{ secrets.RELEASE_ADMIN_APP_PRIVATE_KEY }}"), 3)
        scrubbed = self.text.replace("${{ secrets.RELEASE_ADMIN_APP_ID }}", "").replace(
            "${{ secrets.RELEASE_ADMIN_APP_PRIVATE_KEY }}", ""
        )
        self.assertNotRegex(scrubbed, _re.compile(r"\bsecrets\b", _re.IGNORECASE))

    def test_final_preflight_both_envs_markers(self) -> None:
        self.assertIn("--expected-environment release", self.text)
        self.assertIn("--expected-environment release-admin", self.text)
        self.assertIn("$admin_env_out", self.text)

if __name__ == "__main__":
    unittest.main()
