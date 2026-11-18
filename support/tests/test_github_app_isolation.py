#!/usr/bin/env python3
"""No-App isolation regression tests for the Phase1 release workflow.

Text-only assertions against `.github/workflows/release.yml`; no network, no
secrets, no live App testing. Stdlib only (yaml optional with skip); run with
`python3 -B`.

Contract under test (workflow lane owns `release.yml`): Phase1 removes the
owner-authorized GitHub App, its private key, and any external-reviewer
automation. Automation uses only the read-only `GITHUB_TOKEN`; the
authoritative bypass check is an owner manual live check OUTSIDE the workflow.
The workflow must therefore contain:

* exactly 10 jobs: preflight, build-macos, build-linux, build-windows, attest-macos,
  attest-linux, attest-windows, release-package, windows-archive-smoke,
  release-draft (no `tag-ruleset-admin-*`);
* exactly 2 `environment: release` bindings (release-package + release-draft);
* zero `environment: release-admin`, zero `create-github-app-token`, zero
  `RELEASE_ADMIN_APP_ID` / `RELEASE_ADMIN_APP_PRIVATE_KEY`, zero
  `secrets.` context outside `${{ github.token }}`, zero `contents: none`
  admin jobs, zero `permission-administration`, zero `skip-token-revoke`,
  zero `app-token` / `private-key` references;
* 5 checkouts total (preflight + 3 builds + release-package), none in
  release-draft; preflight carries no release-admin verification;
* explicit disclosures: `BYPASS_ACTORS NOT AUTOMATICALLY VERIFIED` (the
  TOCTOU disclosure: absent bypass fields are expected from the default
  token and are NOT a silent pass), `manual prepublish recheck` remains
  required, and needs `does NOT inherit` SHA binding;
* no automated-bypass claim (`admin-verified`, `automatically verified`,
  fail-closed-on-absent `bypass_actors must be present as a list`), no
  silent pass (fail-closed `sys.exit(1)` / `exit 1` markers stay);
* retained release guarantees: owner id 86115037 / login, canonical
  repository + id, exact tag v0.1.0-testnet.4, `refs/tags/v*` scope,
  prevent_self_review false, can_admins_bypass false.

This filename is preserved for history; the old `GithubAppIsolationTest`
(admin-job) suite is replaced by `NoAppIsolationTest`. The mutating-`gh`
negative tests from the prior suite are preserved in spirit (reject
`gh api -X` / `--method`, `gh release delete` / `edit`) but scoped to the
remaining 10 jobs with job-appropriate strictness: the non-mutation jobs
(preflight/builds/attests) stay read-only, while release-package and
release-draft legitimately run `gh release create --draft` (draft only),
`gh release view`, and `gh attestation verify`.
"""

from __future__ import annotations

import pathlib
import re
import unittest

try:
    import yaml as _yaml
except ImportError:  # pragma: no cover - optional dependency
    _yaml = None

SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
WORKFLOW_PATH = SOURCE_ROOT / ".github" / "workflows" / "release.yml"

EXPECTED_JOBS = frozenset(
    {
        "preflight",
        "build-macos",
        "build-linux",
        "build-windows",
        "attest-macos",
        "attest-linux",
        "attest-windows",
        "release-package",
        "windows-archive-smoke",
        "release-draft",
    }
)
# Jobs that must never mutate anything via gh: preflight reads, builds only
# compile, attest jobs only download/hash/attest via the pinned action.
READONLY_JOBS = (
    "preflight",
    "build-macos",
    "build-linux",
    "attest-macos",
    "attest-linux",
)
# Mutation jobs: packaging + draft creation run gh read/create/verify only.
MUTATION_JOBS = ("release-package", "release-draft")

# Disclosure strings the workflow lane must provide (Phase1 manual-check
# contract). The BYPASS notice doubles as the TOCTOU disclosure: approvals can
# delay mutation after checks, so the absent field is expected, not a pass.
REQUIRED_DISCLOSURES = (
    "BYPASS_ACTORS NOT AUTOMATICALLY VERIFIED",
    "manual prepublish recheck",
    "does NOT inherit",
    "TOCTOU",
    "can delay",
)

# Strings that would claim automated bypass proof; all are forbidden.
FORBIDDEN_BYPASS_CLAIMS = (
    "admin-verified",
    "split tag rulesets admin-verified",
    "automatically verified",
    "bypass_actors must be present as a list",
    "GITHUB_SHA trust is inherited from same-run preflight",
    "no checkout while App token is live",
    "while App token is live",
    "App installation token",
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


def section_job_names(text: str) -> set[str]:
    """Top-level job names from the `jobs:` section (no yaml required)."""
    marker = "\njobs:\n"
    index = text.find(marker)
    if index < 0:
        raise AssertionError("release.yml has no top-level jobs section")
    section = text[index + len(marker):]
    return set(re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\n", section))


def code_lines(block: str) -> str:
    """Block text minus full-line comments (disclosure prose may mention flags)."""
    return "\n".join(
        line for line in block.splitlines() if not line.strip().startswith("#")
    )


class NoAppIsolationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.text = read_workflow_text()

    def job_block(self, job_name: str) -> str:
        self.assertIn(
            "  %s:" % job_name,
            self.text,
            "job %r missing; pending workflow-lane change" % job_name,
        )
        return extract_job_block(self.text, job_name)

    def test_seven_job_set_exact(self) -> None:
        self.assertEqual(
            section_job_names(self.text),
            set(EXPECTED_JOBS),
            "Phase2 workflow must be exactly the 10 no-App jobs",
        )
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.text)
        self.assertEqual(set(parsed["jobs"]), set(EXPECTED_JOBS))
        self.assertEqual(len(parsed["jobs"]), 10)

    def test_zero_create_github_app_token(self) -> None:
        self.assertNotIn(
            "create-github-app-token",
            self.text,
            "Phase1 automation uses only GITHUB_TOKEN; no App-token action allowed",
        )

    def test_zero_app_secrets(self) -> None:
        for marker in ("RELEASE_ADMIN", "PRIVATE_KEY", "private-key"):
            self.assertNotIn(
                marker,
                self.text,
                "Phase1 must carry zero App secrets (found %r)" % marker,
            )

    def test_zero_secrets_context_except_github_token(self) -> None:
        scrubbed = self.text.replace("${{ github.token }}", "")
        self.assertNotIn(
            "secrets.",
            scrubbed,
            "only the default github.token context is allowed; no secrets.* references",
        )
        self.assertNotIn(
            "${{ secrets",
            scrubbed,
            "no secrets template context is allowed in Phase1",
        )
        self.assertIn(
            "${{ github.token }}",
            self.text,
            "automation must still bind GH_TOKEN from the read-only default token",
        )

    def test_zero_release_admin_anywhere(self) -> None:
        self.assertEqual(
            self.text.count("release-admin"),
            0,
            "Phase1 has no release-admin environment, jobs, or verifiers",
        )

    def test_two_release_environments(self) -> None:
        exact_release = re.findall(
            r"(?m)^\s*environment:\s*release\s*(?:#.*)?$", self.text
        )
        self.assertEqual(
            len(exact_release),
            2,
            "exactly 2 plain `environment: release` bindings required, got %r"
            % exact_release,
        )
        for job in MUTATION_JOBS:
            block = self.job_block(job)
            self.assertIn(
                "environment: release",
                block,
                "%s must stay in the release mutation environment" % job,
            )
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.text)
        jobs = parsed["jobs"]
        for job in MUTATION_JOBS:
            self.assertEqual(
                jobs[job].get("environment"),
                "release",
                "%s must stay in the release mutation environment" % job,
            )
        for job in EXPECTED_JOBS - frozenset(MUTATION_JOBS):
            self.assertNotIn(
                "environment",
                jobs[job],
                "%s must carry no environment (only package/draft are gated)" % job,
            )

    def test_zero_contents_none(self) -> None:
        self.assertNotIn(
            "contents: none",
            self.text,
            "no contents:none admin jobs exist in Phase1",
        )

    def test_zero_permission_administration(self) -> None:
        self.assertNotIn(
            "permission-administration",
            self.text,
            "the App permission input is gone with the App integration",
        )
        self.assertNotRegex(
            self.text,
            re.compile(r"permission-\S+\s*:\s*admin"),
            "no admin-level permission may appear",
        )
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.text)
        for job, config in parsed["jobs"].items():
            permissions = config.get("permissions") or {}
            self.assertNotIn(
                "administration",
                permissions,
                "%s must not request an administration permission" % job,
            )

    def test_zero_skip_token_revoke(self) -> None:
        self.assertNotIn(
            "skip-token-revoke",
            self.text,
            "no minted token exists, so no revoke flag may appear",
        )

    def test_zero_app_token_refs(self) -> None:
        for marker in ("app-token", "APP_TOKEN"):
            self.assertNotIn(
                marker,
                self.text,
                "no App token output/step may be referenced (found %r)" % marker,
            )

    def test_four_checkouts_draft_zero(self) -> None:
        self.assertEqual(
            self.text.count("actions/checkout@"),
            5,
            "exactly 5 checkouts total (preflight/builds/package; none in draft/attest/smoke)",
        )
        draft = self.job_block("release-draft")
        self.assertNotIn(
            "actions/checkout@",
            draft,
            "release-draft (no checkout) must verify the remote tag via gh api",
        )
        for job in ("attest-macos", "attest-linux", "attest-windows", "windows-archive-smoke"):
            self.assertNotIn(
                "actions/checkout@",
                self.job_block(job),
                "%s executes no candidate build and must not checkout" % job,
            )
        for job in ("preflight", "build-macos", "build-linux", "release-package"):
            self.assertIn(
                "actions/checkout@",
                self.job_block(job),
                "%s must check out the exact tag ref" % job,
            )

    def test_windows_archive_smoke_no_mutation_no_wallet(self) -> None:
        smoke = self.job_block("windows-archive-smoke")
        for pattern in (
            r"gh\s+api\s+-X\b",
            r"gh\s+api\s+--method\b",
            r"gh\s+api\s+[^\n]*\b(PATCH|PUT|DELETE)\b",
            r"gh\s+release\s+delete\b",
            r"gh\s+release\s+edit\b",
            r"gh\s+release\s+create\b",
            r"gh\s+release\s+upload\b",
        ):
            self.assertNotRegex(
                smoke,
                re.compile(pattern),
                "windows-archive-smoke must not mutate releases (found %r)" % pattern,
            )
        self.assertIn("gh attestation verify", smoke)
        self.assertIn("windows-2025", smoke)
        for marker in ("APPDATA", "RUNNER_TEMP", "Expand-Archive", "--version", "mine --help"):
            self.assertIn(
                marker, smoke, "smoke must run the packaged exe sandboxed (missing %r)" % marker
            )
        self.assertNotIn("astatine init", smoke)
        self.assertNotIn("wallet create", smoke)
        self.assertNotIn("wallet import", smoke)

    def test_preflight_has_no_release_admin_verify(self) -> None:
        preflight = self.job_block("preflight")
        self.assertNotIn(
            "release-admin",
            preflight,
            "preflight verifies only the release environment in Phase1",
        )
        self.assertNotIn(
            "$admin_env_out",
            self.text,
            "no admin environment snapshot may be fetched anywhere",
        )
        self.assertNotIn(
            "--expected-environment release-admin",
            self.text,
            "the protected-environment validator must run release-only",
        )

    def test_manual_bypass_disclosures_present(self) -> None:
        for marker in REQUIRED_DISCLOSURES:
            self.assertIn(
                marker,
                self.text,
                "workflow must disclose %r (manual-check contract)" % marker,
            )
        preflight = self.job_block("preflight")
        self.assertIn(
            "BYPASS_ACTORS NOT AUTOMATICALLY VERIFIED",
            preflight,
            "preflight must print the BYPASS notice instead of silently passing",
        )

    def test_no_automated_bypass_claim(self) -> None:
        lowered = self.text.lower()
        for marker in ("admin-verified", "split tag rulesets admin-verified"):
            self.assertNotIn(
                marker,
                lowered,
                "workflow must not claim automated bypass proof (%r)" % marker,
            )
        # Case-sensitive: the required uppercase disclosure must not be
        # mistaken for a lowercase proof claim.
        self.assertNotIn(
            "automatically verified",
            self.text,
            "workflow must not claim automatic verification in prose",
        )
        for marker in FORBIDDEN_BYPASS_CLAIMS:
            if marker in ("admin-verified", "split tag rulesets admin-verified"):
                continue
            self.assertNotIn(
                marker,
                self.text,
                "App-era bypass claim must be gone (%r)" % marker,
            )

    def test_no_silent_pass(self) -> None:
        self.assertIn(
            "sys.exit(1)",
            self.text,
            "inline validators must fail closed (nonzero exit)",
        )
        self.assertIn(
            "exit 1",
            self.text,
            "shell gates must fail closed (nonzero exit)",
        )
        self.assertIn(
            "fail closed",
            self.text.lower(),
            "workflow must document fail-closed behavior",
        )

    def test_retained_release_guarantees(self) -> None:
        for marker in (
            "86115037",
            "emyrinj",
            "1454137135",
            "Jecta-ai/astatine-miner",
            "v0.1.0-testnet.4",
            '"refs/tags/v*"',
            "prevent_self_review",
            "can_admins_bypass",
        ):
            self.assertIn(
                marker,
                self.text,
                "owner-accepted release guarantee must be retained (%r)" % marker,
            )

    def test_each_remaining_job_forbid_mutating_gh_verbs(self) -> None:
        readonly_patterns = (
            r"gh\s+api\s+-X\b",
            r"gh\s+api\s+--method\b",
            r"gh\s+api\s+[^\n]*\bPOST\b",
            r"gh\s+api\s+[^\n]*\bPATCH\b",
            r"gh\s+api\s+[^\n]*\bPUT\b",
            r"gh\s+api\s+[^\n]*\bDELETE\b",
            r"gh\s+release\s+delete\b",
            r"gh\s+release\s+edit\b",
            r"gh\s+attestation\b",
        )
        for job in READONLY_JOBS:
            block = code_lines(self.job_block(job))
            for pattern in readonly_patterns:
                self.assertNotRegex(
                    block,
                    re.compile(pattern),
                    "%s (read-only) must not contain mutating invocation %r"
                    % (job, pattern),
                )
        # Mutation jobs legitimately create the draft, view releases, and
        # verify attestations; they must still never edit/delete or use -X.
        destructive_patterns = (
            r"gh\s+api\s+-X\b",
            r"gh\s+api\s+--method\b",
            r"gh\s+release\s+delete\b",
            r"gh\s+release\s+edit\b",
        )
        for job in MUTATION_JOBS:
            block = code_lines(self.job_block(job))
            for pattern in destructive_patterns:
                self.assertNotRegex(
                    block,
                    re.compile(pattern),
                    "%s must not contain destructive invocation %r" % (job, pattern),
                )

    def test_mutating_gh_command_rejected(self) -> None:
        # Negative test: injecting a mutating gh command into any remaining
        # job must trip the read-only rule. Full-line comments are ignored so
        # disclosure prose such as "(no -X/--method)" stays allowed.
        patterns = (
            r"gh\s+api\s+-X\b",
            r"gh\s+api\s+--method\b",
            r"gh\s+release\s+delete\b",
            r"gh\s+release\s+edit\b",
        )

        def assert_readonly(block: str) -> None:
            code = code_lines(block)
            for pattern in patterns:
                if re.search(pattern, code):
                    raise AssertionError(
                        "mutating gh invocation forbidden: %r" % pattern
                    )

        for job in sorted(EXPECTED_JOBS):
            block = self.job_block(job)
            assert_readonly(block)  # Baseline must pass.
            for injection in (
                'gh api -X POST "repos/$repo/rulesets"',
                'gh api --method PATCH "repos/$repo/rulesets/$creation_id"',
                'gh release delete "$tag"',
                'gh release edit "$tag" --draft=false',
            ):
                mutated = block + "\n          " + injection + "\n"
                try:
                    assert_readonly(mutated)
                except AssertionError:
                    continue
                self.fail(
                    "%s must reject mutating injection %r" % (job, injection)
                )

    def test_draft_isolated_no_checkout_no_repo_scripts(self) -> None:
        draft = code_lines(self.job_block("release-draft"))
        self.assertNotIn(
            "actions/checkout@",
            draft,
            "release-draft must stay checkout-free (gh api tag-ref lookup)",
        )
        self.assertNotIn(
            "cargo",
            draft,
            "release-draft must not run repo build commands",
        )
        self.assertNotIn(
            "python3 -B support/",
            draft,
            "release-draft must run only inline checks, not repo scripts",
        )


if __name__ == "__main__":
    unittest.main()
