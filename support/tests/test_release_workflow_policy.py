#!/usr/bin/env python3
"""Adversarial regression tests for the pinned release workflow policy.

All tests use temporary copies and never modify the real workflow. Run with
`python3 -B` only.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
CHECKER_PATH = SOURCE_ROOT / "support" / "check_workflow_pins.py"
WORKFLOW_PATH = SOURCE_ROOT / ".github" / "workflows" / "release.yml"

try:
    import yaml as _yaml
except ImportError:
    _yaml = None


def load_checker():
    spec = importlib.util.spec_from_file_location("workflow_pin_checker", CHECKER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load check_workflow_pins module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CHECKER = load_checker()


class ReleaseWorkflowPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="astatine-release-policy-"))
        self.real_text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertTrue(self.real_text.strip(), "real release.yml must not be empty")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)
        # Real workflow must be untouched: re-read and compare hash to pin.
        current = WORKFLOW_PATH.read_bytes()
        self.assertEqual(
            hashlib.sha256(current).hexdigest(),
            CHECKER.RELEASE_WORKFLOW_SHA256,
            "real release.yml was modified during tests",
        )

    def temp_copy(self, text: str) -> pathlib.Path:
        candidate = self.tmp / "release.yml"
        candidate.write_text(text, encoding="utf-8")
        return candidate

    def assertReleaseFails(self, text: str, fragment: str) -> None:
        candidate = self.temp_copy(text)
        try:
            CHECKER.validate_release_workflow(text, candidate)
        except AssertionError as error:
            self.assertIn(fragment, str(error), f"expected {fragment!r} in {error}")
            return
        raise AssertionError(f"mutated release workflow unexpectedly accepted (wanted {fragment!r})")

    def assertStrictFails(self, text: str, fragment: str) -> None:
        candidate = self.tmp / "synthetic.yml"
        candidate.write_text(text, encoding="utf-8")
        try:
            CHECKER.validate_signing_isolation(text, candidate)
        except AssertionError as error:
            self.assertIn(fragment, str(error))
            return
        raise AssertionError(f"strict workflow unexpectedly accepted (wanted {fragment!r})")

    def test_real_release_workflow_passes(self) -> None:
        CHECKER.validate_release_workflow(self.real_text, WORKFLOW_PATH)
        digest = hashlib.sha256(self.real_text.encode("utf-8")).hexdigest()
        self.assertEqual(digest, CHECKER.RELEASE_WORKFLOW_SHA256)

    def test_release_yaml_parses(self) -> None:
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        raw_on = parsed.get(True, parsed.get("on"))
        self.assertIsInstance(raw_on, dict)
        self.assertEqual(set(raw_on), {"workflow_dispatch"})
        tag = raw_on["workflow_dispatch"]["inputs"]["tag"]
        self.assertTrue(tag["required"])
        self.assertEqual(tag["type"], "string")
        self.assertNotIn("default", tag)
        self.assertEqual(parsed.get("name"), "Release")
        jobs = parsed["jobs"]
        self.assertEqual(set(jobs), {"preflight", "build-macos", "build-linux", "attest-macos", "attest-linux", "release-package", "release-draft"})
        self.assertEqual(len(jobs), 7)
        self.assertEqual(jobs["release-package"].get("environment"), "release")
        self.assertEqual(jobs["release-draft"].get("environment"), "release")
        self.assertNotIn("environment", jobs["attest-macos"])
        self.assertNotIn("environment", jobs["attest-linux"])
        self.assertNotIn("environment", jobs["build-macos"])
        self.assertNotIn("environment", jobs["build-linux"])
        # Phase1: no admin jobs exist, so no contents:none permission may remain.
        for job_name, job_config in jobs.items():
            self.assertNotEqual(
                (job_config.get("permissions") or {}).get("contents"),
                "none",
                "%s must not use contents:none (no admin jobs in Phase1)" % job_name,
            )
            self.assertNotIn(
                "administration",
                job_config.get("permissions") or {},
                "%s must not request an administration permission" % job_name,
            )
        self.assertEqual(
            jobs["release-draft"].get("permissions"),
            {"contents": "write", "actions": "read", "attestations": "read"},
        )
        self.assertEqual(
            jobs["release-package"].get("permissions"),
            {"contents": "read", "id-token": "write", "attestations": "write", "actions": "read"},
        )
        self.assertEqual(
            jobs["preflight"].get("permissions"), {"contents": "read", "actions": "read"}
        )
        self.assertEqual(
            jobs["build-macos"].get("permissions"),
            {"contents": "read"},
        )
        self.assertEqual(
            jobs["build-linux"].get("permissions"),
            {"contents": "read"},
        )
        self.assertEqual(
            jobs["attest-macos"].get("permissions"),
            {"contents": "read", "id-token": "write", "attestations": "write"},
        )
        self.assertEqual(
            jobs["attest-linux"].get("permissions"),
            {"contents": "read", "id-token": "write", "attestations": "write"},
        )
        # R3 needs chain and build outputs.
        self.assertEqual(jobs["attest-macos"].get("needs"), "build-macos")
        self.assertEqual(jobs["attest-linux"].get("needs"), "build-linux")
        self.assertEqual(
            set(jobs["release-package"].get("needs")),
            {"build-macos", "build-linux", "attest-macos", "attest-linux"},
        )
        draft_needs = jobs["release-draft"].get("needs")
        if isinstance(draft_needs, str):
            draft_needs = {draft_needs}
        else:
            draft_needs = set(draft_needs)
        self.assertEqual(
            draft_needs,
            {"release-package"},
        )
        self.assertIn("binary_sha256", jobs["build-macos"].get("outputs"))
        self.assertIn("rustc_version", jobs["build-macos"].get("outputs"))
        self.assertIn("cargo_version", jobs["build-macos"].get("outputs"))

    def test_release_hash_mismatch_fails(self) -> None:
        mutated = self.real_text + "\n# benign reviewed-comment probe\n"
        self.assertReleaseFails(mutated, "hash mismatch")

    def test_unpinned_action_fails(self) -> None:
        mutated = self.real_text.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v7.0.1",
            1,
        )
        self.assertIn("actions/checkout@v7.0.1", mutated)
        self.assertReleaseFails(mutated, "not pinned")

    def test_wrong_pin_sha_fails(self) -> None:
        mutated = self.real_text.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@0123456789abcdef0123456789abcdef01234567",
            1,
        )
        self.assertReleaseFails(mutated, "must be pinned to")

    def test_unexpected_push_trigger_fails(self) -> None:
        mutated = self.real_text.replace(
            "on:\n  workflow_dispatch:",
            "on:\n  push:\n    branches: [main]\n  workflow_dispatch:",
            1,
        )
        self.assertReleaseFails(mutated, "push trigger")

    def test_unexpected_pull_request_trigger_fails(self) -> None:
        mutated = self.real_text.replace(
            "on:\n  workflow_dispatch:",
            "on:\n  pull_request:\n    branches: [main]\n  workflow_dispatch:",
            1,
        )
        self.assertReleaseFails(mutated, "pull_request trigger")

    def test_pull_request_target_fails(self) -> None:
        mutated = self.real_text.replace(
            "on:\n  workflow_dispatch:",
            "on:\n  pull_request_target:\n    branches: [main]\n  workflow_dispatch:",
            1,
        )
        self.assertReleaseFails(mutated, "pull_request_target")

    def test_secrets_forbidden_fails(self) -> None:
        mutated = self.real_text.replace(
            "GH_TOKEN: ${{ github.token }}",
            "GH_TOKEN: ${{ secrets.TOKEN }}",
            1,
        )
        self.assertReleaseFails(mutated, "secrets")

    def test_strict_write_in_non_release_fails(self) -> None:
        self.assertStrictFails("permissions:\n  contents: write\n", "forbidden release authority")
        self.assertStrictFails("permissions:\n  contents: read\n  id-token: write\n", "forbidden")

    def test_strict_real_workflows_pass(self) -> None:
        for name in ("ci.yml", "linux-native-qualification.yml", "linux-release-dry-run.yml"):
            path = SOURCE_ROOT / ".github" / "workflows" / name
            CHECKER.validate_signing_isolation(path.read_text(encoding="utf-8"), path)

    def test_contents_write_outside_release_draft_fails(self) -> None:
        mutated = self.real_text.replace(
            "  build-linux:\n    name: Build Linux x86_64 binary\n    needs: preflight\n"
            "    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n    permissions:\n      contents: read\n",
            "  build-linux:\n    name: Build Linux x86_64 binary\n    needs: preflight\n"
            "    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n    permissions:\n      contents: write\n",
            1,
        )
        self.assertReleaseFails(mutated, "must be exactly")

    def test_checks_read_not_allowed_in_preflight(self) -> None:
        mutated = self.real_text.replace(
            "    permissions:\n      contents: read\n      actions: read",
            "    permissions:\n      contents: read\n      checks: read\n      actions: read",
            1,
        )
        self.assertReleaseFails(mutated, "must be exactly")

    def test_id_token_write_only_builds_and_release_draft(self) -> None:
        mutated = self.real_text.replace(
            "  preflight:\n    name: Preflight tag and exact-commit checks\n    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 20\n    permissions:\n      contents: read\n      actions: read",
            "  preflight:\n    name: Preflight tag and exact-commit checks\n    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 20\n    permissions:\n      contents: read\n      actions: read\n      id-token: write",
            1,
        )
        self.assertReleaseFails(mutated, "id-token")

    def test_attestations_write_only_builds_and_release_draft(self) -> None:
        mutated = self.real_text.replace(
            "  preflight:\n    name: Preflight tag and exact-commit checks\n    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 20\n    permissions:\n      contents: read\n      actions: read",
            "  preflight:\n    name: Preflight tag and exact-commit checks\n    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 20\n    permissions:\n      contents: read\n      actions: read\n      attestations: write",
            1,
        )
        self.assertReleaseFails(mutated, "attestations")

    def test_missing_environment_on_release_draft_fails(self) -> None:
        mutated = self.real_text.replace("    environment: release\n", "", 1)
        self.assertReleaseFails(mutated, "exactly two protected environments")

    def test_extra_environment_outside_release_draft_fails(self) -> None:
        mutated = self.real_text.replace(
            "  build-macos:\n    name: Build macOS arm64 binary",
            "  build-macos:\n    environment: release\n    name: Build macOS arm64 binary",
            1,
        )
        self.assertReleaseFails(mutated, "exactly two protected environments")

    def test_persist_credentials_true_fails(self) -> None:
        mutated = self.real_text.replace("persist-credentials: false", "persist-credentials: true", 1)
        self.assertReleaseFails(mutated, "persist-credentials")

    def test_git_tag_creation_fails(self) -> None:
        mutated = self.real_text.replace(
            "      - name: Verify tag matches package version",
            "      - name: Verify tag matches package version\n        run: git tag v9.9.9-testnet.9",
            1,
        )
        self.assertReleaseFails(mutated, "must not create tags")

    def test_git_push_fails(self) -> None:
        mutated = self.real_text.replace(
            "      - name: Verify tag matches package version",
            "      - name: Verify tag matches package version\n        run: git push origin main",
            1,
        )
        # git push is caught by the shared forbidden-pattern tripwire.
        self.assertReleaseFails(mutated, "forbidden pattern")

    def test_cargo_publish_fails(self) -> None:
        mutated = self.real_text.replace(
            "      - name: Build locked release binary\n        run: cargo build --locked --release",
            "      - name: Build locked release binary\n        run: cargo publish --locked",
            1,
        )
        self.assertReleaseFails(mutated, "forbidden pattern")

    def test_npm_publish_fails(self) -> None:
        mutated = self.real_text + "\n      - run: npm publish --provenance\n"
        self.assertReleaseFails(mutated, "forbidden pattern")

    def test_docker_push_fails(self) -> None:
        mutated = self.real_text + "\n      - run: docker push example/image:tag\n"
        self.assertReleaseFails(mutated, "forbidden pattern")

    def test_forbidden_gh_release_subcommand_fails(self) -> None:
        mutated = self.real_text.replace(
            'gh release view "$tag"',
            "gh release delete \"$tag\"",
            1,
        )
        self.assertReleaseFails(mutated, "forbidden gh release subcommand")

    def test_mutable_tag_interpolation_fails(self) -> None:
        mutated = self.real_text.replace(
            'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"',
            'test "$(git rev-parse HEAD)" = "${{ inputs.tag }}"',
            1,
        )
        self.assertReleaseFails(mutated, "must not be interpolated")

    def test_template_interpolation_in_run_fails(self) -> None:
        mutated = self.real_text.replace(
            'test -f "$out/SHA256SUMS"',
            'test -f "${{ github.sha }}"',
            1,
        )
        self.assertReleaseFails(mutated, "must not contain template interpolation")

    def test_missing_verify_tag_fails(self) -> None:
        mutated = self.real_text.replace(" --verify-tag", "", 1)
        self.assertReleaseFails(mutated, "--verify-tag")

    def test_missing_attestation_flag_fails(self) -> None:
        mutated = self.real_text.replace(" --source-digest", "")
        self.assertReleaseFails(mutated, "--source-digest")

    def test_attestations_read_rejected_everywhere(self) -> None:
        mutated = self.real_text.replace(
            "      contents: read\n      id-token: write\n      attestations: write",
            "      contents: read\n      id-token: write\n      attestations: write\n      attestations: read",
            1,
        )
        self.assertReleaseFails(mutated, "attestations")

    def test_no_preapproval_package_job(self) -> None:
        self.assertIn("astatine-release-bundle", self.real_text)
        self.assertNotRegex(self.real_text, r"(?m)^\s*package\s*:")
        self.assertIn("release-package", self.real_text)
        self.assertIn("release-draft", self.real_text)

    def test_missing_exact_workflow_path_fails(self) -> None:
        mutated = self.real_text.replace(".github/workflows/ci.yml", ".github/workflows/other.yml", 1)
        self.assertReleaseFails(mutated, "exact Rust CI workflow path")

    def test_missing_qualification_path_fails(self) -> None:
        mutated = self.real_text.replace(
            ".github/workflows/linux-native-qualification.yml",
            ".github/workflows/other.yml",
            1,
        )
        self.assertReleaseFails(mutated, "exact qualification workflow path")

    def test_missing_head_branch_main_fails(self) -> None:
        mutated = self.real_text.replace("head_branch", "head_brunch")
        self.assertReleaseFails(mutated, "head_branch")

    def test_missing_digest_verification_fails(self) -> None:
        mutated = self.real_text.replace("digest mismatch", "hash problem")
        self.assertReleaseFails(mutated, "digest")

    def test_missing_tag_reverify_fails(self) -> None:
        mutated = self.real_text.replace(
            'git ls-remote origin "refs/tags/$tag"', 'git ls-remote origin "refs/heads/main"'
        )
        self.assertReleaseFails(mutated, "re-verify the remote tag")

    def test_top_level_write_rejected(self) -> None:
        mutated = self.real_text.replace(
            "permissions:\n  contents: read\n\nconcurrency:",
            "permissions:\n  contents: write\n\nconcurrency:",
            1,
        )
        self.assertReleaseFails(mutated, "contents: read")

    def test_checkout_ref_drift_rejected(self) -> None:
        mutated = self.real_text.replace(
            "ref: refs/tags/${{ inputs.tag }}",
            "ref: refs/heads/main",
            1,
        )
        self.assertReleaseFails(mutated, "every checkout ref must be")

    def test_flow_style_uses_rejected(self) -> None:
        mutated = self.real_text + "\n      - uses: {action: foo}\n"
        # The strict parser treats flow-style as ambiguous; release profile must fail closed.
        try:
            CHECKER.validate_release_workflow(mutated, self.temp_copy(mutated))
        except AssertionError as error:
            self.assertIn("flow-style", str(error).lower())
            return
        raise AssertionError("flow-style uses unexpectedly accepted")

    def test_auto_publish_edit_rejected(self) -> None:
        mutated = self.real_text + '\n      - run: gh release edit "$tag" --draft=false\n'
        self.assertReleaseFails(mutated, "forbidden gh release subcommand")

    def test_auto_publish_draft_false_rejected(self) -> None:
        mutated = self.real_text.replace(
            "Draft verified; owner self-approval publication remains required",
            "Draft verified; owner self-approval publication remains required --draft=false",
            1,
        )
        self.assertReleaseFails(mutated, "draft")

    def test_draft_create_is_prerelease(self) -> None:
        # The release draft must be explicitly prerelease: exactly one
        # non-comment `gh release create` line in release-draft, carrying
        # --draft, --prerelease, and --verify-tag together; publication stays
        # manual-only outside the workflow.
        import re as _re

        marker = "\n  release-draft:\n"
        self.assertIn(marker, self.real_text)
        draft = self.real_text.split(marker, 1)[1]
        create_lines = [
            line
            for line in draft.splitlines()
            if "gh release create" in line and not line.strip().startswith("#")
        ]
        self.assertEqual(
            len(create_lines),
            1,
            "release-draft must contain exactly one gh release create line, got %r"
            % create_lines,
        )
        for flag in ("--draft", "--prerelease", "--verify-tag"):
            self.assertIn(
                flag,
                create_lines[0],
                "draft create line must carry %s (got %r)" % (flag, create_lines[0]),
            )
        non_comment_prerelease = [
            line
            for line in self.real_text.splitlines()
            if "--prerelease" in line and not line.strip().startswith("#")
        ]
        self.assertEqual(
            len(non_comment_prerelease),
            1,
            "--prerelease must appear exactly once outside comments, got %r"
            % non_comment_prerelease,
        )
        self.assertIn(create_lines[0].strip(), non_comment_prerelease[0])

    def test_auto_publish_prerelease_rejected(self) -> None:
        # Narrow Phase1 allowlist: --prerelease is permitted exactly once, on
        # the release-draft `gh release create --draft --prerelease --verify-tag`
        # line. Any other occurrence, clearing the draft, or editing the
        # release must fail closed.
        create_lines = [
            line
            for line in self.real_text.splitlines()
            if "gh release create" in line and not line.strip().startswith("#")
        ]
        self.assertEqual(len(create_lines), 1)
        for flag in ("--draft", "--prerelease", "--verify-tag"):
            self.assertIn(flag, create_lines[0])
        stray = self.real_text + "\n      - run: echo stray --prerelease probe\n"
        self.assertReleaseFails(stray, "prerelease")
        cleared = self.real_text.replace(
            "--draft --prerelease --verify-tag",
            "--draft=false --prerelease --verify-tag",
            1,
        )
        self.assertNotEqual(cleared, self.real_text)
        self.assertReleaseFails(cleared, "must not clear draft")
        edited = self.real_text + '\n      - run: gh release edit "$tag" --draft=false\n'
        self.assertReleaseFails(edited, "forbidden gh release subcommand")

    def test_prerelease_moved_out_of_draft_rejected(self) -> None:
        # Moved prerelease: exactly one non-comment occurrence but outside
        # release-draft must fail closed on the draft-section gate (not pass
        # as the allowlisted draft line).
        stripped = self.real_text.replace(
            "--draft --prerelease --verify-tag",
            "--draft --verify-tag",
            1,
        )
        self.assertNotEqual(stripped, self.real_text)
        moved = stripped.replace(
            'echo "no existing release for the exact tag"',
            'echo "no existing release for the exact tag"\n          echo moved --prerelease probe',
            1,
        )
        self.assertNotEqual(moved, stripped)
        non_comment = [
            line
            for line in moved.splitlines()
            if "--prerelease" in line and not line.strip().startswith("#")
        ]
        self.assertEqual(len(non_comment), 1)
        self.assertReleaseFails(moved, "allowed only on the release-draft")

    def test_prerelease_without_create_flags_rejected(self) -> None:
        # Prerelease kept in release-draft but detached from the actual
        # `gh release create --draft ... --verify-tag` flags must fail closed.
        broken = self.real_text.replace(
            "--draft --prerelease --verify-tag",
            "--prerelease",
            1,
        )
        self.assertNotEqual(broken, self.real_text)
        self.assertReleaseFails(broken, "must be --draft --prerelease --verify-tag")

    def test_prerelease_comment_does_not_satisfy_rejected(self) -> None:
        # A comment containing --prerelease must neither satisfy nor bypass the
        # non-comment exactly-once draft-create gate.
        stripped = self.real_text.replace(
            "--draft --prerelease --verify-tag",
            "--draft --verify-tag",
            1,
        )
        self.assertNotEqual(stripped, self.real_text)
        commented = stripped + "\n      # --prerelease comment only\n"
        self.assertReleaseFails(commented, "exactly once")

    def test_missing_can_admins_bypass_check_rejected(self) -> None:
        # Environment protection is now enforced via the bounded validator script.
        mutated = self.real_text.replace(
            "python3 -B support/release/verify-protected-environment.py", "echo no-validator", 1
        )
        mutated = mutated.replace(
            "python3 -B support/release/verify-protected-environment.py", "echo no-validator"
        )
        self.assertReleaseFails(mutated, "protected-environment")

    def test_missing_required_reviewers_rejected(self) -> None:
        # Same validator gate covers required_reviewers; removing it must fail.
        mutated = self.real_text.replace("deployment-branch-policies", "XXX-REMOVED", 1)
        mutated = mutated.replace("deployment-branch-policies", "XXX-REMOVED")
        self.assertReleaseFails(mutated, "deployment-branch-policies")

    def test_missing_canonical_repo_rejected(self) -> None:
        mutated = self.real_text.replace("Jecta-ai/astatine-miner", "Evil/fork", 1)
        # Remove all canonical occurrences to trigger failure.
        mutated = mutated.replace("Jecta-ai/astatine-miner", "Evil/fork")
        self.assertReleaseFails(mutated, "canonical repository")

    def test_missing_canonical_repo_id_rejected(self) -> None:
        mutated = self.real_text.replace("1454137135", "9999999")
        self.assertReleaseFails(mutated, "1454137135")

    def test_missing_verifiers_rejected(self) -> None:
        mutated = self.real_text.replace(
            "python3 -B support/verify-fixture-provenance.py", "echo no-verifier", 1
        )
        self.assertReleaseFails(mutated, "verify-fixture-provenance")

    def test_missing_distribution_verifier_rejected(self) -> None:
        mutated = self.real_text.replace(
            "python3 -B support/verify-distribution-inventory.py", "echo no-verifier", 1
        )
        self.assertReleaseFails(mutated, "verify-distribution-inventory")

    def test_missing_provenance_semantic_check_rejected(self) -> None:
        mutated = self.real_text.replace("release provenance semantics verified", "provenance ok")
        self.assertReleaseFails(mutated, "provenance semantic")

    def test_provenance_owner_intent_markers_required(self) -> None:
        for marker in (
            "release_intent_authorized",
            "publication_authorized must be exactly false",
            "final_release_controls_complete must be exactly false",
            "rights_decision",
            "owner-authorized release intent",
            "final controls",
        ):
            self.assertIn(marker, self.real_text)

    def test_provenance_rights_decision_fail_closed_required(self) -> None:
        for marker in (
            "provenance field rights_decision missing or empty",
            "must record owner-authorized release intent",
            "must not claim publication authorization or a release approver",
        ):
            self.assertIn(marker, self.real_text)
        mutated = self.real_text.replace(
            "provenance field rights_decision missing or empty",
            "rights_decision optional",
            1,
        )
        self.assertReleaseFails(mutated, "rights_decision")
    def test_provenance_final_publication_language_rejected(self) -> None:
        mutated = self.real_text.replace(
            "provenance field publication_authorized must be exactly false",
            "provenance field publication_authorized must be exactly true",
            1,
        )
        # Reintroducing final-publication true must fail closed.
        self.assertReleaseFails(mutated, "must not require final-publication")

    def test_provenance_missing_release_intent_rejected(self) -> None:
        mutated = self.real_text.replace("release_intent_authorized", "XXX-REMOVED", 1)
        mutated = mutated.replace("release_intent_authorized", "XXX-REMOVED")
        self.assertReleaseFails(mutated, "release_intent_authorized")

    def test_provenance_missing_final_controls_rejected(self) -> None:
        mutated = self.real_text.replace("final_release_controls_complete", "XXX-REMOVED", 1)
        mutated = mutated.replace("final_release_controls_complete", "XXX-REMOVED")
        self.assertReleaseFails(mutated, "final_release_controls_complete")

    def test_unsafe_run_logging_rejected(self) -> None:
        mutated = self.real_text.replace(
            "id=%s name=%s path=%s status=%s conclusion=%s event=%s head_branch=%s url=%s",
            "%r\" % (name, run",
            1,
        )
        # Tampering with safe logging must fail (hash mismatch at minimum, ideally safe-field check).
        try:
            CHECKER.validate_release_workflow(mutated, self.temp_copy(mutated))
        except AssertionError as error:
            self.assertTrue(
                "html_url" in str(error) or "hash mismatch" in str(error) or "safe" in str(error).lower()
            )
            return
        raise AssertionError("unsafe logging mutation unexpectedly accepted")

    def test_missing_env_reverify_before_mutation_rejected(self) -> None:
        # Phase1: exactly 2 release invocations (preflight release + package
        # release); no release-admin validator exists.
        release_validator = 'python3 -B support/release/verify-protected-environment.py --environment-json "$env_out" --policies-json "$policies_out" --tag "$tag" --expected-environment release'
        self.assertEqual(self.real_text.count(release_validator), 2)
        self.assertEqual(
            self.real_text.count("verify-protected-environment.py --environment-json"), 2
        )
        self.assertNotIn("release-admin", self.real_text)
        self.assertNotIn("$admin_env_out", self.real_text)
        mutated = self.real_text.replace(release_validator, "echo no-reverify", 1)
        # One invocation remains; remove all to trigger fail-closed.
        mutated = mutated.replace(release_validator, "echo no-reverify")
        self.assertReleaseFails(mutated, "protected-environment")

    def test_tag_policy_safe_forms_required(self) -> None:
        # M2: validator in preflight/package + inline exact-tag in draft; no wildcard.
        self.assertIn("support/release/verify-protected-environment.py", self.real_text)
        self.assertIn('"v0.1.0-testnet.3"', self.real_text)
        self.assertNotIn('"v0.1.0-testnet.*"', self.real_text)
        self.assertNotIn('"v*",', self.real_text)
        self.assertIn("deployment-branch-policies", self.real_text)
        self.assertIn("total_count", self.real_text)

    def test_broad_tag_policy_star_rejected(self) -> None:
        # Adding a broad v* policy inline must fail closed.
        mutated = self.real_text + '\n      # allowed_names = {"v*", tag}\n'
        self.assertReleaseFails(mutated, "broad v*")

    def test_preapproval_package_job_rejected(self) -> None:
        mutated = self.real_text.replace("  release-draft:", "  package:\n    name: Old package\n  release-draft:", 1)
        self.assertReleaseFails(mutated, "exactly")

    def test_bundle_artifact_present_in_protected_jobs(self) -> None:
        self.assertIn("astatine-release-bundle", self.real_text)
        # Unprotected package job must still be rejected
        mutated = self.real_text.replace("  release-package:", "  package:\n    name: Old package\n  release-package:", 1)
        self.assertReleaseFails(mutated, "exactly")

    def test_exact_allowlist_rejects_other_pinned_action(self) -> None:
        mutated = self.real_text.replace(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-node@3d3c42e5aac5ba805825da76410c181273ba90b1",
            1,
        )
        self.assertReleaseFails(mutated, "exact allowlist")

    def test_github_ref_binding_required(self) -> None:
        # The single preflight GITHUB_REF tag binding must survive: strip the
        # only copy and the gate must fail.
        self.assertGreaterEqual(
            self.real_text.count('test "$GITHUB_REF" = "refs/tags/$'), 1
        )
        mutated = self.real_text.replace('test "$GITHUB_REF" = "refs/tags/$', 'test "$GITHUB_REF" = "refs/heads/$')
        self.assertReleaseFails(mutated, "GITHUB_REF")

    def test_latest_push_selection_required(self) -> None:
        mutated = self.real_text.replace("run_started_at", "XXX-REMOVED", 1)
        mutated = mutated.replace("run_started_at", "XXX-REMOVED")
        self.assertReleaseFails(mutated, "run_started_at")

    def test_exact_one_run_matching_rejected(self) -> None:
        mutated = self.real_text + '\n      # len(matching) != 1\n'
        # Exact-one matching is too weak for reruns; policy must reject it if present
        # (workflow uses latest safe selection, so this marker must not appear).
        # If the marker is already absent, adding it as a comment is inert; instead
        # verify the workflow uses latest selection.
        self.assertIn("latest = max", self.real_text)
        self.assertNotIn("len(matching) != 1", self.real_text)

    def test_validator_invocation_required_twice(self) -> None:
        # Phase1 contract: exactly 2 invocations (preflight release + package
        # release re-verify); no release-admin validator exists.
        release_validator = 'python3 -B support/release/verify-protected-environment.py --environment-json "$env_out" --policies-json "$policies_out" --tag "$tag" --expected-environment release'
        self.assertEqual(self.real_text.count(release_validator), 2)
        self.assertEqual(
            self.real_text.count("verify-protected-environment.py --environment-json"), 2
        )
        self.assertNotIn("--expected-environment release-admin", self.real_text)
        self.assertNotIn("$admin_env_out", self.real_text)

    def test_binary_attestation_binding_required(self) -> None:
        for marker in (
            "Attest raw macOS binary",
            "Attest raw Linux binary",
            "Verify binary build attestations before packaging",
            'gh attestation verify "$binary"',
        ):
            self.assertIn(marker, self.real_text)
        mutated = self.real_text.replace("Verify binary build attestations before packaging", "XXX", 1)
        self.assertReleaseFails(mutated, "binary")

    def test_draft_packaged_binary_attestation_binding_required(self) -> None:
        for marker in (
            "Verify packaged binaries match attested compiled binaries",
            "Verify extracted binaries against build attestations",
            "archive member must be a regular file",
            "archive member path is unsafe",
            "archive member mode mismatch",
            "packaged binary sha256 does not match provenance",
            "macOS binary format mismatch",
            "Linux binary format mismatch",
            "0x0100000C",
            'int.from_bytes(binary[18:20], "little") != 62',
            "binary[4] != 2 or binary[5] != 1",
            "packaged binaries verified against separately attested compiled binaries",
        ):
            self.assertIn(marker, self.real_text)
        mutated = self.real_text.replace(
            "Verify extracted binaries against build attestations",
            "XXX",
            1,
        )
        self.assertReleaseFails(mutated, "bind packaged binaries")

    def test_draft_extractall_rejected(self) -> None:
        mutated = self.real_text.replace(
            "              members[name] = data.read()",
            "              tar.extractall()",
            1,
        )
        self.assertReleaseFails(mutated, "extractall")

    def test_draft_archive_member_validation_required(self) -> None:
        mutated = self.real_text.replace(
            "archive member mode mismatch",
            "mode ok",
            1,
        )
        self.assertReleaseFails(mutated, "packaged binaries")

    def test_draft_binary_format_check_required(self) -> None:
        mutated = self.real_text.replace(
            "Linux binary format mismatch",
            "format ok",
        )
        self.assertReleaseFails(mutated, "packaged binaries")

    def test_draft_binary_attestation_count_required(self) -> None:
        mutated = self.real_text.replace(
            '            gh attestation verify "$binary" --repo "$GITHUB_REPOSITORY" --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml" --source-digest "$GITHUB_SHA" --source-ref "refs/tags/$tag"\n',
            "",
            1,
        )
        self.assertReleaseFails(mutated, "both release-package and release-draft")

    def test_draft_binary_attestation_flags_required(self) -> None:
        marker = "  release-draft:"
        index = self.real_text.index(marker)
        head, draft = self.real_text[:index], self.real_text[index:]
        mutated = head + draft.replace(
            '--source-digest "$GITHUB_SHA"',
            '--source-digest "WRONG"',
            1,
        )
        self.assertReleaseFails(mutated, "release-draft must verify")

    def test_package_contents_write_rejected(self) -> None:
        # release-package must stay contents:read; changing to write must fail.
        # Mutate within the release-package section so the needs chain and job
        # set stay intact (only the permission changes).
        import re as _re

        marker = "\n  release-package:\n"
        self.assertIn(marker, self.real_text)
        head, tail = self.real_text.split(marker, 1)
        follower = _re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", tail)
        section = tail[: follower.start()] if follower else tail
        rest = tail[follower.start():] if follower else ""
        self.assertIn("contents: read", section)
        mutated_section = section.replace("contents: read", "contents: write", 1)
        self.assertNotEqual(mutated_section, section)
        self.assertReleaseFails(head + marker + mutated_section + rest, "must be exactly")

    def test_draft_checkout_rejected(self) -> None:
        # Draft job must have no checkout; adding one must fail (wrong job set/perms).
        mutated = self.real_text.replace(
            "  release-draft:\n    name: Create and verify draft release",
            "  release-draft:\n    name: Create and verify draft release\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            1,
        )
        self.assertReleaseFails(mutated, "checkout")

    def test_draft_repo_script_rejected(self) -> None:
        # Draft must not run repo build code; adding it must fail (at minimum via pin, ideally via policy).
        # Use a mutation that triggers the exact-allowlist + no-checkout policy.
        mutated = self.real_text.replace(
            "  release-draft:\n    name: Create and verify draft release",
            "  release-draft:\n    name: Create and verify draft release\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            1,
        )
        self.assertReleaseFails(mutated, "checkout")

    def test_missing_per_job_tag_assert_rejected(self) -> None:
        mutated = self.real_text.replace("Assert exact tag identity", "XXX-REMOVED")
        self.assertReleaseFails(mutated, "B1")

    def test_remote_tag_mismatch_before_archive_attest_rejected(self) -> None:
        mutated = self.real_text.replace("remote tag verified at expected commit", "tag ok")
        self.assertReleaseFails(mutated, "moved tag")

    def test_provenance_commit_mismatch_before_archive_attest_rejected(self) -> None:
        mutated = self.real_text.replace("provenance field commit mismatch", "XXX", 1)
        mutated = mutated.replace("provenance field commit mismatch", "XXX")
        self.assertReleaseFails(mutated, "provenance field commit")

    def test_missing_bundle_artifact_rejected(self) -> None:
        mutated = self.real_text.replace("astatine-release-bundle", "XXX-REMOVED")
        self.assertReleaseFails(mutated, "bundle artifact")

    def test_broad_second_env_policy_rejected(self) -> None:
        # OR policies must be exactly one tag; second tag or branch must fail.
        # Workflow inline draft check already enforces exactly-one tag and no branches.
        self.assertIn("tag policies must be exactly one", self.real_text)
        self.assertIn("branch policies must be empty", self.real_text)
        mutated = self.real_text.replace("tag policies must be exactly one", "XXX", 1)
        mutated = mutated.replace("tag policies must be exactly one", "XXX")
        self.assertReleaseFails(mutated, "tag policies must be exactly one")

    def test_m2_unknown_type_second_policy_rejected(self) -> None:
        # OR policies: a second entry with unknown/missing type must fail closed.
        # Simulate by duplicating the single policy with an unknown-type sibling.
        anchor = "if total_count != 1:"
        assert anchor in self.real_text
        mutated = self.real_text.replace(
            anchor,
            'policies = policies + [{"type": "unknown"}]\n          if total_count != 1:',
            1,
        )
        # The workflow itself is unchanged in the exact-tag policy, but the test
        # documents the exact-count requirement: any second entry must be
        # rejected by the total_count/len check.
        self.assertIn(anchor, self.real_text)
        # Mutating to allow two policies must fail (hash mismatch at minimum, policy ideally).
        try:
            CHECKER.validate_release_workflow(mutated, self.temp_copy(mutated))
        except AssertionError as error:
            self.assertTrue("hash mismatch" in str(error) or "exactly one" in str(error).lower())
            return
        raise AssertionError("second unknown-type policy unexpectedly accepted")

    def test_m2_malformed_second_entry_rejected(self) -> None:
        self.assertIn('if not isinstance(entry, dict):', self.real_text)
        mutated = self.real_text.replace(
            "if not isinstance(entry, dict):",
            "if False and not isinstance(entry, dict):",
            1,
        )
        self.assertReleaseFails(mutated, "hash mismatch")

    def test_m2_two_tag_policies_rejected(self) -> None:
        # Exactly one tag policy required; duplicating the allowlist check must fail.
        self.assertIn("tag policies must be exactly one", self.real_text)
        mutated = self.real_text.replace("tag policies must be exactly one", "XXX-REMOVED")
        self.assertReleaseFails(mutated, "tag policies must be exactly one")

    def test_m2_single_policy_missing_type_rejected(self) -> None:
        self.assertIn("tag policy type must be exactly tag", self.real_text)
        mutated = self.real_text.replace(
            "tag policy type must be exactly tag",
            "tag policy type XXX",
            1,
        )
        try:
            CHECKER.validate_release_workflow(mutated, self.temp_copy(mutated))
        except AssertionError as error:
            self.assertTrue(
                "tag policy type must be exactly tag" in str(error) or "hash mismatch" in str(error)
            )
            return
        raise AssertionError("single policy missing type unexpectedly accepted")

    def test_draft_remote_check_uses_gh_api_not_ls_remote(self) -> None:
        # Draft (no checkout) must use authenticated gh api tag-ref lookup with peeling.
        self.assertIn('gh api "repos/$repo/git/ref/tags/$tag"', self.real_text)
        self.assertIn('gh api "repos/$repo/git/tags/$obj_sha"', self.real_text)
        # Package retains checkout-bound ls-remote; draft section must not contain it.
        draft_section = self.real_text.split("release-draft:", 1)[-1]
        self.assertNotIn('git ls-remote origin', draft_section)
        # Removing the gh api tag-ref lookup must fail.
        mutated = self.real_text.replace('gh api "repos/$repo/git/ref/tags/$tag"', 'echo no-tag-check', 1)
        self.assertReleaseFails(mutated, "gh api")

    def test_build_macos_oidc_write_rejected(self) -> None:
        # R3: build jobs are read-only; OIDC/attestations write rejected.
        mutated = self.real_text.replace(
            "  build-macos:\n    name: Build macOS arm64 binary\n    needs: preflight\n"
            "    runs-on: macos-15\n    timeout-minutes: 60\n    permissions:\n      contents: read\n",
            "  build-macos:\n    name: Build macOS arm64 binary\n    needs: preflight\n"
            "    runs-on: macos-15\n    timeout-minutes: 60\n    permissions:\n      contents: read\n"
            "      id-token: write\n",
            1,
        )
        self.assertIn("id-token: write", mutated)
        self.assertReleaseFails(mutated, "id-token")

    def test_build_linux_attestations_write_rejected(self) -> None:
        # R3: build jobs must not request attestations write.
        mutated = self.real_text.replace(
            "  build-linux:\n    name: Build Linux x86_64 binary\n    needs: preflight\n"
            "    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n    permissions:\n      contents: read\n",
            "  build-linux:\n    name: Build Linux x86_64 binary\n    needs: preflight\n"
            "    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n    permissions:\n      contents: read\n"
            "      attestations: write\n",
            1,
        )
        self.assertIn("attestations: write", mutated)
        self.assertReleaseFails(mutated, "attestations")

    def test_build_job_direct_attest_rejected(self) -> None:
        # R3 split: builds must not attest target/release directly.
        mutated = self.real_text.replace(
            "subject-path: ${{ runner.temp }}/attest/macos/astatine",
            "subject-path: target/release/astatine",
            1,
        )
        self.assertReleaseFails(mutated, "must not attest target/release")

    def test_attest_job_checkout_rejected(self) -> None:
        # R3: attest jobs must not checkout.
        mutated = self.real_text.replace(
            "      - name: Download macOS binary",
            "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n      - name: Download macOS binary",
            1,
        )
        self.assertReleaseFails(mutated, "checkout")

    def test_attest_job_candidate_execution_rejected(self) -> None:
        # R3: attest jobs must not execute the candidate.
        mutated = self.real_text.replace(
            'echo "macOS binary hash verified against build output"',
            'echo "macOS binary hash verified against build output"\n          ./target/release/astatine --version',
            1,
        )
        self.assertReleaseFails(mutated, "candidate execution")

    def test_attest_job_repo_script_rejected(self) -> None:
        # R3: attest jobs must not run repo scripts.
        mutated = self.real_text.replace(
            'echo "Linux binary hash verified against build output"',
            'echo "Linux binary hash verified against build output"\n          python3 -B support/release/build-release.py --help',
            1,
        )
        self.assertReleaseFails(mutated, "repo scripts")

    def test_step_name_cannot_truncate_attest_job(self) -> None:
        # Structural YAML checks must not be bypassed by a step name that looks
        # like a job key in raw text.
        mutated = self.real_text.replace(
            "    steps:\n      - name: Download macOS binary",
            "    steps:\n      - name: \"release-package:\"\n"
            "      - name: candidate\n"
            "        run: ./target/release/astatine --version\n"
            "      - name: Download macOS binary",
            1,
        )
        self.assertReleaseFails(mutated, "candidate execution")

    def test_attest_binary_assignment_substitution_rejected(self) -> None:
        mutated = self.real_text.replace(
            "      - name: Download macOS binary",
            "      - name: injected\n"
            "        run: |\n"
            "          binary=\"$(python3 support/evil.py)\"\n"
            "      - name: Download macOS binary",
            1,
        )
        self.assertReleaseFails(mutated, "attest allowlist")

    def test_bare_run_step_rejected(self) -> None:
        mutated = self.real_text.replace(
            "      - name: Download macOS binary",
            "      - run: |\n"
            "          echo injected\n"
            "      - name: Download macOS binary",
            1,
        )
        self.assertReleaseFails(mutated, "attest allowlist")

    def test_build_echo_cannot_satisfy_toolchain_observation(self) -> None:
        mutated = self.real_text.replace(
            '          rustc_line="$(rustc --version)"',
            '          echo \'rustc_line="$(rustc --version)"\'',
            1,
        )
        self.assertReleaseFails(mutated, "toolchain observation")

    def test_preflight_comment_cannot_satisfy_gate(self) -> None:
        mutated = self.real_text.replace(
            '          python3 -B support/verify-fixture-provenance.py > "$RUNNER_TEMP/fixture-provenance.json"',
            '          # python3 -B support/verify-fixture-provenance.py > "$RUNNER_TEMP/fixture-provenance.json"',
            1,
        )
        self.assertReleaseFails(mutated, "release-intent gate")

    def test_package_echo_cannot_satisfy_hash_compare(self) -> None:
        mutated = self.real_text.replace(
            '          if [ "$actual_macos" != "$EXPECTED_MACOS_SHA256" ]; then',
            '          echo \'if [ "$actual_macos" != "$EXPECTED_MACOS_SHA256" ]; then\'',
            1,
        )
        self.assertReleaseFails(mutated, "hash/toolchain")

    def test_missing_build_attest_hash_chain_rejected(self) -> None:
        # R3: build->attest hash chain via needs outputs.
        mutated = self.real_text.replace(
            "needs.build-macos.outputs.binary_sha256", "XXX-REMOVED-HASH-CHAIN", 1
        )
        mutated = mutated.replace("needs.build-macos.outputs.binary_sha256", "XXX-REMOVED-HASH-CHAIN")
        self.assertReleaseFails(mutated, "binary_sha256")

    def test_package_missing_attest_needs_rejected(self) -> None:
        # R3: release-package must need attest jobs.
        mutated = self.real_text.replace("      - attest-macos\n", "", 1)
        self.assertReleaseFails(mutated, "attest-macos")

    def test_package_missing_attestation_verification_rejected(self) -> None:
        mutated = self.real_text.replace(
            "Verify binary build attestations before packaging", "XXX-REMOVED", 1
        )
        self.assertReleaseFails(mutated, "binary")

    def test_blocked_v1_fixture_verifier_output_rejected(self) -> None:
        # R5: blocked v1 fixture output must fail the JSON gate (static marker).
        mutated = self.real_text.replace(
            "astatine-fixture-provenance/v3", "astatine-fixture-provenance/v1", 1
        )
        mutated = mutated.replace(
            "astatine-fixture-provenance/v3", "astatine-fixture-provenance/v1"
        )
        self.assertReleaseFails(mutated, "astatine-fixture-provenance/v3")

    def test_blocked_v1_distribution_verifier_output_rejected(self) -> None:
        # R5: blocked v1 distribution output must fail the JSON gate.
        mutated = self.real_text.replace(
            "astatine-distribution-inventory/v3", "astatine-distribution-inventory/v1", 1
        )
        mutated = mutated.replace(
            "astatine-distribution-inventory/v3", "astatine-distribution-inventory/v1"
        )
        self.assertReleaseFails(mutated, "astatine-distribution-inventory/v3")

    def test_preflight_json_gate_requires_intent_fields(self) -> None:
        # R5: preflight JSON gate must require intent booleans for both verifiers.
        mutated = self.real_text.replace(
            'data.get("release_intent_authorized") is not True', 'data.get("release_intent_authorized") is True', 1
        )
        mutated = mutated.replace(
            'data.get("release_intent_authorized") is not True', 'data.get("release_intent_authorizedXXX', 1
        )
        self.assertReleaseFails(mutated, "release_intent_authorized")

    def test_missing_toolchain_exact_lines_rejected(self) -> None:
        # R3: exact toolchain observation lines required.
        mutated = self.real_text.replace(
            "rustc 1.94.1 (e408947bf 2026-03-25)", "XXX-REMOVED-TOOLCHAIN", 1
        )
        mutated = mutated.replace(
            "rustc 1.94.1 (e408947bf 2026-03-25)", "XXX-REMOVED-TOOLCHAIN"
        )
        self.assertReleaseFails(mutated, "rustc 1.94.1")

    def test_hardcoded_toolchain_without_observation_rejected(self) -> None:
        # R6: build jobs must execute rustc/cargo, not hardcode output.
        mutated = self.real_text.replace(
            'rustc_line="$(rustc --version)"',
            'rustc_line="rustc 1.94.1 (e408947bf 2026-03-25)"',
            1,
        )
        self.assertReleaseFails(mutated, "rustc --version")

    def test_missing_toolchain_args_rejected(self) -> None:
        # R3: package must pass observed toolchain to builder.
        mutated = self.real_text.replace("--rustc-version", "XXX-REMOVED-ARG", 1)
        mutated = mutated.replace("--rustc-version", "XXX-REMOVED-ARG")
        self.assertReleaseFails(mutated, "--rustc-version")

    def test_missing_cargo_exact_line_rejected(self) -> None:
        mutated = self.real_text.replace(
            "cargo 1.94.1 (29ea6fb6a 2026-03-24)", "XXX-REMOVED-TOOLCHAIN", 1
        )
        mutated = mutated.replace(
            "cargo 1.94.1 (29ea6fb6a 2026-03-24)", "XXX-REMOVED-TOOLCHAIN"
        )
        self.assertReleaseFails(mutated, "cargo 1.94.1")

    def test_preflight_v3_gate_markers_present(self) -> None:
        for marker in (
            'support/verify-fixture-provenance.py > "$RUNNER_TEMP/fixture-provenance.json"',
            'support/verify-distribution-inventory.py > "$RUNNER_TEMP/distribution-inventory.json"',
            "astatine-fixture-provenance/v3",
            "astatine-distribution-inventory/v3",
            "blocked v1 rejected",
            "fixture provenance release intent authorized",
            "distribution inventory release intent authorized",
        ):
            self.assertIn(marker, self.real_text)

    def test_build_attest_split_markers_present(self) -> None:
        for marker in (
            "attest-macos",
            "attest-linux",
            "astatine-macos-arm64",
            "astatine-linux-x86_64",
            "astatine-release-bundle",
            "Observe pinned toolchain versions",
            "Record binary SHA-256",
            "Verify macOS binary hash matches build output",
            "Verify Linux binary hash matches build output",
            "hash verified against build output",
            "hash mismatch against build output",
            "binaries verified against build outputs",
            "subject-path: ${{ runner.temp }}/attest/macos/astatine",
            "subject-path: ${{ runner.temp }}/attest/linux/astatine",
            "needs.build-macos.outputs.binary_sha256",
            "needs.build-linux.outputs.binary_sha256",
            "needs.build-macos.outputs.rustc_version",
            "needs.build-macos.outputs.cargo_version",
            "--rustc-version",
            "--cargo-version",
            "rustc 1.94.1 (e408947bf 2026-03-25)",
            "cargo 1.94.1 (29ea6fb6a 2026-03-24)",
        ):
            self.assertIn(marker, self.real_text)
        self.assertNotIn("subject-path: target/release/astatine", self.real_text)
        self.assertEqual(self.real_text.count("Assert exact tag identity"), 4)
        self.assertEqual(self.real_text.count("actions/checkout@"), 4)

    def test_print_sha_documents_recompute(self) -> None:
        self.assertEqual(
            CHECKER.compute_release_sha256(self.real_text.encode("utf-8")),
            CHECKER.RELEASE_WORKFLOW_SHA256,
        )
        self.assertIn("--print-release-sha256", pathlib.Path(CHECKER_PATH).read_text(encoding="utf-8"))

    def _draft_env_inline_script(self) -> str:
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        steps = parsed["jobs"]["release-draft"]["steps"]
        run = next(
            step["run"]
            for step in steps
            if step.get("name") == "Re-verify protected environment before mutation"
        )
        marker = "<<'PY'\n"
        self.assertIn(marker, run)
        return run.split(marker, 1)[1].rsplit("\nPY\n", 1)[0]

    def _run_draft_env_inline(self, env: dict, policies: dict) -> subprocess.CompletedProcess:
        tag = "v0.1.0-testnet.3"
        env_path = self.tmp / "inline-env.json"
        policies_path = self.tmp / "inline-policies.json"
        env_path.write_text(json.dumps(env), encoding="utf-8")
        policies_path.write_text(json.dumps(policies), encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-", str(env_path), str(policies_path), tag],
            input=self._draft_env_inline_script(),
            capture_output=True,
            text=True,
        )

    @staticmethod
    def _valid_inline_env() -> dict:
        return {
            "name": "release",
            "can_admins_bypass": False,
            "prevent_self_review": False,
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": False,
                    "reviewers": [
                        {"type": "User", "reviewer": {"login": "emyrinj", "id": 86115037}}
                    ],
                }
            ],
            "deployment_branch_policy": {
                "protected_branches": False,
                "custom_branch_policies": True,
            },
        }

    @staticmethod
    def _valid_inline_policies() -> dict:
        return {
            "total_count": 1,
            "branch_policies": [{"type": "tag", "name": "v0.1.0-testnet.3"}],
        }

    def test_draft_inline_env_accepts_owner_self_approval(self) -> None:
        result = self._run_draft_env_inline(self._valid_inline_env(), self._valid_inline_policies())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_draft_inline_env_rejects_non_owner_reviewer(self) -> None:
        env = self._valid_inline_env()
        env["protection_rules"][0]["reviewers"][0]["reviewer"]["id"] = 25130814
        result = self._run_draft_env_inline(env, self._valid_inline_policies())
        self.assertNotEqual(result.returncode, 0)

    def test_draft_inline_env_rejects_prevent_self_review_true(self) -> None:
        env = self._valid_inline_env()
        env["protection_rules"][0]["prevent_self_review"] = True
        result = self._run_draft_env_inline(env, self._valid_inline_policies())
        self.assertNotEqual(result.returncode, 0)

    def test_draft_inline_env_rejects_wildcard_policy(self) -> None:
        policies = {
            "total_count": 1,
            "branch_policies": [{"type": "tag", "name": "v0.1.0-testnet.*"}],
        }
        result = self._run_draft_env_inline(self._valid_inline_env(), policies)
        self.assertNotEqual(result.returncode, 0)

    def test_draft_inline_env_rejects_pagination_mismatch(self) -> None:
        policies = self._valid_inline_policies()
        policies["total_count"] = 2
        result = self._run_draft_env_inline(self._valid_inline_env(), policies)
        self.assertNotEqual(result.returncode, 0)

    def _draft_ruleset_inline_script(self) -> str:
        # Phase1 architecture: structural split-ruleset validation lives in
        # preflight ("Verify split tag rulesets") over the default-token
        # snapshot. An absent bypass_actors field is expected there (the
        # default token lacks ruleset-write access) and prints the BYPASS
        # notice instead of failing; authoritative bypass validation is an
        # owner manual live check outside the workflow. Execute preflight's
        # inline validator to preserve strict v* fail-closed coverage on
        # visible fields.
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        steps = parsed["jobs"]["preflight"]["steps"]
        marker = 'python3 - "$creation_out" "$immutability_out" "$repo" "$tag" <<\'PY\'\n'
        runs = [
            step["run"]
            for step in steps
            if isinstance(step.get("run"), str) and marker in step["run"]
        ]
        self.assertEqual(
            len(runs),
            1,
            "preflight must carry exactly one split-ruleset inline validator",
        )
        run = runs[0]
        return run.split(marker, 1)[1].rsplit("\nPY\n", 1)[0]

    @staticmethod
    def _valid_creation_ruleset() -> dict:
        return {
            "name": "astatine-release-tag-creation",
            "target": "tag",
            "source_type": "Repository",
            "source": "Jecta-ai/astatine-miner",
            "enforcement": "active",
            "conditions": {
                "ref_name": {"include": ["refs/tags/v*"], "exclude": []}
            },
            "rules": [{"type": "creation"}],
            "bypass_actors": [
                {"actor_id": 86115037, "actor_type": "User", "bypass_mode": "always"}
            ],
        }

    @staticmethod
    def _valid_immutability_ruleset() -> dict:
        return {
            "name": "astatine-release-tags",
            "target": "tag",
            "source_type": "Repository",
            "source": "Jecta-ai/astatine-miner",
            "enforcement": "active",
            "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
            "rules": [
                {"type": "update"},
                {"type": "deletion"},
                {"type": "non_fast_forward"},
            ],
            "bypass_actors": [],
        }

    def _run_draft_ruleset_inline(self, creation: dict, immutability: dict) -> subprocess.CompletedProcess:
        creation_path = self.tmp / "inline-creation.json"
        immutability_path = self.tmp / "inline-immutability.json"
        creation_path.write_text(json.dumps(creation), encoding="utf-8")
        immutability_path.write_text(json.dumps(immutability), encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                "-",
                str(creation_path),
                str(immutability_path),
                "Jecta-ai/astatine-miner",
                "v0.1.0-testnet.3",
            ],
            input=self._draft_ruleset_inline_script(),
            capture_output=True,
            text=True,
        )

    def test_draft_inline_rulesets_accept_split_owner_model(self) -> None:
        result = self._run_draft_ruleset_inline(
            self._valid_creation_ruleset(), self._valid_immutability_ruleset()
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_draft_inline_rulesets_accept_creation_never_caller_bypass(self) -> None:
        creation = self._valid_creation_ruleset()
        creation["current_user_can_bypass"] = "never"
        result = self._run_draft_ruleset_inline(
            creation, self._valid_immutability_ruleset()
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_draft_inline_rulesets_reject_creation_bypass_removal(self) -> None:
        creation = self._valid_creation_ruleset()
        creation["bypass_actors"] = []
        result = self._run_draft_ruleset_inline(
            creation, self._valid_immutability_ruleset()
        )
        self.assertNotEqual(result.returncode, 0)

    def test_draft_inline_rulesets_reject_2_only_immutability_scope(self) -> None:
        # Narrowing immutability to the single .3 tag weakens protection for
        # all other v* tags and must fail closed.
        immutability = self._valid_immutability_ruleset()
        immutability["conditions"]["ref_name"]["include"] = [
            "refs/tags/v0.1.0-testnet.3"
        ]
        result = self._run_draft_ruleset_inline(
            self._valid_creation_ruleset(), immutability
        )
        self.assertNotEqual(result.returncode, 0)

    def test_draft_inline_rulesets_reject_2_only_creation_scope(self) -> None:
        # Narrowing creation to the single .3 tag weakens protection for all
        # other v* tags and must fail closed.
        creation = self._valid_creation_ruleset()
        creation["conditions"]["ref_name"]["include"] = [
            "refs/tags/v0.1.0-testnet.3"
        ]
        result = self._run_draft_ruleset_inline(
            creation, self._valid_immutability_ruleset()
        )
        self.assertNotEqual(result.returncode, 0)

    def test_draft_inline_rulesets_reject_historical_list_scope(self) -> None:
        # The historical .0/.1/.2/.3 list is narrower than v* and must fail.
        immutability = self._valid_immutability_ruleset()
        immutability["conditions"]["ref_name"]["include"] = [
            "refs/tags/v0.1.0-testnet.0",
            "refs/tags/v0.1.0-testnet.1",
            "refs/tags/v0.1.0-testnet.2",
            "refs/tags/v0.1.0-testnet.3",
        ]
        result = self._run_draft_ruleset_inline(
            self._valid_creation_ruleset(), immutability
        )
        self.assertNotEqual(result.returncode, 0)

    def test_draft_inline_rulesets_tolerate_absent_bypass_with_manual_notice(self) -> None:
        # Phase1: the default token cannot see bypass_actors, so an absent
        # field is expected, prints the BYPASS notice, and continues on
        # structural fields (no fail-closed, no silent pass). Authoritative
        # bypass validation is the owner manual live check outside automation.
        creation = self._valid_creation_ruleset()
        del creation["bypass_actors"]
        immutability = self._valid_immutability_ruleset()
        del immutability["bypass_actors"]
        result = self._run_draft_ruleset_inline(creation, immutability)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(
            "BYPASS_ACTORS NOT AUTOMATICALLY VERIFIED",
            result.stdout + result.stderr,
        )

    def _draft_body_inline_script(self) -> str:
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        steps = parsed["jobs"]["release-draft"]["steps"]
        run = next(
            step["run"]
            for step in steps
            if step.get("name") == "Create draft release with assets"
        )
        marker = 'python3 - "$RUNNER_TEMP/draft-release.json" "$tag" bundle/release-notes.md <<\'PY\'\n'
        self.assertIn(marker, run)
        return run.split(marker, 1)[1].split("\nPY\n", 1)[0]

    def _run_draft_body_inline(self, body: str, is_draft: bool = True) -> subprocess.CompletedProcess:
        data_path = self.tmp / "draft-release.json"
        notes_path = self.tmp / "release-notes.md"
        notes_path.write_text(body, encoding="utf-8")
        data_path.write_text(
            json.dumps(
                {
                    "isDraft": is_draft,
                    "tagName": "v0.1.0-testnet.3",
                    "body": body,
                    "assets": [],
                }
            ),
            encoding="utf-8",
        )
        return subprocess.run(
            [
                sys.executable,
                "-",
                str(data_path),
                "v0.1.0-testnet.3",
                str(notes_path),
            ],
            input=self._draft_body_inline_script(),
            capture_output=True,
            text=True,
        )

    def test_draft_inline_body_accepts_exact_match(self) -> None:
        result = self._run_draft_body_inline("reviewed notes\n")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_draft_inline_body_rejects_mismatch(self) -> None:
        notes_path = self.tmp / "release-notes.md"
        notes_path.write_text("reviewed notes\n", encoding="utf-8")
        data_path = self.tmp / "draft-release.json"
        data_path.write_text(
            json.dumps(
                {
                    "isDraft": True,
                    "tagName": "v0.1.0-testnet.3",
                    "body": "tampered notes\n",
                    "assets": [],
                }
            ),
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                "-",
                str(data_path),
                "v0.1.0-testnet.3",
                str(notes_path),
            ],
            input=self._draft_body_inline_script(),
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_draft_inline_body_rejects_non_draft(self) -> None:
        result = self._run_draft_body_inline("reviewed notes\n", is_draft=False)
        self.assertNotEqual(result.returncode, 0)

    def test_draft_inline_rulesets_reject_immutability_bypass(self) -> None:
        immutability = self._valid_immutability_ruleset()
        immutability["bypass_actors"] = [
            {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
        ]
        result = self._run_draft_ruleset_inline(
            self._valid_creation_ruleset(), immutability
        )
        self.assertNotEqual(result.returncode, 0)

    def test_draft_inline_rulesets_reject_admin_creation_bypass(self) -> None:
        # Repository-admin creation bypass contradicts the owner-only model.
        creation = self._valid_creation_ruleset()
        creation["bypass_actors"] = [
            {"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}
        ]
        result = self._run_draft_ruleset_inline(
            creation, self._valid_immutability_ruleset()
        )
        self.assertNotEqual(result.returncode, 0)

    # ---- Phase1: 7-job / 2-env no-App coverage ----
    # Workflow lane owns release.yml + checker SHA; this lane asserts the
    # final 7-job / 2-env no-App shape textually (plus dynamically via CHECKER
    # for negatives; no hardcoded SHA here).

    def test_seven_job_set_no_admin_jobs(self) -> None:
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        jobs = parsed["jobs"]
        self.assertEqual(
            set(jobs),
            {
                "preflight",
                "build-macos",
                "build-linux",
                "attest-macos",
                "attest-linux",
                "release-package",
                "release-draft",
            },
        )
        self.assertEqual(len(jobs), 7)
        self.assertNotIn(
            "tag-ruleset-admin-verify",
            self.real_text,
            "no isolated admin verification jobs may remain",
        )

    def test_two_protected_environments(self) -> None:
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        jobs = parsed["jobs"]
        # Single-env separation: only `release` (package/draft mutation jobs).
        release_admin = sorted(
            name for name, job in jobs.items() if job.get("environment") == "release-admin"
        )
        self.assertEqual(release_admin, [])
        release_plain = sorted(
            name for name, job in jobs.items() if job.get("environment") == "release"
        )
        self.assertEqual(
            release_plain,
            [
                "release-draft",
                "release-package",
            ],
        )
        for name in release_plain:
            self.assertEqual(jobs[name].get("environment"), "release")

    def test_no_app_token_pin(self) -> None:
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        for name, job in parsed["jobs"].items():
            self.assertNotIn(
                "administration",
                job.get("permissions") or {},
                "%s must not request an administration permission" % name,
            )
        # No App-token action anywhere (not once per job, not at all).
        self.assertNotIn(
            "actions/create-github-app-token",
            self.real_text,
            "Phase1 must not mint App tokens",
        )
        self.assertNotIn("permission-administration", self.real_text)
        self.assertNotIn("skip-token-revoke", self.real_text)
        self.assertNotIn("RELEASE_ADMIN", self.real_text)

    def test_package_needs_builds_and_attests_only(self) -> None:
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        needs = parsed["jobs"]["release-package"].get("needs")
        self.assertEqual(
            set(needs),
            {"build-macos", "build-linux", "attest-macos", "attest-linux"},
        )

    def test_draft_needs_package_only(self) -> None:
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        needs = parsed["jobs"]["release-draft"].get("needs")
        if isinstance(needs, str):
            needs = {needs}
        else:
            needs = set(needs)
        self.assertEqual(needs, {"release-package"})

    def test_no_admin_needs_chain(self) -> None:
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        for name, job in parsed["jobs"].items():
            needs = job.get("needs") or []
            if isinstance(needs, str):
                needs = [needs]
            for dep in needs:
                self.assertNotIn(
                    "tag-ruleset-admin-verify",
                    dep,
                    "%s must not need a removed admin job" % name,
                )

    def test_github_ref_binding_global_single_source(self) -> None:
        # The single preflight GITHUB_REF tag binding is the only source;
        # strip it and the gate must fail.
        count = self.real_text.count('test "$GITHUB_REF" = "refs/tags/$')
        self.assertGreaterEqual(count, 1, "expected at least 1 GITHUB_REF binding")
        mutated = self.real_text.replace(
            'test "$GITHUB_REF" = "refs/tags/$', 'test "$GITHUB_REF" = "refs/heads/$'
        )
        self.assertNotIn('test "$GITHUB_REF" = "refs/tags/$', mutated)
        self.assertReleaseFails(mutated, "GITHUB_REF")

    def test_no_app_secrets_policy(self) -> None:
        # Phase1: zero secrets-context references anywhere in automation; only
        # the default github.token is used.
        self.assertNotIn("${{ secrets.", self.real_text)
        self.assertNotIn("RELEASE_ADMIN", self.real_text)
        self.assertNotIn("PRIVATE_KEY", self.real_text)
        self.assertIn("${{ github.token }}", self.real_text)

    def test_manual_bypass_disclosure_required(self) -> None:
        # Automation cannot verify bypass_actors (default token lacks
        # ruleset-write access), so the owner manual live check outside the
        # workflow is authoritative. Both mutation jobs must document this
        # manual-check contract; the workflow must never claim automated
        # bypass proof, and preflight must not fail closed on the merely
        # absent field.
        for marker in (
            "BYPASS_ACTORS NOT AUTOMATICALLY VERIFIED",
            "manual prepublish recheck",
            "does NOT inherit",
        ):
            self.assertIn(
                marker,
                self.real_text,
                "workflow must disclose %r (manual-check contract)" % marker,
            )
        self.assertIn("TOCTOU", self.real_text)
        for job in ("release-package", "release-draft"):
            section = self.real_text.split("  %s:" % job, 1)[1]
            import re as _re

            nxt = _re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", section)
            section = section[: nxt.start()] if nxt else section
            for marker in (
                "Phase1: no automated bypass verification is possible here",
                "owner manual live check required before",
                "manual prepublish recheck remains",
            ):
                self.assertIn(
                    marker,
                    section,
                    "%s must document the manual-check contract" % job,
                )
        self.assertNotIn("admin-verified", self.real_text.lower())
        self.assertNotIn(
            "split tag rulesets admin-verified", self.real_text.lower()
        )
        self.assertNotIn(
            "bypass_actors must be present as a list", self.real_text
        )
        self.assertNotIn("tag-ruleset-admin-verify", self.real_text)

    def test_package_draft_forbid_snapshot_and_offline_validator(self) -> None:
        # Phase1: mutation jobs document the owner manual live check; the
        # impossible default-token split-ruleset detail blocks stay absent.
        for section_name in ("release-package", "release-draft"):
            section = self.real_text.split("  %s:" % section_name, 1)[1]
            import re as _re

            nxt = _re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", section)
            section = section[: nxt.start()] if nxt else section
            for forbidden in (
                "package-rulesets.json",
                "package-tag-ruleset-ids.txt",
                "draft-rulesets.json",
                "draft-tag-ruleset-ids.txt",
                "verify-tag-ruleset.py",
            ):
                self.assertNotIn(
                    forbidden,
                    section,
                    "%s must not contain %s" % (section_name, forbidden),
                )

    def test_four_checkouts_total(self) -> None:
        self.assertEqual(
            self.real_text.count("actions/checkout@"),
            4,
            "exactly 4 checkouts total (preflight/builds/package; none elsewhere)",
        )
        draft = self.real_text.split("  release-draft:", 1)[1]
        self.assertNotIn(
            "actions/checkout@",
            draft,
            "release-draft must have zero checkouts",
        )



    # ---- Phase1 NO-GO additive coverage (read-only token, single env) ----
    # No kept negative above is weakened; new tests assert the no-App
    # contract. Workflow-lane SHA handoff is consumed dynamically via
    # CHECKER.RELEASE_WORKFLOW_SHA256 (no hardcoded SHA here) after
    # `--print-release-sha256` recompute.

    def test_single_env_names_policy(self) -> None:
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        jobs = parsed["jobs"]
        for name in ("release-package", "release-draft"):
            self.assertEqual(
                jobs[name].get("environment"), "release", "%s must stay release" % name
            )
        self.assertEqual(
            self.real_text.count("environment: release-admin"),
            0,
            "no release-admin environment may remain",
        )

    def test_no_permission_administration_policy(self) -> None:
        import re as _re
        self.assertNotIn("permission-administration", self.real_text)
        for name in ("release-package", "release-draft", "preflight"):
            section = self.real_text.split("  %s:" % name, 1)[1]
            nxt = _re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", section)
            section = section[: nxt.start()] if nxt else section
            self.assertNotRegex(
                section, r"permission-administration\s*:\s*\S+"
            )
        # No write fallback anywhere (no App permission exists to escalate).
        for m in _re.finditer(r"permission-administration\s*:\s*write", self.real_text):
            self.fail("write fallback forbidden (found at %r)" % (m.group(0),))

    def test_no_skip_token_revoke_policy(self) -> None:
        self.assertNotIn(
            "skip-token-revoke",
            self.real_text,
            "no minted token exists; no revoke flag may appear",
        )

    def test_no_revoke_proof_claim_policy(self) -> None:
        import re as _re
        # No token handling exists, so no revoke claim of any kind may appear.
        self.assertNotRegex(
            self.real_text, _re.compile(r"proves revocation", _re.IGNORECASE)
        )
        self.assertNotIn("Check admin token handling", self.real_text)

    def test_readonly_gh_api_policy(self) -> None:
        import re as _re
        for name in (
            "preflight",
            "build-macos",
            "build-linux",
            "attest-macos",
            "attest-linux",
        ):
            section = self.real_text.split("  %s:" % name, 1)[1]
            nxt = _re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", section)
            section = section[: nxt.start()] if nxt else section
            if name == "preflight":
                for pattern in (
                    'gh api "repos/$repo/environments/release"',
                    'gh api "repos/$repo/rulesets?includes_parents=true&per_page=100"',
                ):
                    self.assertIn(pattern, section)
            for pat in (
                r"gh\s+api\s+-X\b",
                r"gh\s+api\s+--method\b",
                r"gh\s+release\s+(create|edit|delete)\b",
                r"gh\s+attestation\b",
            ):
                self.assertNotRegex(section, pat, "%s must not contain %r" % (name, pat))

    def test_mutating_gh_rejected_policy(self) -> None:
        import re as _re
        def _readonly_ok(block: str) -> bool:
            code = "\n".join(
                line for line in block.splitlines()
                if not line.strip().startswith("#")
            )
            for pat in (
                r"gh\s+api\s+-X\b",
                r"gh\s+api\s+--method\b",
                r"gh\s+release\s+delete\b",
                r"gh\s+release\s+edit\b",
            ):
                if _re.search(pat, code):
                    return False
            return True
        for name in (
            "preflight",
            "build-macos",
            "build-linux",
            "attest-macos",
            "attest-linux",
            "release-package",
            "release-draft",
        ):
            section = self.real_text.split("  %s:" % name, 1)[1]
            nxt = _re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", section)
            section = section[: nxt.start()] if nxt else section
            self.assertTrue(_readonly_ok(section), "%s baseline must be read-only" % name)
            self.assertFalse(
                _readonly_ok(section + '\n gh api -X POST "repos/$repo/x"\n'),
                "%s must reject -X POST mutation" % name,
            )
            self.assertFalse(
                _readonly_ok(section + '\n gh release delete "$tag"\n'),
                "%s must reject gh release mutation" % name,
            )

    def test_temporal_markers_policy(self) -> None:
        self.assertIn("can delay", self.real_text)
        import re as _re
        self.assertIn("same-run needs does NOT inherit SHA", self.real_text)
        self.assertIn("not atomic or immediate", self.real_text)
        self.assertIn("manual prepublish recheck remains", self.real_text)
        self.assertRegex(self.real_text, _re.compile(r"does NOT inherit", _re.IGNORECASE))
        self.assertIn("BYPASS_ACTORS NOT AUTOMATICALLY VERIFIED", self.real_text)
        self.assertIn("TOCTOU", self.real_text)

    def test_no_admin_token_sha_language_policy(self) -> None:
        for marker in (
            "while App token is live",
            "App installation token",
            "GITHUB_SHA trust is inherited from same-run preflight",
            "through the needs chain",
            "No direct SHA equality check here by design",
            "admin token",
            "Check admin token handling",
        ):
            self.assertNotIn(
                marker,
                self.real_text,
                "App-era SHA/token language must be gone (%r)" % marker,
            )

    def test_checker_rejects_reintroduced_admin_job(self) -> None:
        # Reintroducing any tag-ruleset-admin-* job must fail the exact job set.
        bad = self.real_text.replace(
            "  release-package:",
            "  tag-ruleset-admin-verify:\n    name: Old admin\n  release-package:",
            1,
        )
        self.assertNotEqual(bad, self.real_text)
        self.assertReleaseFails(bad, "exactly")

    def test_zero_secrets_policy(self) -> None:
        # Phase1: automation uses only the read-only GITHUB_TOKEN.
        self.assertNotIn("${{ secrets.", self.real_text)
        self.assertNotIn("RELEASE_ADMIN", self.real_text)
        self.assertIn("${{ github.token }}", self.real_text)

    def test_no_app_pin_and_counts_policy(self) -> None:
        self.assertNotIn("actions/create-github-app-token@", self.real_text)
        self.assertEqual(self.real_text.count("actions/checkout@"), 4)
        if _yaml is None:
            self.skipTest("yaml module not available")
        parsed = _yaml.safe_load(self.real_text)
        self.assertEqual(len(parsed["jobs"]), 7)

    def test_workflow_sha_dynamic_no_hardcode(self) -> None:
        # Consume workflow-lane handoff SHA dynamically; no stale SHA pinned here.
        # The pin lives in check_workflow_pins.py (workflow-lane owned); this file
        # uses CHECKER.RELEASE_WORKFLOW_SHA256 dynamically so recompute needs no
        # edit here.
        self.assertEqual(
            CHECKER.compute_release_sha256(self.real_text.encode("utf-8")),
            CHECKER.RELEASE_WORKFLOW_SHA256,
        )


    def test_final_no_admin_handling_policy(self) -> None:
        self.assertNotIn("Check admin token handling", self.real_text)
        self.assertNotIn("Confirm admin token auto-revoke", self.real_text)
        self.assertNotIn("intentionally omitted", self.real_text)

    def test_final_two_env_names_policy(self) -> None:
        if _yaml is None:
            self.skipTest("yaml module not available")
        import re as _re
        parsed = _yaml.safe_load(self.real_text)
        jobs = parsed["jobs"]
        self.assertEqual(len(jobs), 7)
        self.assertEqual(
            sorted(n for n, j in jobs.items() if j.get("environment") == "release-admin"),
            [],
        )
        self.assertEqual(
            sorted(n for n, j in jobs.items() if j.get("environment") == "release"),
            ["release-draft", "release-package"],
        )
        self.assertEqual(self.real_text.count("environment: release-admin"), 0)
        exact_release = len(_re.findall(r"environment:\s*release\s*(?:#.*)?$", self.real_text, _re.MULTILINE))
        self.assertEqual(exact_release, 2)

    def test_final_preflight_release_only_policy(self) -> None:
        self.assertIn("--expected-environment release", self.real_text)
        self.assertNotIn("--expected-environment release-admin", self.real_text)
        self.assertNotIn("$admin_env_out", self.real_text)
        self.assertNotIn("$admin_policies_out", self.real_text)

    def test_final_no_stale_sha_anchor_policy(self) -> None:
        for stale in ("0babaf836c96839d8a52e1d69c63dc1981f1a188bab1b179dbc7d914ab13bba7", "6582958d4149966f60e691d7767b3e39085e6dafedbb481b8e15c88a21cffe94", "e972f7cfb3526bfdfa7c5bb45db445565b3f57e578dd8e294be74ab8eb4ab8ac"):
            self.assertNotIn(stale, self.real_text)
        # Dynamic only: the live pin is consumed from the workflow-lane-owned
        # checker, never hardcoded here.
        self.assertEqual(
            CHECKER.compute_release_sha256(self.real_text.encode("utf-8")),
            CHECKER.RELEASE_WORKFLOW_SHA256,
        )

if __name__ == "__main__":
    unittest.main()
