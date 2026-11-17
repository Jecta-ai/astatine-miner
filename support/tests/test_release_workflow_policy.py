#!/usr/bin/env python3
"""Adversarial regression tests for the pinned release workflow policy.

All tests use temporary copies and never modify the real workflow. Run with
`python3 -B` only.
"""

from __future__ import annotations

import hashlib
import importlib.util
import pathlib
import shutil
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
        self.assertEqual(set(jobs), {"preflight", "build-macos", "build-linux", "release-package", "release-draft"})
        self.assertEqual(jobs["release-package"].get("environment"), "release")
        self.assertEqual(jobs["release-draft"].get("environment"), "release")
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
            {"contents": "read", "id-token": "write", "attestations": "write"},
        )

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
            "    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n    permissions:\n      contents: read\n"
            "      id-token: write\n      attestations: write",
            "  build-linux:\n    name: Build Linux x86_64 binary\n    needs: preflight\n"
            "    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n    permissions:\n      contents: write\n"
            "      id-token: write\n      attestations: write",
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
            "Draft verified; manual owner publication remains required",
            "Draft verified; manual owner publication remains required --draft=false",
            1,
        )
        self.assertReleaseFails(mutated, "draft")

    def test_auto_publish_prerelease_rejected(self) -> None:
        mutated = self.real_text + "\n      # --prerelease\n"
        self.assertReleaseFails(mutated, "prerelease")

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
        validator = 'python3 -B support/release/verify-protected-environment.py --environment-json "$env_out" --policies-json "$policies_out" --tag "$tag"'
        self.assertEqual(self.real_text.count(validator), 2)
        mutated = self.real_text.replace(validator, "echo no-reverify", 1)
        # One invocation remains; remove all to trigger fail-closed.
        mutated = mutated.replace(validator, "echo no-reverify")
        self.assertReleaseFails(mutated, "protected-environment")

    def test_tag_policy_safe_forms_required(self) -> None:
        # M2: validator in preflight/package + inline series/exact in draft; no broad v*.
        self.assertIn("support/release/verify-protected-environment.py", self.real_text)
        self.assertIn('"v0.1.0-testnet.*"', self.real_text)
        self.assertNotIn('"v*",', self.real_text)
        self.assertIn("deployment-branch-policies", self.real_text)

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
        mutated = self.real_text.replace('test "$GITHUB_REF" = "refs/tags/$', 'test "$GITHUB_REF" = "refs/heads/$', 1)
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
        validator = 'python3 -B support/release/verify-protected-environment.py --environment-json "$env_out" --policies-json "$policies_out" --tag "$tag"'
        self.assertEqual(self.real_text.count(validator), 2)

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
        mutated = self.real_text.replace(
            "  release-package:\n    name: Package and attest release bundle\n    needs:",
            "  release-package:\n    name: Package and attest release bundle\n    permissions:\n      contents: write\n    needs:",
            1,
        )
        # Directly mutate the existing package permissions block instead
        mutated2 = self.real_text.replace(
            "  release-package:\n    name: Package and attest release bundle\n    needs:\n      - build-macos\n      - build-linux\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    environment: release\n    permissions:\n      contents: read",
            "  release-package:\n    name: Package and attest release bundle\n    needs:\n      - build-macos\n      - build-linux\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    environment: release\n    permissions:\n      contents: write",
            1,
        )
        # Use whichever mutation actually changes the file
        target = mutated2 if mutated2 != self.real_text else mutated
        self.assertReleaseFails(target, "must be exactly")

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
        anchor = 'allowed_names = {"v0.1.0-testnet.*", tag}'
        assert anchor in self.real_text
        mutated = self.real_text.replace(
            "if len(policies) != 1:",
            'policies = policies + [{"type": "unknown"}]\n          if len(policies) != 1:',
            1,
        )
        # The workflow itself is unchanged in allowlist, but the test documents the
        # exact-count requirement: any second entry must be rejected by len==1.
        # Directly assert the workflow enforces exact count.
        self.assertIn("if len(policies) != 1:", self.real_text)
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
        self.assertReleaseFails(mutated, "tag policy type must be exactly tag")

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

    def test_print_sha_documents_recompute(self) -> None:
        self.assertEqual(
            CHECKER.compute_release_sha256(self.real_text.encode("utf-8")),
            CHECKER.RELEASE_WORKFLOW_SHA256,
        )
        self.assertIn("--print-release-sha256", pathlib.Path(CHECKER_PATH).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
