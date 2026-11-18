#!/usr/bin/env python3
"""Release-intent v3 tests for support/verify-distribution-inventory.py and gate.py.

The original 49 blocked-state tests remain unchanged in
``test_distribution_inventory.py`` against frozen blocked fixtures; this file
is additive and does not replace them.

Copies the real release-intent inventory/provenance plus license evidence into
a temporary directory and mutates only that copy. Blocked-state regression uses
a synthetic blocked-shaped copy built from the gate's retained blocked
constants. No test touches the real tree, network, wallet, or build. Run with
``python3 -B`` so no ``__pycache__`` directories are written.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = Path(
    os.environ.get(
        "ASTATINE_DISTRIBUTION_VERIFIER_PATH",
        str(SOURCE_ROOT / "support" / "verify-distribution-inventory.py"),
    )
).resolve()
GATE_PATH = SOURCE_ROOT / "support" / "release" / "gate.py"
INVENTORY_REL = Path("support/release/distribution-inventory.json")
PROVENANCE_REL = Path("tests/fixtures/PROVENANCE.json")
NEEDED_FILES = [
    "support/release/distribution-inventory.json",
    "tests/fixtures/PROVENANCE.json",
    "tests/fixtures/README.md",
    "tests/fixtures/LICENSE-APACHE-2.0.txt",
    "tests/fixtures/LICENSE-MIT.txt",
    "tests/fixtures/NOTICE",
    "tests/fixtures/OPENZEPPELIN_LICENSE.txt",
    "Cargo.toml",
    "support/release-repository.txt",
    "support/update-evm-test-fixtures.py",
    "support/update-genesis-coordinator-fixture.py",
    "support/release/RELEASE_NOTES-v0.1.0-testnet.1.md",
    "support/release/RELEASE_NOTES-v0.1.0-testnet.2.md",
    "support/release/RELEASE_NOTES-v0.1.0-testnet.4.md",
]


def load_verifier():
    spec = importlib.util.spec_from_file_location(
        "distribution_inventory_verifier", VERIFIER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load distribution inventory verifier module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_gate():
    spec = importlib.util.spec_from_file_location("astatine_gate", GATE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load gate module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = load_verifier()
GATE = load_gate()


class DistributionInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="astatine-dist-inventory-")
        self.root = Path(self.tempdir.name)
        for relative in NEEDED_FILES:
            src = SOURCE_ROOT / relative
            if not src.is_file():
                continue
            dest = self.root / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def inventory(self) -> dict:
        return json.loads((self.root / INVENTORY_REL).read_text(encoding="utf-8"))

    def write_inventory(self, inventory: dict) -> None:
        (self.root / INVENTORY_REL).write_text(
            json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    def provenance(self) -> dict:
        return json.loads((self.root / PROVENANCE_REL).read_text(encoding="utf-8"))

    def write_provenance(self, provenance: dict) -> None:
        (self.root / PROVENANCE_REL).write_text(
            json.dumps(provenance, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    def test_real_release_intent_inventory_passes(self) -> None:
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["schema"], "astatine-distribution-inventory/v3")
        self.assertTrue(result["release_intent_authorized"])
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["final_release_controls_complete"])
        self.assertEqual(result["source_distribution"], "RELEASE-INTENT-AUTHORIZED")
        self.assertEqual(result["binary_distribution"], "RELEASE-INTENT-AUTHORIZED")
        self.assertEqual(
            result["rights_decision"],
            "OWNER-AUTHORIZED RELEASE INTENT \u2014 project owner authorized first-party "
            "source and binary distribution intent for v0.1.0-testnet.4 under the "
            "explicitly documented owner self-approval policy; technical NOTICE review "
            "recorded; final release controls outstanding; not a legal conclusion, not "
            "independent review, and not a separate approval.",
        )
        self.assertEqual(
            result["notice_applicability"],
            "TECHNICALLY REVIEWED \u2014 no separate upstream NOTICE file was found in "
            "the pinned contract fixture subtrees; the private EVM root NOTICE is "
            "scoped to a separate Rust subtree; Apache-2.0 license text and fixture "
            "NOTICE are included. This is an evidence-based technical review, not a "
            "legal conclusion or separate approval.",
        )
        self.assertEqual(result["blocking_open"], [])
        self.assertEqual(
            result["notice_checklist_status"],
            "TECHNICAL REVIEW RECORDED \u2014 owner-authorized release intent under the "
            "explicit owner self-approval policy; final release controls outstanding",
        )
        self.assertEqual(
            result["release_intent_authorization"],
            "OWNER-AUTHORIZED RELEASE INTENT \u2014 FINAL CONTROLS OUTSTANDING \u2014 OWNER SELF-APPROVAL",
        )
        self.assertIn(
            "repository technical review", result["technical_notice_review"].lower()
        )
        self.assertEqual(
            result["review_ci_branch_push_authorization"],
            "SUPERSEDED \u2014 OWNER-AUTHORIZED RELEASE INTENT",
        )
        self.assertEqual(
            result["release_controls"],
            "DRAFT-ONLY \u2014 OWNER SELF-APPROVAL AFTER IMMUTABLE TAG/RELEASE VERIFICATION",
        )
        self.assertEqual(result["archive_members_checked"], 6)
        self.assertEqual(result["source_members_checked"], 4)
        self.assertEqual(result["generated_members_checked"], 2)
        self.assertEqual(result["fixture_paths_checked"], 4)
        self.assertEqual(result["targets"], ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"])
        self.assertIn("does NOT authorize final publication", result["disclaimer"])
        self.assertNotIn("publication_authorized\": true", json.dumps(result))

    def test_gate_load_release_intent_shape(self) -> None:
        gate = GATE.load_gate(self.root)
        self.assertEqual(gate["state"], "release-intent-authorized")
        self.assertTrue(gate["release_intent_authorized"])
        self.assertFalse(gate["publication_authorized"])
        self.assertFalse(gate["final_release_controls_complete"])
        self.assertEqual(gate["source_status"], "RELEASE-INTENT-AUTHORIZED")
        self.assertEqual(gate["binary_status"], "RELEASE-INTENT-AUTHORIZED")
        self.assertEqual(gate["targets"], ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc"])
        self.assertEqual(gate["repository"], "Jecta-ai/astatine-miner")
        self.assertTrue(gate["package_version"])
        for key in (
            "rights_decision",
            "notice_applicability",
            "release_intent_authorization",
            "technical_notice_review",
            "release_controls",
            "archive_members",
            "generated_members",
            "forbidden_globs",
            "fixture_paths",
        ):
            self.assertIn(key, gate)

    def test_old_publication_decision_key_rejected(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["publication_decision"] = "AUTHORIZED by data edit"
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_old_publication_authorization_key_rejected(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["publication_authorization"] = {"status": "AUTHORIZED"}
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_old_publication_keys_in_provenance_rejected(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["publication_decision"] = "AUTHORIZED by data edit"
        self.write_provenance(provenance)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_invented_release_approver_rejected(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["release_intent_authorization"]["authorized_by"] = (
            "project owner and release approver"
        )
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_approval_roles_tamper_rejected(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["release_intent_authorization"]["approval_roles"] = (
            "Project owner and a separately appointed release approver."
        )
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_legal_conclusion_claim_rejected(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["release_intent_authorization"]["technical_notice_review"][
            "legal_conclusion"
        ] = True
        self.write_provenance(provenance)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_separate_approval_claim_rejected(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["release_intent_authorization"]["technical_notice_review"][
            "separate_approval"
        ] = True
        self.write_provenance(provenance)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_final_controls_true_in_authorization_rejected(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["release_intent_authorization"]["final_release_controls_complete"] = True
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_final_controls_true_in_source_rejected(self) -> None:
        inventory = self.inventory()
        inventory["source_distribution"]["final_release_controls_complete"] = True
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_final_controls_true_in_release_controls_rejected(self) -> None:
        inventory = self.inventory()
        inventory["release_controls"]["final_release_controls_complete"] = True
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_missing_citations_rejected(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["release_intent_authorization"]["technical_notice_review"][
            "citations"
        ] = []
        self.write_provenance(provenance)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_deleted_citations_rejected(self) -> None:
        provenance = self.provenance()
        del provenance["rights_review"]["release_intent_authorization"]["technical_notice_review"][
            "citations"
        ]
        self.write_provenance(provenance)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_data_only_rights_decision_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["rights_decision"] = "AUTHORIZED by data edit"
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_data_only_rule_weakening_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["rule"] = "Distribution is allowed."
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_missing_evidence_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["release_intent_authorization"]["evidence"] = []
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_missing_license_file_fails(self) -> None:
        (self.root / "tests/fixtures/LICENSE-APACHE-2.0.txt").unlink()
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_renamed_license_file_fails(self) -> None:
        # Point a fixture license_text at a non-authorized path.
        provenance = self.provenance()
        provenance["fixtures"][0]["license"]["license_text"] = "tests/fixtures/MISSING.txt"
        self.write_provenance(provenance)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_changed_license_hash_fails(self) -> None:
        (self.root / "tests/fixtures/NOTICE").write_text("tampered notice\n", encoding="utf-8")
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_fixture_marked_as_archive_member_fails(self) -> None:
        provenance = self.provenance()
        provenance["fixtures"][0]["release_archive_member"] = True
        self.write_provenance(provenance)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "must not be a release archive member"):
            VERIFIER.verify(self.root)

    def test_fixture_injected_into_archive_members_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["archive_members"].append(
            {"source": "tests/fixtures/AstatineMiner.json", "archive_path": "AstatineMiner.json", "required": True}
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "fixture|allowlist|archive_members changed"):
            VERIFIER.verify(self.root)

    def test_forbidden_glob_removal_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["forbidden_globs"] = ["tests/fixtures/**"]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "forbidden glob"):
            VERIFIER.verify(self.root)

    def test_forbidden_glob_member_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["generated_members"][0]["archive_path"] = "tests/fixtures/BUILD-INFO.json"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "forbidden glob"):
            VERIFIER.verify(self.root)

    def test_wrong_targets_fail(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["targets"] = ["x86_64-unknown-linux-gnu"]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "targets changed"):
            VERIFIER.verify(self.root)

    def test_wrong_allowlist_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["archive_members"] = [
            {"source": "target/release/astatine", "archive_path": "astatine", "required": True},
            {"source": "LICENSE-MIT", "archive_path": "LICENSE-MIT", "required": True},
        ]
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_wrong_generator_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["generated_members"][0]["generator"] = "support/release/build-dry-run.py"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "generated_members changed"):
            VERIFIER.verify(self.root)

    def test_weakened_release_controls_fail(self) -> None:
        inventory = self.inventory()
        inventory["release_controls"]["environment_required_reviewer"] = False
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_weakened_tag_policy_fails(self) -> None:
        inventory = self.inventory()
        inventory["release_controls"]["tag_policy"] = "refs/tags/*"
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_draft_only_release_controls_present(self) -> None:
        gate = GATE.load_gate(self.root)
        controls = gate["release_controls"]
        self.assertEqual(
            controls["status"],
            "DRAFT-ONLY \u2014 OWNER SELF-APPROVAL AFTER IMMUTABLE TAG/RELEASE VERIFICATION",
        )
        self.assertEqual(controls["publication_mode"], "draft-only-manual-publish")
        self.assertTrue(controls["manual_publish_required"])
        self.assertTrue(controls["immutable_setting_admin_verification_required"])
        self.assertTrue(controls["immutable_release"])
        self.assertIn(
            "repository writers and write-capable apps are restricted so only the release owner/admin can publish or modify the draft",
            controls["external_blockers"],
        )

    def test_weakened_publication_mode_fails(self) -> None:
        inventory = self.inventory()
        inventory["release_controls"]["publication_mode"] = "auto-publish"
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_weakened_manual_publish_fails(self) -> None:
        inventory = self.inventory()
        inventory["release_controls"]["manual_publish_required"] = False
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_weakened_immutable_admin_verification_fails(self) -> None:
        inventory = self.inventory()
        inventory["release_controls"]["immutable_setting_admin_verification_required"] = False
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_blocked_state_regression(self) -> None:
        # Synthetic blocked-shaped copy must still verify as blocked with the
        # old fail-closed reporting.
        with tempfile.TemporaryDirectory(prefix="astatine-dist-blocked-") as tmp:
            root = Path(tmp)
            self._write_blocked_tree(root)
            result = VERIFIER.verify(root)
            self.assertEqual(result["status"], "PASS")
            self.assertFalse(result["publication_authorized"])
            self.assertEqual(result["source_distribution"], "BLOCKED")
            self.assertEqual(result["binary_distribution"], "BLOCKED")
            self.assertEqual(result["blocking_open"], ["RIGHTS-02", "RIGHTS-03", "RIGHTS-04", "RIGHTS-05"])
            self.assertEqual(result["archive_members_checked"], 5)
            gate = GATE.load_gate(root)
            self.assertEqual(gate["state"], "blocked")
            self.assertFalse(gate["publication_authorized"])

    def _write_blocked_tree(self, root: Path) -> None:
        push_auth = dict(GATE.BLOCKED_REVIEW_PUSH_AUTH)
        inventory = {
            "schema": "astatine-distribution-inventory/v1",
            "scope": "test blocked scope",
            "rights_gate": {
                "source": "tests/fixtures/PROVENANCE.json",
                "publication_decision": GATE.BLOCKED_PUBLICATION_DECISION,
                "notice_applicability": GATE.BLOCKED_NOTICE_APPLICABILITY,
                "blocking_open": list(GATE.BLOCKED_BLOCKING_OPEN),
                "fail_closed": True,
                "rule": "test blocked rule",
                "review_ci_branch_push_authorization": push_auth,
            },
            "source_distribution": {"status": "BLOCKED", "reason": "test blocked"},
            "binary_distribution": {
                "status": "BLOCKED",
                "reason": "test blocked",
                "target": "x86_64-unknown-linux-gnu",
                "archive_members": [
                    {"source": "target/release/astatine", "archive_path": "astatine", "required": True},
                    {"source": "LICENSE-MIT", "archive_path": "LICENSE-MIT", "required": True},
                    {"source": "THIRD_PARTY_LICENSES.md", "archive_path": "THIRD_PARTY_LICENSES.md", "required": True},
                ],
                "generated_members": [
                    {"archive_path": "BUILD-INFO.json", "generator": "support/release/build-dry-run.py", "required": True},
                    {"archive_path": "INSTALL.md", "generator": "support/release/build-dry-run.py", "required": True},
                ],
                "forbidden_globs": ["tests/fixtures/**", "**/PROVENANCE.json"],
                "fixture_paths": [
                    "tests/fixtures/AstatineMiner.json",
                    "tests/fixtures/AstatineGenesisCoordinator.json",
                    "tests/fixtures/MockAST.json",
                    "tests/fixtures/synthetic-injective-virtual-receipt.json",
                ],
            },
        }
        items = [
            {
                "id": "RIGHTS-01",
                "action": "Record the project owner's confirmation of first-party ownership of AstatineMiner and AstatineGenesisCoordinator.",
                "owner": "project owner",
                "status": "DONE",
                "blocking": True,
                "evidence": "test evidence",
            }
        ]
        for blocker in GATE.BLOCKED_BLOCKING_OPEN:
            detail = GATE.BLOCKED_BLOCKER_DETAILS[blocker]
            items.append(
                {
                    "id": blocker,
                    "action": detail["action"],
                    "owner": detail["owner"],
                    "status": "OPEN",
                    "blocking": True,
                    "evidence": detail["evidence"],
                }
            )
        provenance = {
            "schema": "astatine-fixture-provenance/v1",
            "rights_review": {
                "publication_decision": GATE.BLOCKED_PUBLICATION_DECISION,
                "notice_applicability": GATE.BLOCKED_NOTICE_APPLICABILITY,
                "rights_holder_authority": GATE.ATTESTED_RIGHTS,
                "owner_attestation": {"status": GATE.ATTESTED_RIGHTS, "independent_verification": False},
                "notice_checklist": {"status": GATE.BLOCKED_CHECKLIST_STATUS, "scope": "test", "items": items},
                "review_ci_branch_push_authorization": push_auth,
            },
            "fixtures": [
                {"path": p, "release_archive_member": False}
                for p in [
                    "tests/fixtures/AstatineMiner.json",
                    "tests/fixtures/AstatineGenesisCoordinator.json",
                    "tests/fixtures/MockAST.json",
                    "tests/fixtures/synthetic-injective-virtual-receipt.json",
                ]
            ],
        }
        (root / "support/release").mkdir(parents=True, exist_ok=True)
        (root / "support/release/distribution-inventory.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
        (root / "tests/fixtures").mkdir(parents=True, exist_ok=True)
        (root / "tests/fixtures/PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
        for rel in ("Cargo.toml", "support/release-repository.txt"):
            src = SOURCE_ROOT / rel
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

    def test_historical_release_intent_rewrite_rejected(self) -> None:
        inventory = self.inventory()
        inventory["historical_release_intent"]["tag"] = "v0.1.0-testnet.4"
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_historical_release_intent_omission_rejected(self) -> None:
        inventory = self.inventory()
        del inventory["historical_release_intent"]
        self.write_inventory(inventory)
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_cli_failure_returns_structured_json(self) -> None:
        import contextlib
        import io
        from unittest import mock

        inventory = self.inventory()
        inventory["rights_gate"]["rights_decision"] = "RELEASE-INTENT by data edit"
        self.write_inventory(inventory)
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["verify-distribution-inventory.py", str(self.root)]):
            with contextlib.redirect_stderr(stderr):
                return_code = VERIFIER.main()
        self.assertEqual(return_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
