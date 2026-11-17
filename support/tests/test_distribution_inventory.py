#!/usr/bin/env python3
"""Safe offline tests for support/verify-distribution-inventory.py.

These are the original 49 blocked-state regression tests, retained unchanged in
behavior. They copy frozen blocked v1 inventory/provenance fixtures into a
temporary directory and mutate only that copy; the authorized v3 state is
covered separately in test_distribution_inventory_authorized.py. They never touch the real
source tree, network, wallet, build, or production runtime. Run with
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
INVENTORY_REL = Path("support/release/distribution-inventory.json")
PROVENANCE_REL = Path("tests/fixtures/PROVENANCE.json")
BLOCKED_ROOT = Path(__file__).resolve().parent / "fixtures" / "blocked-gate"

EXPECTED_BLOCKING_OPEN = ["RIGHTS-02", "RIGHTS-03", "RIGHTS-04", "RIGHTS-05"]


def load_verifier():
    spec = importlib.util.spec_from_file_location(
        "distribution_inventory_verifier", VERIFIER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load distribution inventory verifier module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = load_verifier()


class DistributionInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="astatine-dist-inventory-")
        self.root = Path(self.tempdir.name)
        for relative in (INVENTORY_REL, PROVENANCE_REL):
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(BLOCKED_ROOT / relative.name, destination)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def inventory(self) -> dict:
        return json.loads((self.root / INVENTORY_REL).read_text(encoding="utf-8"))

    def write_inventory(self, inventory: dict) -> None:
        (self.root / INVENTORY_REL).write_text(
            json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
        )

    def provenance(self) -> dict:
        return json.loads((self.root / PROVENANCE_REL).read_text(encoding="utf-8"))

    def write_provenance(self, provenance: dict) -> None:
        (self.root / PROVENANCE_REL).write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )

    def test_real_inventory_passes(self) -> None:
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertFalse(result["publication_authorized"])
        self.assertEqual(result["source_distribution"], "BLOCKED")
        self.assertEqual(result["binary_distribution"], "BLOCKED")
        self.assertEqual(result["notice_applicability"], "UNRESOLVED")
        self.assertEqual(result["blocking_open"], EXPECTED_BLOCKING_OPEN)
        self.assertEqual(result["archive_members_checked"], 5)
        self.assertEqual(result["source_members_checked"], 3)
        self.assertEqual(result["generated_members_checked"], 2)
        self.assertEqual(
            result["review_ci_branch_push_authorization"],
            "AUTHORIZED \u2014 REVIEW/CI ONLY",
        )
        self.assertEqual(result["fixture_paths_checked"], 4)
        self.assertIn("does NOT authorize publication", result["disclaimer"])
        self.assertIn("reviewed code", result["disclaimer"])

    def test_all_existing_blockers_stay_open(self) -> None:
        inventory = self.inventory()
        self.assertEqual(inventory["rights_gate"]["blocking_open"], EXPECTED_BLOCKING_OPEN)
        provenance = self.provenance()
        items = {
            item["id"]: item
            for item in provenance["rights_review"]["notice_checklist"]["items"]
        }
        for blocker in EXPECTED_BLOCKING_OPEN:
            self.assertIn(blocker, items)
            self.assertEqual(items[blocker]["status"], "OPEN")
            self.assertTrue(items[blocker]["blocking"])
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")

    def test_fixture_injected_into_archive_members_fails(self) -> None:
        inventory = self.inventory()
        members = inventory["binary_distribution"]["archive_members"]
        members.append(
            {
                "source": "tests/fixtures/AstatineMiner.json",
                "archive_path": "AstatineMiner.json",
                "required": True,
            }
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "allows a fixture into the release archive"
        ):
            VERIFIER.verify(self.root)

    def test_provenance_path_as_archive_member_fails(self) -> None:
        inventory = self.inventory()
        members = inventory["binary_distribution"]["archive_members"]
        members.append(
            {
                "source": "tests/fixtures/PROVENANCE.json",
                "archive_path": "PROVENANCE.json",
                "required": True,
            }
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "release archive"
        ):
            VERIFIER.verify(self.root)

    def test_generated_members_match_ordered_contract(self) -> None:
        inventory = self.inventory()
        generated = inventory["binary_distribution"]["generated_members"]
        self.assertEqual(
            [(entry["archive_path"], entry["generator"]) for entry in generated],
            [
                ("BUILD-INFO.json", "support/release/build-dry-run.py"),
                ("INSTALL.md", "support/release/build-dry-run.py"),
            ],
        )
        self.assertTrue(all(entry["required"] is True for entry in generated))

    def test_remove_generated_member_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["generated_members"] = [
            entry
            for entry in inventory["binary_distribution"]["generated_members"]
            if entry["archive_path"] != "INSTALL.md"
        ]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "generated_members changed"
        ):
            VERIFIER.verify(self.root)

    def test_rename_generated_member_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["generated_members"][0]["archive_path"] = (
            "BUILD-INFO-v2.json"
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "generated_members changed"
        ):
            VERIFIER.verify(self.root)

    def test_inject_generated_member_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["generated_members"].append(
            {
                "archive_path": "EXTRA.md",
                "generator": "support/release/build-dry-run.py",
                "required": True,
            }
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "generated_members changed"
        ):
            VERIFIER.verify(self.root)

    def test_generated_member_fixture_glob_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["generated_members"][0]["archive_path"] = (
            "tests/fixtures/BUILD-INFO.json"
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "forbidden glob into the release archive"
        ):
            VERIFIER.verify(self.root)

    def test_generated_member_provenance_glob_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["generated_members"][1]["archive_path"] = (
            "docs/PROVENANCE.json"
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "forbidden glob into the release archive"
        ):
            VERIFIER.verify(self.root)

    def test_generated_member_duplicate_fails(self) -> None:
        inventory = self.inventory()
        generated = inventory["binary_distribution"]["generated_members"]
        generated.append(dict(generated[0]))
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "duplicate generated member"
        ):
            VERIFIER.verify(self.root)

    def test_generated_member_overlap_with_source_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["generated_members"][0]["archive_path"] = (
            "astatine"
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "overlaps a source archive member path"
        ):
            VERIFIER.verify(self.root)

    def test_generated_member_required_false_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["generated_members"][1]["required"] = False
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "required must be true"
        ):
            VERIFIER.verify(self.root)

    def test_generated_member_generator_change_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["generated_members"][0]["generator"] = (
            "support/release/other-script.py"
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "generator changed"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_copy_status_release_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_gate"]["review_ci_branch_push_authorization"]
        auth["status"] = "AUTHORIZED \u2014 RELEASE"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "push authorization changed"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_copy_date_change_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_gate"]["review_ci_branch_push_authorization"]
        auth["authorized_on"] = "2026-11-17"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "push authorization changed"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_copy_scope_change_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_gate"]["review_ci_branch_push_authorization"]
        auth["scope"] = "Push the branch for review, CI and release."
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "push authorization changed"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_copy_blocked_item_removed_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_gate"]["review_ci_branch_push_authorization"]
        auth["not_authorized"].remove("workflow attestation dispatch")
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "push authorization changed"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_copy_gate_statement_change_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_gate"]["review_ci_branch_push_authorization"]
        auth["rights_gate_unchanged"] = "Gate resolved; distribution allowed."
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "push authorization changed"
        ):
            VERIFIER.verify(self.root)

    def test_removing_fixture_forbidden_glob_fails(self) -> None:
        inventory = self.inventory()
        globs = inventory["binary_distribution"]["forbidden_globs"]
        globs.remove("tests/fixtures/**")
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "missing required forbidden glob"
        ):
            VERIFIER.verify(self.root)

    def test_removing_provenance_forbidden_glob_fails(self) -> None:
        inventory = self.inventory()
        globs = inventory["binary_distribution"]["forbidden_globs"]
        globs.remove("**/PROVENANCE.json")
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "missing required forbidden glob"
        ):
            VERIFIER.verify(self.root)

    def test_changing_gate_decision_to_allowed_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["publication_decision"] = "APPROVED for release"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "does not match tests/fixtures/PROVENANCE.json"
        ):
            VERIFIER.verify(self.root)

    def test_changing_gate_decision_text_mismatch_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["publication_decision"] = (
            "BLOCKED for a different recorded reason"
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "does not match tests/fixtures/PROVENANCE.json"
        ):
            VERIFIER.verify(self.root)

    def test_provenance_gate_must_stay_blocked(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["publication_decision"] = "APPROVED for release"
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "publication decision changed"
        ):
            VERIFIER.verify(self.root)

    def test_decision_blocked_but_approved_fails(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["publication_decision"] = "BLOCKED but approved"
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "publication decision changed"
        ):
            VERIFIER.verify(self.root)

    def test_notice_applicability_must_stay_unresolved(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["notice_applicability"] = "RESOLVED"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "does not match tests/fixtures/PROVENANCE.json"
        ):
            VERIFIER.verify(self.root)

    def test_provenance_notice_change_fails(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["notice_applicability"] = "RESOLVED"
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "NOTICE applicability must remain UNRESOLVED"
        ):
            VERIFIER.verify(self.root)

    def test_pass_reports_attestation_and_checklist_gate(self) -> None:
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(
            result["rights_holder_authority"],
            "OWNER-ATTESTED \u2014 not independently verified",
        )
        self.assertEqual(
            result["owner_attestation_status"],
            "OWNER-ATTESTED \u2014 not independently verified",
        )
        self.assertFalse(result["owner_attestation_independent_verification"])
        self.assertEqual(
            result["notice_checklist_status"], "OPEN \u2014 publication remains BLOCKED"
        )

    def test_rights_holder_authority_change_fails(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["rights_holder_authority"] = "ESTABLISHED"
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "rights status must remain honest"
        ):
            VERIFIER.verify(self.root)

    def test_owner_attestation_independently_verified_fails(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["owner_attestation"]["independent_verification"] = True
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "must not be represented as independent verification",
        ):
            VERIFIER.verify(self.root)

    def test_owner_attestation_status_change_fails(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["owner_attestation"]["status"] = (
            "INDEPENDENTLY VERIFIED"
        )
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "owner attestation status must remain honest"
        ):
            VERIFIER.verify(self.root)

    def test_checklist_status_closed_fails(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["notice_checklist"]["status"] = (
            "CLOSED \u2014 publication approved"
        )
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "notice checklist status changed"
        ):
            VERIFIER.verify(self.root)

    def test_checklist_status_open_approved_fails(self) -> None:
        provenance = self.provenance()
        provenance["rights_review"]["notice_checklist"]["status"] = "OPEN \u2014 approved"
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "notice checklist status changed"
        ):
            VERIFIER.verify(self.root)

    def test_blocker_action_reword_fails(self) -> None:
        provenance = self.provenance()
        for item in provenance["rights_review"]["notice_checklist"]["items"]:
            if item["id"] == "RIGHTS-02":
                item["action"] = "Decide whether Apache-2.0 NOTICE propagation applies."
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "item action changed: RIGHTS-02"
        ):
            VERIFIER.verify(self.root)

    def test_blocker_evidence_reword_fails(self) -> None:
        provenance = self.provenance()
        for item in provenance["rights_review"]["notice_checklist"]["items"]:
            if item["id"] == "RIGHTS-05":
                item["evidence"] = "rights_review.publication_decision is APPROVED."
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "item evidence changed: RIGHTS-05"
        ):
            VERIFIER.verify(self.root)

    def test_fixture_release_member_true_fails(self) -> None:
        provenance = self.provenance()
        provenance["fixtures"][0]["release_archive_member"] = True
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not be a release archive member"
        ):
            VERIFIER.verify(self.root)

    def test_fixture_release_member_missing_fails(self) -> None:
        provenance = self.provenance()
        del provenance["fixtures"][1]["release_archive_member"]
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "is missing release_archive_member"
        ):
            VERIFIER.verify(self.root)

    def test_source_distribution_data_only_allowed_fails(self) -> None:
        inventory = self.inventory()
        inventory["source_distribution"]["status"] = "ALLOWED"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "source distribution must remain BLOCKED"
        ):
            VERIFIER.verify(self.root)

    def test_binary_distribution_data_only_allowed_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["status"] = "ALLOWED"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "binary distribution must remain BLOCKED"
        ):
            VERIFIER.verify(self.root)

    def test_mismatch_fixture_paths_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["fixture_paths"].append(
            "tests/fixtures/extra-fixture.json"
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "do not match the fixture set"
        ):
            VERIFIER.verify(self.root)

    def test_provenance_blocker_closed_fails(self) -> None:
        provenance = self.provenance()
        for item in provenance["rights_review"]["notice_checklist"]["items"]:
            if item["id"] == "RIGHTS-02":
                item["status"] = "DONE"
        self.write_provenance(provenance)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "blocking item is not OPEN: RIGHTS-02"
        ):
            VERIFIER.verify(self.root)

    def test_inventory_blocking_open_changed_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_gate"]["blocking_open"] = ["RIGHTS-02", "RIGHTS-03"]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "blocking_open changed"
        ):
            VERIFIER.verify(self.root)

    def test_path_traversal_member_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["archive_members"][0]["source"] = (
            "target/../../etc/passwd"
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "contains traversal"
        ):
            VERIFIER.verify(self.root)

    def test_absolute_member_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["archive_members"][0]["source"] = (
            "/tmp/astatine"
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not be absolute"
        ):
            VERIFIER.verify(self.root)

    def test_backslash_member_fails(self) -> None:
        inventory = self.inventory()
        inventory["binary_distribution"]["archive_members"][0]["source"] = (
            "target\\release\\astatine"
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not contain backslash"
        ):
            VERIFIER.verify(self.root)

    def test_duplicate_member_fails(self) -> None:
        inventory = self.inventory()
        members = inventory["binary_distribution"]["archive_members"]
        members.append(dict(members[0]))
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "duplicate archive member"
        ):
            VERIFIER.verify(self.root)

    def test_missing_required_member_fails(self) -> None:
        inventory = self.inventory()
        members = inventory["binary_distribution"]["archive_members"]
        inventory["binary_distribution"]["archive_members"] = [
            member for member in members if member["source"] != "LICENSE-MIT"
        ]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "allowlist|missing required archive member"
        ):
            VERIFIER.verify(self.root)

    def test_symlink_member_fails(self) -> None:
        real = self.root / "real-license.txt"
        real.write_text("license stand-in\n", encoding="utf-8")
        link = self.root / "LICENSE-MIT"
        os.symlink(real, link)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "symlink"
        ):
            VERIFIER.verify(self.root)

    def test_cli_failure_returns_structured_json(self) -> None:
        import contextlib
        import io
        from unittest import mock

        inventory = self.inventory()
        inventory["binary_distribution"]["status"] = "ALLOWED"
        self.write_inventory(inventory)
        stderr = io.StringIO()
        with mock.patch.object(
            sys, "argv", ["verify-distribution-inventory.py", str(self.root)]
        ):
            with contextlib.redirect_stderr(stderr):
                return_code = VERIFIER.main()
        self.assertEqual(return_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("BLOCKED", payload["error"])


if __name__ == "__main__":
    unittest.main()
