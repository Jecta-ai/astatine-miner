#!/usr/bin/env python3
"""Live v3 tests for support/verify-fixture-provenance.py.

The original 66 blocked-state tests remain in
``test_fixture_provenance_blocked.py`` against frozen blocked fixtures; this
file is additive and covers the current v3 gate. Tests copy fixture
copies into a temporary directory and never touch the real source tree,
network, wallet, Keychain, Anvil, GPU, or production runtime.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SOURCE_ROOT = Path(__file__).resolve().parents[2]
VERIFIER_PATH = Path(
    os.environ.get(
        "ASTATINE_VERIFIER_PATH",
        str(SOURCE_ROOT / "support" / "verify-fixture-provenance.py"),
    )
).resolve()
SCRUB_PATHS = [
    "README.md",
    "MACOS_ARM64.md",
    "src/protocol.rs",
    "support/update-evm-test-fixtures.py",
    "support/update-genesis-coordinator-fixture.py",
    "tests/fixtures/README.md",
]
INVENTORY_REL = Path("tests/fixtures/PROVENANCE.json")
FIXTURE_REL = Path("tests/fixtures/AstatineMiner.json")
FIXTURE_README_REL = Path("tests/fixtures/README.md")
LICENSE_REL = Path("tests/fixtures/OPENZEPPELIN_LICENSE.txt")
APACHE_REL = Path("tests/fixtures/LICENSE-APACHE-2.0.txt")
MIT_REL = Path("tests/fixtures/LICENSE-MIT.txt")
NOTICE_REL = Path("tests/fixtures/NOTICE")


def load_verifier():
    spec = importlib.util.spec_from_file_location("fixture_provenance_verifier", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load verifier module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VERIFIER = load_verifier()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


class FixtureProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="astatine-fixture-verify-")
        self.root = Path(self.tempdir.name)
        shutil.copytree(SOURCE_ROOT / "tests" / "fixtures", self.root / "tests" / "fixtures")
        for relative in SCRUB_PATHS:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(SOURCE_ROOT / relative, destination)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def inventory(self) -> dict:
        return json.loads((self.root / INVENTORY_REL).read_text(encoding="utf-8"))

    def write_inventory(self, inventory: dict) -> None:
        (self.root / INVENTORY_REL).write_text(
            json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
        )

    def update_fixture_entry(self, inventory: dict, relative: Path, data: bytes) -> None:
        for entry in inventory["fixtures"]:
            if entry["path"] == relative.as_posix():
                entry["sha256"] = sha256_hex(data)
                entry["bytes"] = len(data)
                entry["canonical_git_blob_sha1"] = git_blob_sha1(data)
                return
        raise AssertionError(f"missing inventory entry for {relative}")

    def update_document_entry(self, inventory: dict, relative: Path, data: bytes) -> None:
        for document in inventory["documents"]:
            if document["path"] == relative.as_posix():
                document["sha256"] = sha256_hex(data)
                document["bytes"] = len(data)
                return
        raise AssertionError(f"missing document entry for {relative}")

    def update_legal_entry(self, inventory: dict, relative: Path, data: bytes) -> None:
        for artifact in inventory["legal_artifacts"]:
            if artifact["path"] == relative.as_posix():
                artifact["sha256"] = sha256_hex(data)
                artifact["bytes"] = len(data)
                return
        raise AssertionError(f"missing legal artifact entry for {relative}")

    def test_real_inventory_passes_as_v3(self) -> None:
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["schema"], "astatine-fixture-provenance/v3")
        self.assertEqual(result["fixtures_checked"], 4)
        self.assertEqual(result["documents_checked"], 1)
        self.assertEqual(result["legal_artifacts_checked"], 4)
        self.assertEqual(result["scrub_paths_checked"], 6)
        self.assertTrue(result["release_intent_authorized"])
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["final_release_controls_complete"])
        self.assertEqual(
            result["notice_checklist_status"],
            "TECHNICAL REVIEW RECORDED \u2014 owner-authorized release intent under the explicit owner self-approval policy; final release controls outstanding",
        )
        self.assertEqual(result["blocking_open"], [])
        self.assertEqual(result["notice_checklist_blocking_open"], 0)
        self.assertEqual(
            result["authorization_status"], "OWNER-AUTHORIZED RELEASE INTENT \u2014 FINAL CONTROLS OUTSTANDING \u2014 OWNER SELF-APPROVAL"
        )
        self.assertEqual(
            result["rights_decision"],
            "OWNER-AUTHORIZED RELEASE INTENT \u2014 project owner authorized first-party source and binary distribution intent for v0.1.0-testnet.4 under the explicitly documented owner self-approval policy; technical NOTICE review recorded; final release controls outstanding; not a legal conclusion, not independent review, and not a separate approval.",
        )
        self.assertEqual(
            result["review_ci_branch_push_authorization"],
            "SUPERSEDED \u2014 OWNER-AUTHORIZED RELEASE INTENT",
        )
        self.assertEqual(
            result["notice_applicability"],
            "TECHNICALLY REVIEWED \u2014 no separate upstream NOTICE file was found in the pinned contract fixture subtrees; the private EVM root NOTICE is scoped to a separate Rust subtree; Apache-2.0 license text and fixture NOTICE are included. This is an evidence-based technical review, not a legal conclusion or separate approval.",
        )

    def test_tampered_fixture_bytes_fail(self) -> None:
        path = self.root / FIXTURE_REL
        document = json.loads(path.read_text(encoding="utf-8"))
        bytecode = document["bytecode"]["object"]
        document["bytecode"]["object"] = bytecode[:-1] + ("0" if bytecode[-1] != "0" else "1")
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "SHA-256 changed"):
            VERIFIER.verify(self.root)

    def test_source_pin_change_with_matching_hash_fails(self) -> None:
        path = self.root / FIXTURE_REL
        document = json.loads(path.read_text(encoding="utf-8"))
        document["source_commit"] = "0" * 40
        data = (json.dumps(document, indent=2) + "\n").encode()
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_fixture_entry(inventory, FIXTURE_REL, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "source pin changed"):
            VERIFIER.verify(self.root)

    def test_forbidden_abi_key_fails(self) -> None:
        path = self.root / FIXTURE_REL
        document = json.loads(path.read_text(encoding="utf-8"))
        document["abi"] = []
        data = (json.dumps(document, indent=2) + "\n").encode()
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_fixture_entry(inventory, FIXTURE_REL, data)
        for entry in inventory["fixtures"]:
            if entry["path"] == FIXTURE_REL.as_posix():
                entry["json_keys"] = sorted(list(entry["json_keys"]) + ["abi"])
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "forbidden key abi"):
            VERIFIER.verify(self.root)

    def test_missing_openzeppelin_license_fails(self) -> None:
        (self.root / LICENSE_REL).unlink()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "cannot read"):
            VERIFIER.verify(self.root)

    def test_missing_apache_license_fails(self) -> None:
        (self.root / APACHE_REL).unlink()
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_missing_mit_license_fails(self) -> None:
        (self.root / MIT_REL).unlink()
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_missing_notice_fails(self) -> None:
        (self.root / NOTICE_REL).unlink()
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)

    def test_extra_legal_artifact_file_fails(self) -> None:
        probe = self.root / "tests" / "fixtures" / "EXTRA-LICENSE.txt"
        probe.write_text("extra", encoding="utf-8")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "unexpected file"):
            VERIFIER.verify(self.root)

    def test_renamed_apache_legal_artifact_fails(self) -> None:
        inventory = self.inventory()
        for artifact in inventory["legal_artifacts"]:
            if artifact["path"] == APACHE_REL.as_posix():
                artifact["path"] = "tests/fixtures/LICENSE-APACHE-RENAMED.txt"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "not expected"):
            VERIFIER.verify(self.root)

    def test_altered_apache_content_fails(self) -> None:
        path = self.root / APACHE_REL
        data = path.read_bytes().replace(b"Apache License", b"X License")
        self.assertNotIn(b"Apache License", data)
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_legal_entry(inventory, APACHE_REL, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "Apache-2.0 license text"):
            VERIFIER.verify(self.root)

    def test_altered_mit_content_fails(self) -> None:
        path = self.root / MIT_REL
        data = path.read_bytes().replace(b"Permission is hereby granted", b"X")
        self.assertNotIn(b"Permission is hereby granted", data)
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_legal_entry(inventory, MIT_REL, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "MIT license text"):
            VERIFIER.verify(self.root)

    def test_altered_notice_content_fails(self) -> None:
        path = self.root / NOTICE_REL
        text = path.read_text(encoding="utf-8").replace("AstatineMiner", "Redacted")
        self.assertNotIn("AstatineMiner", text)
        data = text.encode()
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_legal_entry(inventory, NOTICE_REL, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "missing required marker"):
            VERIFIER.verify(self.root)

    def test_notice_accurate_oz_scope_passes(self) -> None:
        # Accurate L9 scope must be present in the temp NOTICE copy.
        text = (self.root / NOTICE_REL).read_text(encoding="utf-8")
        lowered = " ".join(text.lower().split())
        for phrase in (
            "pinned evm source trees reference",
            "dbb6104ce834628e473d2173bbc9d47f81a9eec3",
            "imports one openzeppelin component",
            "zero direct openzeppelin imports",
            "for any fixture redistribution to which it applies",
            "does not assert openzeppelin code in every fixture",
        ):
            self.assertIn(phrase, lowered)
        self.assertNotIn("with any redistribution of mockast", lowered)
        # Verifier must still pass with the accurate scope.
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")

    def test_notice_missing_oz_scope_fails(self) -> None:
        path = self.root / NOTICE_REL
        text = path.read_text(encoding="utf-8")
        # Drop the GenesisCoordinator zero-imports sentence to simulate under-claiming.
        redacted = text.replace("declares zero direct OpenZeppelin", "has OpenZeppelin")
        self.assertNotIn("zero direct OpenZeppelin", redacted)
        data = redacted.encode()
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_legal_entry(inventory, NOTICE_REL, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "zero direct OpenZeppelin imports"
        ):
            VERIFIER.verify(self.root)

    def test_notice_narrow_mockast_only_fails(self) -> None:
        path = self.root / NOTICE_REL
        text = path.read_text(encoding="utf-8")
        narrow = text.replace(
            "for any fixture redistribution\n  to which it applies",
            "with any redistribution of MockAST",
        )
        # Fall back if line-wrap differs: ensure old narrow phrase present.
        if "with any redistribution of MockAST" not in narrow:
            narrow = text + "\nwith any redistribution of MockAST\n"
        data = narrow.encode()
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_legal_entry(inventory, NOTICE_REL, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not narrow OZ retention|must retain the OZ notice"
        ):
            VERIFIER.verify(self.root)

    def test_openzeppelin_evidence_scope_missing_accurate_scope_fails(self) -> None:
        inventory = self.inventory()
        inventory["openzeppelin"]["evidence_scope"] = (
            "Exact pinned LICENSE verified locally and against retained upstream license evidence. "
            "This resolves license identity only, not first-party rights or notice applicability."
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "evidence_scope must scope both pinned EVM"
        ):
            VERIFIER.verify(self.root)

    def test_readme_accurate_oz_scope_present(self) -> None:
        text = (self.root / FIXTURE_README_REL).read_text(encoding="utf-8")
        lowered = " ".join(text.lower().split())
        for phrase in (
            "both pinned evm source trees reference",
            "imports one openzeppelin component",
            "zero direct openzeppelin imports",
            "for any fixture redistribution to which it applies",
            "does not assert openzeppelin code in every fixture",
        ):
            self.assertIn(phrase, lowered)

    def test_data_only_authorization_without_license_files_fails(self) -> None:
        inventory = self.inventory()
        inventory["legal_artifacts"] = [
            a for a in inventory["legal_artifacts"] if a["path"] == LICENSE_REL.as_posix()
        ]
        self.write_inventory(inventory)
        (self.root / APACHE_REL).unlink()
        (self.root / MIT_REL).unlink()
        (self.root / NOTICE_REL).unlink()
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must include the OpenZeppelin|legal artifact path inventory changed"
        ):
            VERIFIER.verify(self.root)

    def test_checklist_done_without_evidence_fails(self) -> None:
        inventory = self.inventory()
        for item in inventory["rights_review"]["notice_checklist"]["items"]:
            if item["id"] == "RIGHTS-03":
                item["evidence"] = ""
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must be a non-empty string|DONE without evidence"
        ):
            VERIFIER.verify(self.root)

    def test_missing_mockast_evidence_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_review"]["release_intent_authorization"]
        auth["evidence"] = [e for e in auth["evidence"] if "mockast" not in e.lower()]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "missing MockAST"):
            VERIFIER.verify(self.root)

    def test_missing_mockast_attestation_scope_fails(self) -> None:
        inventory = self.inventory()
        att = inventory["rights_review"]["owner_attestation"]
        att["scope"] = "The AstatineMiner and AstatineGenesisCoordinator contracts are first-party works."
        att["attestation_source"] = "The project owner confirmed ownership on 2026-11-17; not independently verified."
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "must include MockAST|missing MockAST"):
            VERIFIER.verify(self.root)

    def test_independent_verification_claim_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["owner_attestation"]["independent_verification"] = True
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not be represented as independent verification"
        ):
            VERIFIER.verify(self.root)
        inventory = self.inventory()
        inventory["rights_review"]["owner_attestation"]["independent_verification"] = False
        inventory["rights_review"]["release_intent_authorization"]["independent_verification"] = True
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not claim independent verification"
        ):
            VERIFIER.verify(self.root)

    def test_private_origin_marker_in_readme_fails(self) -> None:
        marker = "fixture-test-owner/fixture-test-repo"
        path = self.root / FIXTURE_README_REL
        data = path.read_bytes() + f"\nleak: {marker}\n".encode()
        path.write_bytes(data)
        inventory = self.inventory()
        inventory["scrub_policy"]["prohibited_name_marker_sha256"].append(
            sha256_hex(marker.lower().encode())
        )
        self.update_document_entry(inventory, FIXTURE_README_REL, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "private-origin marker"):
            VERIFIER.verify(self.root)

    def test_regeneration_script_sha256_mismatch_fails(self) -> None:
        inventory = self.inventory()
        for entry in inventory["fixtures"]:
            if entry["id"] == "FIX-01":
                digest = entry["regeneration"]["script_sha256"]
                mutated = ("0" if digest[0] != "0" else "1") + digest[1:]
                entry["regeneration"]["script_sha256"] = mutated
                break
        else:
            self.fail("FIX-01 regeneration entry missing")
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "regeneration script SHA-256 changed"):
            VERIFIER.verify(self.root)

    def test_missing_regeneration_script_fails(self) -> None:
        (self.root / "support" / "update-evm-test-fixtures.py").unlink()
        with self.assertRaisesRegex(VERIFIER.VerificationError, "regeneration script"):
            VERIFIER.verify(self.root)

    def test_renamed_regeneration_script_fails(self) -> None:
        original = self.root / "support" / "update-genesis-coordinator-fixture.py"
        renamed = self.root / "support" / "update-genesis-coordinator-fixture-renamed.py"
        original.rename(renamed)
        try:
            with self.assertRaisesRegex(VERIFIER.VerificationError, "regeneration script"):
                VERIFIER.verify(self.root)
        finally:
            if renamed.exists():
                renamed.rename(original)

    def test_scripted_status_downgrade_fails(self) -> None:
        inventory = self.inventory()
        for entry in inventory["fixtures"]:
            if entry["id"] == "FIX-02":
                entry["regeneration"] = {
                    "status": "not_scripted",
                    "performed_in_this_review": False,
                    "detail": "data-only downgrade must not bypass script verification",
                }
                break
        else:
            self.fail("FIX-02 regeneration entry missing")
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "scripted regeneration coverage"):
            VERIFIER.verify(self.root)

    def test_regeneration_script_swap_fails(self) -> None:
        inventory = self.inventory()
        for entry in inventory["fixtures"]:
            if entry["id"] == "FIX-02":
                entry["regeneration"]["script"] = "support/update-evm-test-fixtures.py"
                entry["regeneration"]["script_sha256"] = (
                    "8d96c7ee80c021de9d3f679c17322db4da1fa7433c23429fde9eef1407b18615"
                )
                break
        else:
            self.fail("FIX-02 regeneration entry missing")
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "script mapping changed"):
            VERIFIER.verify(self.root)

    def test_private_origin_marker_in_protocol_rs_fails(self) -> None:
        marker = "fixture-test-owner/fixture-test-protocol"
        path = self.root / "src" / "protocol.rs"
        data = path.read_bytes() + f"\n// leak: {marker}\n".encode()
        path.write_bytes(data)
        inventory = self.inventory()
        inventory["scrub_policy"]["prohibited_name_marker_sha256"].append(
            sha256_hex(marker.lower().encode())
        )
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "private-origin marker"):
            VERIFIER.verify(self.root)

    def test_scrub_policy_covers_protocol_test_comment(self) -> None:
        inventory = self.inventory()
        self.assertIn("src/protocol.rs", inventory["scrub_policy"]["paths"])
        self.assertEqual(
            inventory["scrub_policy"]["retained_private_origin_reference"]["status"],
            "genericized",
        )
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["scrub_paths_checked"], 6)

    def test_rights_status_cannot_be_upgraded(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["rights_holder_authority"] = "ESTABLISHED"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "rights status must remain honest"):
            VERIFIER.verify(self.root)

    def test_owner_attestation_cannot_claim_independence_or_omit_fields(self) -> None:
        inventory = self.inventory()
        del inventory["rights_review"]["owner_attestation"]["independent_verification"]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "owner_attestation"):
            VERIFIER.verify(self.root)

        inventory = self.inventory()
        inventory["rights_review"]["owner_attestation"]["independent_verification"] = True
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not be represented as independent verification"
        ):
            VERIFIER.verify(self.root)

    def test_prior_attestation_rewrite_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["owner_attestation"]["prior_attestations"][0]["attested_on"] = "2026-11-16"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "prior record changed|prior attestation"):
            VERIFIER.verify(self.root)

    def test_notice_checklist_cannot_be_emptied(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["notice_checklist"]["items"] = []
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "notice_checklist items must not be empty"
        ):
            VERIFIER.verify(self.root)

    def test_blocked_publication_requires_blocking_items(self) -> None:
        inventory = self.inventory()
        for item in inventory["rights_review"]["notice_checklist"]["items"]:
            item["blocking"] = False
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            "rights gate item is not blocking: RIGHTS-02",
        ):
            VERIFIER.verify(self.root)

    def test_rights_decision_wrong_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["rights_decision"] = "BLOCKED but approved"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must be the exact v3"
        ):
            VERIFIER.verify(self.root)

    def test_old_publication_keys_rejected(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["publication_decision"] = "AUTHORIZED"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not contain publication_decision"
        ):
            VERIFIER.verify(self.root)
        inventory = self.inventory()
        inventory["rights_review"]["publication_authorization"] = {"status": "X"}
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not contain publication_authorization"
        ):
            VERIFIER.verify(self.root)

    def test_release_approver_invention_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["release_intent_authorization"]["authorized_by"] = "project owner and release approver"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "project owner only|must be authorized by project owner only|must not invent a release approver"
        ):
            VERIFIER.verify(self.root)
        inventory = self.inventory()
        for item in inventory["rights_review"]["notice_checklist"]["items"]:
            if item["id"] == "RIGHTS-02":
                item["owner"] = "project owner and release approver"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must be repository technical review|must not invent a release approver"
        ):
            VERIFIER.verify(self.root)
        inventory = self.inventory()
        inventory["rights_review"]["release_intent_authorization"]["evidence"] = [
            "Project owner and release approver decided NOTICE."
        ]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not invent a release approver"
        ):
            VERIFIER.verify(self.root)

    def test_legal_conclusion_claim_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["release_intent_authorization"]["technical_notice_review"]["legal_conclusion"] = True
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not claim a legal conclusion"
        ):
            VERIFIER.verify(self.root)
        inventory = self.inventory()
        inventory["rights_review"]["release_intent_authorization"]["technical_notice_review"]["legal_conclusion"] = False
        inventory["rights_review"]["release_intent_authorization"]["technical_notice_review"]["separate_approval"] = True
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not claim a separate approval"
        ):
            VERIFIER.verify(self.root)

    def test_final_controls_complete_true_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["release_intent_authorization"]["final_release_controls_complete"] = True
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must remain outstanding|must not claim complete"
        ):
            VERIFIER.verify(self.root)

    def test_missing_technical_citations_fails(self) -> None:
        inventory = self.inventory()
        tech = inventory["rights_review"]["release_intent_authorization"]["technical_notice_review"]
        tech["citations"] = [c for c in tech["citations"] if c != "tests/fixtures/NOTICE"]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "citations must list the six"
        ):
            VERIFIER.verify(self.root)

    def test_v2_schema_rejected(self) -> None:
        inventory = self.inventory()
        inventory["schema"] = "astatine-fixture-provenance/v2"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "unexpected inventory schema|superseded by v3"
        ):
            VERIFIER.verify(self.root)

    def test_checklist_status_wrong_fails(self) -> None:
        inventory = self.inventory()
        inventory["rights_review"]["notice_checklist"]["status"] = "OPEN \u2014 approved"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must be TECHNICAL REVIEW RECORDED"
        ):
            VERIFIER.verify(self.root)

    def test_blocker_action_reword_fails(self) -> None:
        inventory = self.inventory()
        for item in inventory["rights_review"]["notice_checklist"]["items"]:
            if item["id"] == "RIGHTS-03":
                item["action"] = "If the fixtures remain, add license text."
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "item action changed: RIGHTS-03"
        ):
            VERIFIER.verify(self.root)

    def test_blocker_evidence_missing_reference_fails(self) -> None:
        inventory = self.inventory()
        for item in inventory["rights_review"]["notice_checklist"]["items"]:
            if item["id"] == "RIGHTS-05":
                item["evidence"] = "Recorded."
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "missing required reference"
        ):
            VERIFIER.verify(self.root)

    def test_fixture_release_member_true_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"][0]["release_archive_member"] = True
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must not be a release archive member"
        ):
            VERIFIER.verify(self.root)

    def test_fixture_release_member_missing_fails(self) -> None:
        inventory = self.inventory()
        del inventory["fixtures"][1]["release_archive_member"]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "is missing required fields"
        ):
            VERIFIER.verify(self.root)

    def test_pass_reports_exact_v3_gate_values(self) -> None:
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(
            result["rights_decision"],
            "OWNER-AUTHORIZED RELEASE INTENT \u2014 project owner authorized first-party source and binary distribution intent for v0.1.0-testnet.4 under the explicitly documented owner self-approval policy; technical NOTICE review recorded; final release controls outstanding; not a legal conclusion, not independent review, and not a separate approval.",
        )
        self.assertEqual(
            result["notice_checklist_status"], "TECHNICAL REVIEW RECORDED \u2014 owner-authorized release intent under the explicit owner self-approval policy; final release controls outstanding"
        )
        self.assertEqual(
            result["review_ci_branch_push_authorization"],
            "SUPERSEDED \u2014 OWNER-AUTHORIZED RELEASE INTENT",
        )
        self.assertTrue(result["release_intent_authorized"])
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["final_release_controls_complete"])
        self.assertEqual(result["blocking_open"], [])

    def test_release_identity_mutation_fails(self) -> None:
        inventory = self.inventory()
        inventory["release"]["tag"] = "v0.1.0-testnet.1"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "release identity"
        ):
            VERIFIER.verify(self.root)

    def test_historical_release_intent_mutation_fails(self) -> None:
        inventory = self.inventory()
        inventory["historical_release_intent"]["tag"] = "v0.1.0-testnet.4"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "historical .1 release intent"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_status_release_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_review"]["review_ci_branch_push_authorization"]
        auth["status"] = "AUTHORIZED \u2014 RELEASE"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must be SUPERSEDED"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_date_change_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_review"]["review_ci_branch_push_authorization"]
        auth["authorized_on"] = "2026-11-17"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "push authorization date changed"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_scope_change_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_review"]["review_ci_branch_push_authorization"]
        auth["scope"] = "Push the branch for review, CI and release."
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "push authorization scope changed"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_blocked_item_removed_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_review"]["review_ci_branch_push_authorization"]
        auth["not_authorized"].remove("tag or public release publication")
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "push blocked list changed"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_gate_statement_change_fails(self) -> None:
        inventory = self.inventory()
        auth = inventory["rights_review"]["review_ci_branch_push_authorization"]
        auth["rights_gate_unchanged"] = "RIGHTS-02 through RIGHTS-05 resolved."
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "push gate statement changed"
        ):
            VERIFIER.verify(self.root)

    def test_review_push_authorization_missing_fails(self) -> None:
        inventory = self.inventory()
        del inventory["rights_review"]["review_ci_branch_push_authorization"]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "missing required fields|must be an object"
        ):
            VERIFIER.verify(self.root)

    def test_openzeppelin_path_must_remain(self) -> None:
        inventory = self.inventory()
        inventory["openzeppelin"]["license_text"] = MIT_REL.as_posix()
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "must still point to"
        ):
            VERIFIER.verify(self.root)

    def test_synthetic_receipt_shape_is_pinned(self) -> None:
        receipt_rel = Path("tests/fixtures/synthetic-injective-virtual-receipt.json")
        path = self.root / receipt_rel
        document = json.loads(path.read_text(encoding="utf-8"))
        document["logs"] = [log for log in document["logs"] if not log.get("virtual")]
        data = (json.dumps(document, indent=2) + "\n").encode()
        path.write_bytes(data)
        inventory = self.inventory()
        self.update_fixture_entry(inventory, receipt_rel, data)
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError, "synthetic receipt log count changed"
        ):
            VERIFIER.verify(self.root)

    def test_fixture_identity_substitution_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"][3]["path"] = "tests/fixtures/AstatineMiner.json"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            r"fixtures\[3\] path substitution changes the expected fixture identity: "
            r"tests/fixtures/AstatineMiner\.json",
        ):
            VERIFIER.verify(self.root)

    def test_fixture_path_outside_expected_directory_fails(self) -> None:
        other_dir = self.root / "other"
        other_dir.mkdir()
        shutil.copy2(self.root / FIXTURE_REL, other_dir / FIXTURE_REL.name)
        inventory = self.inventory()
        inventory["fixtures"][0]["path"] = f"other/{FIXTURE_REL.name}"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            r"fixtures\[0\] path is not an expected fixture: other/AstatineMiner\.json",
        ):
            VERIFIER.verify(self.root)

    def test_fixture_path_traversal_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"][0]["path"] = "tests/fixtures/../fixtures/AstatineMiner.json"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "contains traversal"):
            VERIFIER.verify(self.root)

    def test_fixture_path_absolute_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"][0]["path"] = "/tmp/AstatineMiner.json"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "must not be absolute"):
            VERIFIER.verify(self.root)

    def test_fixture_file_symlink_fails(self) -> None:
        path = self.root / FIXTURE_REL
        target = self.root / "outside-AstatineMiner.json"
        shutil.copy2(path, target)
        path.unlink()
        os.symlink(target, path)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "symlink"):
            VERIFIER.verify(self.root)

    def test_directory_at_fixture_path_fails(self) -> None:
        path = self.root / FIXTURE_REL
        path.unlink()
        path.mkdir()
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            r"fixture JSON entry must be a regular file: AstatineMiner\.json",
        ):
            VERIFIER.verify(self.root)

    def test_document_symlink_fails(self) -> None:
        path = self.root / FIXTURE_README_REL
        target = self.root / "outside-README.md"
        shutil.copy2(path, target)
        path.unlink()
        os.symlink(target, path)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            r"fixture directory contains a symlink: README\.md",
        ):
            VERIFIER.verify(self.root)

    def test_legal_artifact_symlink_fails(self) -> None:
        path = self.root / LICENSE_REL
        target = self.root / "outside-OPENZEPPELIN_LICENSE.txt"
        shutil.copy2(path, target)
        path.unlink()
        os.symlink(target, path)
        with self.assertRaisesRegex(
            VERIFIER.VerificationError,
            r"fixture directory contains a symlink: OPENZEPPELIN_LICENSE\.txt",
        ):
            VERIFIER.verify(self.root)

    def test_parent_directory_symlink_fails(self) -> None:
        fixtures = self.root / "tests" / "fixtures"
        real = self.root / "tests" / "fixtures-real"
        fixtures.rename(real)
        os.symlink(real, fixtures)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "symlink component"):
            VERIFIER.verify(self.root)

    def test_document_path_traversal_fails(self) -> None:
        inventory = self.inventory()
        inventory["documents"][0]["path"] = "tests/fixtures/../fixtures/README.md"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "contains traversal"):
            VERIFIER.verify(self.root)

    def test_scrub_path_absolute_fails(self) -> None:
        inventory = self.inventory()
        inventory["scrub_policy"]["paths"][0] = "/tmp/README.md"
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "must not be absolute"):
            VERIFIER.verify(self.root)

    def test_null_fixtures_list_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"] = None
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "fixtures must be a list"):
            VERIFIER.verify(self.root)

    def test_null_fixture_entry_fails(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"][0] = None
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "fixtures\\[0\\] must be an object"):
            VERIFIER.verify(self.root)

    def test_null_openzeppelin_fails(self) -> None:
        inventory = self.inventory()
        inventory["openzeppelin"] = None
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "openzeppelin must be an object"):
            VERIFIER.verify(self.root)

    def test_null_document_entry_fails(self) -> None:
        inventory = self.inventory()
        inventory["documents"] = [None]
        self.write_inventory(inventory)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "documents\\[0\\] must be an object"):
            VERIFIER.verify(self.root)

    def test_invalid_utf8_scrub_document_fails(self) -> None:
        (self.root / "README.md").write_bytes(b"\xff\xfe\x80invalid\n")
        with self.assertRaisesRegex(VERIFIER.VerificationError, "not valid UTF-8"):
            VERIFIER.verify(self.root)

    def test_cli_schema_failure_returns_structured_json(self) -> None:
        inventory = self.inventory()
        inventory["fixtures"] = None
        self.write_inventory(inventory)
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["verify-fixture-provenance.py", str(self.root)]):
            with contextlib.redirect_stderr(stderr):
                return_code = VERIFIER.main()
        self.assertEqual(return_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("fixtures must be a list", payload["error"])

    def test_scandir_oserror_returns_structured_json(self) -> None:
        denied = PermissionError(13, "Permission denied")
        stderr = io.StringIO()
        with mock.patch.object(VERIFIER.os, "scandir", side_effect=denied):
            with mock.patch.object(sys, "argv", ["verify-fixture-provenance.py", str(self.root)]):
                with contextlib.redirect_stderr(stderr):
                    return_code = VERIFIER.main()
        self.assertEqual(return_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("cannot scan fixture directory tests/fixtures", payload["error"])

    def test_root_resolve_oserror_returns_structured_json(self) -> None:
        denied = PermissionError(13, "Permission denied")
        stderr = io.StringIO()
        with mock.patch.object(VERIFIER.Path, "resolve", side_effect=denied):
            with mock.patch.object(sys, "argv", ["verify-fixture-provenance.py", str(self.root)]):
                with contextlib.redirect_stderr(stderr):
                    return_code = VERIFIER.main()
        self.assertEqual(return_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("source root is not readable", payload["error"])

    def test_unlisted_txt_extra_fails(self) -> None:
        probe = self.root / "tests" / "fixtures" / "extra-probe.txt"
        probe.write_text("unlisted", encoding="utf-8")
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("unexpected file", message)
        self.assertIn("extra-probe.txt", message)
        self.assertTrue(probe.is_file())
        self.assertTrue((self.root / FIXTURE_REL).is_file())

    def test_unlisted_extensionless_extra_fails(self) -> None:
        probe = self.root / "tests" / "fixtures" / "extra-noext"
        probe.write_text("unlisted", encoding="utf-8")
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("unexpected file", message)
        self.assertIn("extra-noext", message)

    def test_unlisted_uppercase_json_extra_fails(self) -> None:
        probe = self.root / "tests" / "fixtures" / "EXTRA-PROBE.JSON"
        probe.write_text("unlisted", encoding="utf-8")
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("unexpected file", message)
        self.assertIn("EXTRA-PROBE.JSON", message)

    def test_unlisted_lowercase_json_extra_fails(self) -> None:
        probe = self.root / "tests" / "fixtures" / "extra-probe.json"
        probe.write_text("unlisted", encoding="utf-8")
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("unexpected file", message)
        self.assertIn("extra-probe.json", message)

    def test_hidden_file_fails(self) -> None:
        probe = self.root / "tests" / "fixtures" / ".hidden-probe"
        probe.write_text("unlisted", encoding="utf-8")
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("unexpected file", message)
        self.assertIn(".hidden-probe", message)

    def test_hidden_directory_fails(self) -> None:
        probe_dir = self.root / "tests" / "fixtures" / ".hidden-dir"
        probe_dir.mkdir()
        (probe_dir / "inner.txt").write_text("nested", encoding="utf-8")
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn(".hidden-dir", message)
        self.assertIn("unexpected directory", message)

    def test_nested_directory_fails(self) -> None:
        nested = self.root / "tests" / "fixtures" / "nested-probe"
        nested.mkdir()
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("nested-probe", message)
        self.assertIn("unexpected directory", message)

    def test_nested_file_fails(self) -> None:
        nested = self.root / "tests" / "fixtures" / "nested-file-probe"
        nested.mkdir()
        (nested / "inner.txt").write_text("nested", encoding="utf-8")
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("nested-file-probe", message)

    def test_nested_basename_collision_fails(self) -> None:
        nested = self.root / "tests" / "fixtures" / "nested-collision"
        nested.mkdir()
        shutil.copy2(self.root / FIXTURE_REL, nested / "AstatineMiner.json")
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("nested-collision", message)

    def test_symlink_to_listed_file_fails(self) -> None:
        link = self.root / "tests" / "fixtures" / "link-to-listed.json"
        os.symlink(self.root / FIXTURE_REL, link)
        with self.assertRaisesRegex(VERIFIER.VerificationError, "symlink"):
            VERIFIER.verify(self.root)
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        self.assertIn("link-to-listed.json", str(ctx.exception))
        self.assertTrue(link.is_symlink())

    def test_symlink_to_unlisted_outside_file_fails(self) -> None:
        outside = self.root / "outside-target.txt"
        outside.write_text("outside", encoding="utf-8")
        link = self.root / "tests" / "fixtures" / "evil-outside-link"
        os.symlink(outside, link)
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("symlink", message)
        self.assertIn("evil-outside-link", message)

    def test_symlink_to_directory_fails(self) -> None:
        real_dir = self.root / "real-dir"
        real_dir.mkdir()
        (real_dir / "kept.txt").write_text("kept", encoding="utf-8")
        link = self.root / "tests" / "fixtures" / "link-to-dir"
        os.symlink(real_dir, link)
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("symlink", message)
        self.assertIn("link-to-dir", message)

    def test_dangling_symlink_fails(self) -> None:
        link = self.root / "tests" / "fixtures" / "dangling-link"
        os.symlink(self.root / "no-such-target-xyz-12345", link)
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("symlink", message)
        self.assertIn("dangling-link", message)

    def test_directory_replacing_expected_document_fails(self) -> None:
        path = self.root / FIXTURE_README_REL
        path.unlink()
        path.mkdir()
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("README.md", message)

    def test_fifo_entry_fails(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("os.mkfifo is unavailable on this platform")
        probe = self.root / "tests" / "fixtures" / "fifo-probe"
        try:
            os.mkfifo(probe)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"FIFO is unsupported in this environment: {error}")
        try:
            with self.assertRaises(VERIFIER.VerificationError) as ctx:
                VERIFIER.verify(self.root)
            message = str(ctx.exception)
            self.assertIn("fifo-probe", message)
        finally:
            try:
                probe.unlink()
            except OSError:
                pass

    def test_valid_tree_passes_with_exact_counts(self) -> None:
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["fixtures_checked"], 4)
        self.assertEqual(result["documents_checked"], 1)
        self.assertEqual(result["legal_artifacts_checked"], 4)
        self.assertEqual(result["scrub_paths_checked"], 6)
        fixture_dir = self.root / "tests" / "fixtures"
        names = sorted(entry.name for entry in os.scandir(fixture_dir))
        self.assertEqual(
            names,
            sorted(
                [
                    "AstatineGenesisCoordinator.json",
                    "AstatineMiner.json",
                    "MockAST.json",
                    "LICENSE-APACHE-2.0.txt",
                    "LICENSE-MIT.txt",
                    "NOTICE",
                    "OPENZEPPELIN_LICENSE.txt",
                    "PROVENANCE.json",
                    "README.md",
                    "synthetic-injective-virtual-receipt.json",
                ]
            ),
        )
        self.assertEqual(
            result["rights_decision"],
            "OWNER-AUTHORIZED RELEASE INTENT \u2014 project owner authorized first-party source and binary distribution intent for v0.1.0-testnet.4 under the explicitly documented owner self-approval policy; technical NOTICE review recorded; final release controls outstanding; not a legal conclusion, not independent review, and not a separate approval.",
        )
        self.assertEqual(result["notice_applicability"], "TECHNICALLY REVIEWED \u2014 no separate upstream NOTICE file was found in the pinned contract fixture subtrees; the private EVM root NOTICE is scoped to a separate Rust subtree; Apache-2.0 license text and fixture NOTICE are included. This is an evidence-based technical review, not a legal conclusion or separate approval.")
        self.assertTrue(result["release_intent_authorized"])
        self.assertFalse(result["publication_authorized"])
        self.assertFalse(result["final_release_controls_complete"])

    def test_failed_verification_is_read_only(self) -> None:
        probe = self.root / "tests" / "fixtures" / "readonly-probe.txt"
        probe.write_text("probe-bytes", encoding="utf-8")
        before = {
            relative: (self.root / relative).read_bytes()
            for relative in (
                FIXTURE_REL,
                FIXTURE_README_REL,
                LICENSE_REL,
                INVENTORY_REL,
            )
        }
        with self.assertRaises(VERIFIER.VerificationError):
            VERIFIER.verify(self.root)
        self.assertTrue(probe.is_file())
        self.assertEqual(probe.read_text(encoding="utf-8"), "probe-bytes")
        for relative, data in before.items():
            self.assertTrue((self.root / relative).is_file())
            self.assertEqual((self.root / relative).read_bytes(), data)

    def test_cli_unlisted_extra_returns_structured_json(self) -> None:
        probe = self.root / "tests" / "fixtures" / "cli-extra-probe.txt"
        probe.write_text("unlisted", encoding="utf-8")
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["verify-fixture-provenance.py", str(self.root)]):
            with contextlib.redirect_stderr(stderr):
                return_code = VERIFIER.main()
        self.assertEqual(return_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("unexpected file", payload["error"])
        self.assertIn("cli-extra-probe.txt", payload["error"])
        self.assertTrue(probe.is_file())

    def test_cli_nested_directory_returns_structured_json(self) -> None:
        nested = self.root / "tests" / "fixtures" / "cli-nested-probe"
        nested.mkdir()
        (nested / "inner.txt").write_text("nested", encoding="utf-8")
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", ["verify-fixture-provenance.py", str(self.root)]):
            with contextlib.redirect_stderr(stderr):
                return_code = VERIFIER.main()
        self.assertEqual(return_code, 1)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["status"], "FAIL")
        self.assertIn("cli-nested-probe", payload["error"])

    def test_fixture_rel_path_helper_uses_relative_paths(self) -> None:
        self.assertEqual(
            VERIFIER.fixture_rel_path("tests/fixtures/README.md"), "README.md"
        )
        self.assertEqual(
            VERIFIER.fixture_rel_path("tests/fixtures/AstatineMiner.json"),
            "AstatineMiner.json",
        )
        self.assertIsNone(VERIFIER.fixture_rel_path("other/README.md"))
        self.assertIsNone(VERIFIER.fixture_rel_path("tests/other/README.md"))
        self.assertIsNone(
            VERIFIER.fixture_rel_path("tests/fixtures/../fixtures/README.md")
        )

    def test_nested_readme_basename_collision_fails(self) -> None:
        nested = self.root / "tests" / "fixtures" / "nested-readme-collision"
        nested.mkdir()
        shutil.copy2(self.root / FIXTURE_README_REL, nested / "README.md")
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        self.assertIn("nested-readme-collision", str(ctx.exception))

    def test_unlisted_control_character_filename_is_escaped(self) -> None:
        if os.name != "posix":
            self.skipTest("control characters in filenames are not portable")
        name = "control\nname-\x1b[31m"
        probe = self.root / "tests" / "fixtures" / name
        try:
            probe.write_text("unlisted", encoding="utf-8")
        except OSError as error:
            self.skipTest(f"control-character filename unsupported: {error}")
        with self.assertRaises(VERIFIER.VerificationError) as ctx:
            VERIFIER.verify(self.root)
        message = str(ctx.exception)
        self.assertIn("unexpected file", message)
        self.assertNotIn("\n", message)
        self.assertNotIn("\x1b", message)
        self.assertIn("control\\nname-\\x1b[31m", message)
        self.assertTrue(probe.is_file())

    def test_scandir_oserror_reports_generic_errno_not_path(self) -> None:
        secret = "[REDACTED]"
        cases = (
            (
                PermissionError(13, f"{self.root}/{secret}\nEVIL\x1b[31m"),
                "PermissionError (errno 13)",
            ),
            (
                OSError(f"{self.root}/{secret}\nEVIL\x1b[31m"),
                "OSError (errno unknown)",
            ),
        )
        for denied, expected in cases:
            with self.subTest(expected=expected):
                with mock.patch.object(VERIFIER.os, "scandir", side_effect=denied):
                    with self.assertRaises(VERIFIER.VerificationError) as ctx:
                        VERIFIER.verify(self.root)
                message = str(ctx.exception)
                self.assertIn(
                    "cannot scan fixture directory tests/fixtures", message
                )
                self.assertIn(expected, message)
                self.assertNotIn(str(self.root), message)
                self.assertNotIn(secret, message)
                self.assertNotIn("EVIL", message)
                self.assertNotIn("\n", message)
                self.assertNotIn("\x1b", message)

    def test_blocked_state_regression_passes_for_blocked_copy(self) -> None:
        inventory = self.inventory()
        inventory["schema"] = "astatine-fixture-provenance/v1"
        inventory["scrub_policy"]["paths"] = [
            "README.md",
            "MACOS_ARM64.md",
            "support/update-evm-test-fixtures.py",
            "support/update-genesis-coordinator-fixture.py",
            "tests/fixtures/README.md",
        ]
        inventory["scrub_policy"]["retained_private_origin_reference"] = {
            "path": "src/protocol.rs",
            "status": "retained in source",
            "reason": "`src/protocol.rs` is production Rust source. The reference is a comment inside the `#[cfg(test)]` test module and is not compiled into the release binary. It is retained unchanged in this source tree; any privacy decision about it is outside this inventory.",
        }
        inventory["scrub_policy"]["note"] = "Private-origin repository names were replaced with generic descriptions in prose and help text. No fixture bytes, deployment pins or protocol identifiers were changed."
        inventory["verification"]["date_utc"] = "2026-11-14"
        inventory["verification"]["change_note"] = "FIX-04 was replaced in this review by a synthetic receipt authored in this repository; the three contract bytecode fixtures were not regenerated. The rights/notice checklist records the release-blocking actions."
        inventory["legal_artifacts"] = [
            a for a in inventory["legal_artifacts"] if a["path"] == LICENSE_REL.as_posix()
        ]
        for entry in inventory["fixtures"]:
            lic = entry.get("license", {})
            lic.pop("license_text", None)
            lic.pop("copyright", None)
            if entry["id"] in ("FIX-01", "FIX-02"):
                lic["rights_status"] = "unresolved; license identity is declared but redistribution authority and applicable notices are not established" if entry["id"] == "FIX-01" else "unresolved; the pinned source repository tree contains no LICENSE/NOTICE and redistribution authority is not established"
            elif entry["id"] == "FIX-03":
                lic["rights_status"] = "unresolved; authorship and redistribution authority remain for the rights holder to confirm"
        rr = inventory["rights_review"]
        rr["notice_applicability"] = "UNRESOLVED"
        rr["publication_decision"] = "BLOCKED pending review of rights and notice applicability; first-party ownership is owner-attested and not independently verified."
        rr.pop("publication_authorization", None)
        rr.pop("rights_decision", None)
        rr.pop("release_intent_authorization", None)
        rr["owner_attestation"] = {
            "status": "OWNER-ATTESTED \u2014 not independently verified",
            "scope": "The AstatineMiner and AstatineGenesisCoordinator contracts are first-party works developed and owned by the project owner.",
            "attested_on": "2026-11-15",
            "attestation_source": "The project owner explicitly confirmed ownership of the first-party ASTATINE mining and genesis coordinator contracts for Phase D; not independently verified.",
            "independent_verification": False,
        }
        rr["notice_checklist"]["status"] = "OPEN \u2014 publication remains BLOCKED"
        for item in rr["notice_checklist"]["items"]:
            if item["id"] == "RIGHTS-02":
                item["owner"] = "project owner and release approver"
                item["status"] = "OPEN"
                item["evidence"] = "rights_review.copyright_evidence; fixtures FIX-01 and FIX-02 both set release_archive_member to false."
            elif item["id"] == "RIGHTS-03":
                item["owner"] = "project owner"
                item["status"] = "OPEN"
                item["evidence"] = "tests/fixtures ships OPENZEPPELIN_LICENSE.txt only; no Apache-2.0 license text accompanies FIX-01 or FIX-02."
            elif item["id"] == "RIGHTS-04":
                item["owner"] = "project owner"
                item["status"] = "OPEN"
                item["evidence"] = "FIX-03 license.declaration_evidence; legal_artifacts OPENZEPPELIN_LICENSE.txt."
            elif item["id"] == "RIGHTS-05":
                item["owner"] = "release approver"
                item["status"] = "OPEN"
                item["evidence"] = "rights_review.publication_decision is BLOCKED."
        push = rr["review_ci_branch_push_authorization"]
        push["status"] = "AUTHORIZED \u2014 REVIEW/CI ONLY"
        push.pop("superseded_by", None)
        push.pop("superseded_on", None)
        push["authorized_by"] = "project owner"
        push["authorized_on"] = "2026-11-16"
        push["scope"] = "Push the fix/phase-e-e02-e07 remediation branch to the already-public repository solely for review and CI."
        push["public_repository_visibility"] = "The repository is already public. That visibility does not authorize a source archive, binary archive or release, tag or release publication, or workflow attestation dispatch."
        push["not_authorized"] = ["source archive distribution", "binary archive or release distribution", "tag or public release publication", "workflow attestation dispatch", "broader license grant or legal clearance", "resolution of RIGHTS-02 through RIGHTS-05"]
        push["rights_gate_unchanged"] = "RIGHTS-02 through RIGHTS-05 remain OPEN and blocking; source_distribution and binary_distribution remain BLOCKED."
        self.write_inventory(inventory)
        (self.root / APACHE_REL).unlink()
        (self.root / MIT_REL).unlink()
        (self.root / NOTICE_REL).unlink()
        result = VERIFIER.verify(self.root)
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["schema"], "astatine-fixture-provenance/v1")
        self.assertFalse(result["publication_authorized"])
        self.assertEqual(result["notice_checklist_status"], "OPEN \u2014 publication remains BLOCKED")
        self.assertNotEqual(result["blocking_open"], [])


if __name__ == "__main__":
    unittest.main()
